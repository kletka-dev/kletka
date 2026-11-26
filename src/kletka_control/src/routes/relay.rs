use axum::extract::ws::{
    CloseFrame as AxumCloseFrame, Message as AxumMsg, WebSocket, WebSocketUpgrade,
};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use kletka_types::{
    MAX_FILE_PULL_BYTES, MAX_FILE_PUSH_BYTES, MAX_SESSIONS_PER_USER, MAX_SESSIONS_PER_VM,
    RelayLimits, SESSION_IDLE_TIMEOUT_SECS, SESSION_ROW_TTL_SECS, SessionHeader, SessionKind,
};
use uuid::Uuid;

use crate::audit::{self, Event, RequestMeta};
use crate::auth::UserContext;
use crate::error::{ApiError, ApiResult};
use crate::routes::vms::find_vm;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedKind {
    Console,
    Exec,
    Proxy,
}

fn kind_matches(expected: ExpectedKind, kind: &SessionKind) -> bool {
    matches!(
        (expected, kind),
        (ExpectedKind::Console, SessionKind::Console { .. })
            | (ExpectedKind::Exec, SessionKind::Exec { .. })
            | (ExpectedKind::Proxy, SessionKind::Proxy { .. })
    )
}

fn axum_to_tungstenite(msg: AxumMsg) -> tokio_tungstenite::tungstenite::Message {
    use tokio_tungstenite::tungstenite::Message as TMsg;
    match msg {
        AxumMsg::Text(text) => TMsg::Text(text.to_string().into()),
        AxumMsg::Binary(data) => TMsg::Binary(data),
        AxumMsg::Ping(data) => TMsg::Ping(data),
        AxumMsg::Pong(data) => TMsg::Pong(data),
        AxumMsg::Close(frame) => TMsg::Close(frame.map(|f| {
            use tokio_tungstenite::tungstenite::protocol::frame::CloseFrame as TFrame;
            TFrame {
                code: f.code.into(),
                reason: f.reason.as_str().into(),
            }
        })),
    }
}

fn tungstenite_to_axum(msg: tokio_tungstenite::tungstenite::Message) -> Option<AxumMsg> {
    use tokio_tungstenite::tungstenite::Message as TMsg;
    match msg {
        TMsg::Text(text) => Some(AxumMsg::Text(text.to_string().into())),
        TMsg::Binary(data) => Some(AxumMsg::Binary(data)),
        TMsg::Ping(data) => Some(AxumMsg::Ping(data)),
        TMsg::Pong(data) => Some(AxumMsg::Pong(data)),
        TMsg::Close(frame) => Some(AxumMsg::Close(frame.map(|f| AxumCloseFrame {
            code: f.code.into(),
            reason: f.reason.as_str().into(),
        }))),
        TMsg::Frame(_) => None,
    }
}

fn http_to_ws(addr: &str) -> String {
    let base = addr.trim_end_matches('/');
    if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else {
        base.to_string()
    }
}

#[derive(Clone)]
pub struct Placement {
    pub session_id: Uuid,
    pub vm_id: String,
    pub node_id: String,
    pub node_addr: String,
    pub vm_name: String,
    pub namespace_id: String,
    pub secret: String,
}

async fn resolve_target(
    state: &AppState,
    vm: &crate::routes::vms::VmRow,
) -> ApiResult<(String, String, String)> {
    if vm.assigned_node.is_none() {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("vm '{}' is not placed on any node yet", vm.name),
        ));
    };
    let vm_id = vm.uuid()?;
    state.provisioner.relay_target(&vm_id).await
}

async fn check_and_record(
    state: &AppState,
    user: &UserContext,
    vm_key: &str,
    kind: &SessionKind,
) -> ApiResult<Placement> {
    let vm = find_vm(&state.db, user, vm_key).await?;
    let now = crate::db::now();
    crate::db::query("UPDATE vms SET last_active_at = ? WHERE id = ?")
        .bind(now)
        .bind(&vm.id)
        .execute(&state.db)
        .await?;
    let (per_vm,): (i64,) =
        crate::db::query_as("SELECT COUNT(*) FROM sessions WHERE vm_id = ? AND expires_at > ?")
            .bind(&vm.id)
            .bind(now)
            .fetch_one(&state.db)
            .await?;
    if per_vm as usize >= MAX_SESSIONS_PER_VM {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "vm '{}' already has {per_vm} open sessions (max {MAX_SESSIONS_PER_VM})",
                vm.name
            ),
        ));
    }
    let (per_user,): (i64,) = crate::db::query_as(
        "SELECT COUNT(*) FROM sessions WHERE created_by = ? AND expires_at > ?",
    )
    .bind(user.user_id.to_string())
    .bind(now)
    .fetch_one(&state.db)
    .await?;
    if per_user as usize >= MAX_SESSIONS_PER_USER {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            format!("you already have {per_user} open sessions (max {MAX_SESSIONS_PER_USER})"),
        ));
    }
    let (node_id, node_addr, secret) = resolve_target(state, &vm).await?;
    let session_id = Uuid::new_v4();
    let kind_json =
        serde_json::to_string(kind).map_err(|e| ApiError::internal(format!("bad kind: {e}")))?;
    crate::db::query(
        "INSERT INTO sessions (id, vm_id, node_id, kind_json, created_by, expires_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(session_id.to_string())
    .bind(&vm.id)
    .bind(&node_id)
    .bind(kind_json)
    .bind(user.user_id.to_string())
    .bind(crate::db::now() + SESSION_ROW_TTL_SECS as i64)
    .execute(&state.db)
    .await?;
    Ok(Placement {
        session_id,
        vm_id: vm.id,
        node_id,
        node_addr,
        vm_name: vm.name,
        namespace_id: vm.namespace_id,
        secret,
    })
}

async fn relay(
    state: AppState,
    user: UserContext,
    meta: RequestMeta,
    vm_key: String,
    expected: ExpectedKind,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let placeholder = match expected {
        ExpectedKind::Console => SessionKind::Console { serial: false },
        ExpectedKind::Exec => SessionKind::Exec {
            cmd: Vec::new(),
            pty: false,
        },
        ExpectedKind::Proxy => SessionKind::Proxy { tcp_port: 0 },
    };
    let placement = check_and_record(&state, &user, &vm_key, &placeholder).await?;
    let vm_name = placement.vm_name.clone();
    let (header_tx, header_rx) = tokio::sync::oneshot::channel::<SessionKind>();
    {
        let db = state.db.clone();
        let user_id = user.user_id;
        let vm_id = placement.vm_id.clone();
        let namespace_id = placement.namespace_id.clone();
        tokio::spawn(async move {
            if let Ok(kind) = header_rx.await {
                let (action, detail) = session_audit(&kind);
                audit::record(
                    &db,
                    Event::user(user_id, action, &meta)
                        .vm(vm_id, vm_name)
                        .namespace(namespace_id)
                        .detail(detail),
                )
                .await;
            }
        });
    }
    Ok(ws.on_upgrade(move |socket| {
        pipe(socket, state, user, vm_key, expected, placement, header_tx)
    }))
}

fn session_audit(kind: &SessionKind) -> (&'static str, serde_json::Value) {
    match kind {
        SessionKind::Exec { cmd, pty } => (
            "session.exec",
            serde_json::json!({ "cmd": cmd.join(" "), "pty": pty }),
        ),
        SessionKind::Console { serial } => {
            ("session.console", serde_json::json!({ "serial": serial }))
        }
        SessionKind::Proxy { tcp_port } => {
            ("session.proxy", serde_json::json!({ "port": tcp_port }))
        }
        SessionKind::FilePush { dst, .. } => ("file.push", serde_json::json!({ "path": dst })),
        SessionKind::FilePull { src } => ("file.pull", serde_json::json!({ "path": src })),
    }
}

type LimitsFn = fn(&SessionKind) -> RelayLimits;

#[allow(clippy::too_many_arguments)]
async fn pipe(
    mut cli: WebSocket,
    state: AppState,
    user: UserContext,
    vm_key: String,
    expected: ExpectedKind,
    placement: Placement,
    header_tx: tokio::sync::oneshot::Sender<SessionKind>,
) {
    let renew_db = state.db.clone();
    let renew_session_id = placement.session_id.to_string();
    let renewal = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(SESSION_ROW_TTL_SECS / 3));
        interval.tick().await;
        loop {
            interval.tick().await;
            let expires_at = crate::db::now() + SESSION_ROW_TTL_SECS as i64;
            let _ = crate::db::query("UPDATE sessions SET expires_at = ? WHERE id = ?")
                .bind(expires_at)
                .bind(&renew_session_id)
                .execute(&renew_db)
                .await;
        }
    });
    let mut up_bytes: u64 = 0;
    let mut down_bytes: u64 = 0;
    let outcome = pipe_inner(
        &mut cli,
        &placement,
        &placement.secret,
        expected,
        &mut up_bytes,
        &mut down_bytes,
        SessionKind::relay_limits,
        Some(header_tx),
    )
    .await;
    renewal.abort();
    tracing::info!(
        session = %placement.session_id,
        vm = %vm_key,
        node = %placement.node_id,
        user = %user.user_id,
        up = up_bytes,
        down = down_bytes,
        outcome,
        "relay session closed"
    );
    let _ = cli.close().await;
    let _ = crate::db::query("DELETE FROM sessions WHERE id = ?")
        .bind(placement.session_id.to_string())
        .execute(&state.db)
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn pipe_inner(
    cli: &mut WebSocket,
    placement: &Placement,
    node_secret: &str,
    expected: ExpectedKind,
    up_bytes: &mut u64,
    down_bytes: &mut u64,
    limits_fn: LimitsFn,
    header_tx: Option<tokio::sync::oneshot::Sender<SessionKind>>,
) -> &'static str {
    use tokio_tungstenite::tungstenite::Message as TMsg;

    let header_msg = match tokio::time::timeout(
        std::time::Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS),
        cli.recv(),
    )
    .await
    {
        Ok(Some(Ok(AxumMsg::Text(text)))) => text.to_string(),
        Ok(Some(Ok(_))) => return "first-frame-not-text",
        _ => return "header-timeout",
    };
    let header: SessionHeader = match serde_json::from_str(&header_msg) {
        Ok(header) => header,
        Err(_) => return "bad-header",
    };
    if !kind_matches(expected, &header.kind) {
        return "kind-mismatch";
    }
    if let Some(tx) = header_tx {
        let _ = tx.send(header.kind.clone());
    }

    let node_url = format!(
        "{}/internal/session?vm={}",
        http_to_ws(&placement.node_addr),
        placement.vm_id
    );
    let request = match tokio_tungstenite::tungstenite::handshake::client::Request::builder()
        .method("GET")
        .uri(node_url.as_str())
        .header(
            "Host",
            placement
                .node_addr
                .trim_start_matches("http://")
                .trim_start_matches("https://"),
        )
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .header("x-node-secret", node_secret)
        .body(())
    {
        Ok(request) => request,
        Err(_) => return "node-request-build-failed",
    };
    let (mut node, _) = match tokio_tungstenite::connect_async(request).await {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(node = %placement.node_id, url = %node_url, %err, "node dial failed");
            return "node-unreachable";
        }
    };
    if node.send(TMsg::Text(header_msg.into())).await.is_err() {
        return "node-header-send-failed";
    }

    let limits = limits_fn(&header.kind);
    let max_deadline = limits
        .max_secs
        .map(|secs| tokio::time::Instant::now() + std::time::Duration::from_secs(secs));
    let mut idle = limits
        .idle_secs
        .map(|secs| tokio::time::interval(std::time::Duration::from_secs(secs)));
    if let Some(idle) = idle.as_mut() {
        idle.tick().await;
    }
    let mut last_activity = tokio::time::Instant::now();
    loop {
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(max_deadline.unwrap_or_else(|| {
                tokio::time::Instant::now() + std::time::Duration::from_secs(365 * 24 * 3600)
            })) => return "max-time",
            _idle_tick = async {
                match idle.as_mut() {
                    Some(idle) => Some(idle.tick().await),
                    None => std::future::pending().await,
                }
            } => {
                let idle_secs = limits.idle_secs.expect("idle timer set implies a limit");
                if last_activity.elapsed() >= std::time::Duration::from_secs(idle_secs) {
                    return "idle-timeout";
                }
            }
            from_cli = cli.recv() => {
                match from_cli {
                    Some(Ok(msg)) => {
                        last_activity = tokio::time::Instant::now();
                        if let AxumMsg::Binary(data) = &msg {
                            *up_bytes += data.len() as u64;
                        }
                        if *up_bytes + *down_bytes > limits.byte_cap {
                            return "byte-cap";
                        }
                        let tmsg = axum_to_tungstenite(msg);
                        let was_close = matches!(tmsg, TMsg::Close(_));
                        if node.send(tmsg).await.is_err() {
                            return "node-send-failed";
                        }
                        if was_close {
                            return "cli-closed";
                        }
                    }
                    _ => {
                        let _ = node.send(TMsg::Close(None)).await;
                        return "cli-closed";
                    }
                }
            }
            from_node = node.next() => {
                match from_node {
                    Some(Ok(tmsg)) => {
                        last_activity = tokio::time::Instant::now();
                        let capped = if let TMsg::Binary(data) = &tmsg {
                            *down_bytes += data.len() as u64;
                            *up_bytes + *down_bytes > limits.byte_cap
                        } else {
                            false
                        };
                        if capped {
                            return "byte-cap";
                        }
                        match tungstenite_to_axum(tmsg) {
                            Some(amsg) => {
                                let was_close = matches!(amsg, AxumMsg::Close(_));
                                if cli.send(amsg).await.is_err() {
                                    return "cli-send-failed";
                                }
                                if was_close {
                                    return "node-closed";
                                }
                            }
                            None => return "node-closed",
                        }
                    }
                    _ => return "node-closed",
                }
            }
        }
    }
}

pub async fn console(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    relay(state, user, meta, id, ExpectedKind::Console, ws).await
}

pub async fn exec(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    relay(state, user, meta, id, ExpectedKind::Exec, ws).await
}

pub async fn proxy(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    relay(state, user, meta, id, ExpectedKind::Proxy, ws).await
}

pub async fn file_push(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Query(query): Query<FilePushQuery>,
    _headers: HeaderMap,
    body: axum::body::Body,
) -> ApiResult<Response> {
    let kind = SessionKind::FilePush {
        dst: query.dst.clone(),
        mode: query.mode,
    };
    let placement = check_and_record(&state, &user, &id, &kind).await?;
    audit_file(&state, &user, &meta, &placement, &kind, query.sudo).await;
    let bytes = axum::body::to_bytes(body, MAX_FILE_PUSH_BYTES)
        .await
        .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds 256 MiB cap"))?;
    let mut url = format!(
        "{}/internal/file/push?vm={}&dst={}",
        placement.node_addr.trim_end_matches('/'),
        kletka_types::urlencode(&placement.vm_id),
        kletka_types::urlencode(&query.dst),
    );
    if query.sudo {
        url.push_str("&sudo=true");
    }
    if let Some(mode) = query.mode {
        url.push_str(&format!("&mode={mode}"));
    }
    let res = state
        .provisioner
        .http
        .post(&url)
        .header("x-node-secret", &placement.secret)
        .header("content-type", "application/octet-stream")
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("node unreachable: {e}")))?;
    let status = res.status();
    let body = res
        .bytes()
        .await
        .map_err(|e| ApiError::internal(format!("node read: {e}")))?;
    tracing::info!(
        session = %placement.session_id,
        vm = %id,
        node = %placement.node_id,
        user = %user.user_id,
        up = bytes.len(),
        status = %status,
        "file push relayed"
    );
    let axum_status = crate::k8s::http_status(status.as_u16());
    Ok((axum_status, headers_out(), body.to_vec()).into_response())
}

async fn audit_file(
    state: &AppState,
    user: &UserContext,
    meta: &RequestMeta,
    placement: &Placement,
    kind: &SessionKind,
    sudo: bool,
) {
    let (action, mut detail) = session_audit(kind);
    detail["sudo"] = serde_json::Value::Bool(sudo);
    audit::record(
        &state.db,
        Event::user(user.user_id, action, meta)
            .vm(&placement.vm_id, &placement.vm_name)
            .namespace(&placement.namespace_id)
            .detail(detail),
    )
    .await;
}

pub async fn file_pull(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Query(query): Query<FilePullQuery>,
) -> ApiResult<Response> {
    let kind = SessionKind::FilePull {
        src: query.src.clone(),
    };
    let placement = check_and_record(&state, &user, &id, &kind).await?;
    audit_file(&state, &user, &meta, &placement, &kind, query.sudo).await;
    let mut url = format!(
        "{}/internal/file/pull?vm={}&src={}",
        placement.node_addr.trim_end_matches('/'),
        kletka_types::urlencode(&placement.vm_id),
        kletka_types::urlencode(&query.src),
    );
    if query.sudo {
        url.push_str("&sudo=true");
    }
    let res = state
        .provisioner
        .http
        .get(&url)
        .header("x-node-secret", &placement.secret)
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("node unreachable: {e}")))?;
    let status = res.status();
    if status.is_success()
        && res
            .content_length()
            .is_some_and(|len| len > MAX_FILE_PULL_BYTES as u64)
    {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file exceeds 256 MiB cap",
        ));
    }
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let down = res.content_length().unwrap_or(0);
    tracing::info!(
        session = %placement.session_id,
        vm = %id,
        node = %placement.node_id,
        user = %user.user_id,
        down,
        status = %status,
        "file pull relayed"
    );
    let axum_status = crate::k8s::http_status(status.as_u16());
    Ok((
        axum_status,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        axum::body::Body::from_stream(res.bytes_stream()),
    )
        .into_response())
}

#[derive(Debug, serde::Deserialize)]
pub struct FilePushQuery {
    pub dst: String,
    #[serde(default)]
    pub sudo: bool,
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Debug, serde::Deserialize)]
pub struct FilePullQuery {
    pub src: String,
    #[serde(default)]
    pub sudo: bool,
}

fn headers_out() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().expect("static"),
    );
    headers
}

#[cfg(test)]
mod tests {
    #[test]
    fn sessions_map_to_audit_events() {
        let (action, detail) = session_audit(&SessionKind::Exec {
            cmd: vec!["uname".into(), "-a".into()],
            pty: false,
        });
        assert_eq!(action, "session.exec");
        assert_eq!(detail, serde_json::json!({"cmd": "uname -a", "pty": false}));
        assert_eq!(
            session_audit(&SessionKind::Proxy { tcp_port: 8080 }),
            ("session.proxy", serde_json::json!({"port": 8080}))
        );
        assert_eq!(
            session_audit(&SessionKind::FilePull {
                src: "/etc/hosts".into()
            })
            .0,
            "file.pull"
        );
    }

    use super::*;
    use crate::k8s::{K8sConfig, K8sProvisioner, pod_name};
    use crate::state::AppState;
    use kletka_types::RELAY_BYTE_CAP;
    use tower::ServiceExt;

    use crate::testing::TEST_PASSWORD;

    #[tokio::test]
    async fn console_tunnel_carries_header_resize_and_trailer() {
        let agent_listener = match tokio::net::TcpListener::bind("127.0.0.1:8081").await {
            Ok(listener) => listener,
            Err(err) => {
                eprintln!("skipping: cannot bind agent port 8081: {err}");
                return;
            }
        };

        let vm_id = uuid::Uuid::new_v4();
        let pod = pod_name(&vm_id);

        let agent = tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message as TMsg;

            let (stream, _) = agent_listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            async fn next_text(
                ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
            ) -> String {
                match ws.next().await {
                    Some(Ok(TMsg::Text(text))) => text.to_string(),
                    Some(Ok(TMsg::Binary(data))) => {
                        panic!("expected a text frame, got binary {data:?}")
                    }
                    _ => panic!("session ended before the expected text frame"),
                }
            }

            let header = next_text(&mut ws).await;
            assert!(header.contains(r#""kind":"console""#), "{header}");
            assert!(header.contains(r#""serial":false"#), "{header}");
            assert!(header.contains(r#""pty_cols":140"#), "{header}");
            assert!(header.contains(r#""pty_rows":40"#), "{header}");
            assert!(header.contains(r#""term":"xterm-256color""#), "{header}");
            assert!(header.contains(r#""colorterm":"truecolor""#), "{header}");

            let resize = next_text(&mut ws).await;
            assert_eq!(resize, r#"{"pty_cols":99,"pty_rows":42}"#);

            ws.send(TMsg::Binary(b"tunnel-ok".to_vec().into()))
                .await
                .unwrap();
            ws.send(TMsg::Text(r#"{"exit":0}"#.into())).await.unwrap();
        });

        let pod_json = serde_json::json!({
            "apiVersion": "v1", "kind": "Pod",
            "metadata": { "name": pod, "namespace": "kletka-vms" },
            "status": { "phase": "Running", "podIP": "127.0.0.1" }
        });
        let secret_json = serde_json::json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": { "name": format!("{pod}-token"), "namespace": "kletka-vms" },
            "data": { "token": "dDBrM24=" }
        });
        let kube_client = kube::Client::new(
            tower::service_fn(move |req: axum::http::Request<kube::client::Body>| {
                let pod_json = pod_json.clone();
                let secret_json = secret_json.clone();
                async move {
                    let body = if req.uri().path().contains("/secrets/") {
                        secret_json
                    } else {
                        pod_json
                    };
                    let response = axum::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(kube::client::Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap();
                    Ok::<_, tower::BoxError>(response)
                }
            }),
            "kletka-vms".to_string(),
        );

        let dir = std::env::temp_dir().join(format!("kletka-relay-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::connect(&format!("sqlite:{}/t.db?mode=rwc", dir.display()))
            .await
            .unwrap();
        let provisioner = K8sProvisioner::for_tests_with_client(K8sConfig::default(), kube_client);
        let state = AppState::new(
            pool.clone(),
            std::sync::Arc::new(provisioner),
            "test-admin".to_string(),
            crate::ratelimit::RateLimits::disabled(),
            Default::default(),
        );
        let app = crate::router(state);

        let signup = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/auth/signup")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_string(
                            &serde_json::json!({"email": "relay@example.com", "password": TEST_PASSWORD}),
                        )
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let signup_body = http_body_util::BodyExt::collect(signup.into_body())
            .await
            .unwrap()
            .to_bytes();
        let signup_json: serde_json::Value = serde_json::from_slice(&signup_body).unwrap();
        let token = signup_json["token"].as_str().unwrap().to_string();
        let user_id = signup_json["user_id"].as_str().unwrap().to_string();

        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, \
             status, assigned_node, created_at)
             VALUES (?, ?, 't1', 'default', 1, 512, 0, 1, 'running', ?, 0)",
        )
        .bind(vm_id.to_string())
        .bind(&user_id)
        .bind(&pod)
        .execute(&pool)
        .await
        .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("ws://{addr}/v1/vms/{vm_id}/console");
        let request = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri(url.as_str())
            .header("host", format!("{addr}"))
            .header("authorization", format!("Bearer {token}"))
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header(
                "sec-websocket-key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .unwrap();
        let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();

        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as TMsg;
        ws.send(TMsg::Text(
            r#"{"kind":"console","serial":false,"pty_cols":140,"pty_rows":40,"term":"xterm-256color","colorterm":"truecolor"}"#
                .into(),
        ))
        .await
        .unwrap();
        ws.send(TMsg::Text(r#"{"pty_cols":99,"pty_rows":42}"#.into()))
            .await
            .unwrap();

        let mut saw_output = false;
        let mut saw_trailer = false;
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(30), ws.next()).await {
                Ok(Some(Ok(TMsg::Binary(data)))) if data.as_ref() == b"tunnel-ok" => {
                    saw_output = true;
                }
                Ok(Some(Ok(TMsg::Text(text)))) if text.contains(r#""exit":0"#) => {
                    saw_trailer = true;
                    break;
                }
                Ok(Some(Ok(_))) => {}
                _ => break,
            }
        }
        assert!(saw_output, "agent output never crossed the relay");
        assert!(saw_trailer, "exit trailer never crossed the relay");

        agent.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn test_limits(kind: &SessionKind) -> RelayLimits {
        match kind {
            SessionKind::Console { .. } | SessionKind::Proxy { .. } => {
                SessionKind::relay_limits(kind)
            }
            _ => RelayLimits {
                idle_secs: Some(1),
                max_secs: Some(10),
                byte_cap: RELAY_BYTE_CAP,
            },
        }
    }

    async fn spawn_fake_node() -> (String, tokio::sync::oneshot::Receiver<String>) {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message as TMsg;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let header = loop {
                match ws.next().await {
                    Some(Ok(TMsg::Text(text))) => break text.to_string(),
                    Some(Ok(_)) => continue,
                    other => panic!("fake node: session ended before the header: {other:?}"),
                }
            };
            let _ = tx.send(header);
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    TMsg::Binary(data) => {
                        if ws.send(TMsg::Binary(data)).await.is_err() {
                            break;
                        }
                    }
                    TMsg::Close(_) => break,
                    _ => {}
                }
            }
        });
        (format!("http://{addr}"), rx)
    }

    async fn spawn_relay_pipes(
        placement: Placement,
        expected: ExpectedKind,
        limits_fn: LimitsFn,
    ) -> (String, tokio::sync::mpsc::UnboundedReceiver<&'static str>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let app = axum::Router::new().route(
            "/relay-pipe",
            axum::routing::get(move |ws: WebSocketUpgrade| {
                let placement = placement.clone();
                let tx = tx.clone();
                async move {
                    ws.on_upgrade(move |mut sock| async move {
                        let mut up_bytes = 0u64;
                        let mut down_bytes = 0u64;
                        let outcome = pipe_inner(
                            &mut sock,
                            &placement,
                            &placement.secret,
                            expected,
                            &mut up_bytes,
                            &mut down_bytes,
                            limits_fn,
                            None,
                        )
                        .await;
                        let _ = tx.send(outcome);
                        let _ = sock.close().await;
                    })
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), rx)
    }

    #[tokio::test]
    async fn relay_reaps_idle_interactive_sessions() {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message as TMsg;

        let (node_addr, header_rx) = spawn_fake_node().await;
        let placement = Placement {
            session_id: uuid::Uuid::new_v4(),
            vm_id: "vm-1".to_string(),
            vm_name: "vm-1".to_string(),
            namespace_id: "ns-1".to_string(),
            node_id: "node-1".to_string(),
            node_addr,
            secret: "node-secret".to_string(),
        };
        let (relay_addr, mut outcomes) =
            spawn_relay_pipes(placement, ExpectedKind::Exec, test_limits).await;

        let (mut ws, _) = tokio_tungstenite::connect_async(
            format!("{relay_addr}/relay-pipe").replacen("http://", "ws://", 1),
        )
        .await
        .unwrap();
        ws.send(TMsg::Text(
            r#"{"kind":"exec","cmd":["true"],"pty":false}"#.into(),
        ))
        .await
        .unwrap();
        let header = tokio::time::timeout(std::time::Duration::from_secs(10), header_rx)
            .await
            .expect("header relayed")
            .expect("fake node read the header");
        assert!(header.contains(r#""kind":"exec""#), "{header}");

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), outcomes.recv())
            .await
            .expect("relay reaped the idle session")
            .expect("outcome channel open");
        assert_eq!(outcome, "idle-timeout");
        let closed = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("close observed");
        assert!(closed.is_some(), "relay closed the client side");
    }

    #[tokio::test]
    async fn relay_console_session_outlives_idle_limit() {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message as TMsg;

        let (node_addr, header_rx) = spawn_fake_node().await;
        let placement = Placement {
            session_id: uuid::Uuid::new_v4(),
            vm_id: "vm-1".to_string(),
            vm_name: "vm-1".to_string(),
            namespace_id: "ns-1".to_string(),
            node_id: "node-1".to_string(),
            node_addr,
            secret: "node-secret".to_string(),
        };
        let (relay_addr, mut outcomes) =
            spawn_relay_pipes(placement, ExpectedKind::Console, test_limits).await;

        let (mut ws, _) = tokio_tungstenite::connect_async(
            format!("{relay_addr}/relay-pipe").replacen("http://", "ws://", 1),
        )
        .await
        .unwrap();
        ws.send(TMsg::Text(r#"{"kind":"console","serial":false}"#.into()))
            .await
            .unwrap();
        let header = tokio::time::timeout(std::time::Duration::from_secs(10), header_rx)
            .await
            .expect("header relayed")
            .expect("fake node read the header");
        assert!(header.contains(r#""kind":"console""#), "{header}");

        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), outcomes.recv())
                .await
                .is_err(),
            "relay must keep an idle console open"
        );
        ws.send(TMsg::Binary(b"still connected".to_vec().into()))
            .await
            .unwrap();
        match tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("console response")
        {
            Some(Ok(TMsg::Binary(data))) => assert_eq!(data.as_ref(), b"still connected"),
            other => panic!("unexpected console response: {other:?}"),
        }
        ws.close(None).await.unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(10), outcomes.recv())
                .await
                .expect("relay closed")
                .expect("outcome channel open"),
            "cli-closed"
        );
    }

    #[tokio::test]
    async fn relay_proxy_session_outlives_interactive_idle_cap() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message as TMsg;

        let (node_addr, header_rx) = spawn_fake_node().await;
        let placement = Placement {
            session_id: uuid::Uuid::new_v4(),
            vm_id: "vm-1".to_string(),
            vm_name: "vm-1".to_string(),
            namespace_id: "ns-1".to_string(),
            node_id: "node-1".to_string(),
            node_addr,
            secret: "node-secret".to_string(),
        };
        let (relay_addr, mut outcomes) =
            spawn_relay_pipes(placement, ExpectedKind::Proxy, test_limits).await;

        let (mut ws, _) = tokio_tungstenite::connect_async(
            format!("{relay_addr}/relay-pipe").replacen("http://", "ws://", 1),
        )
        .await
        .unwrap();
        ws.send(TMsg::Text(r#"{"kind":"proxy","tcp_port":3000}"#.into()))
            .await
            .unwrap();
        let header = tokio::time::timeout(std::time::Duration::from_secs(10), header_rx)
            .await
            .expect("header relayed")
            .expect("fake node read the header");
        assert!(header.contains(r#""kind":"proxy""#), "{header}");

        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        ws.send(TMsg::Binary(b"ping".to_vec().into()))
            .await
            .unwrap();
        let echo = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("echo arrived")
            .expect("session open")
            .expect("frame ok");
        assert_eq!(echo, TMsg::Binary(b"ping".to_vec().into()));
        assert!(
            outcomes.try_recv().is_err(),
            "proxy session must not be reaped while quiet"
        );

        let _ = ws.close(None).await;
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), outcomes.recv())
            .await
            .expect("session ended")
            .expect("outcome channel open");
        assert_eq!(outcome, "cli-closed");
    }
}
