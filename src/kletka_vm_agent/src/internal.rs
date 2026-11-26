use crate::reply::{json_error, json_ok, reader_body};
use crate::session::SessionState;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use kletka::checkpoint::CheckpointOperation;
use kletka::store::VmState;
use kletka_runtime::error::RuntimeError;
use kletka_runtime::runtime::VmRuntime;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Clone)]
pub struct InternalState {
    pub session: SessionState,
    pub vm_id: Uuid,
    pub runtime: Arc<VmRuntime>,
}

pub fn router(state: InternalState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/internal/lifecycle", post(lifecycle))
        .route("/internal/snapshot", post(snapshot))
        .route("/internal/wireguard", put(wireguard))
        .route("/internal/disk", get(disk_get).put(disk_put))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<InternalState>) -> (StatusCode, String) {
    let record = match state.runtime.find_vm(&state.vm_id.to_string()) {
        Ok(record) => record,
        Err(err) => return (StatusCode::SERVICE_UNAVAILABLE, err.to_string()),
    };
    if record.state != VmState::Running {
        return (StatusCode::SERVICE_UNAVAILABLE, "vm not running".into());
    }
    if state.runtime.guest_ssh_ready(&record).await {
        (StatusCode::OK, "running".into())
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "guest ssh login not ready yet".into(),
        )
    }
}

use kletka_types::{LifecycleOp, LifecycleRequest, SnapshotOp, SnapshotRequest, WireguardRequest};

async fn lifecycle(
    State(state): State<InternalState>,
    headers: HeaderMap,
    Json(req): Json<LifecycleRequest>,
) -> Response {
    if let Some(rejection) = state.session.reject_unauthorized(&headers) {
        return rejection;
    }
    let LifecycleOp::Stop = req.op;
    let runtime = state.runtime.clone();
    let key = state.vm_id.to_string();
    let result = tokio::spawn(async move { runtime.stop_vm(&key).await })
        .await
        .unwrap_or_else(|err| Err(format!("stop task failed: {err}").into()));
    match result {
        Ok(_) => json_ok(serde_json::json!({ "status": "ok" })),
        Err(RuntimeError::VmNotFound(_)) => {
            json_ok(serde_json::json!({ "status": "already stopped" }))
        }
        Err(err) => json_error(StatusCode::CONFLICT, err),
    }
}

async fn wireguard(
    State(state): State<InternalState>,
    headers: HeaderMap,
    Json(req): Json<WireguardRequest>,
) -> Response {
    if let Some(rejection) = state.session.reject_unauthorized(&headers) {
        return rejection;
    }
    if req
        .wireguard_config
        .as_ref()
        .is_some_and(|config| config.len() > kletka_types::MAX_WIREGUARD_CONFIG_BYTES)
    {
        return json_error(StatusCode::BAD_REQUEST, "wireguard config is too large");
    }
    let record = match state.runtime.find_vm(&state.vm_id.to_string()) {
        Ok(record) => record,
        Err(err) => {
            return json_error(StatusCode::CONFLICT, err);
        }
    };
    if record.state != VmState::Running {
        return json_error(StatusCode::CONFLICT, "vm is not running");
    }
    match crate::session::configure_wireguard(
        &state.session.data_dir,
        &state.vm_id.to_string(),
        req.wireguard_config.as_deref(),
    )
    .await
    {
        Ok(()) => json_ok(serde_json::json!({ "status": "ok" })),
        Err(err) => json_error(StatusCode::CONFLICT, err),
    }
}

async fn snapshot(
    State(state): State<InternalState>,
    headers: HeaderMap,
    Json(req): Json<SnapshotRequest>,
) -> Response {
    if let Some(rejection) = state.session.reject_unauthorized(&headers) {
        return rejection;
    }

    let vm = state.vm_id.to_string();
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string);
    let operation = match (req.op, name) {
        (SnapshotOp::List, _) => CheckpointOperation::List(vm),
        (SnapshotOp::Create, Some(name)) => CheckpointOperation::Create {
            vm,
            name,
            memory: req.memory,
        },
        (SnapshotOp::Delete, Some(name)) => CheckpointOperation::Delete { vm, name },
        (SnapshotOp::Rollback, Some(name)) => CheckpointOperation::Rollback { vm, name },
        (op, None) => {
            let what = match op {
                SnapshotOp::Create => "create",
                SnapshotOp::Delete => "delete",
                SnapshotOp::Rollback => "rollback",
                SnapshotOp::List => "list",
            };
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("{what} needs a snapshot name"),
            );
        }
    };

    match state.runtime.checkpoint(operation).await {
        Ok(data) => json_ok(match req.op {
            SnapshotOp::List => serde_json::json!({ "snapshots": data }),
            SnapshotOp::Create => serde_json::json!({ "snapshot": data }),
            SnapshotOp::Delete | SnapshotOp::Rollback => data,
        }),
        Err(err) => {
            let status = match err {
                RuntimeError::VmNotFound(_) | RuntimeError::CheckpointNotFound(_) => {
                    StatusCode::NOT_FOUND
                }
                RuntimeError::NotStopped { .. } => StatusCode::CONFLICT,
                RuntimeError::Failed(_) => StatusCode::BAD_REQUEST,
            };
            json_error(status, err)
        }
    }
}

const DISK_CHUNK: usize = 512 * 1024;

fn instance_overlay(session: &crate::session::SessionState, vm_id: &Uuid) -> std::path::PathBuf {
    session.instance_dir(vm_id).join("overlay.ext4")
}

async fn disk_get(State(state): State<InternalState>, headers: HeaderMap) -> Response {
    if let Some(rejection) = state.session.reject_unauthorized(&headers) {
        return rejection;
    }
    let record = match state.runtime.find_vm(&state.vm_id.to_string()) {
        Ok(record) => record,
        Err(err) => {
            return json_error(StatusCode::NOT_FOUND, err);
        }
    };
    if record.state != VmState::Stopped {
        return json_error(StatusCode::CONFLICT, "vm is not stopped");
    }
    let Some(overlay) = record.overlay_path.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            "vm has no CoW overlay; clone requires an overlay-boot image",
        );
    };
    let file = match tokio::fs::File::open(&overlay).await {
        Ok(file) => file,
        Err(err) => {
            return json_error(
                StatusCode::NOT_FOUND,
                format!("cannot open the vm disk: {err}"),
            );
        }
    };
    let len = tokio::fs::metadata(&overlay)
        .await
        .map(|m| m.len())
        .unwrap_or(0);
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_LENGTH, len.to_string())],
        reader_body(file, DISK_CHUNK),
    )
        .into_response()
}

async fn disk_put(
    State(state): State<InternalState>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> Response {
    if let Some(rejection) = state.session.reject_unauthorized(&headers) {
        return rejection;
    }
    if let Ok(record) = state.runtime.find_vm(&state.vm_id.to_string())
        && record.state == VmState::Running
    {
        return json_error(
            StatusCode::CONFLICT,
            "vm is running; clone into it would corrupt the disk",
        );
    }
    let overlay = instance_overlay(&state.session, &state.vm_id);
    let tmp = overlay.with_extension("ext4.clone-part");
    if let Some(parent) = overlay.parent()
        && let Err(err) = tokio::fs::create_dir_all(parent).await
    {
        return disk_put_error("cannot create the instance dir", err, &tmp).await;
    }
    let _ = tokio::fs::remove_file(&tmp).await;
    let result = disk_put_stream(body, &tmp, &overlay).await;
    match result {
        Ok(written) => {
            tracing::info!(
                vm = %state.vm_id,
                written,
                "clone disk installed as the vm overlay"
            );
            json_ok(serde_json::json!({ "size": written }))
        }
        Err((message, err)) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            let (status, detail) = match err {
                Some(err) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("{message}: {err}"),
                ),
                None => (StatusCode::PAYLOAD_TOO_LARGE, message),
            };
            tracing::warn!(vm = %state.vm_id, %detail, "clone disk receive failed");
            json_error(status, detail)
        }
    }
}

async fn disk_put_stream(
    body: axum::body::Body,
    tmp: &std::path::Path,
    overlay: &std::path::Path,
) -> Result<u64, (String, Option<std::io::Error>)> {
    let cap = kletka_types::MAX_VM_DISK_MIB as u64 * 1024 * 1024;
    let mut file = tokio::fs::File::create(tmp).await.map_err(|err| {
        (
            "cannot create the clone disk staging file".to_string(),
            Some(err),
        )
    })?;
    let mut written: u64 = 0;
    let mut stream = body.into_data_stream();
    use futures_util::StreamExt as _;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|err| {
            (
                "cannot receive the clone disk body".to_string(),
                Some(std::io::Error::other(err.to_string())),
            )
        })?;
        written += chunk.len() as u64;
        if written > cap {
            return Err(("the clone disk exceeds the disk size cap".to_string(), None));
        }
        file.write_all(&chunk)
            .await
            .map_err(|err| ("cannot write the clone disk".to_string(), Some(err)))?;
    }
    file.sync_all()
        .await
        .map_err(|err| ("cannot flush the clone disk".to_string(), Some(err)))?;
    tokio::fs::rename(tmp, overlay)
        .await
        .map_err(|err| ("cannot install the clone disk".to_string(), Some(err)))?;
    Ok(written)
}

async fn disk_put_error(what: &str, err: std::io::Error, tmp: &std::path::Path) -> Response {
    let _ = tokio::fs::remove_file(tmp).await;
    json_error(StatusCode::INTERNAL_SERVER_ERROR, format!("{what}: {err}"))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    fn state() -> InternalState {
        let vm_id = Uuid::new_v4();
        let data_dir = std::env::temp_dir().join(format!("kletka-agent-test-{vm_id}"));
        let paths = kletka::system::KletkaPaths::with_data_dir(&data_dir);
        let runtime = Arc::new(VmRuntime::new(paths).unwrap());
        InternalState {
            session: SessionState {
                node_secret: "t0k3n".into(),
                node_id: "pod".into(),
                data_dir,
            },
            vm_id,
            runtime,
        }
    }

    fn put_record(state: &InternalState, vm_state: VmState, overlay: Option<std::path::PathBuf>) {
        let paths = kletka::system::KletkaPaths::with_data_dir(&state.session.data_dir);
        paths.ensure().unwrap();
        let registry = kletka::store::Registry::open(&paths);
        let record = registry
            .list()
            .unwrap()
            .into_iter()
            .find(|record| record.id == state.vm_id);
        let exists = record.is_some();
        let mut record = record.unwrap_or(kletka::store::VmRecord {
            id: state.vm_id,
            name: state.vm_id.to_string(),
            image: "default".into(),
            state: vm_state,
            kernel_path: "/img/vmlinux".into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            overlay_path: overlay.clone(),
            vsock_cid: None,
            network: None,
            fc_pid: None,
            slirp_pid: None,
            ssh_addr: None,
            ssh_port: None,
            vcpu_count: 1,
            memory_mib: 128,
            disk_mib: 256,
            created_at: kletka_types::time::Timestamp::UNIX_EPOCH,
        });
        record.state = vm_state;
        record.overlay_path = overlay;
        if exists {
            registry.update(record).unwrap();
        } else {
            registry.insert(record).unwrap();
        }
    }

    fn overlay_of(state: &InternalState) -> std::path::PathBuf {
        state
            .session
            .data_dir
            .join("instances")
            .join(state.vm_id.to_string())
            .join("overlay.ext4")
    }

    async fn send(
        app: Router,
        request: Request<Body>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024 * 1024)
            .await
            .unwrap();
        (status, headers, bytes.to_vec())
    }

    async fn send_json(app: Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let (status, _, bytes) = send(app, request).await;
        let json: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn disk_request(method: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri("/internal/disk")
            .header("x-node-secret", "t0k3n")
            .body(body)
            .unwrap()
    }

    #[test]
    fn lifecycle_op_parses_snake_case() {
        let req: LifecycleRequest = serde_json::from_str(r#"{"op":"stop"}"#).unwrap();
        assert_eq!(req.op, LifecycleOp::Stop);
        assert!(serde_json::from_str::<LifecycleRequest>(r#"{"op":"start"}"#).is_err());
        assert!(serde_json::from_str::<LifecycleRequest>(r#"{"op":"reboot"}"#).is_err());
    }

    #[tokio::test]
    async fn readyz_follows_the_guest_lifecycle() {
        let vm_id = Uuid::new_v4();
        let data_dir = std::env::temp_dir().join(format!("kletka-agent-readyz-{vm_id}"));
        let paths = kletka::system::KletkaPaths::with_data_dir(&data_dir);
        paths.ensure().unwrap();
        let registry = kletka::store::Registry::open(&paths);
        let record = |state: VmState| kletka::store::VmRecord {
            id: vm_id,
            name: "vm-x".into(),
            image: "default".into(),
            state,
            kernel_path: "/kernel".into(),
            rootfs_path: "/rootfs.ext4".into(),
            overlay_path: None,
            vsock_cid: None,
            network: None,
            fc_pid: None,
            slirp_pid: None,
            ssh_addr: None,
            ssh_port: None,
            vcpu_count: 1,
            memory_mib: 128,
            disk_mib: 256,
            created_at: kletka_types::time::Timestamp::UNIX_EPOCH,
        };
        registry.insert(record(VmState::Stopped)).unwrap();

        let app = router(InternalState {
            session: SessionState {
                node_secret: "t0k3n".into(),
                node_id: "pod".into(),
                data_dir,
            },
            vm_id,
            runtime: Arc::new(VmRuntime::new(paths).unwrap()),
        });

        let request = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = send(app.clone(), request).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let running = record(VmState::Running);
        registry.update(running).unwrap();
        let request = Request::builder()
            .uri("/readyz")
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = send(app, request).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn secret_check_rejects_wrong_and_accepts_right() {
        let state = state();
        let mut headers = HeaderMap::new();
        assert!(state.session.reject_unauthorized(&headers).is_some());
        headers.insert("x-node-secret", "wrong".parse().unwrap());
        assert!(state.session.reject_unauthorized(&headers).is_some());
        headers.insert("x-node-secret", "t0k3n".parse().unwrap());
        assert!(state.session.reject_unauthorized(&headers).is_none());
    }

    #[test]
    fn snapshot_op_parses_snake_case() {
        for (raw, expected) in [
            ("list", SnapshotOp::List),
            ("create", SnapshotOp::Create),
            ("delete", SnapshotOp::Delete),
            ("rollback", SnapshotOp::Rollback),
        ] {
            let req: SnapshotRequest =
                serde_json::from_str(&format!(r#"{{"op":"{raw}"}}"#)).unwrap();
            assert_eq!(req.op, expected);
            assert!(!req.memory, "memory defaults to false");
        }

        assert!(
            serde_json::from_str::<SnapshotRequest>(r#"{"op":"restore"}"#).is_err(),
            "unknown op must not parse"
        );
        let req: SnapshotRequest =
            serde_json::from_str(r#"{"op":"create","memory":true}"#).unwrap();
        assert_eq!(req.op, SnapshotOp::Create);
        assert!(req.memory);
        assert!(req.name.is_none());
    }

    #[tokio::test]
    async fn snapshot_endpoint_auth_validation_and_dial() {
        let app = router(state());

        let request = Request::builder()
            .method("POST")
            .uri("/internal/snapshot")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"op":"list"}"#))
            .unwrap();
        let (status, body) = send_json(app.clone(), request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");

        let request = Request::builder()
            .method("POST")
            .uri("/internal/snapshot")
            .header("x-node-secret", "t0k3n")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"op":"create"}"#))
            .unwrap();
        let (status, body) = send_json(app.clone(), request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("needs a snapshot name"),
            "{body}"
        );

        let request = Request::builder()
            .method("POST")
            .uri("/internal/snapshot")
            .header("x-node-secret", "t0k3n")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"op":"list"}"#))
            .unwrap();
        let (status, _) = send_json(app, request).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn disk_endpoints_require_auth() {
        let app = router(state());
        for method in ["GET", "PUT"] {
            let request = Request::builder()
                .method(method)
                .uri("/internal/disk")
                .body(Body::empty())
                .unwrap();
            let (status, _, _) = send(app.clone(), request).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method}");
        }
    }

    #[tokio::test]
    async fn disk_get_streams_a_stopped_overlays_bytes() {
        let state = state();
        let overlay = overlay_of(&state);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"overlay-bytes-0123456789").unwrap();
        put_record(&state, VmState::Stopped, Some(overlay));

        let app = router(state);
        let (status, headers, body) = send(app, disk_request("GET", Body::empty())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("content-length").unwrap().to_str().unwrap(),
            "24"
        );
        assert_eq!(body, b"overlay-bytes-0123456789");
    }

    #[tokio::test]
    async fn disk_get_refuses_a_running_vm_and_a_legacy_record() {
        let state = state();
        let overlay = overlay_of(&state);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"x").unwrap();
        put_record(&state, VmState::Running, Some(overlay));

        let app = router(state.clone());
        let (status, _) = send_json(app, disk_request("GET", Body::empty())).await;
        assert_eq!(status, StatusCode::CONFLICT);

        put_record(&state, VmState::Stopped, None);
        let app = router(state);
        let (status, body) = send_json(app, disk_request("GET", Body::empty())).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(
            body["error"].as_str().unwrap().contains("overlay"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn disk_put_installs_bytes_and_refuses_a_running_vm() {
        let state = state();
        let overlay = overlay_of(&state);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        put_record(&state, VmState::Running, Some(overlay.clone()));

        let app = router(state.clone());
        let (status, body) =
            send_json(app, disk_request("PUT", Body::from(b"clone".to_vec()))).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        put_record(&state, VmState::Stopped, Some(overlay.clone()));
        let app = router(state.clone());
        let (status, body) =
            send_json(app, disk_request("PUT", Body::from(vec![0u8; 1024 * 1024]))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["size"].as_u64().unwrap(), 1024 * 1024);
        assert_eq!(std::fs::metadata(&overlay).unwrap().len(), 1024 * 1024);
        assert!(!overlay.with_extension("ext4.clone-part").exists());
    }

    #[tokio::test]
    async fn disk_put_works_without_a_record() {
        let state = state();
        let overlay = overlay_of(&state);
        let app = router(state);
        let (status, body) = send_json(
            app,
            disk_request("PUT", Body::from(b"fresh-clone-disk".to_vec())),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(std::fs::read(&overlay).unwrap(), b"fresh-clone-disk");
    }

    #[tokio::test]
    async fn disk_put_leaves_a_half_written_target_untouched() {
        let state = state();
        let overlay = overlay_of(&state);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::write(&overlay, b"original-state").unwrap();

        let stream = futures_util::stream::iter(vec![
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"partial")),
            Err(std::io::Error::other("mid-body stream failure")),
        ]);
        let app = router(state);
        let (status, _) = send_json(
            app,
            disk_request("PUT", axum::body::Body::from_stream(stream)),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(std::fs::read(&overlay).unwrap(), b"original-state");
        assert!(!overlay.with_extension("ext4.clone-part").exists());
    }
}
