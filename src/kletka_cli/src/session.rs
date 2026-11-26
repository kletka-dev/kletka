use std::io::Write as _;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt as _};
use kletka_types::{SessionHeader, SessionKind};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::{self, Message, client::IntoClientRequest as _};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use crate::client::{Client, status_error};
use crate::error::{CliError, CliResult, error_chain};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsWrite = SplitSink<Ws, Message>;
type WsRead = SplitStream<Ws>;

const DETACH_BYTE: u8 = 0x1d;

fn ws_url(control_url: &str, vm_id: &Uuid, op: &str) -> String {
    let base = control_url.trim_end_matches('/');
    let base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{base}/v1/vms/{vm_id}/{op}")
}

fn header(kind: SessionKind) -> SessionHeader {
    SessionHeader {
        session_id: None,
        kind,
        pty_cols: None,
        pty_rows: None,
        term: None,
        colorterm: None,
    }
}

async fn open(
    client: &Client,
    vm_id: &Uuid,
    header: &SessionHeader,
) -> CliResult<(WsWrite, WsRead)> {
    let op = match &header.kind {
        SessionKind::Exec { .. } => "exec",
        SessionKind::Console { .. } => "console",
        SessionKind::Proxy { .. } => "proxy",
        SessionKind::FilePush { .. } | SessionKind::FilePull { .. } => {
            unreachable!("file transfers use HTTP")
        }
    };
    let mut request = ws_url(client.url(), vm_id, op)
        .into_client_request()
        .map_err(|err| {
            CliError::new(format!(
                "'{}' is not a valid control-plane URL",
                client.url()
            ))
            .detail(err)
        })?;
    let auth = format!("Bearer {}", client.token()).parse().map_err(|_| {
        CliError::new("the stored token is malformed").hint("run `kletka login` again")
    })?;
    request.headers_mut().insert("authorization", auth);
    if let Some(namespace) = client.namespace() {
        let value = namespace
            .parse()
            .map_err(|_| CliError::new(format!("'{namespace}' is not a valid namespace name")))?;
        request
            .headers_mut()
            .insert(kletka_types::NAMESPACE_HEADER, value);
    }

    let (ws, _) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|err| connect_error(client.url(), op, err))?;
    let (mut write, read) = ws.split();
    let text = serde_json::to_string(header).expect("session header serializes");
    write
        .send(Message::Text(text.into()))
        .await
        .map_err(|err| CliError::new("the session closed before it started").detail(err))?;
    Ok((write, read))
}

fn connect_error(url: &str, op: &str, err: tungstenite::Error) -> CliError {
    match err {
        tungstenite::Error::Http(response) => status_error(
            response.status(),
            response.body().as_deref().unwrap_or_default(),
            &format!("open a {op} session"),
        ),
        other => CliError::new(format!("cannot reach the control plane at {url}"))
            .hint("check the URL and your network connection")
            .detail(error_chain(&other)),
    }
}

fn exit_code(text: &str) -> Option<i32> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value.get("exit")?.as_i64().map(|code| code as i32)
}

fn write_stdout(data: &[u8]) -> CliResult<()> {
    let mut stdout = std::io::stdout();
    stdout
        .write_all(data)
        .and_then(|()| stdout.flush())
        .map_err(|err| CliError::new("cannot write to stdout").detail(err))
}

fn lost(err: impl std::fmt::Display) -> CliError {
    CliError::new("lost the connection to the session").detail(err)
}

pub fn stdin_reader(chunk: usize) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel(16);
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdin = std::io::stdin();
        let mut buf = vec![0u8; chunk];
        while let Ok(n @ 1..) = stdin.read(&mut buf) {
            if tx.blocking_send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    rx
}

pub async fn exec(
    client: &Client,
    vm_id: &Uuid,
    cmd: &[String],
    mut stdin: mpsc::Receiver<Vec<u8>>,
) -> CliResult<i32> {
    let kind = SessionKind::Exec {
        cmd: cmd.to_vec(),
        pty: false,
    };
    let (mut write, mut read) = open(client, vm_id, &header(kind)).await?;

    let mut stdin_open = true;
    loop {
        tokio::select! {
            chunk = stdin.recv(), if stdin_open => match chunk {
                Some(bytes) if bytes.is_empty() => {}
                Some(bytes) => write.send(Message::Binary(bytes.into())).await.map_err(lost)?,
                None => {
                    stdin_open = false;
                    write.send(Message::Binary(Vec::new().into())).await.map_err(lost)?;
                }
            },
            msg = read.next() => match msg {
                Some(Ok(Message::Binary(data))) => write_stdout(&data)?,
                Some(Ok(Message::Text(text))) => {
                    if let Some(code) = exit_code(&text) {
                        return Ok(code);
                    }
                }
                Some(Ok(Message::Close(frame))) => return Err(ended_early(frame)),
                Some(Ok(_)) => {}
                Some(Err(err)) => return Err(lost(err)),
                None => return Err(ended_early(None)),
            },
        }
    }
}

fn ended_early(frame: Option<tungstenite::protocol::CloseFrame>) -> CliError {
    let reason = frame
        .map(|frame| frame.reason.to_string())
        .unwrap_or_default();
    let err = CliError::new("the session ended before the command finished");
    if reason.is_empty() {
        err
    } else {
        err.detail(reason)
    }
}

pub async fn exec_pty(client: &Client, vm_id: &Uuid, cmd: &[String]) -> CliResult<i32> {
    let kind = SessionKind::Exec {
        cmd: cmd.to_vec(),
        pty: true,
    };
    interactive(client, vm_id, kind, stdin_reader(64))
        .await?
        .ok_or_else(|| ended_early(None))
}

pub async fn console(client: &Client, vm_name: &str, vm_id: &Uuid, serial: bool) -> CliResult<()> {
    let kind = SessionKind::Console { serial };
    match interactive(client, vm_id, kind, stdin_reader(64)).await? {
        None | Some(0) => Ok(()),
        Some(code) => Err(CliError::new("could not open a shell in the VM")
            .hint(format!(
                "the guest may still be booting; retry, or use `kletka console --serial -n {vm_name}`"
            ))
            .detail(format!("guest ssh exited with status {code}"))),
    }
}

async fn interactive(
    client: &Client,
    vm_id: &Uuid,
    kind: SessionKind,
    mut stdin: mpsc::Receiver<Vec<u8>>,
) -> CliResult<Option<i32>> {
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    use tokio::signal::unix::{SignalKind, signal};

    let (cols, rows) = crossterm::terminal::size()
        .map(|(c, r)| (Some(c), Some(r)))
        .unwrap_or((None, None));
    let env = |name| std::env::var(name).ok().filter(|v: &String| !v.is_empty());
    let header = SessionHeader {
        pty_cols: cols,
        pty_rows: rows,
        term: env("TERM"),
        colorterm: env("COLORTERM"),
        ..header(kind)
    };
    let (mut write, mut read) = open(client, vm_id, &header).await?;
    let mut resized = signal(SignalKind::window_change())
        .map_err(|err| CliError::new("cannot watch for terminal resizes").detail(err))?;

    struct RawMode;
    impl Drop for RawMode {
        fn drop(&mut self) {
            let _ = disable_raw_mode();
        }
    }
    let raw_mode = enable_raw_mode().is_ok().then_some(RawMode);

    let mut exit = None;
    let mut close_reason = None;
    loop {
        tokio::select! {
            biased;
            input = stdin.recv() => match input {
                Some(bytes) if bytes.contains(&DETACH_BYTE) => break,
                Some(bytes) => write.send(Message::Binary(bytes.into())).await.map_err(lost)?,
                None => break,
            },
            _ = resized.recv() => {
                if let Ok((cols, rows)) = crossterm::terminal::size() {
                    let resize = format!(r#"{{"pty_cols":{cols},"pty_rows":{rows}}}"#);
                    let _ = write.send(Message::Text(resize.into())).await;
                }
            }
            msg = read.next() => match msg {
                Some(Ok(Message::Binary(data))) => write_stdout(&data)?,
                Some(Ok(Message::Text(text))) => {
                    if let Some(code) = exit_code(&text) {
                        exit = Some(code);
                        break;
                    }
                }
                Some(Ok(Message::Close(frame))) => {
                    close_reason = frame.map(|f| f.reason.to_string()).filter(|r| !r.is_empty());
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
        }
    }
    drop(raw_mode);
    if let Some(reason) = close_reason.filter(|_| exit.is_none()) {
        eprintln!("\nsession closed by the control plane: {reason}");
    }
    Ok(exit)
}

pub async fn proxy_forward(
    client: &Client,
    vm_id: &Uuid,
    remote_port: u16,
    stream: TcpStream,
) -> CliResult<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let kind = SessionKind::Proxy {
        tcp_port: remote_port,
    };
    let (mut ws_write, mut ws_read) = open(client, vm_id, &header(kind)).await?;
    let (mut tcp_read, mut tcp_write) = stream.into_split();
    let mut buf = vec![0u8; 8192];
    let mut local_open = true;
    loop {
        tokio::select! {
            read = tcp_read.read(&mut buf), if local_open => match read {
                Ok(0) | Err(_) => {
                    local_open = false;
                    ws_write.send(Message::Binary(Vec::new().into())).await.map_err(lost)?;
                }
                Ok(n) => ws_write.send(Message::Binary(buf[..n].to_vec().into())).await.map_err(lost)?,
            },
            msg = ws_read.next() => match msg {
                Some(Ok(Message::Binary(data))) => {
                    tcp_write.write_all(&data).await.map_err(lost)?;
                }
                _ => return Ok(()),
            },
        }
    }
}

pub async fn serve_proxy(
    client: &Client,
    vm_id: Uuid,
    bind: std::net::Ipv4Addr,
    forwards: &[(u16, u16)],
) -> CliResult<()> {
    let mut listeners = Vec::new();
    for &(local, remote) in forwards {
        let listener = tokio::net::TcpListener::bind((bind, local))
            .await
            .map_err(|err| {
                let message = if err.kind() == std::io::ErrorKind::AddrInUse {
                    format!("port {local} on {bind} is already in use")
                } else {
                    format!("cannot listen on {bind}:{local}")
                };
                CliError::new(message).detail(err)
            })?;
        listeners.push((listener, remote));
    }

    let shutdown = async {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    };
    proxy_serve_loop(
        &listeners,
        |stream, remote_port| {
            let client = client.clone();
            tokio::spawn(async move {
                if let Err(err) = proxy_forward(&client, &vm_id, remote_port, stream).await {
                    tracing::warn!("port {remote_port}: {err}");
                }
            });
        },
        shutdown,
    )
    .await;
    Ok(())
}

const ACCEPT_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

async fn accept_any(
    listeners: &[(tokio::net::TcpListener, u16)],
) -> std::io::Result<(TcpStream, u16)> {
    use futures_util::future::{FutureExt as _, select_all};
    if listeners.is_empty() {
        return futures_util::future::pending().await;
    }
    let mut alive: Vec<&(tokio::net::TcpListener, u16)> = listeners.iter().collect();
    loop {
        let accepts = alive.iter().map(|&(listener, port)| {
            async move { listener.accept().await.map(|(stream, _)| (stream, *port)) }.boxed()
        });
        let (result, index, _) = select_all(accepts).await;
        match result {
            Ok(pair) => return Ok(pair),
            Err(err) => {
                let (_, port) = alive[index];
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted
                ) {
                    tracing::debug!(port, %err, "proxy: transient accept error; retrying");
                    tokio::task::yield_now().await;
                    continue;
                }
                tracing::warn!(port, %err, "proxy: listener failed; skipping it");
                alive.remove(index);
                if alive.is_empty() {
                    return Err(err);
                }
            }
        }
    }
}

pub async fn proxy_serve_loop(
    listeners: &[(tokio::net::TcpListener, u16)],
    mut on_accept: impl FnMut(TcpStream, u16) + Send,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = accept_any(listeners) => match accepted {
                Ok((stream, remote_port)) => on_accept(stream, remote_port),
                Err(err) => {
                    tracing::warn!(%err, "proxy: accept failed; retrying");
                    tokio::time::sleep(ACCEPT_RETRY_BACKOFF).await;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::Message as TMsg;

    #[test]
    fn ws_url_shapes() {
        let id = Uuid::nil();
        assert_eq!(
            ws_url("http://127.0.0.1:8080/", &id, "exec"),
            format!("ws://127.0.0.1:8080/v1/vms/{id}/exec")
        );
        assert_eq!(
            ws_url("https://ctl.example/", &id, "console"),
            format!("wss://ctl.example/v1/vms/{id}/console")
        );
    }

    async fn fake_relay<F, Fut>(handler: F) -> (String, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(WebSocketStream<TcpStream>, String) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let header = match ws.next().await {
                Some(Ok(TMsg::Text(text))) => text.to_string(),
                other => panic!("expected a text header, got {other:?}"),
            };
            handler(ws, header).await;
        });
        (format!("http://{addr}"), task)
    }

    fn bytes_then_eof(bytes: &[u8]) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(4);
        tx.try_send(bytes.to_vec()).unwrap();
        rx
    }

    #[tokio::test]
    async fn exec_streams_stdin_and_returns_the_exit_code() {
        let (url, server) = fake_relay(|mut ws, header| async move {
            assert!(header.contains("\"pty\":false"), "{header}");
            assert!(header.contains("uname"), "{header}");
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    TMsg::Binary(data) if data.is_empty() => break,
                    TMsg::Binary(data) => ws.send(TMsg::Binary(data)).await.unwrap(),
                    _ => {}
                }
            }
            ws.send(TMsg::Text(r#"{"exit":3}"#.into())).await.unwrap();
        })
        .await;

        let client = Client::new(url, "tok");
        let code = exec(
            &client,
            &Uuid::new_v4(),
            &["uname".into()],
            bytes_then_eof(b"in"),
        )
        .await
        .unwrap();
        assert_eq!(code, 3);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn exec_without_trailer_is_an_error() {
        let (url, server) = fake_relay(|mut ws, _| async move {
            let _ = ws.close(None).await;
        })
        .await;
        let client = Client::new(url, "tok");
        let (_tx, rx) = mpsc::channel(1);
        let err = exec(&client, &Uuid::new_v4(), &["true".into()], rx)
            .await
            .unwrap_err();
        assert!(err.message.contains("ended before"), "{}", err.message);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn interactive_returns_the_trailer_code() {
        let (url, server) = fake_relay(|mut ws, header| async move {
            assert!(header.contains("\"pty\":true"), "{header}");
            ws.send(TMsg::Text(r#"{"exit":7}"#.into())).await.unwrap();
        })
        .await;
        let client = Client::new(url, "tok");
        let (_tx, rx) = mpsc::channel(1);
        let kind = SessionKind::Exec {
            cmd: vec!["sh".into()],
            pty: true,
        };
        let code = interactive(&client, &Uuid::new_v4(), kind, rx)
            .await
            .unwrap();
        assert_eq!(code, Some(7));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn interactive_ends_when_the_far_end_closes() {
        let (url, server) = fake_relay(|mut ws, header| async move {
            assert!(header.contains("\"serial\":true"), "{header}");
            ws.send(TMsg::Binary(b"guest says hi".to_vec().into()))
                .await
                .unwrap();
        })
        .await;
        let client = Client::new(url, "tok");
        let (_tx, rx) = mpsc::channel(1);
        let code = interactive(
            &client,
            &Uuid::new_v4(),
            SessionKind::Console { serial: true },
            rx,
        )
        .await
        .unwrap();
        assert_eq!(code, None);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_upgrade_surfaces_the_api_error() {
        use axum::response::IntoResponse as _;
        let app = axum::Router::new().fallback(|| async {
            (
                axum::http::StatusCode::CONFLICT,
                axum::Json(serde_json::json!({ "error": "vm is not running" })),
            )
                .into_response()
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = Client::new(format!("http://{addr}"), "tok");
        let (_tx, rx) = mpsc::channel(1);
        let err = exec(&client, &Uuid::new_v4(), &[], rx).await.unwrap_err();
        assert_eq!(err.message, "vm is not running");
    }

    #[tokio::test]
    async fn proxy_forward_roundtrip() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (url, server) = fake_relay(|mut ws, header| async move {
            assert!(header.contains("\"tcp_port\":80"), "{header}");
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    TMsg::Binary(data) if data.is_empty() => break,
                    TMsg::Binary(data) => ws.send(TMsg::Binary(data)).await.unwrap(),
                    _ => {}
                }
            }
        })
        .await;
        let client = Client::new(url, "tok");

        let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        let forward = tokio::spawn(async move {
            let (stream, _) = local.accept().await.unwrap();
            proxy_forward(&client, &Uuid::new_v4(), 80, stream)
                .await
                .unwrap();
        });
        let mut conn = TcpStream::connect(local_addr).await.unwrap();
        conn.write_all(b"proxy-ping").await.unwrap();
        let mut buf = [0u8; 16];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"proxy-ping");
        conn.shutdown().await.unwrap();
        forward.await.unwrap();
        server.await.unwrap();
    }

    async fn dead_listener() -> (tokio::net::TcpListener, u16) {
        use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
        let bad = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = bad.local_addr().unwrap();
        let _probe = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(unsafe { std::fs::File::from_raw_fd(bad.as_raw_fd()) });
        (bad, addr.port())
    }

    #[tokio::test]
    async fn proxy_serve_loop_survives_a_dead_listener() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let good = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = good.local_addr().unwrap();
        let (bad, bad_port) = dead_listener().await;
        let listeners: &'static [(tokio::net::TcpListener, u16)] =
            Box::leak(vec![(good, good_addr.port()), (bad, bad_port)].into_boxed_slice());

        let (tx, mut rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(proxy_serve_loop(
            listeners,
            move |stream, port| {
                let _ = tx.send((stream, port));
            },
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut conn = TcpStream::connect(good_addr).await.unwrap();
        conn.write_all(b"ping").await.unwrap();
        let (mut stream, port) = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .expect("serve loop alive")
            .expect("connection forwarded");
        assert_eq!(port, good_addr.port());
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), serve)
            .await
            .expect("serve loop ends on shutdown")
            .unwrap();
    }

    #[tokio::test]
    async fn proxy_serve_loop_keeps_retrying_when_every_listener_is_dead() {
        let (bad, bad_port) = dead_listener().await;
        let listeners: &'static [(tokio::net::TcpListener, u16)] =
            Box::leak(vec![(bad, bad_port)].into_boxed_slice());

        let (tx, mut rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let serve = tokio::spawn(proxy_serve_loop(
            listeners,
            move |stream, port| {
                let _ = tx.send((stream, port));
            },
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !serve.is_finished(),
            "serve loop must not exit on accept errors"
        );
        assert!(rx.try_recv().is_err(), "nothing should be accepted");

        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), serve)
            .await
            .expect("serve loop ends on shutdown")
            .unwrap();
    }
}
