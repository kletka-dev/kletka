use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade, close_code};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use kletka::host_nat::SlirpClient;
use kletka::store::{Registry, VmRecord, VmState};
use kletka_types::{SessionHeader, SessionKind};

use crate::reply::json_error;

#[derive(Debug, Clone)]
pub struct SessionState {
    pub node_secret: String,
    pub node_id: String,
    pub data_dir: PathBuf,
}

impl SessionState {
    pub fn reject_unauthorized(&self, headers: &HeaderMap) -> Option<Response> {
        let secret = headers
            .get("x-node-secret")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if !secret.is_empty() && kletka_types::secrets_equal(secret, &self.node_secret) {
            return None;
        }
        Some(json_error(StatusCode::UNAUTHORIZED, "bad node secret"))
    }

    pub fn instance_dir(&self, id: &uuid::Uuid) -> PathBuf {
        kletka::system::KletkaPaths::with_data_dir(&self.data_dir).instance_dir(id)
    }
}

#[derive(Debug, Deserialize)]
pub struct SessionQuery {
    pub vm: String,
}

pub fn router(state: SessionState) -> Router {
    Router::new()
        .route("/internal/session", get(session))
        .with_state(state)
}

async fn session(
    State(state): State<SessionState>,
    Query(query): Query<SessionQuery>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if let Some(rejection) = state.reject_unauthorized(&headers) {
        return rejection;
    }
    if query.vm.trim().is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "missing ?vm=");
    }
    ws.on_upgrade(move |socket| handle(socket, state, query.vm))
}

async fn handle(mut socket: WebSocket, state: SessionState, vm_id: String) {
    let header_text = match socket.recv().await {
        Some(Ok(Message::Text(text))) => text.to_string(),
        other => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, ?other, "session: first frame not text");
            close_with(
                &mut socket,
                close_code::POLICY,
                "first frame must be the text header",
            )
            .await;
            return;
        }
    };
    let header: SessionHeader = match serde_json::from_str(&header_text) {
        Ok(header) => header,
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "session: bad header");
            close_with(
                &mut socket,
                close_code::POLICY,
                "unparseable session header",
            )
            .await;
            return;
        }
    };
    match &header.kind {
        SessionKind::Exec { cmd, pty } => {
            exec_bridge(
                &mut socket,
                &state,
                &vm_id,
                cmd.clone(),
                *pty,
                PtySpec::of(&header),
            )
            .await;
        }
        SessionKind::Console { serial } => {
            console_bridge(&mut socket, &state, &vm_id, *serial, PtySpec::of(&header)).await;
        }
        SessionKind::Proxy { tcp_port } => {
            proxy_bridge(&mut socket, &state, &vm_id, *tcp_port).await;
        }
        other => {
            let reason = format!("{other:?} relay not served yet");
            tracing::warn!(node = %state.node_id, vm = %vm_id, reason = %reason, "session: kind not served");
            close_with(&mut socket, close_code::POLICY, reason).await;
        }
    }
    let _ = futures_util::SinkExt::close(&mut socket).await;
}

pub struct SshTarget {
    pub key: PathBuf,
    pub port: u16,
    pub dest: String,
}

impl SshTarget {
    pub fn command(&self, remote_cmd: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new("ssh");
        command
            .args(ssh_common_args(&self.key, self.port))
            .arg(&self.dest)
            .arg(remote_cmd)
            .kill_on_drop(true);
        command
    }
}

#[derive(Debug, Clone)]
pub struct PtySpec {
    pub cols: u16,
    pub rows: u16,
    pub term: String,
    pub color_term: Option<String>,
}

impl Default for PtySpec {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            term: "xterm-256color".to_string(),
            color_term: None,
        }
    }
}

fn safe_color_term(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then_some(value)
}

impl PtySpec {
    pub fn of(header: &SessionHeader) -> Self {
        let defaults = Self::default();
        Self {
            cols: header.pty_cols.unwrap_or(defaults.cols),
            rows: header.pty_rows.unwrap_or(defaults.rows),
            term: header
                .term
                .clone()
                .filter(|t| !t.is_empty())
                .unwrap_or(defaults.term),
            color_term: header
                .colorterm
                .as_deref()
                .and_then(safe_color_term)
                .map(str::to_string),
        }
    }
}

fn parse_resize(text: &str) -> Option<(u16, u16)> {
    #[derive(Deserialize)]
    struct Resize {
        pty_cols: u16,
        pty_rows: u16,
    }
    serde_json::from_str::<Resize>(text)
        .ok()
        .map(|r| (r.pty_cols, r.pty_rows))
}

pub fn find_vm_record(data_dir: &Path, vm_id: &str) -> Result<VmRecord, String> {
    let paths = kletka::system::KletkaPaths::with_data_dir(data_dir);
    Registry::open(&paths)
        .find(vm_id)
        .map_err(|err| err.to_string())?
        .ok_or_else(|| format!("no vm for '{vm_id}'"))
}

pub fn ssh_target(data_dir: &Path, vm_id: &str) -> Result<(SshTarget, VmRecord), String> {
    let record = find_vm_record(data_dir, vm_id)?;
    let key = kletka::system::KletkaPaths::with_data_dir(data_dir)
        .instance_dir(&record.id)
        .join("ssh_key");
    if !key.is_file() {
        return Err(format!(
            "vm '{}' has no ssh key; recreate it to generate one",
            record.name
        ));
    }
    let (Some(port), Some(addr)) = (record.ssh_port, &record.ssh_addr) else {
        return Err(format!(
            "vm '{}' has no networking (created with --no-nat?)",
            record.name
        ));
    };
    if !kletka::system::on_path("ssh") {
        return Err("ssh client not found on PATH; install openssh-clients".to_string());
    }
    Ok((
        SshTarget {
            key,
            port,
            dest: format!("user@{addr}"),
        },
        record,
    ))
}

pub async fn configure_wireguard(
    data_dir: &Path,
    vm_id: &str,
    config: Option<&str>,
) -> Result<(), String> {
    let (target, _) = ssh_target(data_dir, vm_id)?;
    let operation = if config.is_some() { "apply" } else { "clear" };
    let mut command = target.command(&format!(
        "sudo /usr/local/sbin/kletka-wireguard {operation}"
    ));
    command
        .stdin(if config.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|err| format!("cannot start guest WireGuard command: {err}"))?;
    if let Some(config) = config {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("guest WireGuard command has no stdin")?;
        stdin
            .write_all(config.as_bytes())
            .await
            .map_err(|err| format!("cannot send guest WireGuard config: {err}"))?;
    }
    let status = child
        .wait()
        .await
        .map_err(|err| format!("cannot wait for guest WireGuard command: {err}"))?;
    if !status.success() {
        if status.code() == Some(127) {
            return Err(
                "guest image lacks WireGuard support; rebase it onto a current image and retry"
                    .to_string(),
            );
        }
        return Err(format!("guest WireGuard command failed: {status}"));
    }
    Ok(())
}

pub fn ssh_common_args(key: &Path, port: u16) -> Vec<String> {
    kletka::guest::ssh_common_args(key, port, 5, 3)
}

pub fn ssh_command(
    target: &SshTarget,
    cmd: &[String],
    pty: bool,
    spec: &PtySpec,
) -> tokio::process::Command {
    let mut argv = ssh_common_args(&target.key, target.port);
    if pty {
        argv.push("-tt".to_string());
    }
    argv.push(target.dest.clone());
    let color_term = pty.then_some(spec.color_term.as_deref()).flatten();
    if !cmd.is_empty() || color_term.is_some() {
        argv.push("--".to_string());
        if let Some(color_term) = color_term {
            argv.push("env".to_string());
            argv.push(format!("COLORTERM={color_term}"));
            if cmd.is_empty() {
                argv.push("$SHELL".to_string());
                argv.push("-l".to_string());
            }
        }
        argv.extend(cmd.iter().cloned());
    }
    let mut child = tokio::process::Command::new("ssh");
    child
        .args(&argv)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    child
}

fn spawn_ssh_pty(
    target: &SshTarget,
    cmd: &[String],
    spec: &PtySpec,
) -> Result<(tokio::process::Child, crate::pty::Pty), String> {
    let (pty, slave) =
        crate::pty::Pty::open(spec.cols, spec.rows).map_err(|err| format!("open pty: {err}"))?;
    let [stdin, stdout, stderr] = slave
        .into_stdio()
        .map_err(|err| format!("pty stdio: {err}"))?;
    let mut command = ssh_command(target, cmd, true, spec);
    command
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .env("TERM", &spec.term);
    unsafe {
        command.pre_exec(crate::pty::PtySlave::become_controlling_tty);
    }
    let child = command
        .spawn()
        .map_err(|err| format!("spawn ssh on pty: {err}"))?;
    Ok((child, pty))
}

enum Out {
    Data(Vec<u8>),
    StdoutDone,
    StderrDone,
}

fn spawn_reader<R>(mut reader: R, tx: tokio::sync::mpsc::Sender<Out>, done: Out)
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = tx.send(done).await;
                    break;
                }
                Ok(n) => {
                    if tx.send(Out::Data(buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

async fn peer_gone() -> SocketMsg {
    futures_util::future::pending().await
}

pub enum SocketMsg {
    Data(Vec<u8>),
    Resize { cols: u16, rows: u16 },
    Closed,
}

pub trait SessionSocket: Send {
    async fn recv_msg(&mut self) -> SocketMsg;
    async fn send_data(&mut self, data: Vec<u8>) -> bool;
    async fn send_trailer(&mut self, code: i32) -> bool;
}

impl SessionSocket for WebSocket {
    async fn recv_msg(&mut self) -> SocketMsg {
        loop {
            match self.recv().await {
                Some(Ok(Message::Text(text))) => match parse_resize(&text) {
                    Some((cols, rows)) => return SocketMsg::Resize { cols, rows },
                    None => continue,
                },
                Some(Ok(Message::Binary(data))) => return SocketMsg::Data(data.to_vec()),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                _ => return SocketMsg::Closed,
            }
        }
    }

    async fn send_data(&mut self, data: Vec<u8>) -> bool {
        self.send(Message::Binary(data.into())).await.is_ok()
    }

    async fn send_trailer(&mut self, code: i32) -> bool {
        let trailer = serde_json::json!({ "exit": code }).to_string();
        self.send(Message::Text(trailer.into())).await.is_ok()
    }
}

pub async fn pipe_child(
    socket: &mut impl SessionSocket,
    mut child: tokio::process::Child,
) -> Result<i32, String> {
    let stdin = child.stdin.take().ok_or("no child stdin")?;
    let mut stdin = Some(stdin);
    let stdout = child.stdout.take().ok_or("no child stdout")?;
    let stderr = child.stderr.take().ok_or("no child stderr")?;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Out>(64);

    spawn_reader(stdout, tx.clone(), Out::StdoutDone);
    spawn_reader(stderr, tx, Out::StderrDone);

    let mut outs_done = 0u8;
    let mut peer_open = true;
    loop {
        tokio::select! {
            biased;
            msg = async {
                if peer_open {
                    socket.recv_msg().await
                } else {
                    peer_gone().await
                }
            } => {
                match msg {
                    SocketMsg::Data(data) if !data.is_empty() => {
                        let mut failed = false;
                        if let Some(pipe) = stdin.as_mut() {
                            failed = pipe.write_all(&data).await.is_err();
                        }
                        if failed {
                            stdin = None;
                        }
                    }
                    SocketMsg::Resize { .. } => {}
                    _ => {
                        peer_open = false;
                        stdin = None;
                    }
                }
            }
            item = rx.recv() => {
                match item {
                    Some(Out::Data(data)) => {
                        if !socket.send_data(data).await {
                            break;
                        }
                    }
                    Some(Out::StdoutDone) | Some(Out::StderrDone) => {
                        outs_done += 1;
                        if outs_done >= 2 {
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }
    let status = child.wait().await.map_err(|e| format!("wait: {e}"))?;
    let code = status.code().unwrap_or(1);
    socket.send_trailer(code).await;
    Ok(code)
}

pub async fn pipe_pty(
    socket: &mut impl SessionSocket,
    mut child: tokio::process::Child,
    pty: crate::pty::Pty,
) -> Result<i32, String> {
    let (read, mut write, resize) = pty.split();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Out>(64);

    spawn_reader(read, tx, Out::StdoutDone);

    let mut peer_open = true;
    loop {
        tokio::select! {
            biased;
            msg = async {
                if peer_open {
                    socket.recv_msg().await
                } else {
                    peer_gone().await
                }
            } => {
                match msg {
                    SocketMsg::Data(data) if !data.is_empty() => {
                        if write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    SocketMsg::Data(_) => {
                        let _ = write.write_all(&[0x04]).await;
                    }
                    SocketMsg::Resize { cols, rows } => resize.apply(cols, rows),
                    SocketMsg::Closed => {
                        peer_open = false;
                        let _ = child.start_kill();
                    }
                }
            }
            item = rx.recv() => {
                match item {
                    Some(Out::Data(data)) => {
                        if !socket.send_data(data).await {
                            break;
                        }
                    }
                    Some(Out::StdoutDone) | Some(Out::StderrDone) | None => break,
                }
            }
        }
    }
    let status = child.wait().await.map_err(|e| format!("wait: {e}"))?;
    let code = status.code().unwrap_or(1);
    socket.send_trailer(code).await;
    Ok(code)
}

async fn exec_bridge(
    socket: &mut WebSocket,
    state: &SessionState,
    vm_id: &str,
    cmd: Vec<String>,
    pty: bool,
    spec: PtySpec,
) {
    let (target, _record) = match ssh_target(&state.data_dir, vm_id) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "session: no ssh target");
            close_with(socket, close_code::ERROR, err).await;
            return;
        }
    };
    tracing::info!(node = %state.node_id, vm = %vm_id, pty, "exec session started");
    if pty {
        match spawn_ssh_pty(&target, &cmd, &spec) {
            Ok((child, pty)) => match pipe_pty(socket, child, pty).await {
                Ok(code) => {
                    tracing::info!(node = %state.node_id, vm = %vm_id, code, "exec session done")
                }
                Err(err) => {
                    tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "exec session failed")
                }
            },
            Err(err) => {
                close_with(socket, close_code::ERROR, err).await;
            }
        }
        return;
    }
    let child = match ssh_command(&target, &cmd, pty, &spec).spawn() {
        Ok(child) => child,
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "session: spawn failed");
            close_with(socket, close_code::ERROR, format!("spawn ssh: {err}")).await;
            return;
        }
    };
    match pipe_child(socket, child).await {
        Ok(code) => tracing::info!(node = %state.node_id, vm = %vm_id, code, "exec session done"),
        Err(err) => tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "exec session failed"),
    }
}

pub fn serial_sock_path(instances_dir: &Path, local_id: &uuid::Uuid) -> PathBuf {
    instances_dir.join(local_id.to_string()).join("serial.sock")
}

async fn console_bridge(
    socket: &mut WebSocket,
    state: &SessionState,
    vm_id: &str,
    serial: bool,
    spec: PtySpec,
) {
    let record = match find_vm_record(&state.data_dir, vm_id) {
        Ok(record) => record,
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "session: no local vm");
            close_with(socket, close_code::ERROR, err).await;
            return;
        }
    };
    if serial {
        let instances = state.data_dir.join("instances");
        let serial_sock = serial_sock_path(&instances, &record.id);
        if !serial_sock.exists() {
            close_with(
                socket,
                close_code::ERROR,
                format!("vm '{}' is not running", record.name),
            )
            .await;
            return;
        }
        let stream = match tokio::net::UnixStream::connect(&serial_sock).await {
            Ok(stream) => stream,
            Err(err) => {
                close_with(
                    socket,
                    close_code::ERROR,
                    format!("cannot attach to serial console: {err}"),
                )
                .await;
                return;
            }
        };
        tracing::info!(node = %state.node_id, vm = %vm_id, "serial session started");
        serial_bridge(socket, stream).await;
        return;
    }
    let (target, _record) = match ssh_target(&state.data_dir, vm_id) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "session: no ssh target");
            close_with(socket, close_code::ERROR, err).await;
            return;
        }
    };
    let (child, pty) = match spawn_ssh_pty(&target, &[], &spec) {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "session: spawn failed");
            close_with(socket, close_code::ERROR, err).await;
            return;
        }
    };
    tracing::info!(node = %state.node_id, vm = %vm_id, "ssh console session started");
    match pipe_pty(socket, child, pty).await {
        Ok(code) => {
            tracing::info!(node = %state.node_id, vm = %vm_id, code, "console session done")
        }
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "console session failed")
        }
    }
}

async fn proxy_bridge(socket: &mut WebSocket, state: &SessionState, vm_id: &str, tcp_port: u16) {
    use kletka::host_nat::GUEST_IP;

    let record = match find_vm_record(&state.data_dir, vm_id) {
        Ok(record) => record,
        Err(err) => {
            tracing::warn!(node = %state.node_id, vm = %vm_id, %err, "proxy: no local vm");
            close_with(socket, close_code::ERROR, err).await;
            return;
        }
    };
    if record.state != VmState::Running {
        close_with(
            socket,
            close_code::ERROR,
            format!(
                "vm '{}' is not running; start it before proxying",
                record.name
            ),
        )
        .await;
        return;
    }
    if !record.network.as_ref().is_some_and(|net| net.nat) {
        close_with(
            socket,
            close_code::ERROR,
            format!(
                "vm '{}' has no NAT networking; proxy requires NAT (recreate the vm)",
                record.name
            ),
        )
        .await;
        return;
    }
    let slirp_sock = state.instance_dir(&record.id).join("slirp.sock");
    if !slirp_sock.exists() {
        close_with(
            socket,
            close_code::ERROR,
            format!(
                "vm '{}' network is down (slirp socket missing); restart the vm",
                record.name
            ),
        )
        .await;
        return;
    }
    let client = SlirpClient::new(&slirp_sock);

    let eph = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener.local_addr().map(|a| a.port()).unwrap_or(0),
        Err(err) => {
            close_with(socket, close_code::ERROR, format!("ephemeral bind: {err}")).await;
            return;
        }
    };
    if eph == 0 {
        close_with(
            socket,
            close_code::ERROR,
            "ephemeral bind failed".to_string(),
        )
        .await;
        return;
    }
    let fwd_id = match client
        .add_hostfwd(
            "tcp",
            std::net::Ipv4Addr::LOCALHOST,
            eph,
            GUEST_IP,
            tcp_port,
        )
        .await
    {
        Ok(id) => id,
        Err(err) => {
            close_with(socket, close_code::ERROR, format!("add_hostfwd: {err}")).await;
            return;
        }
    };
    let guard = HostFwdGuard::new(&client, fwd_id);
    let mut stream = None;
    for _ in 0..10 {
        match tokio::net::TcpStream::connect(("127.0.0.1", eph)).await {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
        }
    }
    match stream {
        Some(stream) => {
            tracing::info!(node = %state.node_id, vm = %vm_id, port = tcp_port, "proxy session started");
            proxy_pipe(socket, stream).await;
            guard.release().await;
        }
        None => {
            guard.release().await;
            close_with(socket, close_code::ERROR, "dial guest failed".to_string()).await;
        }
    }
    tracing::info!(node = %state.node_id, vm = %vm_id, port = tcp_port, "proxy session done");
}

struct HostFwdGuard {
    client: SlirpClient,
    fwd_id: u32,
    released: bool,
}

impl HostFwdGuard {
    fn new(client: &SlirpClient, fwd_id: u32) -> Self {
        Self {
            client: client.clone(),
            fwd_id,
            released: false,
        }
    }

    async fn release(mut self) {
        self.released = true;
        if let Err(err) = self.client.remove_hostfwd(self.fwd_id).await {
            tracing::warn!(fwd = self.fwd_id, %err, "proxy: remove_hostfwd failed");
        }
    }
}

impl Drop for HostFwdGuard {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let client = self.client.clone();
        let fwd_id = self.fwd_id;
        tokio::spawn(async move {
            if let Err(err) = client.remove_hostfwd(fwd_id).await {
                tracing::warn!(fwd = fwd_id, %err, "proxy: leaked hostfwd removal failed");
            }
        });
    }
}

async fn close_with(socket: &mut WebSocket, code: u16, reason: impl Into<String>) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into().into(),
        })))
        .await;
}

pub async fn proxy_pipe(socket: &mut impl SessionSocket, stream: tokio::net::TcpStream) {
    let (rd, wr) = stream.into_split();
    bridge_stream(socket, rd, wr, 8192).await;
}

pub async fn serial_bridge(socket: &mut impl SessionSocket, stream: tokio::net::UnixStream) {
    let (rd, wr) = stream.into_split();
    bridge_stream(socket, rd, wr, 4096).await;
}

async fn bridge_stream<R, W>(socket: &mut impl SessionSocket, mut rd: R, mut wr: W, buf_size: usize)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; buf_size];
    loop {
        tokio::select! {
            biased;
            msg = socket.recv_msg() => {
                match msg {
                    SocketMsg::Data(data) if !data.is_empty() => {
                        if wr.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    SocketMsg::Data(_) => {
                        let _ = wr.shutdown().await;
                    }
                    SocketMsg::Resize { .. } => {}
                    SocketMsg::Closed => break,
                }
            }
            read = rd.read(&mut buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if !socket.send_data(buf[..n].to_vec()).await {
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
struct TestSocket {
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
}

#[cfg(test)]
impl SessionSocket for TestSocket {
    async fn recv_msg(&mut self) -> SocketMsg {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as TMsg;
        match self.ws.next().await {
            Some(Ok(TMsg::Binary(data))) => SocketMsg::Data(data.to_vec()),
            Some(Ok(TMsg::Text(text))) => match parse_resize(&text) {
                Some((cols, rows)) => SocketMsg::Resize { cols, rows },
                None => SocketMsg::Closed,
            },
            _ => SocketMsg::Closed,
        }
    }

    async fn send_data(&mut self, data: Vec<u8>) -> bool {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as TMsg;
        self.ws.send(TMsg::Binary(data.into())).await.is_ok()
    }

    async fn send_trailer(&mut self, code: i32) -> bool {
        use futures_util::SinkExt;
        use tokio_tungstenite::tungstenite::Message as TMsg;
        let trailer = serde_json::json!({ "exit": code }).to_string();
        self.ws.send(TMsg::Text(trailer.into())).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kletka::store::VmNetworkConfig;

    #[test]
    fn ssh_argv_shapes() {
        let target = SshTarget {
            key: PathBuf::from("/x/ssh_key"),
            port: 2222,
            dest: "user@127.0.0.2".to_string(),
        };
        let cmd = ssh_command(
            &target,
            &["uname".to_string(), "-a".to_string()],
            false,
            &PtySpec::default(),
        );
        let dbg = format!("{cmd:?}");
        assert!(dbg.contains("\"ssh\""), "{dbg}");
        assert!(dbg.contains("user@127.0.0.2"), "{dbg}");
        assert!(dbg.contains("uname"), "{dbg}");
        assert!(!dbg.contains("-tt"), "{dbg}");
        assert!(!dbg.contains("COLORTERM"), "{dbg}");
        let pty = ssh_command(&target, &[], true, &PtySpec::default());
        let dbg = format!("{pty:?}");
        assert!(dbg.contains("-tt"), "{dbg}");
        assert!(!dbg.contains("COLORTERM"), "{dbg}");
        assert!(!dbg.contains("--"), "{dbg}");
        let spec = PtySpec {
            color_term: Some("truecolor".to_string()),
            ..PtySpec::default()
        };
        let console = ssh_command(&target, &[], true, &spec);
        let dbg = format!("{console:?}");
        assert!(dbg.contains("\"--\""), "{dbg}");
        assert!(dbg.contains("\"env\""), "{dbg}");
        assert!(dbg.contains("COLORTERM=truecolor"), "{dbg}");
        assert!(dbg.contains("\"$SHELL\" \"-l\""), "{dbg}");
        let exec = ssh_command(&target, &["vim".to_string()], true, &spec);
        let dbg = format!("{exec:?}");
        assert!(dbg.contains("\"COLORTERM=truecolor\" \"vim\""), "{dbg}");
        assert!(!dbg.contains("$SHELL"), "{dbg}");
    }

    #[test]
    fn pty_spec_reads_colorterm_and_drops_unsafe_values() {
        let header = |colorterm: Option<&str>| SessionHeader {
            session_id: None,
            kind: SessionKind::Console { serial: false },
            pty_cols: None,
            pty_rows: None,
            term: None,
            colorterm: colorterm.map(str::to_string),
        };
        assert_eq!(
            PtySpec::of(&header(Some("truecolor")))
                .color_term
                .as_deref(),
            Some("truecolor")
        );
        assert_eq!(PtySpec::of(&header(None)).color_term, None);
        assert_eq!(PtySpec::of(&header(Some(""))).color_term, None);
        for hostile in ["truecolor; rm -rf /", "a b", "`id`", "24'bit"] {
            assert_eq!(
                PtySpec::of(&header(Some(hostile))).color_term,
                None,
                "{hostile} must not reach the guest command"
            );
        }
    }

    #[tokio::test]
    async fn pipe_child_echoes_and_reports_exit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            use futures_util::StreamExt;
            use tokio_tungstenite::tungstenite::Message as TMsg;
            let mut saw_echo = false;
            let mut saw_trailer = false;
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    TMsg::Binary(data) if data.as_ref() == b"hello-relay" => saw_echo = true,
                    TMsg::Text(text) if text.contains("\"exit\":0") => saw_trailer = true,
                    _ => {}
                }
                if saw_echo && saw_trailer {
                    break;
                }
            }
            (saw_echo, saw_trailer)
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async("ws://x/internal/session", stream)
            .await
            .unwrap();
        let mut socket = TestSocket { ws };
        let child = tokio::process::Command::new("sh")
            .args(["-c", "printf hello-relay"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let code = pipe_child(&mut socket, child).await.unwrap();
        assert_eq!(code, 0);
        let (saw_echo, saw_trailer) = server.await.unwrap();
        assert!(saw_echo && saw_trailer);
    }

    #[tokio::test]
    async fn pty_session_carries_size_and_trailer() {
        if !std::path::Path::new("/dev/ptmx").exists() {
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            use futures_util::StreamExt;
            use tokio_tungstenite::tungstenite::Message as TMsg;
            let mut saw_size = false;
            let mut saw_trailer = false;
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    TMsg::Binary(data) if String::from_utf8_lossy(&data).trim() == "13 31" => {
                        saw_size = true;
                    }
                    TMsg::Text(text) if text.contains("\"exit\":0") => saw_trailer = true,
                    _ => {}
                }
                if saw_size && saw_trailer {
                    break;
                }
            }
            (saw_size, saw_trailer)
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async("ws://x/internal/session", stream)
            .await
            .unwrap();
        let mut socket = TestSocket { ws };

        let (pty, slave) = crate::pty::Pty::open(31, 13).unwrap();
        let [stdin, stdout, stderr] = slave.into_stdio().unwrap();
        let mut command = std::process::Command::new("stty");
        command
            .arg("size")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr);
        {
            use std::os::unix::process::CommandExt as _;
            unsafe {
                command.pre_exec(crate::pty::PtySlave::become_controlling_tty);
            }
        }
        let child = tokio::process::Command::from(command)
            .kill_on_drop(true)
            .spawn()
            .unwrap();

        let code = pipe_pty(&mut socket, child, pty).await.unwrap();
        assert_eq!(code, 0);
        let (saw_size, saw_trailer) = server.await.unwrap();
        assert!(saw_size, "the child never saw the 13x31 pty size");
        assert!(saw_trailer, "exit trailer never arrived");
    }

    fn find_sshd() -> Option<PathBuf> {
        for candidate in [PathBuf::from("/usr/sbin/sshd"), PathBuf::from("sshd")] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join("sshd"))
                .find(|p| p.is_file())
        })
    }

    #[tokio::test]
    #[ignore = "real sshd; requires sshd and ssh-keygen"]
    async fn ssh_pty_session_resizes_end_to_end() {
        let Some(sshd) = find_sshd() else {
            eprintln!("skipping: no sshd binary");
            return;
        };

        let dir = std::env::temp_dir().join(format!("kletka-ssh-e2e-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        for key in ["host_key", "client_key"] {
            let status = std::process::Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(dir.join(key))
                .status()
                .expect("ssh-keygen");
            assert!(status.success(), "ssh-keygen {key} failed");
        }
        std::fs::copy(dir.join("client_key.pub"), dir.join("authorized_keys")).unwrap();
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let config = format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}/host_key\n\
             AuthorizedKeysFile {}/authorized_keys\nStrictModes no\n\
             PasswordAuthentication no\nPubkeyAuthentication yes\nUsePAM no\n",
            dir.display(),
            dir.display()
        );
        std::fs::write(dir.join("sshd_config"), config).unwrap();

        let mut sshd_child = tokio::process::Command::new(&sshd)
            .args(["-D", "-e", "-f"])
            .arg(dir.join("sshd_config"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn sshd");
        for _ in 0..50 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message as TMsg;

            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

            async fn until(
                ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
                needle: &str,
            ) -> Option<String> {
                let mut seen = String::new();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                loop {
                    let next = match tokio::time::timeout_at(deadline.into(), ws.next()).await {
                        Ok(next) => next,
                        Err(_) => return None,
                    };
                    match next? {
                        Ok(TMsg::Binary(data)) => {
                            seen.push_str(&String::from_utf8_lossy(&data));
                            if seen.contains(needle) {
                                return Some(seen);
                            }
                        }
                        Ok(TMsg::Text(text)) if text.contains("\"exit\":0") => return None,
                        _ => {}
                    }
                }
            }

            ws.send(TMsg::Binary(b"stty size\n".to_vec().into()))
                .await
                .unwrap();
            until(&mut ws, "13 31").await;

            ws.send(TMsg::Text(r#"{"pty_cols":99,"pty_rows":42}"#.into()))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            ws.send(TMsg::Binary(b"stty size\n".to_vec().into()))
                .await
                .unwrap();
            until(&mut ws, "42 99").await;

            ws.send(TMsg::Binary(b"exit\n".to_vec().into()))
                .await
                .unwrap();
            let _ = until(&mut ws, "\u{0}never").await;
            true
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async("ws://x/internal/session", stream)
            .await
            .unwrap();
        let mut socket = TestSocket { ws };
        let target = SshTarget {
            key: dir.join("client_key"),
            port,
            dest: "127.0.0.1".to_string(),
        };
        let spec = PtySpec {
            cols: 31,
            rows: 13,
            term: "xterm-256color".to_string(),
            color_term: None,
        };
        let (child, pty) = spawn_ssh_pty(&target, &[], &spec).expect("spawn ssh on pty");
        let code = pipe_pty(&mut socket, child, pty)
            .await
            .expect("pty session");
        assert_eq!(code, 0, "ssh should exit 0 after the shell exits");

        let resized = tokio::time::timeout(std::time::Duration::from_secs(60), server)
            .await
            .expect("server task")
            .unwrap();
        assert!(resized, "the remote terminal never observed the resize");

        let _ = sshd_child.kill().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn pipe_child_peer_drop_ends_stdin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message as TMsg;
            ws.send(TMsg::Binary(b"hello-relay".to_vec().into()))
                .await
                .unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                if let TMsg::Binary(data) = msg
                    && data.as_ref() == b"hello-relay"
                {
                    return true;
                }
            }
            false
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async("ws://x/internal/session", stream)
            .await
            .unwrap();
        let mut socket = TestSocket { ws };
        let child = tokio::process::Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            pipe_child(&mut socket, child),
        )
        .await
        .expect("pipe_child hung")
        .unwrap();
        assert_eq!(code, 0);
    }

    #[tokio::test]
    async fn pipe_child_empty_binary_means_stdin_eof() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message as TMsg;
            ws.send(TMsg::Binary(b"ping".to_vec().into()))
                .await
                .unwrap();
            ws.send(TMsg::Binary(Vec::new().into())).await.unwrap();
            let mut saw_echo = false;
            let mut saw_trailer = false;
            while let Some(Ok(msg)) = ws.next().await {
                match msg {
                    TMsg::Binary(data) if data.as_ref() == b"ping" => saw_echo = true,
                    TMsg::Text(text) if text.contains("\"exit\":0") => saw_trailer = true,
                    _ => {}
                }
                if saw_echo && saw_trailer {
                    break;
                }
            }
            (saw_echo, saw_trailer)
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async("ws://x/internal/session", stream)
            .await
            .unwrap();
        let mut socket = TestSocket { ws };
        let child = tokio::process::Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let code = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            pipe_child(&mut socket, child),
        )
        .await
        .expect("pipe_child hung")
        .unwrap();
        assert_eq!(code, 0);
        let (saw_echo, saw_trailer) = server.await.unwrap();
        assert!(saw_echo && saw_trailer);
    }

    #[test]
    fn serial_sock_path_shape() {
        let id = uuid::Uuid::nil();
        assert_eq!(
            serial_sock_path(Path::new("/data/instances"), &id),
            PathBuf::from(format!("/data/instances/{id}/serial.sock"))
        );
    }

    struct ScriptSocket {
        inbound: std::collections::VecDeque<SocketMsg>,
        outbound: std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    }

    impl SessionSocket for ScriptSocket {
        async fn recv_msg(&mut self) -> SocketMsg {
            match self.inbound.pop_front() {
                Some(msg) => msg,
                None => peer_gone().await,
            }
        }

        async fn send_data(&mut self, data: Vec<u8>) -> bool {
            self.outbound.lock().unwrap().push(data);
            true
        }

        async fn send_trailer(&mut self, _code: i32) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn serial_bridge_roundtrips_until_guest_eof() {
        let (a, mut b) = tokio::net::UnixStream::pair().unwrap();
        let outbound = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut socket = ScriptSocket {
            inbound: [SocketMsg::Data(b"cli-in".to_vec())].into(),
            outbound: outbound.clone(),
        };
        let bridge = tokio::spawn(async move { serial_bridge(&mut socket, a).await });
        b.write_all(b"guest-out").await.unwrap();
        let mut buf = [0u8; 16];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"cli-in");
        drop(b);
        tokio::time::timeout(std::time::Duration::from_secs(10), bridge)
            .await
            .expect("bridge hung")
            .unwrap();
        assert_eq!(&outbound.lock().unwrap()[..], &[b"guest-out".to_vec()]);
    }

    #[tokio::test]
    async fn proxy_pipe_echoes_until_close() {
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = echo.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        });

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            use futures_util::{SinkExt, StreamExt};
            use tokio_tungstenite::tungstenite::Message as TMsg;
            ws.send(TMsg::Binary(b"proxy-bytes".to_vec().into()))
                .await
                .unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                if let TMsg::Binary(data) = msg
                    && data.as_ref() == b"proxy-bytes"
                {
                    break;
                }
            }
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async("ws://x/internal/session", stream)
            .await
            .unwrap();
        let mut socket = TestSocket { ws };
        let guest = tokio::net::TcpStream::connect(echo_addr).await.unwrap();
        proxy_pipe(&mut socket, guest).await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pipe_child_reports_nonzero_exit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use futures_util::StreamExt;
            use tokio_tungstenite::tungstenite::Message as TMsg;
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            while let Some(Ok(msg)) = ws.next().await {
                if let TMsg::Text(text) = msg
                    && text.contains("\"exit\":3")
                {
                    return true;
                }
            }
            false
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (ws, _) = tokio_tungstenite::client_async("ws://x/internal/session", stream)
            .await
            .unwrap();
        let mut socket = TestSocket { ws };
        let child = tokio::process::Command::new("sh")
            .args(["-c", "exit 3"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let code = pipe_child(&mut socket, child).await.unwrap();
        assert_eq!(code, 3);
        assert!(server.await.unwrap());
    }

    type WsStream = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    fn stub_record(id: uuid::Uuid, name: &str, state: &str, nat: bool) -> VmRecord {
        VmRecord {
            id,
            name: name.to_string(),
            image: "default".to_string(),
            state: match state {
                "running" => VmState::Running,
                _ => VmState::Stopped,
            },
            kernel_path: PathBuf::from("/img/vmlinux"),
            rootfs_path: PathBuf::from("/img/rootfs.ext4"),
            overlay_path: None,
            vsock_cid: None,
            network: Some(VmNetworkConfig { nat }),
            fc_pid: None,
            slirp_pid: None,
            ssh_addr: Some("127.42.0.2".to_string()),
            ssh_port: Some(20_002),
            vcpu_count: 1,
            memory_mib: 512,
            disk_mib: 0,
            created_at: kletka_types::time::Timestamp::UNIX_EPOCH,
        }
    }

    async fn serve_stub_slirp(
        listener: tokio::net::UnixListener,
        ops: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        forward_guest: bool,
    ) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&chunk[..n]),
                    }
                }
                let command: serde_json::Value =
                    serde_json::from_slice(&raw).unwrap_or(serde_json::json!(null));
                let response = match command["execute"].as_str().unwrap_or("") {
                    "add_hostfwd" => {
                        let host_port = command["arguments"]["host_port"].as_u64().unwrap_or(0);
                        let guest_port = command["arguments"]["guest_port"].as_u64().unwrap_or(0);
                        ops.lock()
                            .unwrap()
                            .push(format!("add:host={host_port},guest={guest_port}"));
                        if forward_guest {
                            tokio::spawn(echo_on(host_port as u16));
                        }
                        serde_json::json!({ "return": { "id": 7 } })
                    }
                    "remove_hostfwd" => {
                        let id = command["arguments"]["id"].as_u64().unwrap_or(0);
                        ops.lock().unwrap().push(format!("remove:{id}"));
                        serde_json::json!({ "return": {} })
                    }
                    _ => serde_json::json!({ "error": "unsupported" }),
                };
                let _ = stream
                    .write_all(&serde_json::to_vec(&response).unwrap())
                    .await;
            }
        });
    }

    async fn echo_on(port: u16) {
        let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await else {
            return;
        };
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (mut rd, mut wr) = stream.split();
            let _ = tokio::io::copy(&mut rd, &mut wr).await;
        }
    }

    async fn stub_env(
        record: VmRecord,
        with_slirp: Option<(std::sync::Arc<std::sync::Mutex<Vec<String>>>, bool)>,
    ) -> (PathBuf, SessionState, String) {
        let dir = std::env::temp_dir().join(format!(
            "kp-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = kletka::system::KletkaPaths::with_data_dir(&dir);
        paths.ensure().unwrap();
        Registry::open(&paths).insert(record.clone()).unwrap();
        if let Some((ops, forward_guest)) = with_slirp {
            let instance = dir.join("instances").join(record.id.to_string());
            std::fs::create_dir_all(&instance).unwrap();
            let slirp = tokio::net::UnixListener::bind(instance.join("slirp.sock")).unwrap();
            serve_stub_slirp(slirp, ops, forward_guest).await;
        }
        let state = SessionState {
            node_secret: "test-secret".to_string(),
            node_id: "test-node".to_string(),
            data_dir: dir.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server_state = state.clone();
        tokio::spawn(async move {
            axum::serve(listener, router(server_state)).await.unwrap();
        });
        (dir, state, addr)
    }

    async fn dial_session(node_addr: &str, secret: &str, vm: &str, kind: &SessionKind) -> WsStream {
        use tokio_tungstenite::tungstenite::Message as TMsg;
        use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
        let mut request = format!("ws://{node_addr}/internal/session?vm={vm}")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "x-node-secret",
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(secret).unwrap(),
        );
        let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        let header = SessionHeader {
            session_id: None,
            kind: kind.clone(),
            pty_cols: None,
            pty_rows: None,
            term: None,
            colorterm: None,
        };
        futures_util::SinkExt::send(
            &mut ws,
            TMsg::Text(serde_json::to_string(&header).unwrap().into()),
        )
        .await
        .unwrap();
        ws
    }

    async fn dial_proxy(node_addr: &str, secret: &str, tcp_port: u16) -> WsStream {
        dial_session(
            node_addr,
            secret,
            "calm-fox",
            &SessionKind::Proxy { tcp_port },
        )
        .await
    }

    async fn close_reason(ws: &mut WsStream) -> Option<String> {
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::Message as TMsg;
        loop {
            match ws.next().await? {
                Ok(TMsg::Close(frame)) => return frame.map(|frame| frame.reason.to_string()),
                Ok(_) => continue,
                Err(err) => return Some(err.to_string()),
            }
        }
    }

    #[tokio::test]
    async fn proxy_bridge_reports_a_stopped_vm() {
        let record = stub_record(uuid::Uuid::new_v4(), "calm-fox", "stopped", true);
        let (dir, state, addr) = stub_env(record, None).await;
        let mut ws = dial_proxy(&addr, &state.node_secret, 3000).await;
        let reason =
            tokio::time::timeout(std::time::Duration::from_secs(10), close_reason(&mut ws))
                .await
                .expect("session closed")
                .expect("close reason present");
        assert!(reason.contains("not running"), "{reason}");
        assert!(!reason.contains("NAT"), "{reason}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn proxy_bridge_reports_a_nat_less_vm() {
        let record = stub_record(uuid::Uuid::new_v4(), "calm-fox", "running", false);
        let (dir, state, addr) = stub_env(record, None).await;
        let mut ws = dial_proxy(&addr, &state.node_secret, 3000).await;
        let reason =
            tokio::time::timeout(std::time::Duration::from_secs(10), close_reason(&mut ws))
                .await
                .expect("session closed")
                .expect("close reason present");
        assert!(reason.contains("no NAT networking"), "{reason}");
        assert!(!reason.contains("not running"), "{reason}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn proxy_bridge_reports_a_dead_slirp_socket() {
        let record = stub_record(uuid::Uuid::new_v4(), "calm-fox", "running", true);
        let (dir, state, addr) = stub_env(record, None).await;
        let mut ws = dial_proxy(&addr, &state.node_secret, 3000).await;
        let reason =
            tokio::time::timeout(std::time::Duration::from_secs(10), close_reason(&mut ws))
                .await
                .expect("session closed")
                .expect("close reason present");
        assert!(reason.contains("network is down"), "{reason}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn proxy_bridge_roundtrips_and_removes_the_forward() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message as TMsg;

        let record = stub_record(uuid::Uuid::new_v4(), "calm-fox", "running", true);
        let ops = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (dir, state, addr) = stub_env(record, Some((ops.clone(), true))).await;
        let mut ws = dial_proxy(&addr, &state.node_secret, 3000).await;

        ws.send(TMsg::Binary(b"proxy-ping".to_vec().into()))
            .await
            .unwrap();
        let echo = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next())
            .await
            .expect("echo arrived")
            .expect("session open")
            .expect("frame ok");
        assert_eq!(echo, TMsg::Binary(b"proxy-ping".to_vec().into()));

        let seen = ops.lock().unwrap().clone();
        let add = seen
            .iter()
            .find(|op| op.starts_with("add:"))
            .expect("forward added");
        assert!(add.ends_with(",guest=3000"), "{add}");

        let _ = futures_util::SinkExt::close(&mut ws).await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let seen = ops.lock().unwrap().clone();
            if seen.iter().any(|op| op.starts_with("remove:")) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "forward was never removed: {seen:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn proxy_bridge_removes_the_forward_when_the_dial_fails() {
        let record = stub_record(uuid::Uuid::new_v4(), "calm-fox", "running", true);
        let ops = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (dir, state, addr) = stub_env(record, Some((ops.clone(), false))).await;
        let mut ws = dial_proxy(&addr, &state.node_secret, 3000).await;
        let reason =
            tokio::time::timeout(std::time::Duration::from_secs(15), close_reason(&mut ws))
                .await
                .expect("session closed")
                .expect("close reason present");
        assert!(reason.contains("dial guest failed"), "{reason}");
        let seen = ops.lock().unwrap().clone();
        assert!(
            seen.iter().any(|op| op.starts_with("remove:")),
            "forward leaked after a failed dial: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn find_image_version_dir() -> Option<PathBuf> {
        if let Some(dir) = std::env::var_os("KLETKA_TEST_IMAGE_DIR") {
            let dir = PathBuf::from(dir);
            if dir.join("vmlinux").is_file() && dir.join("rootfs.ext4").is_file() {
                return Some(dir);
            }
        }
        let home = std::env::var_os("HOME")?;
        let versions = PathBuf::from(home).join(".local/share/kletka/images/default/versions");
        let mut candidates: Vec<PathBuf> = std::fs::read_dir(&versions)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|dir| dir.join("vmlinux").is_file() && dir.join("rootfs.ext4").is_file())
            .collect();
        candidates.sort();
        candidates.into_iter().next()
    }

    fn host_can_run_vms() -> bool {
        if !std::path::Path::new("/dev/kvm").exists() {
            return false;
        }
        let on_path = |binary: &str| {
            std::env::var_os("PATH").is_some_and(|paths| {
                std::env::split_paths(&paths).any(|dir| dir.join(binary).is_file())
            })
        };
        ["firecracker", "slirp4netns", "unshare", "ssh"]
            .iter()
            .all(|b| on_path(b))
    }

    fn ephemeral_rules(list: &serde_json::Value) -> usize {
        list["entries"]
            .as_array()
            .map(|rules| {
                rules
                    .iter()
                    .filter(|rule| rule["host_addr"].as_str() == Some("127.0.0.1"))
                    .count()
            })
            .unwrap_or(0)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "boots a real firecracker VM; needs /dev/kvm, slirp4netns and a built image"]
    async fn proxy_session_reaches_a_real_guest() {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message as TMsg;

        if !host_can_run_vms() {
            eprintln!("skipping: no /dev/kvm or firecracker/slirp4netns/unshare/ssh on PATH");
            return;
        }
        let Some(source_dir) = find_image_version_dir() else {
            eprintln!("skipping: no bootable image found (set KLETKA_TEST_IMAGE_DIR)");
            return;
        };
        let version = source_dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        eprintln!("e2e: using image {version} from {}", source_dir.display());

        let data = std::env::temp_dir().join(format!(
            "ke2e-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ));
        let images = data.join("images/default");
        std::fs::create_dir_all(images.join("versions")).unwrap();
        std::os::unix::fs::symlink(&source_dir, images.join("versions").join(&version)).unwrap();
        std::os::unix::fs::symlink(
            images.join("versions").join(&version),
            images.join("current"),
        )
        .unwrap();

        let paths = kletka::system::KletkaPaths::with_data_dir(&data);
        let runtime = std::sync::Arc::new(
            kletka_runtime::runtime::VmRuntime::new(paths.clone()).expect("runtime init"),
        );

        let body_runtime = runtime.clone();
        let body = tokio::spawn(async move {
            let record = tokio::time::timeout(
                std::time::Duration::from_secs(180),
                body_runtime.create_vm(
                    kletka_types::VmSpec {
                        name: "proxy-e2e".to_string(),
                        image: "default".to_string(),
                        nat: true,
                        ..kletka_types::VmSpec::default()
                    },
                    Some("proxy-e2e"),
                ),
            )
            .await
            .expect("vm create timed out")
            .expect("vm created and booted");
            tokio::time::timeout(std::time::Duration::from_secs(90), async {
                while !body_runtime.guest_ssh_ready(&record).await {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            })
            .await
            .expect("guest ssh ready");
            let vm_id = record.id.to_string();
            eprintln!("e2e: vm proxy-e2e ({vm_id}) is running");

            let state = SessionState {
                node_secret: "e2e-secret".to_string(),
                node_id: "e2e-node".to_string(),
                data_dir: paths.data_dir().to_path_buf(),
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let node_addr = listener.local_addr().unwrap().to_string();
            tokio::spawn(async move {
                axum::serve(listener, router(state)).await.unwrap();
            });

            let guest_port = 12399u16;
            let script = format!(
                "sudo /usr/sbin/sshd -p {guest_port} 2>&1; echo sshd-rc=$?; \
                 for i in $(seq 40); do \
                 (exec 3<>/dev/tcp/127.0.0.1/{guest_port}) 2>/dev/null && exit 0; \
                 sleep 0.5; done; exit 1"
            );
            let mut exec_ws = dial_session(
                &node_addr,
                "e2e-secret",
                "proxy-e2e",
                &SessionKind::Exec {
                    cmd: vec![format!("bash -c {}", crate::file::sh_quote(&script))],
                    pty: false,
                },
            )
            .await;
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(60), exec_ws.next())
                    .await
                    .expect("exec session alive")
                    .expect("exec session open")
                    .expect("exec frame")
                {
                    TMsg::Text(text) if text.contains("\"exit\":0") => break,
                    TMsg::Text(text) => panic!("guest listener setup failed: {text}"),
                    TMsg::Binary(data) => eprintln!(
                        "e2e: exec output: {}",
                        String::from_utf8_lossy(&data).trim()
                    ),
                    TMsg::Close(frame) => panic!(
                        "guest listener setup closed: {:?}",
                        frame.map(|frame| frame.reason.to_string())
                    ),
                    _ => {}
                }
            }
            eprintln!("e2e: guest listener on :{guest_port} is up");

            let slirp_sock = paths.instances_path().join(&vm_id).join("slirp.sock");
            let slirp = kletka::host_nat::SlirpClient::new(&slirp_sock);
            let before = slirp.list_hostfwd().await.expect("list_hostfwd");
            eprintln!("e2e: hostfwd before session: {before}");
            assert_eq!(
                ephemeral_rules(&before),
                0,
                "no ephemeral forward before the session: {before}"
            );

            let mut ws = dial_session(
                &node_addr,
                "e2e-secret",
                "proxy-e2e",
                &SessionKind::Proxy {
                    tcp_port: guest_port,
                },
            )
            .await;

            let mut banner = Vec::new();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !banner.starts_with(b"SSH-") {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no ssh banner: {banner:?}"
                );
                match ws.next().await {
                    Some(Ok(TMsg::Binary(data))) => banner.extend_from_slice(&data),
                    other => panic!("proxy session ended before the banner: {other:?}"),
                }
            }
            eprintln!(
                "e2e: guest banner: {}",
                String::from_utf8_lossy(&banner[..16])
            );

            let during = slirp.list_hostfwd().await.expect("list_hostfwd");
            eprintln!("e2e: hostfwd during session: {during}");
            assert_eq!(
                ephemeral_rules(&during),
                1,
                "one ephemeral forward during the session: {during}"
            );

            ws.send(TMsg::Binary(b"KLETKA-E2E\r\n".to_vec().into()))
                .await
                .unwrap();
            let mut reply = Vec::new();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while reply.is_empty() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "no reply from the guest: {reply:?}"
                );
                match ws.next().await {
                    Some(Ok(TMsg::Binary(data))) => reply.extend_from_slice(&data),
                    other => panic!("proxy session ended before the reply: {other:?}"),
                }
            }
            eprintln!(
                "e2e: guest reply: {}",
                String::from_utf8_lossy(&reply).trim()
            );

            let _ = ws.close(None).await;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let after = loop {
                let list = slirp.list_hostfwd().await.expect("list_hostfwd");
                if ephemeral_rules(&list) == 0 {
                    break list;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "ephemeral forward was never removed: {list}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            };
            eprintln!("e2e: hostfwd after session: {after}");
            record.id
        });

        let outcome = body.await;
        if let Ok(vm_id) = &outcome {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                runtime.delete_vm(&vm_id.to_string()),
            )
            .await;
        }
        let _ = std::fs::remove_dir_all(&data);
        if let Err(join) = outcome {
            std::panic::resume_unwind(join.into_panic());
        }
    }
}
