use std::io::{IsTerminal as _, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use kletka_types::{
    AccountInfo, AuditEvent, CreateVmRequest, ImageInfo, SnapshotInfo, Vm, VmStatus, urlencode,
};
use reqwest::{Method, RequestBuilder, Response, StatusCode};
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::error::{CliError, CliResult, ErrorKind, error_chain, io_error};

const BOOT_TIMEOUT: Duration = Duration::from_secs(180);
const CLONE_TIMEOUT: Duration = Duration::from_secs(900);
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Debug, Clone)]
pub struct Client {
    url: String,
    token: String,
    namespace: Option<String>,
    http: reqwest::Client,
}

impl Client {
    pub fn new(url: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            url: url.into().trim_end_matches('/').to_string(),
            token: token.into(),
            namespace: None,
            http: reqwest::Client::new(),
        }
    }

    pub fn with_namespace(mut self, namespace: Option<String>) -> Self {
        self.namespace = namespace;
        self
    }

    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let request = self
            .http
            .request(method, format!("{}{path}", self.url))
            .bearer_auth(&self.token);
        match &self.namespace {
            Some(namespace) => request.header(kletka_types::NAMESPACE_HEADER, namespace),
            None => request,
        }
    }

    async fn send(&self, request: RequestBuilder, action: &str) -> CliResult<Response> {
        let response = request
            .send()
            .await
            .map_err(|err| transport_error(&self.url, &err))?;
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let body = response.bytes().await.unwrap_or_default();
        Err(status_error(status, &body, action))
    }

    async fn json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        action: &str,
    ) -> CliResult<T> {
        self.send(request, action)
            .await?
            .json()
            .await
            .map_err(|err| transport_error(&self.url, &err))
    }

    pub async fn list(&self) -> CliResult<Vec<Vm>> {
        self.json(self.request(Method::GET, "/v1/vms"), "list VMs")
            .await
    }

    pub async fn show(&self, key: &str) -> CliResult<Vm> {
        let path = format!("/v1/vms/{}", urlencode(key));
        self.json(self.request(Method::GET, &path), "look up the VM")
            .await
    }

    pub async fn images(&self) -> CliResult<Vec<ImageInfo>> {
        self.json(self.request(Method::GET, "/v1/images"), "list images")
            .await
    }

    pub async fn account(&self) -> CliResult<AccountInfo> {
        self.json(self.request(Method::GET, "/v1/auth/me"), "read your quota")
            .await
    }

    pub async fn create(&self, request: &CreateVmRequest) -> CliResult<Vm> {
        let created: kletka_types::CreateVmResponse = self
            .json(
                self.request(Method::POST, "/v1/vms").json(request),
                "create the VM",
            )
            .await?;
        self.wait_until_running(&created.vm, "start").await
    }

    pub async fn start(&self, vm: &Vm) -> CliResult<Vm> {
        let path = format!("/v1/vms/{}/start", vm.id);
        self.send(self.request(Method::POST, &path), "start the VM")
            .await?;
        self.wait_until_running(vm, "start").await
    }

    pub async fn stop(&self, vm: &Vm) -> CliResult<()> {
        let path = format!("/v1/vms/{}/stop", vm.id);
        self.send(self.request(Method::POST, &path), "stop the VM")
            .await?;
        Ok(())
    }

    pub async fn set_idle_timeout(&self, vm: &Vm, secs: Option<u64>) -> CliResult<Vm> {
        let path = format!("/v1/vms/{}", vm.id);
        let body = serde_json::json!({ "idle_timeout_secs": secs });
        self.json(
            self.request(Method::PATCH, &path).json(&body),
            "update the VM",
        )
        .await
    }

    pub async fn resize(
        &self,
        vm: &Vm,
        vcpu: Option<usize>,
        memory_mib: Option<usize>,
        disk_mib: Option<usize>,
    ) -> CliResult<Vm> {
        let path = format!("/v1/vms/{}/resize", vm.id);
        let body = kletka_types::ResizeVmRequest {
            vcpu,
            memory_mib,
            disk_mib,
        };
        self.json(
            self.request(Method::POST, &path).json(&body),
            "resize the VM",
        )
        .await
    }

    pub async fn rebase(&self, vm: &Vm, image: Option<&str>) -> CliResult<Vm> {
        let path = format!("/v1/vms/{}/rebase", vm.id);
        let body = kletka_types::RebaseVmRequest {
            image: image.map(str::to_string),
        };
        self.send(
            self.request(Method::POST, &path).json(&body),
            "rebase the VM",
        )
        .await?;
        self.wait_until_running(vm, "rebase").await
    }

    pub async fn clone_vm(&self, vm: &Vm, name: Option<&str>) -> CliResult<Vm> {
        let path = format!("/v1/vms/{}/clone", vm.id);
        let body = kletka_types::CloneVmRequest {
            name: name.map(str::to_string),
        };
        let created: Vm = self
            .json(
                self.request(Method::POST, &path).json(&body),
                "clone the VM",
            )
            .await?;
        self.wait_until_cloned(&vm.name, &created).await
    }

    pub(crate) async fn wait_until_cloned(&self, source: &str, dest: &Vm) -> CliResult<Vm> {
        let mut progress = Progress::start(format!(
            "copying the disk of '{source}' into '{}'",
            dest.name
        ));
        let deadline = Instant::now() + CLONE_TIMEOUT;
        loop {
            match self.show(&dest.id.to_string()).await {
                Ok(current) => match current.status {
                    VmStatus::Cloning => {}
                    VmStatus::Failed => {
                        progress.finish("failed");
                        return Err(
                            CliError::new(format!("the clone of '{}' failed", dest.name)).hint(
                                "try again; if it keeps failing, ask an admin to check the \
                                 control-plane logs",
                            ),
                        );
                    }
                    _ => {
                        progress.finish("done");
                        return Ok(current);
                    }
                },
                Err(err) if err.is_not_found() => {
                    progress.finish("rolled back");
                    return Err(CliError::new(format!(
                        "the clone of '{}' was rolled back by the control plane",
                        dest.name
                    ))
                    .hint(
                        "try again; if it keeps failing, ask an admin to check the \
                         control-plane logs",
                    ));
                }
                Err(err) => return Err(err),
            }
            if Instant::now() >= deadline {
                progress.finish("still copying");
                tracing::debug!("clone wait timed out; the copy continues server-side");
                return self.show(&dest.id.to_string()).await;
            }
            progress.tick();
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    pub async fn configure_wireguard(&self, vm: &Vm, config: Option<String>) -> CliResult<Vm> {
        let path = format!("/v1/vms/{}/wireguard", vm.id);
        let body = kletka_types::WireguardRequest {
            wireguard_config: config,
        };
        self.json(
            self.request(Method::PUT, &path).json(&body),
            "update the WireGuard configuration",
        )
        .await
    }

    pub async fn destroy(&self, vm: &Vm) -> CliResult<bool> {
        let path = format!("/v1/vms/{}", vm.id);
        self.send(self.request(Method::DELETE, &path), "destroy the VM")
            .await?;

        let mut progress = Progress::start(format!("waiting for VM '{}' to be torn down", vm.name));
        let deadline = Instant::now() + TEARDOWN_TIMEOUT;
        while Instant::now() < deadline {
            match self.show(&vm.id.to_string()).await {
                Err(err) if err.is_not_found() => {
                    progress.finish("done");
                    return Ok(true);
                }
                Err(err) => tracing::debug!(%err, "teardown poll failed; retrying"),
                Ok(_) => {}
            }
            progress.tick();
            tokio::time::sleep(POLL_INTERVAL).await;
        }
        progress.finish("still in progress");
        Ok(false)
    }

    pub(crate) async fn wait_until_running(&self, vm: &Vm, verb: &str) -> CliResult<Vm> {
        let mut progress = Progress::start(format!("waiting for VM '{}' to {verb}", vm.name));
        let deadline = Instant::now() + BOOT_TIMEOUT;
        loop {
            let current = self.show(&vm.id.to_string()).await?;
            match current.status {
                VmStatus::Running => {
                    progress.finish("running");
                    return Ok(current);
                }
                VmStatus::Failed => {
                    progress.finish("failed");
                    return Err(
                        CliError::new(format!("VM '{}' failed to {verb}", vm.name)).hint(format!(
                            "retry with `kletka start -n {}`; if it keeps failing, ask an admin \
                             to check the control-plane logs",
                            vm.name
                        )),
                    );
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                progress.finish("timed out");
                return Err(CliError::new(format!(
                    "VM '{}' did not {verb} within {}s",
                    vm.name,
                    BOOT_TIMEOUT.as_secs()
                ))
                .hint("it may still come up; check `kletka list`"));
            }
            progress.tick();
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    pub async fn ensure_running(&self, vm: &Vm) -> CliResult<Vm> {
        match vm.status {
            VmStatus::Running => Ok(vm.clone()),
            VmStatus::Pending | VmStatus::Rebasing => self.wait_until_running(vm, "start").await,
            VmStatus::Cloning => {
                let cloned = self.wait_until_cloned(&vm.name, vm).await?;
                self.start(&cloned).await
            }
            _ => self.start(vm).await,
        }
    }

    pub async fn audit(&self, vm: Option<&str>, limit: usize) -> CliResult<Vec<AuditEvent>> {
        let mut path = format!("/v1/audit?limit={limit}");
        if let Some(vm) = vm {
            path.push_str(&format!("&vm={}", kletka_types::urlencode(vm)));
        }
        let page: kletka_types::AuditPage = self
            .json(self.request(Method::GET, &path), "read the audit log")
            .await?;
        Ok(page.events)
    }

    pub async fn snapshot_list(&self, vm: &Vm) -> CliResult<Vec<SnapshotInfo>> {
        let path = format!("/v1/vms/{}/snapshots", vm.id);
        self.json(self.request(Method::GET, &path), "list snapshots")
            .await
    }

    pub async fn snapshot_create(
        &self,
        vm: &Vm,
        name: &str,
        memory: bool,
    ) -> CliResult<SnapshotInfo> {
        let path = format!("/v1/vms/{}/snapshots", vm.id);
        let body = kletka_types::CreateSnapshotRequest {
            name: name.to_string(),
            memory,
        };
        self.json(
            self.request(Method::POST, &path).json(&body),
            "create the snapshot",
        )
        .await
    }

    pub async fn snapshot_delete(&self, vm: &Vm, name: &str) -> CliResult<()> {
        let path = format!("/v1/vms/{}/snapshots/{}", vm.id, urlencode(name));
        self.send(self.request(Method::DELETE, &path), "delete the snapshot")
            .await?;
        Ok(())
    }

    pub async fn snapshot_rollback(&self, vm: &Vm, name: &str) -> CliResult<()> {
        let path = format!("/v1/vms/{}/snapshots/{}/rollback", vm.id, urlencode(name));
        self.send(self.request(Method::POST, &path), "roll back the snapshot")
            .await?;
        Ok(())
    }

    pub async fn file_push(&self, vm: &Vm, src: &Path, dst: &str, sudo: bool) -> CliResult<()> {
        let meta = std::fs::metadata(src)
            .map_err(|err| io_error(format!("cannot read '{}'", src.display()), err))?;
        if meta.is_dir() {
            return Err(CliError::new(format!(
                "'{}' is a directory; only single files can be copied",
                src.display()
            ))
            .hint("archive it first (e.g. `tar czf app.tgz app`), then push the archive"));
        }
        if meta.len() > kletka_types::MAX_FILE_PUSH_BYTES as u64 {
            return Err(CliError::new(format!(
                "'{}' is larger than the 256 MiB transfer limit",
                src.display()
            )));
        }
        let bytes = std::fs::read(src)
            .map_err(|err| io_error(format!("cannot read '{}'", src.display()), err))?;
        let mut path = format!("/v1/vms/{}/file/push?dst={}", vm.id, urlencode(dst));
        if sudo {
            path.push_str("&sudo=true");
        }
        let request = self
            .request(Method::POST, &path)
            .header("content-type", "application/octet-stream")
            .body(bytes);
        self.send(request, "upload the file").await?;
        Ok(())
    }

    pub async fn file_pull(&self, vm: &Vm, src: &str, dst: &Path, sudo: bool) -> CliResult<()> {
        let mut path = format!("/v1/vms/{}/file/pull?src={}", vm.id, urlencode(src));
        if sudo {
            path.push_str("&sudo=true");
        }
        let mut response = self
            .send(self.request(Method::GET, &path), "download the file")
            .await?;

        let target = if dst.is_dir() {
            let name = Path::new(src)
                .file_name()
                .map(|name| name.to_os_string())
                .unwrap_or_else(|| "file".into());
            dst.join(name)
        } else {
            dst.to_path_buf()
        };
        if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|err| io_error(format!("cannot create '{}'", parent.display()), err))?;
        }
        let partial = target.with_extension("kletka-part");
        let result = async {
            let mut file = std::fs::File::create(&partial)
                .map_err(|err| io_error(format!("cannot write '{}'", target.display()), err))?;
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|err| transport_error(&self.url, &err))?
            {
                file.write_all(&chunk)
                    .map_err(|err| io_error(format!("cannot write '{}'", target.display()), err))?;
            }
            std::fs::rename(&partial, &target)
                .map_err(|err| io_error(format!("cannot write '{}'", target.display()), err))
        }
        .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&partial);
        }
        result
    }
}

pub struct LoginOutcome {
    pub user_id: Uuid,
    pub signed_up: bool,
    pub token: String,
}

pub async fn auth_methods(url: &str) -> CliResult<kletka_types::AuthMethods> {
    let http = reqwest::Client::new();
    let response = http
        .get(format!("{url}/v1/auth/methods"))
        .send()
        .await
        .map_err(|err| transport_error(url, &err))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.bytes().await.unwrap_or_default();
        return Err(status_error(status, &body, "read the sign-in methods"));
    }
    response
        .json()
        .await
        .map_err(|err| transport_error(url, &err))
}

pub async fn oauth_start(
    url: &str,
    provider: &str,
    redirect_uri: Option<&str>,
) -> CliResult<kletka_types::OAuthStart> {
    let http = reqwest::Client::new();
    let body = serde_json::json!({ "provider": provider, "redirect_uri": redirect_uri });
    let response = http
        .post(format!("{url}/v1/auth/oauth/cli/start"))
        .json(&body)
        .send()
        .await
        .map_err(|err| transport_error(url, &err))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.bytes().await.unwrap_or_default();
        return Err(status_error(status, &body, "start the OAuth sign-in"));
    }
    response
        .json()
        .await
        .map_err(|err| transport_error(url, &err))
}

pub async fn oauth_poll(url: &str, state: &str) -> CliResult<kletka_types::OAuthPoll> {
    let http = reqwest::Client::new();
    let path = format!("/v1/auth/oauth/poll/{}", urlencode(state));
    let response = http
        .get(format!("{url}{path}"))
        .send()
        .await
        .map_err(|err| transport_error(url, &err))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.bytes().await.unwrap_or_default();
        return Err(status_error(status, &body, "check the OAuth sign-in"));
    }
    response
        .json()
        .await
        .map_err(|err| transport_error(url, &err))
}

pub async fn login(url: &str, email: &str, password: &str) -> CliResult<LoginOutcome> {
    let http = reqwest::Client::new();
    let payload = serde_json::json!({ "email": email, "password": password });
    let post = |path: &str| http.post(format!("{url}{path}")).json(&payload).send();

    let mut response = post("/v1/auth/login")
        .await
        .map_err(|err| transport_error(url, &err))?;
    let signed_up = response.status() == StatusCode::NOT_FOUND;
    if signed_up {
        response = post("/v1/auth/signup")
            .await
            .map_err(|err| transport_error(url, &err))?;
    }
    let status = response.status();
    if !status.is_success() {
        let body = response.bytes().await.unwrap_or_default();
        let err = status_error(status, &body, "log in");
        return Err(if status == StatusCode::UNAUTHORIZED {
            CliError::new(server_message(&body).unwrap_or_else(|| "wrong password".into()))
        } else {
            err
        });
    }
    let session: kletka_types::AuthResponse = response
        .json()
        .await
        .map_err(|err| transport_error(url, &err))?;
    Ok(LoginOutcome {
        user_id: session.user_id,
        signed_up,
        token: session.token,
    })
}

pub(crate) fn server_message(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()?
        .get("error")?
        .as_str()
        .map(str::to_string)
}

pub(crate) fn status_error(status: StatusCode, body: &[u8], action: &str) -> CliError {
    let message = server_message(body);
    let detail = match &message {
        Some(message) => format!("HTTP {status}: {message}"),
        None => format!("HTTP {status}"),
    };
    let err = match status.as_u16() {
        401 => CliError::new("not logged in, or your session has expired")
            .kind(ErrorKind::Unauthorized)
            .hint("run `kletka login`"),
        402 => {
            let message = message.unwrap_or_else(|| "limit reached".into());
            CliError::new(format!("quota exceeded: {message}")).hint(
                "destroy VMs you no longer need, ask an admin to raise your limits, \
                       or see both with `kletka quota`",
            )
        }
        404 => {
            CliError::new(message.unwrap_or_else(|| "not found".into())).kind(ErrorKind::NotFound)
        }
        400..=499 => CliError::new(message.unwrap_or_else(|| format!("cannot {action}"))),
        _ => CliError::new(format!("the control plane could not {action}"))
            .hint("try again; if it keeps failing, ask an admin to check the control-plane logs"),
    };
    err.detail(detail)
}

pub(crate) fn transport_error(url: &str, err: &reqwest::Error) -> CliError {
    let detail = error_chain(err);
    let err = if err.is_timeout() {
        CliError::new(format!(
            "the control plane at {url} did not respond in time"
        ))
        .hint("check your network connection and try again")
    } else if err.is_connect() {
        CliError::new(format!("cannot reach the control plane at {url}")).hint(
            "check the URL (`--control-url`, KLETKA_CONTROL_URL, or `kletka login --control`) \
             and your network connection",
        )
    } else if err.is_builder() {
        CliError::new(format!("'{url}' is not a valid control-plane URL"))
            .hint("URLs look like https://control.example.com")
    } else if err.is_decode() {
        CliError::new("the control plane sent an unexpected response")
            .hint("make sure the URL points at a kletka control plane and the CLI is up to date")
    } else {
        CliError::new(format!("the request to {url} failed"))
    };
    err.detail(detail)
}

struct Progress {
    tty: bool,
    last_tick: Instant,
}

impl Progress {
    fn start(message: String) -> Self {
        eprint!("{message}");
        let _ = std::io::stderr().flush();
        Self {
            tty: std::io::stderr().is_terminal(),
            last_tick: Instant::now(),
        }
    }

    fn tick(&mut self) {
        if self.tty && self.last_tick.elapsed() >= Duration::from_secs(1) {
            eprint!(".");
            let _ = std::io::stderr().flush();
            self.last_tick = Instant::now();
        }
    }

    fn finish(&self, outcome: &str) {
        eprintln!(" {outcome}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode as AxumStatus;
    use axum::response::IntoResponse;
    use std::sync::{Arc, Mutex};

    #[test]
    fn status_errors_are_friendly() {
        let body = br#"{"error":"vm 'web' not found"}"#;
        let err = status_error(StatusCode::NOT_FOUND, body, "look up the VM");
        assert!(err.is_not_found());
        assert_eq!(err.message, "vm 'web' not found");

        let err = status_error(StatusCode::UNAUTHORIZED, b"", "list VMs");
        assert_eq!(err.kind, ErrorKind::Unauthorized);
        assert!(err.hint.unwrap().contains("kletka login"));

        let err = status_error(
            StatusCode::PAYMENT_REQUIRED,
            br#"{"error":"too many VMs"}"#,
            "x",
        );
        assert_eq!(err.message, "quota exceeded: too many VMs");
        assert!(
            err.hint.as_deref().unwrap().contains("kletka quota"),
            "the 402 hint points at the new command"
        );

        let err = status_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            br#"{"error":"database error: disk I/O"}"#,
            "list VMs",
        );
        assert_eq!(err.message, "the control plane could not list VMs");
        assert!(err.detail.unwrap().contains("disk I/O"));
    }

    #[tokio::test]
    async fn unreachable_control_plane_is_explained() {
        let client = Client::new("http://127.0.0.1:9", "tok");
        let err = client.list().await.unwrap_err();
        assert!(
            err.message.contains("cannot reach the control plane"),
            "{}",
            err.message
        );
        assert!(err.detail.is_some());
    }

    async fn serve_fake() -> String {
        use axum::extract::Path as AxPath;
        use axum::routing::{get, post};

        type Vms = Arc<Mutex<Vec<Vm>>>;
        let vms: Vms = Arc::default();
        let find = |vms: &[Vm], key: &str| {
            vms.iter()
                .position(|v| v.name == key || v.id.to_string() == key)
        };
        let not_found = || {
            (
                AxumStatus::NOT_FOUND,
                axum::Json(serde_json::json!({ "error": "vm not found" })),
            )
                .into_response()
        };

        let app = axum::Router::new()
            .route(
                "/v1/auth/me",
                get(|| async {
                    axum::Json(serde_json::json!({
                        "user_id": "00000000-0000-0000-0000-000000000000",
                        "email": "fake@example.com",
                        "quotas": { "max_vms": 5, "max_vcpu": 8, "max_mem_mib": 8192 },
                        "usage": { "vms": 1, "vcpu": 2, "mem_mib": 1024 }
                    }))
                }),
            )
            .route(
                "/v1/vms",
                get({
                    let vms = vms.clone();
                    move || async move { axum::Json(vms.lock().unwrap().clone()) }
                })
                .post({
                    let vms = vms.clone();
                    move |axum::Json(body): axum::Json<serde_json::Value>| async move {
                        let name = body["name"].as_str().unwrap_or("auto-vm").to_string();
                        if name == "over-quota" {
                            return (
                                AxumStatus::PAYMENT_REQUIRED,
                                axum::Json(serde_json::json!({ "error": "too many VMs" })),
                            )
                                .into_response();
                        }
                        let vm = Vm {
                            id: Uuid::new_v4(),
                            name,
                            image: "default".into(),
                            vcpu: 2,
                            memory_mib: 1024,
                            disk_mib: 0,
                            nat: true,
                            status: VmStatus::Pending,
                            assigned_node: None,
                            idle_timeout_secs: 28_800,
                            idle_timeout_default: true,
                            last_active_at: None,
                        };
                        vms.lock().unwrap().push(vm.clone());
                        let (vms, id) = (vms.clone(), vm.id);
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            for v in vms.lock().unwrap().iter_mut().filter(|v| v.id == id) {
                                v.status = VmStatus::Running;
                            }
                        });
                        axum::Json(serde_json::json!({ "vm": vm })).into_response()
                    }
                }),
            )
            .route(
                "/v1/vms/{key}",
                get({
                    let vms = vms.clone();
                    move |AxPath(key): AxPath<String>| async move {
                        let vms = vms.lock().unwrap();
                        match find(&vms, &key) {
                            Some(i) => axum::Json(vms[i].clone()).into_response(),
                            None => not_found(),
                        }
                    }
                })
                .delete({
                    let vms = vms.clone();
                    move |AxPath(key): AxPath<String>| async move {
                        let mut vms = vms.lock().unwrap();
                        match find(&vms, &key) {
                            Some(i) => {
                                let vm = vms.remove(i);
                                axum::Json(serde_json::json!({ "deleted": vm.name }))
                                    .into_response()
                            }
                            None => not_found(),
                        }
                    }
                }),
            )
            .route(
                "/v1/vms/{key}/{op}",
                post({
                    let vms = vms.clone();
                    move |AxPath((key, op)): AxPath<(String, String)>| async move {
                        let mut vms = vms.lock().unwrap();
                        match find(&vms, &key) {
                            Some(i) => {
                                vms[i].status = if op == "start" {
                                    VmStatus::Running
                                } else {
                                    VmStatus::Stopped
                                };
                                axum::Json(serde_json::json!({})).into_response()
                            }
                            None => not_found(),
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn create_request(name: &str) -> CreateVmRequest {
        CreateVmRequest {
            name: Some(name.into()),
            image: Some("default".into()),
            vcpu: Some(2),
            memory_mib: Some(1024),
            disk_mib: Some(0),
            nat: Some(true),
            wireguard_config: None,
            ssh_keys: vec![],
            idle_timeout_secs: None,
        }
    }

    #[tokio::test]
    async fn crud_roundtrip_against_fake_control() {
        let client = Client::new(serve_fake().await, "tok");

        assert!(client.list().await.unwrap().is_empty());
        let vm = client.create(&create_request("web")).await.unwrap();
        assert_eq!(vm.name, "web");
        assert_eq!(vm.status, VmStatus::Running);
        assert_eq!(client.show("web").await.unwrap().id, vm.id);

        client.stop(&vm).await.unwrap();
        assert_eq!(client.show("web").await.unwrap().status, VmStatus::Stopped);
        assert_eq!(client.start(&vm).await.unwrap().status, VmStatus::Running);

        assert!(client.destroy(&vm).await.unwrap());
        assert!(client.list().await.unwrap().is_empty());
        assert!(client.show("web").await.unwrap_err().is_not_found());
    }

    #[tokio::test]
    async fn quota_rejection_is_explained() {
        let client = Client::new(serve_fake().await, "tok");
        let err = client
            .create(&create_request("over-quota"))
            .await
            .unwrap_err();
        assert_eq!(err.message, "quota exceeded: too many VMs");
        assert!(err.hint.is_some());
    }

    #[tokio::test]
    async fn account_fetches_quota_and_usage() {
        let client = Client::new(serve_fake().await, "tok");
        let account = client.account().await.unwrap();
        assert_eq!(account.email, "fake@example.com");
        assert_eq!(account.quotas.max_vcpu, 8);
        assert_eq!(account.usage.vms, 1);
    }

    #[tokio::test]
    async fn file_push_rejects_directories_and_missing_files() {
        let client = Client::new("http://127.0.0.1:9", "tok");
        let vm = Vm {
            id: Uuid::nil(),
            name: "vm".into(),
            image: "default".into(),
            vcpu: 1,
            memory_mib: 1,
            disk_mib: 0,
            nat: true,
            status: VmStatus::Running,
            assigned_node: None,
            idle_timeout_secs: 28_800,
            idle_timeout_default: true,
            last_active_at: None,
        };
        let dir = std::env::temp_dir();
        let err = client
            .file_push(&vm, &dir, "/dst", false)
            .await
            .unwrap_err();
        assert!(err.message.contains("is a directory"), "{}", err.message);

        let missing = dir.join(format!("kletka-missing-{}", Uuid::new_v4()));
        let err = client
            .file_push(&vm, &missing, "/dst", false)
            .await
            .unwrap_err();
        assert!(err.message.contains("no such file"), "{}", err.message);
    }
}
