use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    Router,
    routing::{get, post},
};
use serde::Deserialize;
use std::process::Stdio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::reply::{json_error, json_ok, reader_body};
use crate::session::SessionState;
use kletka_types::{MAX_FILE_PULL_BYTES, MAX_FILE_PUSH_BYTES};

pub fn router(state: SessionState) -> Router {
    Router::new()
        .route("/internal/file/push", post(push))
        .route("/internal/file/pull", get(pull))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
pub struct PushQuery {
    pub vm: String,
    pub dst: String,
    #[serde(default)]
    pub sudo: bool,
    #[serde(default)]
    pub mode: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PullQuery {
    pub vm: String,
    pub src: String,
    #[serde(default)]
    pub sudo: bool,
}

pub fn validate_guest_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') {
        return Err(format!("guest path must be absolute: '{path}'"));
    }
    if path.contains("..") {
        return Err(format!("guest path must not contain '..': '{path}'"));
    }
    if path.contains('\0') {
        return Err("guest path contains null byte".to_string());
    }
    Ok(())
}

pub fn sh_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\"'\"'"))
}

pub fn push_remote_cmd(dst: &str, sudo: bool) -> String {
    if sudo {
        format!("sudo tee {} > /dev/null", sh_quote(dst))
    } else {
        format!("cat > {}", sh_quote(dst))
    }
}

pub fn pull_remote_cmd(src: &str, sudo: bool) -> String {
    if sudo {
        format!("sudo cat {}", sh_quote(src))
    } else {
        format!("cat {}", sh_quote(src))
    }
}

pub fn pull_size_cmd(src: &str, sudo: bool) -> String {
    let quoted = sh_quote(src);
    if sudo {
        format!("sudo test -r {quoted} && sudo stat -c %s {quoted}")
    } else {
        format!("test -r {quoted} && stat -c %s {quoted}")
    }
}

async fn push(
    State(state): State<SessionState>,
    Query(query): Query<PushQuery>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(rejection) = state.reject_unauthorized(&headers) {
        return rejection;
    }
    if let Err(err) = validate_guest_path(&query.dst) {
        return json_error(StatusCode::BAD_REQUEST, err);
    }
    if headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|len| len > MAX_FILE_PUSH_BYTES)
    {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds 256 MiB cap");
    }
    let mut stream = std::pin::pin!(body.into_data_stream());
    let mut received: usize = 0;
    let (target, _record) = match crate::session::ssh_target(&state.data_dir, &query.vm) {
        Ok(pair) => pair,
        Err(err) => {
            return json_error(StatusCode::NOT_FOUND, err);
        }
    };
    let mut child = match target
        .command(&push_remote_cmd(&query.dst, query.sudo))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn ssh: {err}"),
            );
        }
    };
    let mut aborted = false;
    let mut stdin_broken = false;
    use futures_util::StreamExt as _;
    if let Some(mut stdin) = child.stdin.take() {
        while let Some(chunk) = stream.as_mut().next().await {
            let Ok(chunk) = chunk else {
                aborted = true;
                break;
            };
            received += chunk.len();
            if received > MAX_FILE_PUSH_BYTES {
                aborted = true;
                break;
            }
            if stdin.write_all(&chunk).await.is_err() {
                stdin_broken = true;
                break;
            }
        }
        drop(stdin);
    }
    if aborted {
        let _ = child.kill().await;
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds 256 MiB cap");
    }
    if stdin_broken {
        let _ = child.kill().await;
        return json_error(StatusCode::BAD_GATEWAY, "ssh stdin broken");
    }
    let output = match child.wait_with_output().await {
        Ok(output) => output,
        Err(err) => {
            return json_error(StatusCode::BAD_GATEWAY, format!("wait ssh: {err}"));
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return json_error(
            StatusCode::BAD_GATEWAY,
            format!("push failed: {}", stderr.trim()),
        );
    }
    if let Some(mode) = query.mode {
        let status = target
            .command(&format!("chmod {:o} {}", mode, sh_quote(&query.dst)))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        if !matches!(status, Ok(s) if s.success()) {
            return json_error(StatusCode::BAD_GATEWAY, "chmod failed");
        }
    }
    tracing::info!(node = %state.node_id, vm = %query.vm, dst = %query.dst, bytes = received, "file push done");
    json_ok(serde_json::json!({ "pushed": query.dst }))
}

async fn pull(
    State(state): State<SessionState>,
    Query(query): Query<PullQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(rejection) = state.reject_unauthorized(&headers) {
        return rejection;
    }
    if let Err(err) = validate_guest_path(&query.src) {
        return json_error(StatusCode::BAD_REQUEST, err);
    }
    let (target, _record) = match crate::session::ssh_target(&state.data_dir, &query.vm) {
        Ok(pair) => pair,
        Err(err) => {
            return json_error(StatusCode::NOT_FOUND, err);
        }
    };

    let sized = match target
        .command(&pull_size_cmd(&query.src, query.sudo))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        Ok(output) => output,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn ssh: {err}"),
            );
        }
    };
    if !sized.status.success() {
        let stderr = String::from_utf8_lossy(&sized.stderr);
        return json_error(
            StatusCode::NOT_FOUND,
            format!("pull failed: {}", stderr.trim()),
        );
    }
    let size = match String::from_utf8_lossy(&sized.stdout).trim().parse::<u64>() {
        Ok(size) => size,
        Err(_) => {
            return json_error(StatusCode::BAD_GATEWAY, "pull failed: unreadable file size");
        }
    };
    if size > MAX_FILE_PULL_BYTES as u64 {
        return json_error(StatusCode::PAYLOAD_TOO_LARGE, "file exceeds 256 MiB cap");
    }

    let child = match target
        .command(&pull_remote_cmd(&query.src, query.sudo))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawn ssh: {err}"),
            );
        }
    };
    let Some(body) = child_stdout_body(child, size) else {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "ssh stdout unavailable");
    };
    tracing::info!(node = %state.node_id, vm = %query.vm, src = %query.src, bytes = size, "file pull streaming");
    let content_length = size.to_string();
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/octet-stream"),
            (axum::http::header::CONTENT_LENGTH, content_length.as_str()),
        ],
        body,
    )
        .into_response()
}

struct ChildStdout {
    _child: tokio::process::Child,
    stdout: tokio::io::Take<tokio::process::ChildStdout>,
}

impl AsyncRead for ChildStdout {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

fn child_stdout_body(mut child: tokio::process::Child, limit: u64) -> Option<Body> {
    let stdout = child.stdout.take()?.take(limit);
    Some(reader_body(
        ChildStdout {
            _child: child,
            stdout,
        },
        64 * 1024,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pull_body_outlives_the_handler_that_spawned_the_child() {
        let child = tokio::process::Command::new("sh")
            .args(["-c", "sleep 0.2; head -c 5000000 /dev/zero"])
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let body = child_stdout_body(child, 4_000_000).expect("stdout is piped");
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        assert_eq!(
            bytes.len(),
            4_000_000,
            "the body is capped at the stat size"
        );
    }

    #[test]
    fn path_validation() {
        assert!(validate_guest_path("/etc/app.conf").is_ok());
        assert!(validate_guest_path("relative").is_err());
        assert!(validate_guest_path("/a/../b").is_err());
        assert!(validate_guest_path("/x\0y").is_err());
    }

    #[test]
    fn quoting() {
        assert_eq!(sh_quote("/a/b"), "'/a/b'");
        assert_eq!(sh_quote("/a'b"), "'/a'\"'\"'b'");
    }

    #[test]
    fn remote_cmds_match_local_cli() {
        assert_eq!(push_remote_cmd("/x", false), "cat > '/x'");
        assert_eq!(push_remote_cmd("/x", true), "sudo tee '/x' > /dev/null");
        assert_eq!(pull_remote_cmd("/x", false), "cat '/x'");
        assert_eq!(pull_remote_cmd("/x", true), "sudo cat '/x'");
    }

    #[test]
    fn pull_size_cmd_checks_readability_and_quotes() {
        assert_eq!(
            pull_size_cmd("/x", false),
            "test -r '/x' && stat -c %s '/x'"
        );
        assert_eq!(
            pull_size_cmd("/x", true),
            "sudo test -r '/x' && sudo stat -c %s '/x'"
        );
        assert_eq!(
            pull_size_cmd("/x'y", false),
            "test -r '/x'\"'\"'y' && stat -c %s '/x'\"'\"'y'"
        );
    }
}
