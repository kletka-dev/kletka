use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use super::error::FirecrackerError;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct FirecrackerClient {
    sock_path: PathBuf,
}

impl FirecrackerClient {
    pub fn new(sock_path: impl Into<PathBuf>) -> Self {
        Self {
            sock_path: sock_path.into(),
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), FirecrackerError> {
        let future = async {
            let mut stream = UnixStream::connect(&self.sock_path).await?;

            let body = body.unwrap_or("");
            let req = format!(
                "{method} {path} HTTP/1.1\r\n\
                 Host: firecracker\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                body.len()
            );

            stream.write_all(req.as_bytes()).await?;
            stream.flush().await?;

            let mut raw: Vec<u8> = Vec::with_capacity(1024);
            let header_end = loop {
                if let Some(pos) = find(&raw, b"\r\n\r\n") {
                    break pos + 4;
                }

                let mut chunk = [0u8; 4096];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break raw.len();
                }

                raw.extend_from_slice(&chunk[..n]);
            };

            let head = String::from_utf8_lossy(&raw[..header_end.min(raw.len())]);
            let status = head
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|code| code.parse::<u16>().ok())
                .ok_or_else(|| FirecrackerError::Api {
                    status: 0,
                    body: format!("malformed status line: {:.100}", head),
                })?;

            let content_length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.trim()
                        .eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);

            let mut body_bytes = raw[header_end.min(raw.len())..].to_vec();
            while body_bytes.len() < content_length {
                let mut chunk = [0u8; 4096];
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }

                body_bytes.extend_from_slice(&chunk[..n]);
            }

            Ok((status, String::from_utf8_lossy(&body_bytes).into_owned()))
        };

        match tokio::time::timeout(REQUEST_TIMEOUT, future).await {
            Ok(result) => result,
            Err(_) => Err(FirecrackerError::Timeout(
                "firecracker api request".to_string(),
            )),
        }
    }

    pub async fn put_json(
        &self,
        path: &str,
        json: &serde_json::Value,
    ) -> Result<(), FirecrackerError> {
        let body = serde_json::to_string(json)?;
        let (status, resp) = self.request("PUT", path, Some(&body)).await?;
        ensure_success(status, &resp)
    }
}

fn ensure_success(status: u16, body: &str) -> Result<(), FirecrackerError> {
    if (200..300).contains(&status) {
        return Ok(());
    }

    Err(FirecrackerError::Api {
        status,
        body: body.to_string(),
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::test_util::TempDir;
    use serde_json::json;
    use tokio::net::UnixListener;

    async fn serve(listener: UnixListener) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };

            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];

            let header_end = loop {
                if let Some(pos) = find(&raw, b"\r\n\r\n") {
                    break pos + 4;
                }

                let n = stream.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break raw.len();
                }

                raw.extend_from_slice(&chunk[..n]);
            };

            let head = String::from_utf8_lossy(&raw[..header_end.min(raw.len())]);
            let request_line = head.lines().next().unwrap_or_default();
            let path = request_line
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_string();

            let (status, reason, body) = match path.as_str() {
                "/ok" => ("204", "No Content", String::new()),
                "/json" => ("200", "OK", r#"{"state": "Running"}"#.to_string()),
                _ => (
                    "400",
                    "Bad Request",
                    r#"{"fault_message": "nope"}"#.to_string(),
                ),
            };

            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            if stream.write_all(response.as_bytes()).await.is_err() {
                continue;
            }
        }
    }

    #[tokio::test]
    async fn request_roundtrip_and_errors() {
        let dir = TempDir::new("api");
        let sock = dir.path().join("api.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        tokio::spawn(serve(listener));
        let client = FirecrackerClient::new(&sock);

        client.put_json("/ok", &json!({"a": 1})).await.unwrap();
        client.put_json("/ok", &json!({"b": 2})).await.unwrap();

        let err = client.put_json("/error", &json!({})).await.unwrap_err();
        assert!(matches!(err, FirecrackerError::Api { status: 400, .. }));

        let err = FirecrackerClient::new(dir.path().join("missing.sock"))
            .put_json("/ok", &json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, FirecrackerError::Io(_)));
    }
}
