use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

use crate::client;
use crate::error::{CliError, CliResult, io_error};

const DANCE_TIMEOUT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_secs(3);

pub struct Outcome {
    pub token: String,
    pub email: Option<String>,
}

pub async fn sign_in(url: &str, provider: &str, no_browser: bool) -> CliResult<Outcome> {
    let (from_server, redirect_uri) = if no_browser {
        (None, None)
    } else {
        let server = spawn_local().await?;
        let redirect = format!("http://127.0.0.1:{}/", server.addr.port());
        let rx = server.rx;
        (
            Some(
                Box::pin(async move {
                    rx.await.map_err(|_| CliError::new("local sign-in server closed"))
                })
                    as std::pin::Pin<
                        Box<dyn std::future::Future<Output = CliResult<String>> + Send>,
                    >,
            ),
            Some(redirect),
        )
    };
    let start = client::oauth_start(url, provider, redirect_uri.as_deref()).await?;
    println!("Complete the {} sign-in in your browser:", label(provider));
    println!("  {authorize_url}", authorize_url = start.authorize_url);
    eprintln!("waiting for the sign-in to complete (Ctrl-C to cancel)");
    if redirect_uri.is_some() {
        open_browser(&start.authorize_url);
    }

    let poll = {
        let url = url.to_string();
        let state = start.state.clone();
        Box::pin(async move {
            loop {
                let poll = client::oauth_poll(&url, &state).await?;
                if poll.status == "complete" {
                    return poll.token.ok_or_else(|| {
                        CliError::new("sign-in completed without a token")
                    });
                }
                if poll.status == "expired" {
                    return Err(CliError::new(
                        "the sign-in attempt expired; run `kletka login` again",
                    ));
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
    };
    let token = tokio::select! {
        token = from_server.unwrap_or_else(|| Box::pin(std::future::pending())) => token?,
        token = poll => token?,
        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(
            Instant::now() + DANCE_TIMEOUT,
        )) => {
            return Err(CliError::new("timed out waiting for the sign-in to complete")
                .hint("make sure the browser can reach the control plane and try again"));
        }
    };
    Ok(Outcome { token, email: None })
}

pub fn label(provider: &str) -> String {
    let mut label = provider.to_string();
    if let Some(first) = label.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    label
}

struct LocalServer {
    addr: SocketAddr,
    rx: oneshot::Receiver<String>,
}

async fn spawn_local() -> CliResult<LocalServer> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|err| {
            io_error("cannot start the local sign-in server", err).hint(
                "run `kletka login --no-browser` to sign in with a URL you can open anywhere",
            )
        })?;
    let addr = listener
        .local_addr()
        .map_err(|err| io_error("cannot inspect the local sign-in server", err))?;
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            if let Some(token) = serve_callback(&mut stream).await {
                let _ = tx.send(token);
                break;
            }
        }
    });
    Ok(LocalServer { addr, rx })
}

async fn serve_callback(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buffer.contains(&b'\n') && buffer.len() < 8 * 1024 {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let line = String::from_utf8_lossy(&buffer);
    let line = line.lines().next().unwrap_or_default();
    let target = line.split_whitespace().nth(1).unwrap_or("/");
    let query = target.split_once('?').map(|(_, query)| query).unwrap_or("");
    let token = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "token")
        .map(|(_, value)| urldecode(value))
        .filter(|token| !token.is_empty());
    if token.is_none() {
        respond(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return None;
    }
    let email = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == "email")
        .map(|(_, value)| urldecode(value))
        .unwrap_or_default();
    let body = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>kletka</title></head>\
         <body style=\"font-family:system-ui,sans-serif;text-align:center;padding:4rem\">\
         <h1>Signed in</h1><p>You are signed in as {email}.<br>Return to your terminal to continue.\
         </p></body></html>"
    );
    respond(
        stream,
        &format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    token
}

async fn respond(stream: &mut tokio::net::TcpStream, response: &str) {
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

fn urldecode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 3 <= bytes.len()
            && let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("zz"), 16)
        {
            out.push(byte);
            index += 3;
            continue;
        }
        match bytes[index] {
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn open_browser(url: &str) {
    let opened = open_command(url)
        .and_then(|mut command| command.status().ok())
        .map(|status| status.success())
        .unwrap_or(false);
    if !opened {
        eprintln!("could not open a browser; paste the URL above into any browser on this machine");
    }
}

fn open_command(url: &str) -> Option<std::process::Command> {
    #[cfg(target_os = "macos")]
    {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        Some(command)
    }
    #[cfg(windows)]
    {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", "", url]);
        Some(command)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        Some(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urldecode_handles_percent_and_plus() {
        assert_eq!(urldecode("abc%40example.com"), "abc@example.com");
        assert_eq!(urldecode("a%2Fb+c"), "a/b c");
        assert_eq!(urldecode("plain"), "plain");
        assert_eq!(urldecode("%zz"), "%zz");
    }

    #[test]
    fn labels_are_capitalized() {
        assert_eq!(label("github"), "Github");
        assert_eq!(label("steam"), "Steam");
    }

    #[tokio::test]
    async fn local_server_extracts_the_token() {
        let server = spawn_local().await.unwrap();
        let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let request = "GET /?token=tok123&email=me%40example.com HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = vec![0u8; 512];
        let read = stream.read(&mut reply).await.unwrap();
        let reply = String::from_utf8_lossy(&reply[..read]).to_string();
        assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
        let token = tokio::time::timeout(
            Duration::from_secs(2),
            server.rx,
        )
        .await
        .expect("server must forward the token")
        .unwrap();
        assert_eq!(token, "tok123");
    }

    #[tokio::test]
    async fn local_server_ignores_requests_without_tokens() {
        let server = spawn_local().await.unwrap();
        let mut stream = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        let request = "GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = vec![0u8; 256];
        let read = stream.read(&mut reply).await.unwrap();
        let reply = String::from_utf8_lossy(&reply[..read]).to_string();
        assert!(reply.starts_with("HTTP/1.1 404"), "{reply}");
        stream.shutdown().await.unwrap();
        drop(server);
    }
}
