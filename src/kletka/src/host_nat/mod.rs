use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command;

use crate::vmm::FirecrackerError;

pub const SLIRP_TAP: &str = "tap1";

pub const GUEST_IFACE: &str = "eth0";

pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

pub const GUEST_IP_BOOT_ARG: &str = "ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off";

pub fn ssh_host_port(ssh_addr: Ipv4Addr) -> u16 {
    20_000u16 + u16::from(ssh_addr.octets()[3]) % (u16::from(u8::MAX) - 1)
}

const SLIRP_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

const LOOPBACK_PREFIX: [u8; 3] = [127, 42, 0];
const LOOPBACK_FIRST_HOST: u8 = 2;
const LOOPBACK_LAST_HOST: u8 = 254;

#[derive(Debug, Clone)]
pub struct SlirpProcess {
    pub pid: u32,
}

#[derive(Debug, Clone)]
pub struct SlirpClient {
    sock_path: PathBuf,
}

impl SlirpClient {
    pub fn new(sock_path: impl Into<PathBuf>) -> Self {
        Self {
            sock_path: sock_path.into(),
        }
    }

    async fn execute(
        &self,
        command: serde_json::Value,
    ) -> Result<serde_json::Value, FirecrackerError> {
        let future = async {
            let mut stream = UnixStream::connect(&self.sock_path).await?;
            stream
                .write_all(serde_json::to_string(&command)?.as_bytes())
                .await?;
            stream.shutdown().await?;

            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await?;

            Ok(serde_json::from_slice(&raw)?)
        };

        match tokio::time::timeout(SLIRP_WAIT_TIMEOUT, future).await {
            Ok(result) => result,
            Err(_) => Err(FirecrackerError::Timeout("slirp api request".to_string())),
        }
    }

    pub async fn add_hostfwd(
        &self,
        proto: &str,
        host_addr: Ipv4Addr,
        host_port: u16,
        guest_addr: Ipv4Addr,
        guest_port: u16,
    ) -> Result<u32, FirecrackerError> {
        let response = self
            .execute(serde_json::json!({
                "execute": "add_hostfwd",
                "arguments": {
                    "proto": proto,
                    "host_addr": host_addr.to_string(),
                    "host_port": host_port,
                    "guest_addr": guest_addr.to_string(),
                    "guest_port": guest_port,
                }
            }))
            .await?;

        if let Some(err) = response.get("error") {
            return Err(FirecrackerError::Api {
                status: 0,
                body: err.to_string(),
            });
        }

        let id = response["return"]["id"]
            .as_u64()
            .ok_or_else(|| FirecrackerError::Api {
                status: 0,
                body: "add_hostfwd returned no forward id".to_string(),
            })?;

        Ok(id as u32)
    }

    pub async fn remove_hostfwd(&self, id: u32) -> Result<(), FirecrackerError> {
        let response = self
            .execute(serde_json::json!({
                "execute": "remove_hostfwd",
                "arguments": { "id": id }
            }))
            .await?;

        if let Some(err) = response.get("error") {
            return Err(FirecrackerError::Api {
                status: 0,
                body: err.to_string(),
            });
        }

        Ok(())
    }

    pub async fn list_hostfwd(&self) -> Result<serde_json::Value, FirecrackerError> {
        self.execute(serde_json::json!({ "execute": "list_hostfwd" }))
            .await
    }
}

pub async fn spawn_slirp(fc_pid: u32, sock_path: &Path) -> Result<SlirpProcess, FirecrackerError> {
    if !crate::system::on_path("slirp4netns") {
        return Err(FirecrackerError::MissingBinary("slirp4netns".to_string()));
    }

    let _ = std::fs::remove_file(sock_path);

    let mut cmd = Command::new("slirp4netns");
    cmd.arg("--api-socket")
        .arg(sock_path)
        .arg("--disable-host-loopback")
        .arg(fc_pid.to_string())
        .arg(SLIRP_TAP);
    cmd.process_group(0);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = cmd.spawn()?;
    let Some(pid) = child.id() else {
        return Err(FirecrackerError::Timeout(
            "slirp4netns process spawn".to_string(),
        ));
    };

    tokio::spawn(async move {
        let _ = child.wait().await;
    });

    if let Err(err) = crate::vmm::firecracker::wait_for_socket(sock_path, SLIRP_WAIT_TIMEOUT).await
    {
        crate::system::terminate(pid);
        return Err(err);
    }

    tracing::info!(pid, sock = %sock_path.display(), "slirp4netns spawned");

    Ok(SlirpProcess { pid })
}

pub async fn bring_up(
    fc_pid: u32,
    instance_dir: &Path,
    ssh_addr: Ipv4Addr,
) -> Result<(u32, u16), FirecrackerError> {
    let sock_path = instance_dir.join("slirp.sock");
    let process = spawn_slirp(fc_pid, &sock_path).await?;

    let host_port = ssh_host_port(ssh_addr);
    let client = SlirpClient::new(&sock_path);

    if let Err(err) = client
        .add_hostfwd("tcp", ssh_addr, host_port, GUEST_IP, 22)
        .await
    {
        crate::vmm::firecracker::terminate_and_wait(process.pid, "slirp4netns").await;
        let _ = std::fs::remove_file(&sock_path);
        return Err(FirecrackerError::Other(format!(
            "cannot forward {ssh_addr}:{host_port} to guest {GUEST_IP}:22: {err}"
        )));
    }

    tracing::info!(pid = process.pid, %ssh_addr, host_port, "slirp networking up, ssh forwarded");

    Ok((process.pid, host_port))
}

pub async fn wait_for_ssh(
    ssh_addr: Ipv4Addr,
    host_port: u16,
    timeout: Duration,
) -> Result<(), FirecrackerError> {
    use tokio::io::AsyncReadExt as _;
    use tokio::net::TcpStream;

    let target = std::net::SocketAddr::from((ssh_addr, host_port));
    let deadline = Instant::now() + timeout;

    loop {
        if Instant::now() >= deadline {
            return Err(FirecrackerError::Timeout(format!("ssh banner on {target}")));
        }

        let banner_ok = (async {
            let Ok(mut stream) = TcpStream::connect(target).await else {
                return false;
            };

            let mut buf = [0u8; 8];
            match tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut buf)).await {
                Ok(Ok(_)) => buf.starts_with(b"SSH-"),
                _ => false,
            }
        })
        .await;

        if banner_ok {
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub fn allocate_loopback_addr(used: impl IntoIterator<Item = String>) -> Ipv4Addr {
    let mut taken: Vec<u8> = used
        .into_iter()
        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
        .filter_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .filter(|v4| v4.octets()[..3] == LOOPBACK_PREFIX)
        .map(|v4| v4.octets()[3])
        .collect();
    taken.sort_unstable();

    for host in LOOPBACK_FIRST_HOST..=LOOPBACK_LAST_HOST {
        if !taken.contains(&host) && host_port_free(host) {
            return Ipv4Addr::new(
                LOOPBACK_PREFIX[0],
                LOOPBACK_PREFIX[1],
                LOOPBACK_PREFIX[2],
                host,
            );
        }
    }

    tracing::warn!("loopback address space 127.42.0.x exhausted");
    Ipv4Addr::new(
        LOOPBACK_PREFIX[0],
        LOOPBACK_PREFIX[1],
        LOOPBACK_PREFIX[2],
        LOOPBACK_LAST_HOST,
    )
}

fn host_port_free(octet: u8) -> bool {
    let addr = Ipv4Addr::new(
        LOOPBACK_PREFIX[0],
        LOOPBACK_PREFIX[1],
        LOOPBACK_PREFIX[2],
        octet,
    );
    const BACKOFF_MS: [u64; 5] = [0, 1, 2, 5, 10];
    for (attempt, backoff) in BACKOFF_MS.iter().enumerate() {
        match std::net::TcpListener::bind((addr, ssh_host_port(addr))) {
            Ok(_) => return true,
            Err(err) if err.kind() != std::io::ErrorKind::AddrInUse => {
                tracing::debug!(%addr, %err, "ssh port probe failed");
                return false;
            }
            Err(_) if attempt + 1 == BACKOFF_MS.len() => return false,
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(*backoff));
    }
    unreachable!("backoff table always ends with a return")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::test_util::TempDir;
    use serde_json::json;
    use tokio::net::UnixListener;

    #[test]
    fn allocates_lowest_free_loopback() {
        let next = allocate_loopback_addr([]);
        assert_eq!(next, Ipv4Addr::new(127, 42, 0, 2));

        let next = allocate_loopback_addr(["127.42.0.2".to_string()]);
        assert_eq!(next, Ipv4Addr::new(127, 42, 0, 3));

        let next = allocate_loopback_addr(["127.42.0.2".into(), "127.42.0.3".into()]);
        assert_eq!(next, Ipv4Addr::new(127, 42, 0, 4));

        let next = allocate_loopback_addr(["127.42.0.4".into(), "127.42.0.9".into()]);
        assert_eq!(next, Ipv4Addr::new(127, 42, 0, 2));

        let next = allocate_loopback_addr(["10.0.2.15".into(), "garbage".into()]);
        assert_eq!(next, Ipv4Addr::new(127, 42, 0, 2));

        let squat = std::net::TcpListener::bind((
            Ipv4Addr::new(127, 42, 0, 2),
            ssh_host_port(Ipv4Addr::new(127, 42, 0, 2)),
        ))
        .unwrap();
        let next = allocate_loopback_addr([]);
        assert_eq!(next, Ipv4Addr::new(127, 42, 0, 3));
        drop(squat);
        let next = allocate_loopback_addr([]);
        assert_eq!(next, Ipv4Addr::new(127, 42, 0, 2));
    }

    #[test]
    fn ssh_port_follows_octet() {
        assert_eq!(ssh_host_port(Ipv4Addr::new(127, 42, 0, 2)), 20_002);
        assert_eq!(ssh_host_port(Ipv4Addr::new(127, 42, 0, 254)), 20_000);
        assert_eq!(ssh_host_port(Ipv4Addr::new(127, 42, 0, 100)), 20_100);
    }

    async fn serve(listener: UnixListener) {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };

            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];

            loop {
                let n = stream.read(&mut chunk).await.unwrap_or(0);
                if n == 0 {
                    break;
                }

                raw.extend_from_slice(&chunk[..n]);
            }

            let request: serde_json::Value = serde_json::from_slice(&raw).unwrap_or(json!(null));
            let response =
                if request["execute"] == "add_hostfwd" && request["arguments"]["proto"] == "tcp" {
                    json!({"return": {"id": 1}})
                } else {
                    json!({"error": "unsupported"})
                };

            if stream
                .write_all(&serde_json::to_vec(&response).unwrap())
                .await
                .is_err()
            {
                continue;
            }
        }
    }

    #[tokio::test]
    async fn wait_for_ssh_detects_banner() {
        use tokio::io::AsyncWriteExt as _;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(b"SSH-2.0-Test\r\n").await;
        });
        wait_for_ssh(ssh_addr_of(addr), addr.port(), Duration::from_secs(2))
            .await
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n").await;
        });

        let err = wait_for_ssh(ssh_addr_of(addr), addr.port(), Duration::from_millis(800))
            .await
            .unwrap_err();
        assert!(matches!(err, FirecrackerError::Timeout(_)), "{err}");
    }

    fn ssh_addr_of(addr: std::net::SocketAddr) -> Ipv4Addr {
        match addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => panic!("test listener bound to a non-ipv4 address"),
        }
    }

    #[tokio::test]
    async fn add_hostfwd_roundtrip_and_errors() {
        let dir = TempDir::new("slirp");
        let sock = dir.path().join("slirp.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        tokio::spawn(serve(listener));
        let client = SlirpClient::new(&sock);

        client
            .add_hostfwd("tcp", Ipv4Addr::new(127, 42, 0, 2), 20_002, GUEST_IP, 22)
            .await
            .unwrap();

        let err = client
            .add_hostfwd("udp", Ipv4Addr::new(127, 42, 0, 2), 53, GUEST_IP, 53)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FirecrackerError::Api { status: 0, .. }),
            "{err}"
        );
    }

    #[tokio::test]
    #[ignore = "real slirp4netns; requires an idle host, run with --ignored"]
    async fn bring_up_against_real_slirp4netns() {
        if !crate::system::on_path("slirp4netns") || !crate::system::on_path("unshare") {
            eprintln!("skipping: slirp4netns/unshare not available");
            return;
        }

        let probe = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--net", "true"])
            .status();
        let Ok(probe) = probe else { return };
        if !probe.success() {
            return;
        }

        let dir = TempDir::new("slirp-e2e");
        let script = dir.path().join("sleep.sh");
        std::fs::write(&script, "exec sleep 60\n").unwrap();

        let mut cmd = Command::new("unshare");
        cmd.args(["--user", "--map-root-user", "--net"])
            .arg("bash")
            .arg(&script);
        cmd.process_group(0);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = cmd.spawn().unwrap();
        let Some(sleep_pid) = child.id() else { return };
        tokio::spawn(async move {
            let _ = child.wait().await;
        });

        let ssh_addr = Ipv4Addr::new(127, 42, 0, 99);
        let bring_up = bring_up(sleep_pid, dir.path(), ssh_addr).await;

        match bring_up {
            Ok((slirp_pid, host_port)) => {
                assert_eq!(host_port, 20_099);
                assert!(dir.path().join("slirp.sock").exists());
                crate::system::terminate(slirp_pid);
            }
            Err(err) => {
                crate::system::terminate(sleep_pid);
                panic!("bring_up against real slirp4netns failed: {err}");
            }
        }

        crate::system::terminate(sleep_pid);
    }
}
