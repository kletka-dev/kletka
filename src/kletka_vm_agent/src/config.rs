use std::net::SocketAddr;
use std::path::PathBuf;

use kletka_types::VmSpec;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Config {
    pub vm_id: Uuid,
    pub image: String,
    pub vcpu: usize,
    pub memory_mib: usize,
    pub disk_mib: usize,
    pub nat: bool,
    pub session_token: String,
    pub authorized_keys: String,
    pub vm_name: Option<String>,
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub guest_image_dir: Option<PathBuf>,
    pub guest_image_ref: Option<String>,
    pub rebase: bool,
    pub autostart: bool,
    pub wireguard_config: Option<String>,
}

use kletka_types::{env_bool, env_parse, env_var as env};

fn read_optional_file(path_var: &str, what: &str) -> Result<Option<String>, String> {
    let Some(path) = env(path_var) else {
        return Ok(None);
    };
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("cannot read {what}: {err}")),
    }
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let vm_id: Uuid = env("KLETKA_VM_ID")
            .and_then(|v| v.parse().ok())
            .ok_or("KLETKA_VM_ID must be set to the control-plane VM uuid")?;
        let session_token = env("KLETKA_SESSION_TOKEN")
            .ok_or("KLETKA_SESSION_TOKEN must be set (per-VM session token)")?;
        let wireguard_config = read_optional_file("KLETKA_WIREGUARD_CONFIG", "WireGuard config")?;
        let authorized_keys = read_optional_file("KLETKA_AUTHORIZED_KEYS", "authorized_keys")?
            .map(|keys| keys.trim().to_string())
            .unwrap_or_default();
        Ok(Self {
            vm_id,
            image: env("KLETKA_VM_IMAGE").unwrap_or_else(|| "default".to_string()),
            vcpu: env_parse("KLETKA_VM_VCPU")
                .unwrap_or(2)
                .clamp(1, kletka_types::MAX_VCPUS),
            memory_mib: env_parse("KLETKA_VM_MEMORY_MIB").unwrap_or(1024),
            disk_mib: env_parse("KLETKA_VM_DISK_MIB").unwrap_or(0),
            nat: env_bool("KLETKA_VM_NAT", true),
            session_token,
            vm_name: env("KLETKA_VM_NAME"),
            bind: env_parse("KLETKA_AGENT_BIND")
                .unwrap_or_else(|| "0.0.0.0:8081".parse().expect("default bind")),
            data_dir: env("KLETKA_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/kletka")),
            guest_image_dir: env("KLETKA_GUEST_IMAGE_DIR").map(PathBuf::from),
            guest_image_ref: env("KLETKA_VM_IMAGE_REF"),
            rebase: env_bool("KLETKA_VM_REBASE", false),
            autostart: env_bool("KLETKA_VM_AUTOSTART", true),
            wireguard_config,
            authorized_keys,
        })
    }

    pub fn authorized_keys(&self) -> Option<&str> {
        Some(self.authorized_keys.as_str()).filter(|keys| !keys.is_empty())
    }

    pub fn spec(&self) -> VmSpec {
        VmSpec {
            name: self.vm_id.to_string(),
            image: self.image.clone(),
            vcpu: self.vcpu,
            memory_mib: self.memory_mib,
            disk_mib: self.disk_mib,
            nat: self.nat,
        }
    }
}

#[cfg(test)]
pub(crate) fn test_config() -> Config {
    Config {
        vm_id: Uuid::new_v4(),
        image: "default".into(),
        vcpu: 2,
        memory_mib: 1024,
        disk_mib: 0,
        nat: true,
        session_token: "t0k3n".into(),
        vm_name: None,
        bind: "127.0.0.1:8081".parse().unwrap(),
        data_dir: PathBuf::from("/var/lib/kletka"),
        guest_image_dir: None,
        guest_image_ref: None,
        rebase: false,
        autostart: true,
        wireguard_config: None,
        authorized_keys: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_name_is_the_control_plane_id() {
        let config = test_config();
        let spec = config.spec();
        assert_eq!(spec.name, config.vm_id.to_string());
        assert_eq!(spec.image, "default");
        assert_eq!(spec.memory_mib, 1024);
        assert!(spec.nat);
    }

    #[test]
    fn vm_name_comes_from_the_env() {
        let cases: [(Option<&str>, Option<String>); 3] = [
            (Some("research"), Some("research".to_string())),
            (Some("   "), None),
            (None, None),
        ];
        let old = (
            std::env::var_os("KLETKA_VM_NAME"),
            std::env::var_os("KLETKA_VM_ID"),
            std::env::var_os("KLETKA_SESSION_TOKEN"),
        );
        let vm_id = uuid::Uuid::new_v4().to_string();
        unsafe {
            std::env::set_var("KLETKA_VM_ID", &vm_id);
            std::env::set_var("KLETKA_SESSION_TOKEN", "tok");
        }
        for (set, expected) in cases {
            unsafe {
                match set {
                    Some(value) => std::env::set_var("KLETKA_VM_NAME", value),
                    None => std::env::remove_var("KLETKA_VM_NAME"),
                }
            }
            let config = Config::from_env().unwrap();
            assert_eq!(config.vm_name, expected, "env {set:?}");
            assert_eq!(config.vm_id.to_string(), vm_id);
        }
        unsafe {
            match old.0 {
                Some(value) => std::env::set_var("KLETKA_VM_NAME", value),
                None => std::env::remove_var("KLETKA_VM_NAME"),
            }
            match old.1 {
                Some(value) => std::env::set_var("KLETKA_VM_ID", value),
                None => std::env::remove_var("KLETKA_VM_ID"),
            }
            match old.2 {
                Some(value) => std::env::set_var("KLETKA_SESSION_TOKEN", value),
                None => std::env::remove_var("KLETKA_SESSION_TOKEN"),
            }
        }
    }
}
