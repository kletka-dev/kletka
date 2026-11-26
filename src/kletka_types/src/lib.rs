use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod time;

use time::Timestamp;

pub const API_VERSION: &str = "v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmSpec {
    pub name: String,
    pub image: String,
    pub vcpu: usize,
    pub memory_mib: usize,
    pub disk_mib: usize,
    pub nat: bool,
}

impl Default for VmSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            image: "default".to_string(),
            vcpu: 2,
            memory_mib: 1024,
            disk_mib: 0,
            nat: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vm {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub vcpu: usize,
    pub memory_mib: usize,
    pub disk_mib: usize,
    pub nat: bool,
    pub status: VmStatus,
    pub assigned_node: Option<String>,
    pub idle_timeout_secs: u64,
    pub idle_timeout_default: bool,
    #[serde(default, with = "time::rfc3339_opt")]
    pub last_active_at: Option<Timestamp>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateVmRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpu: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mib: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard_config: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVmResponse {
    pub vm: Vm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub user_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMethods {
    pub password: bool,
    pub oauth: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthStart {
    pub authorize_url: String,
    pub state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthPoll {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaInfo {
    pub max_vms: usize,
    pub max_vcpu: usize,
    pub max_mem_mib: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageInfo {
    pub vms: usize,
    pub vcpu: usize,
    pub mem_mib: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub user_id: Uuid,
    pub email: String,
    pub quotas: QuotaInfo,
    pub usage: UsageInfo,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub platform_admin: bool,
}

pub const NAMESPACE_HEADER: &str = "x-kletka-namespace";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NamespaceRole {
    Member,
    Admin,
    Owner,
}

impl NamespaceRole {
    pub const ALL: [Self; 3] = [Self::Member, Self::Admin, Self::Owner];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str().eq_ignore_ascii_case(raw.trim()))
    }
}

impl std::fmt::Display for NamespaceRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceInfo {
    pub id: Uuid,
    pub name: String,
    pub personal: bool,
    pub role: Option<NamespaceRole>,
    pub members: usize,
    pub quotas: QuotaInfo,
    pub usage: UsageInfo,
    #[serde(with = "time::rfc3339")]
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceMember {
    pub user_id: Uuid,
    pub email: String,
    pub role: NamespaceRole,
    #[serde(with = "time::rfc3339")]
    pub added_at: Timestamp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateNamespaceRequest {
    pub name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateNamespaceRequest {
    #[serde(default)]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub email: String,
    #[serde(default = "default_member_role")]
    pub role: NamespaceRole,
}

fn default_member_role() -> NamespaceRole {
    NamespaceRole::Member
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateMemberRequest {
    pub role: NamespaceRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserSummary {
    pub user_id: Uuid,
    pub email: String,
    pub platform_admin: bool,
    pub max_namespaces: Option<usize>,
    pub namespaces_owned: usize,
    #[serde(with = "time::rfc3339")]
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub platform_admin: Option<bool>,
    #[serde(default, deserialize_with = "present")]
    pub max_namespaces: Option<Option<usize>>,
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: i64,
    #[serde(with = "time::rfc3339")]
    pub created_at: Timestamp,
    pub actor: String,
    pub action: String,
    pub vm_id: Option<String>,
    pub vm_name: Option<String>,
    pub outcome: String,
    #[serde(default)]
    pub detail: serde_json::Value,
    pub source_ip: Option<String>,
}

impl AuditEvent {
    pub fn origin(&self) -> &str {
        match self.actor.as_str() {
            "user" => self.source_ip.as_deref().unwrap_or("-"),
            actor => actor,
        }
    }

    pub fn detail_summary(&self) -> String {
        let Some(map) = self.detail.as_object() else {
            return String::new();
        };
        map.iter()
            .map(|(key, value)| match value {
                serde_json::Value::String(text) => format!("{key}={text}"),
                other => format!("{key}={other}"),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub next_before: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageInfo {
    pub name: String,
    pub reference: String,
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResizeVmRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcpu: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_mib: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_mib: Option<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebaseVmRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneVmRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSnapshotRequest {
    pub name: String,
    #[serde(default)]
    pub memory: bool,
}

pub const MAX_VM_DISK_MIB: usize = 1024 * 1024;
pub const MAX_WIREGUARD_CONFIG_BYTES: usize = 64 * 1024;
pub const GUEST_REF_ANNOTATION: &str = "kletka.dev/guest-ref";

pub const MAX_VCPUS: usize = 32;
pub const MIN_MEMORY_MIB: usize = 128;
pub const MAX_SSH_KEY_BYTES: usize = 8192;

pub fn validate_ssh_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("ssh keys must be non-empty (one openssh public key per entry)".to_string());
    }
    if key.len() > MAX_SSH_KEY_BYTES || !key.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(
            "each ssh key must be one line of printable ASCII (the contents of a .pub file)"
                .to_string(),
        );
    }
    Ok(())
}

pub const MAX_VM_NAME_LEN: usize = 32;
pub const MAX_NAMESPACE_NAME_LEN: usize = 32;

fn validate_label(kind: &str, name: &str, max: usize) -> Result<(), String> {
    let explain = |what: &str| {
        format!(
            "invalid {kind} name '{name}' ({what}): use up to {max} lowercase \
             letters, digits and dashes, starting and ending with a letter or digit"
        )
    };
    if name.is_empty() {
        return Err(explain("empty"));
    }
    if name.len() > max {
        return Err(explain(&format!("longer than {max} characters")));
    }
    let body_ok = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let first = name.as_bytes()[0];
    let last = name.as_bytes()[name.len() - 1];
    let edge_ok = (first.is_ascii_lowercase() || first.is_ascii_digit())
        && (last.is_ascii_lowercase() || last.is_ascii_digit());
    if !body_ok {
        return Err(explain("only a-z, 0-9 and - are allowed"));
    }
    if !edge_ok {
        return Err(explain("must start and end with a letter or digit"));
    }
    Ok(())
}

pub fn validate_vm_name(name: &str) -> Result<(), String> {
    validate_label("vm", name, MAX_VM_NAME_LEN)
}

pub fn validate_namespace_name(name: &str) -> Result<(), String> {
    validate_label("namespace", name, MAX_NAMESPACE_NAME_LEN)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmStatus {
    Pending,
    Rebasing,
    Cloning,
    Running,
    Stopped,
    Failed,
}

impl VmStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Rebasing => "rebasing",
            Self::Cloning => "cloning",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "pending" => Self::Pending,
            "rebasing" => Self::Rebasing,
            "cloning" => Self::Cloning,
            "running" => Self::Running,
            "stopped" => Self::Stopped,
            "failed" => Self::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    pub name: String,
    #[serde(with = "time::rfc3339")]
    pub created_at: Timestamp,
    pub size_bytes: u64,
    pub with_memory: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleOp {
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LifecycleRequest {
    pub op: LifecycleOp,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WireguardRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wireguard_config: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotOp {
    List,
    Create,
    Delete,
    Rollback,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SnapshotRequest {
    pub op: SnapshotOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionKind {
    Exec { cmd: Vec<String>, pty: bool },
    Console { serial: bool },
    FilePush { dst: String, mode: Option<u32> },
    FilePull { src: String },
    Proxy { tcp_port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionHeader {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    #[serde(flatten)]
    pub kind: SessionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pty_cols: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pty_rows: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub colorterm: Option<String>,
}

pub const SESSION_IDLE_TIMEOUT_SECS: u64 = 60;
pub const SESSION_MAX_SECS: u64 = 600;
pub const MAX_SESSIONS_PER_VM: usize = 8;
pub const MAX_SESSIONS_PER_USER: usize = 16;
pub const MAX_SNAPSHOTS_PER_VM: usize = 5;
pub const MAX_FILE_PUSH_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_FILE_PULL_BYTES: usize = MAX_FILE_PUSH_BYTES;
pub const MAX_EXEC_OUTPUT_BYTES: usize = 1024 * 1024;
pub const RELAY_BYTE_CAP: u64 = MAX_EXEC_OUTPUT_BYTES as u64 * 256;
pub const PROXY_RELAY_BYTE_CAP: u64 = 64 * 1024 * 1024 * 1024;
pub const SESSION_ROW_TTL_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    pub idle_secs: Option<u64>,
    pub max_secs: Option<u64>,
    pub byte_cap: u64,
}

impl RelayLimits {
    pub const INTERACTIVE: Self = Self {
        idle_secs: Some(SESSION_IDLE_TIMEOUT_SECS),
        max_secs: Some(SESSION_MAX_SECS),
        byte_cap: RELAY_BYTE_CAP,
    };
    pub const PROXY: Self = Self {
        idle_secs: None,
        max_secs: None,
        byte_cap: PROXY_RELAY_BYTE_CAP,
    };
    pub const CONSOLE: Self = Self {
        idle_secs: None,
        max_secs: None,
        byte_cap: RELAY_BYTE_CAP,
    };
}

impl SessionKind {
    pub fn relay_limits(&self) -> RelayLimits {
        match self {
            SessionKind::Proxy { .. } => RelayLimits::PROXY,
            SessionKind::Console { .. } => RelayLimits::CONSOLE,
            SessionKind::Exec { .. }
            | SessionKind::FilePush { .. }
            | SessionKind::FilePull { .. } => RelayLimits::INTERACTIVE,
        }
    }
}

pub fn urlencode(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

pub fn parse_configmap_ref(raw: &str) -> Result<(&str, &str), String> {
    raw.split_once('/')
        .filter(|(ns, name)| !ns.is_empty() && !name.is_empty())
        .ok_or_else(|| format!("expected '<namespace>/<name>', got '{raw}'"))
}

pub fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

pub fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    env_var(name).and_then(|v| v.trim().parse().ok())
}

pub fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub fn env_bool(name: &str, default: bool) -> bool {
    env_var(name)
        .and_then(|v| parse_bool(&v))
        .unwrap_or(default)
}

pub fn secrets_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

pub fn error_chain(err: &dyn std::error::Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(cause) = source {
        parts.push(cause.to_string());
        source = cause.source();
    }
    parts.join(": caused by: ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_info_serde_stable() {
        let account = AccountInfo {
            user_id: Uuid::nil(),
            email: "user@example.com".into(),
            quotas: QuotaInfo {
                max_vms: 5,
                max_vcpu: 8,
                max_mem_mib: 8192,
            },
            usage: UsageInfo {
                vms: 2,
                vcpu: 4,
                mem_mib: 4096,
            },
            namespace: Some("user".into()),
            platform_admin: false,
        };
        let v = serde_json::to_value(&account).unwrap();
        assert_eq!(v["user_id"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(v["quotas"]["max_vcpu"], 8);
        assert_eq!(v["usage"]["mem_mib"], 4096);
        let back: AccountInfo = serde_json::from_value(v).unwrap();
        assert_eq!(back, account);
        let parsed: AccountInfo = serde_json::from_str(
            r#"{"user_id":"00000000-0000-0000-0000-000000000000","email":"u@e.com",
            "quotas":{"max_vms":5,"max_vcpu":8,"max_mem_mib":8192},
            "usage":{"vms":0,"vcpu":0,"mem_mib":0}}"#,
        )
        .unwrap();
        assert_eq!(parsed.email, "u@e.com");
        assert_eq!(
            parsed.usage,
            UsageInfo {
                vms: 0,
                vcpu: 0,
                mem_mib: 0
            }
        );
    }

    #[test]
    fn vm_record_wire_is_stable() {
        let mut vm = Vm {
            id: Uuid::nil(),
            name: "web".into(),
            image: "default".into(),
            vcpu: 2,
            memory_mib: 1024,
            disk_mib: 0,
            nat: true,
            status: VmStatus::Running,
            assigned_node: Some("vm-00000000".into()),
            idle_timeout_secs: 28_800,
            idle_timeout_default: true,
            last_active_at: None,
        };
        let v = serde_json::to_value(&vm).unwrap();
        for field in [
            "id",
            "name",
            "image",
            "vcpu",
            "memory_mib",
            "disk_mib",
            "nat",
            "status",
            "assigned_node",
            "idle_timeout_secs",
            "idle_timeout_default",
            "last_active_at",
        ] {
            assert!(
                v.get(field).is_some(),
                "{field} missing from the wire shape"
            );
        }
        assert!(v["last_active_at"].is_null());
        vm.last_active_at = Some(time::from_unix(1_700_000_000));
        let v = serde_json::to_value(&vm).unwrap();
        assert_eq!(v["last_active_at"], "2023-11-14T22:13:20Z");
        let wire = r#"{"id":"00000000-0000-0000-0000-000000000000","name":"web","image":"default",
            "vcpu":2,"memory_mib":1024,"disk_mib":0,"nat":true,"status":"running",
            "assigned_node":null,"idle_timeout_secs":0,"idle_timeout_default":false,
            "last_active_at":1700000000}"#;
        let parsed: Vm = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.last_active_at, Some(time::from_unix(1_700_000_000)));
        assert_eq!(parsed.status, VmStatus::Running);
    }

    #[test]
    fn create_request_all_fields_optional() {
        let empty: CreateVmRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(empty, CreateVmRequest::default());
        assert_eq!(serde_json::to_value(&empty).unwrap(), serde_json::json!({}));

        let full: CreateVmRequest = serde_json::from_value(serde_json::json!({
            "name": "x", "image": "default", "vcpu": 4, "memory_mib": 2048,
            "disk_mib": 20480, "nat": true, "wireguard_config": "[Interface]\n",
            "idle_timeout_secs": 0, "ssh_keys": ["ssh-ed25519 AAAA me"]
        }))
        .unwrap();
        assert_eq!(full.name.as_deref(), Some("x"));
        assert_eq!(full.wireguard_config.as_deref(), Some("[Interface]\n"));
        assert_eq!(full.ssh_keys, vec!["ssh-ed25519 AAAA me".to_string()]);
    }

    #[test]
    fn vm_names_validate() {
        for name in ["a", "dev-vm", "a".repeat(32).as_str(), "vm2", "0-9", "9x"] {
            assert!(validate_vm_name(name).is_ok(), "{name} should be valid");
        }
        for (name, why) in [
            ("", "empty"),
            ("a".repeat(33).as_str(), "too long"),
            ("-leading", "leading dash"),
            ("trailing-", "trailing dash"),
            ("Double--Dash".repeat(3).as_str(), "uppercase"),
            ("under_score", "underscore"),
            ("with space", "space"),
            ("ünïcode", "non-ascii"),
        ] {
            assert!(
                validate_vm_name(name).is_err(),
                "{name} should be rejected ({why})"
            );
        }
    }

    #[test]
    fn vm_status_wire_strings() {
        assert_eq!(VmStatus::Cloning.as_str(), "cloning");
        assert_eq!(VmStatus::parse("cloning"), Some(VmStatus::Cloning));
        assert_eq!(VmStatus::parse("running"), Some(VmStatus::Running));
        assert_eq!(VmStatus::parse("nonsense"), None);
        assert_eq!(
            serde_json::to_value(VmStatus::Rebasing).unwrap(),
            serde_json::json!("rebasing")
        );
    }

    #[test]
    fn relay_limits_by_kind() {
        let proxy = SessionKind::Proxy { tcp_port: 8080 }.relay_limits();
        assert_eq!(proxy, RelayLimits::PROXY);
        assert_eq!(proxy.idle_secs, None);
        assert_eq!(proxy.max_secs, None);
        assert_eq!(proxy.byte_cap, PROXY_RELAY_BYTE_CAP);
        assert!(proxy.byte_cap > RELAY_BYTE_CAP);

        let console = SessionKind::Console { serial: false }.relay_limits();
        assert_eq!(console, RelayLimits::CONSOLE);
        assert_eq!(console.idle_secs, None);
        assert_eq!(console.max_secs, None);
        assert_eq!(console.byte_cap, RELAY_BYTE_CAP);

        for kind in [
            SessionKind::Exec {
                cmd: vec!["ls".into()],
                pty: false,
            },
            SessionKind::FilePull { src: "/x".into() },
        ] {
            let limits = kind.relay_limits();
            assert_eq!(limits, RelayLimits::INTERACTIVE);
            assert_eq!(limits.idle_secs, Some(SESSION_IDLE_TIMEOUT_SECS));
            assert_eq!(limits.max_secs, Some(SESSION_MAX_SECS));
            assert_eq!(limits.byte_cap, RELAY_BYTE_CAP);
        }
    }

    #[test]
    fn vm_spec_serde_stable() {
        let spec = VmSpec {
            name: "x".into(),
            image: "default".into(),
            vcpu: 2,
            memory_mib: 1024,
            disk_mib: 0,
            nat: true,
        };
        let v: serde_json::Value = serde_json::to_value(&spec).unwrap();
        assert_eq!(v["vcpu"], 2);
        assert_eq!(v["memory_mib"], 1024);
        assert_eq!(v["nat"], true);
        let back: VmSpec = serde_json::from_value(v).unwrap();
        assert_eq!(back, spec);
    }

    #[test]
    fn snapshot_info_serde_stable() {
        let snapshot = SnapshotInfo {
            name: "clean".into(),
            created_at: time::from_unix(1_700_000_000),
            size_bytes: 4096,
            with_memory: false,
        };
        let v: serde_json::Value = serde_json::to_value(&snapshot).unwrap();
        assert_eq!(v["name"], "clean");
        assert_eq!(v["with_memory"], false);
        let back: SnapshotInfo = serde_json::from_value(v).unwrap();
        assert_eq!(back, snapshot);
    }

    #[test]
    fn session_header_roundtrip() {
        let h = SessionHeader {
            session_id: None,
            kind: SessionKind::Exec {
                cmd: vec!["uname".into(), "-a".into()],
                pty: false,
            },
            pty_cols: Some(120),
            pty_rows: Some(40),
            term: Some("xterm-256color".into()),
            colorterm: Some("truecolor".into()),
        };
        let s = serde_json::to_string(&h).unwrap();
        let back: SessionHeader = serde_json::from_str(&s).unwrap();
        assert_eq!(back, h);
        let legacy = r#"{"kind":"console","serial":false}"#;
        let parsed: SessionHeader = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.pty_cols, None);
        assert_eq!(parsed.term, None);
        assert_eq!(parsed.colorterm, None);
    }

    #[test]
    fn shared_helpers() {
        assert_eq!(urlencode("a b/c&d"), "a%20b/c%26d");
        assert_eq!(urlencode("plain-key.v1_2~3/4"), "plain-key.v1_2~3/4");
        assert_eq!(urlencode("ünïcode"), "%C3%BCn%C3%AFcode");

        assert_eq!(
            parse_configmap_ref("kletka-system/guest-images"),
            Ok(("kletka-system", "guest-images"))
        );
        assert!(parse_configmap_ref("noseparator").is_err());
        assert!(parse_configmap_ref("/name").is_err());
        assert!(parse_configmap_ref("ns/").is_err());
        assert_eq!(
            parse_configmap_ref("a/b/c"),
            Ok(("a", "b/c")),
            "split at the first slash, like both deploy sides did"
        );

        for (raw, parsed) in [
            ("true", Some(true)),
            (" on ", Some(true)),
            ("1", Some(true)),
            ("off", Some(false)),
            ("no", Some(false)),
            ("maybe", None),
            ("", None),
        ] {
            assert_eq!(parse_bool(raw), parsed, "{raw:?}");
        }
    }

    #[test]
    fn ssh_key_validation_bounds_and_charset() {
        assert!(validate_ssh_key("ssh-ed25519 AAAAC3Nza me@host").is_ok());
        assert!(validate_ssh_key("").is_err());
        assert!(validate_ssh_key("two\nlines").is_err());
        assert!(validate_ssh_key("café-key").is_err());
        assert!(validate_ssh_key(&"k".repeat(MAX_SSH_KEY_BYTES + 1)).is_err());
        assert!(validate_ssh_key(&"k".repeat(MAX_SSH_KEY_BYTES)).is_ok());
    }

    #[test]
    fn audit_event_display_helpers() {
        let mut event = AuditEvent {
            id: 1,
            created_at: Timestamp::UNIX_EPOCH,
            actor: "user".into(),
            action: "vm.create".into(),
            vm_id: None,
            vm_name: None,
            outcome: "ok".into(),
            detail: serde_json::json!({ "image": "default", "vcpu": 2 }),
            source_ip: Some("203.0.113.7".into()),
        };
        assert_eq!(event.origin(), "203.0.113.7");
        assert_eq!(event.detail_summary(), "image=default vcpu=2");
        event.source_ip = None;
        assert_eq!(event.origin(), "-");
        event.actor = "system".into();
        event.detail = serde_json::Value::Null;
        assert_eq!(event.origin(), "system");
        assert_eq!(event.detail_summary(), "");
    }

    #[test]
    fn namespace_roles_order_and_parse() {
        use NamespaceRole::*;
        assert!(Member < Admin && Admin < Owner);
        assert_eq!(NamespaceRole::parse("ADMIN"), Some(Admin));
        assert_eq!(NamespaceRole::parse("viewer"), None);
        assert_eq!(serde_json::to_value(Owner).unwrap(), "owner");
        assert!(validate_namespace_name("acme-labs").is_ok());
        assert!(validate_namespace_name("Acme").is_err());
    }

    #[test]
    fn update_user_distinguishes_null_from_absent() {
        let absent: UpdateUserRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(absent.max_namespaces, None);
        let cleared: UpdateUserRequest =
            serde_json::from_str(r#"{"max_namespaces": null}"#).unwrap();
        assert_eq!(cleared.max_namespaces, Some(None));
    }
}
