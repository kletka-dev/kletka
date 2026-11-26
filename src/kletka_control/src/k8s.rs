use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMap, Container, ContainerPort, EmptyDirVolumeSource, EnvVar, EnvVarSource,
    HTTPGetAction, ImageVolumeSource, KeyToPath, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    PersistentVolumeClaimVolumeSource, Pod, PodSecurityContext, Probe, ResourceRequirements,
    SeccompProfile, Secret, SecretKeySelector, SecretVolumeSource, SecurityContext, Toleration,
    Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kletka_types::{MAX_SNAPSHOTS_PER_VM, VmSpec, VmStatus};
use kube::api::{DeleteParams, Patch, PatchParams, PostParams};
use kube::core::dynamic::DynamicObject;
use kube::discovery::ApiResource;
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Api, Client, ResourceExt};
use serde_json::json;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

pub const COMPONENT_LABEL: &str = "kletka.dev/component";
pub const VM_ID_LABEL: &str = "kletka.dev/vm-id";
pub const USER_ID_LABEL: &str = "kletka.dev/user-id";
const COMPONENT_VM: &str = "vm";

const KVM_RESOURCE: &str = "kletka.dev/kvm";
pub use kletka_types::GUEST_REF_ANNOTATION;
pub const ORPHANED_ANNOTATION: &str = "kletka.dev/orphaned";
const TUN_RESOURCE: &str = "kletka.dev/tun";
const AGENT_PORT: i32 = 8081;

fn agent_url(addr: &str, path: &str) -> String {
    format!("http://{addr}:{AGENT_PORT}{path}")
}

pub(crate) const IMAGE_FLOOR_MIB: usize = 2048;

#[derive(Debug, Clone)]
pub struct K8sConfig {
    pub namespace: String,
    pub vm_agent_images: BTreeMap<String, String>,
    pub guest_images: BTreeMap<String, String>,
    pub guest_image_overlay_boots: BTreeMap<String, bool>,
    pub guest_images_configmap: Option<String>,
    pub node_selector: BTreeMap<String, String>,
    pub taint_key: String,
    pub disk_slack_mib: usize,
    pub vm_storage_class: Option<String>,
    pub memory_overhead_mib: usize,
    pub vm_service_account: Option<String>,
}

use kletka_types::env_var as env;

fn available_list<'a, I: Iterator<Item = &'a String>>(names: I) -> String {
    let names: Vec<&str> = names.map(String::as_str).collect();
    if names.is_empty() {
        "<none>".to_string()
    } else {
        names.join(", ")
    }
}

fn parse_pairs(raw: &str) -> BTreeMap<String, String> {
    raw.split(',')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

fn parse_bool_map(raw: &str) -> BTreeMap<String, bool> {
    parse_pairs(raw)
        .into_iter()
        .filter_map(|(name, value)| Some((name, kletka_types::parse_bool(&value)?)))
        .collect()
}

impl Default for K8sConfig {
    fn default() -> Self {
        Self {
            namespace: "kletka-vms".to_string(),
            vm_agent_images: BTreeMap::from([(
                "default".to_string(),
                "kletka-vm-agent:dev".to_string(),
            )]),
            guest_images: BTreeMap::new(),
            guest_image_overlay_boots: BTreeMap::new(),
            guest_images_configmap: None,
            node_selector: BTreeMap::from([("kletka.dev/vm-node".to_string(), "true".to_string())]),
            taint_key: "kletka.dev/untrusted".to_string(),
            disk_slack_mib: 4096,
            vm_storage_class: env("KLETKA_VM_STORAGE_CLASS"),
            memory_overhead_mib: 256,
            vm_service_account: None,
        }
    }
}

impl K8sConfig {
    pub fn agent_image(&self, image: &str) -> ApiResult<String> {
        self.vm_agent_images.get(image).cloned().ok_or_else(|| {
            ApiError::bad_request(format!(
                "no vm-agent image configured for guest image '{image}'; available images: {}",
                available_list(self.vm_agent_images.keys())
            ))
        })
    }

    pub fn guest_image(&self, image: &str) -> ApiResult<String> {
        self.guest_images.get(image).cloned().ok_or_else(|| {
            ApiError::bad_request(format!(
                "unknown guest image '{image}'; available images: {}",
                available_list(self.guest_images.keys())
            ))
        })
    }

    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(ns) = env("KLETKA_K8S_NAMESPACE") {
            config.namespace = ns;
        }
        if let Some(image) = env("KLETKA_VM_AGENT_IMAGE") {
            config.vm_agent_images.insert("default".to_string(), image);
        }
        if let Some(map) = env("KLETKA_VM_AGENT_IMAGES") {
            config.vm_agent_images.extend(parse_pairs(&map));
        }
        if let Some(image) = env("KLETKA_GUEST_IMAGE") {
            config.guest_images.insert("default".to_string(), image);
        }
        if let Some(map) = env("KLETKA_GUEST_IMAGES") {
            config.guest_images.extend(parse_pairs(&map));
        }
        if let Some(map) = env("KLETKA_GUEST_IMAGE_OVERLAY_BOOT") {
            config.guest_image_overlay_boots = parse_bool_map(&map);
        }
        if let Some(configmap) = env("KLETKA_GUEST_IMAGES_CONFIGMAP") {
            config.guest_images_configmap = Some(configmap);
        }
        if let Some(account) = env("KLETKA_VM_SERVICE_ACCOUNT") {
            config.vm_service_account = Some(account);
        }
        if let Some(selector) = env("KLETKA_VM_NODE_SELECTOR") {
            config.node_selector = parse_pairs(&selector);
        }
        if let Some(taint) = env("KLETKA_VM_TAINT") {
            config.taint_key = taint;
        }
        if let Some(slack) = env("KLETKA_VM_DISK_SLACK_MIB").and_then(|v| v.parse().ok()) {
            config.disk_slack_mib = slack;
        }
        if let Some(overhead) = env("KLETKA_VM_MEMORY_OVERHEAD_MIB").and_then(|v| v.parse().ok()) {
            config.memory_overhead_mib = overhead;
        }
        config
    }
}

fn split_configmap_ref(configmap: &str) -> Result<(&str, &str), String> {
    kletka_types::parse_configmap_ref(configmap).map_err(|_| {
        format!("KLETKA_GUEST_IMAGES_CONFIGMAP must be '<namespace>/<name>', got '{configmap}'")
    })
}

fn vm_labels(vm_id: &Uuid, owner_id: Option<&Uuid>) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::from([
        (COMPONENT_LABEL.to_string(), COMPONENT_VM.to_string()),
        (VM_ID_LABEL.to_string(), vm_id.to_string()),
    ]);
    if let Some(owner_id) = owner_id {
        labels.insert(USER_ID_LABEL.to_string(), owner_id.to_string());
    }
    labels
}

fn is_not_found(err: &kube::Error) -> bool {
    matches!(err, kube::Error::Api(status) if status.code == 404)
}

fn secret_string(secret: &Secret, key: &str) -> Option<String> {
    secret
        .data
        .as_ref()?
        .get(key)
        .map(|bytes| String::from_utf8_lossy(&bytes.0).into_owned())
}

fn storage_patch(mib: usize) -> serde_json::Value {
    json!({ "spec": { "resources": { "requests": { "storage": format!("{mib}Mi") } } } })
}

pub fn pod_name(vm_id: &Uuid) -> String {
    format!("vm-{vm_id}")
}

pub fn secret_name(vm_id: &Uuid) -> String {
    format!("{}-token", pod_name(vm_id))
}

pub fn pinned_ref(claim: &PersistentVolumeClaim) -> Option<String> {
    claim
        .metadata
        .annotations
        .as_ref()?
        .get(GUEST_REF_ANNOTATION)
        .filter(|value| !value.trim().is_empty())
        .cloned()
}

pub fn data_claim_name(vm_id: &Uuid) -> String {
    format!("{}-data", pod_name(vm_id))
}

fn claim_mib(config: &K8sConfig, disk_mib: usize, snapshots: usize) -> usize {
    IMAGE_FLOOR_MIB
        .saturating_add(disk_mib.saturating_mul(snapshots + 1))
        .saturating_add(config.disk_slack_mib)
}

pub fn vm_storage_mib(config: &K8sConfig, spec: &VmSpec) -> usize {
    claim_mib(config, spec.disk_mib.max(IMAGE_FLOOR_MIB), 0)
}

pub fn vm_storage_ceiling_mib(config: &K8sConfig, disk_mib: usize) -> usize {
    claim_mib(config, disk_mib.max(IMAGE_FLOOR_MIB), MAX_SNAPSHOTS_PER_VM)
}

fn claim_request_mib(claim: &PersistentVolumeClaim) -> Option<usize> {
    let raw = claim
        .spec
        .as_ref()?
        .resources
        .as_ref()?
        .requests
        .as_ref()?
        .get("storage")?
        .0
        .trim();
    let unit = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let (value, unit) = raw.split_at(unit);
    let value: usize = value.parse().ok()?;
    match unit {
        "" => Some(value / (1024 * 1024)),
        "Ki" => Some(value / 1024),
        "Mi" => Some(value),
        "Gi" => Some(value.saturating_mul(1024)),
        _ => None,
    }
}

pub fn build_data_claim(
    config: &K8sConfig,
    vm_id: &Uuid,
    owner_id: &Uuid,
    spec: &VmSpec,
    guest_image: &str,
) -> PersistentVolumeClaim {
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(data_claim_name(vm_id)),
            namespace: Some(config.namespace.clone()),
            labels: Some(vm_labels(vm_id, Some(owner_id))),
            annotations: Some(BTreeMap::from([(
                GUEST_REF_ANNOTATION.to_string(),
                guest_image.to_string(),
            )])),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_string(),
                    Quantity(format!("{}Mi", vm_storage_mib(config, spec))),
                )])),
                ..Default::default()
            }),
            storage_class_name: config.vm_storage_class.clone(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn cnp_resource() -> ApiResource {
    ApiResource {
        group: "cilium.io".to_string(),
        version: "v2".to_string(),
        api_version: "cilium.io/v2".to_string(),
        kind: "CiliumNetworkPolicy".to_string(),
        plural: "ciliumnetworkpolicies".to_string(),
    }
}

fn new_session_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn plain_env(name: &str, value: impl std::fmt::Display) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value: Some(value.to_string()),
        ..Default::default()
    }
}

pub fn build_secret(
    vm_id: &Uuid,
    namespace: &str,
    token: &str,
    wireguard_config: Option<&str>,
    ssh_keys: Option<&str>,
) -> Secret {
    let mut string_data = BTreeMap::from([("token".to_string(), token.to_string())]);
    string_data.insert(
        "wireguard.conf".to_string(),
        wireguard_config.unwrap_or("").to_string(),
    );
    string_data.insert(
        "authorized_keys".to_string(),
        ssh_keys.unwrap_or("").to_string(),
    );
    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name(vm_id)),
            namespace: Some(namespace.to_string()),
            labels: Some(vm_labels(vm_id, None)),
            ..Default::default()
        },
        string_data: Some(string_data),
        ..Default::default()
    }
}

#[derive(Debug, Clone)]
pub struct PodImages {
    pub agent: String,
    pub guest: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PodSecrets<'a> {
    pub wireguard_config: Option<&'a str>,
    pub ssh_keys: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodIntent {
    Create,
    Rebase,
    Start,
    Maintain,
}

impl PodIntent {
    fn rebasing(self) -> bool {
        self == Self::Rebase
    }

    fn autostart(self) -> bool {
        self != Self::Maintain
    }
}

pub fn build_pod(
    config: &K8sConfig,
    vm_id: &Uuid,
    owner_id: &Uuid,
    spec: &VmSpec,
    agent_image: &str,
    guest_image: &str,
    intent: PodIntent,
) -> Pod {
    let memory_mib = spec.memory_mib + config.memory_overhead_mib;
    let resources = BTreeMap::from([
        ("cpu".to_string(), Quantity(spec.vcpu.to_string())),
        ("memory".to_string(), Quantity(format!("{memory_mib}Mi"))),
        (KVM_RESOURCE.to_string(), Quantity("1".to_string())),
        (TUN_RESOURCE.to_string(), Quantity("1".to_string())),
    ]);
    Pod {
        metadata: ObjectMeta {
            name: Some(pod_name(vm_id)),
            namespace: Some(config.namespace.clone()),
            labels: Some(vm_labels(vm_id, Some(owner_id))),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::core::v1::PodSpec {
            service_account_name: config.vm_service_account.clone(),
            automount_service_account_token: Some(false),
            termination_grace_period_seconds: Some(60),
            node_selector: Some(config.node_selector.clone()),
            tolerations: Some(vec![Toleration {
                key: Some(config.taint_key.clone()),
                operator: Some("Exists".to_string()),
                ..Default::default()
            }]),
            security_context: Some(PodSecurityContext {
                run_as_non_root: Some(true),
                run_as_user: Some(1000),
                fs_group: Some(1000),
                fs_group_change_policy: Some("OnRootMismatch".to_string()),
                seccomp_profile: Some(SeccompProfile {
                    type_: "Localhost".to_string(),
                    localhost_profile: Some("profiles/kletka-vm-agent.json".to_string()),
                }),
                ..Default::default()
            }),
            volumes: Some(vec![
                Volume {
                    name: "instance".to_string(),
                    persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                        claim_name: data_claim_name(vm_id),
                        read_only: Some(false),
                    }),
                    ..Default::default()
                },
                Volume {
                    name: "tmp".to_string(),
                    empty_dir: Some(EmptyDirVolumeSource::default()),
                    ..Default::default()
                },
                Volume {
                    name: "guest".to_string(),
                    image: Some(ImageVolumeSource {
                        reference: Some(guest_image.to_string()),
                        pull_policy: Some("IfNotPresent".to_string()),
                    }),
                    ..Default::default()
                },
                Volume {
                    name: "vm-secrets".to_string(),
                    secret: Some(SecretVolumeSource {
                        secret_name: Some(secret_name(vm_id)),
                        items: Some(vec![
                            KeyToPath {
                                key: "wireguard.conf".to_string(),
                                path: "wireguard.conf".to_string(),
                                ..Default::default()
                            },
                            KeyToPath {
                                key: "authorized_keys".to_string(),
                                path: "authorized_keys".to_string(),
                                ..Default::default()
                            },
                        ]),
                        optional: Some(true),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            containers: vec![Container {
                name: "vm-agent".to_string(),
                image: Some(agent_image.to_string()),
                env: Some(vec![
                    plain_env("KLETKA_VM_ID", vm_id),
                    plain_env("KLETKA_VM_NAME", &spec.name),
                    plain_env("KLETKA_VM_IMAGE", &spec.image),
                    plain_env("KLETKA_VM_VCPU", spec.vcpu),
                    plain_env("KLETKA_VM_MEMORY_MIB", spec.memory_mib),
                    plain_env("KLETKA_VM_DISK_MIB", spec.disk_mib),
                    plain_env("KLETKA_VM_NAT", spec.nat),
                    plain_env("KLETKA_VM_IMAGE_REF", guest_image),
                    plain_env("KLETKA_VM_REBASE", intent.rebasing()),
                    plain_env("KLETKA_VM_AUTOSTART", intent.autostart()),
                    plain_env(
                        "KLETKA_WIREGUARD_CONFIG",
                        "/run/kletka-secrets/wireguard.conf",
                    ),
                    plain_env(
                        "KLETKA_AUTHORIZED_KEYS",
                        "/run/kletka-secrets/authorized_keys",
                    ),
                    plain_env("KLETKA_DATA_DIR", "/var/lib/kletka"),
                    plain_env("KLETKA_GUEST_IMAGE_DIR", "/guest"),
                    plain_env("KLETKA_VSOCK", "off"),
                    EnvVar {
                        name: "KLETKA_SESSION_TOKEN".to_string(),
                        value_from: Some(EnvVarSource {
                            secret_key_ref: Some(SecretKeySelector {
                                name: secret_name(vm_id),
                                key: "token".to_string(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ]),
                ports: Some(vec![ContainerPort {
                    container_port: AGENT_PORT,
                    name: Some("agent".to_string()),
                    ..Default::default()
                }]),
                resources: Some(ResourceRequirements {
                    requests: Some(resources.clone()),
                    limits: Some(resources),
                    ..Default::default()
                }),
                readiness_probe: Some(Probe {
                    http_get: Some(HTTPGetAction {
                        path: Some("/readyz".to_string()),
                        port: IntOrString::Int(AGENT_PORT),
                        ..Default::default()
                    }),
                    period_seconds: Some(1),
                    failure_threshold: Some(60),
                    ..Default::default()
                }),
                liveness_probe: Some(Probe {
                    http_get: Some(HTTPGetAction {
                        path: Some("/healthz".to_string()),
                        port: IntOrString::Int(AGENT_PORT),
                        ..Default::default()
                    }),
                    initial_delay_seconds: Some(5),
                    ..Default::default()
                }),
                security_context: Some(SecurityContext {
                    allow_privilege_escalation: Some(false),
                    read_only_root_filesystem: Some(true),
                    capabilities: Some(Capabilities {
                        drop: Some(vec!["ALL".to_string()]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                volume_mounts: Some(vec![
                    VolumeMount {
                        name: "instance".to_string(),
                        mount_path: "/var/lib/kletka".to_string(),
                        ..Default::default()
                    },
                    VolumeMount {
                        name: "tmp".to_string(),
                        mount_path: "/tmp".to_string(),
                        ..Default::default()
                    },
                    VolumeMount {
                        name: "guest".to_string(),
                        mount_path: "/guest".to_string(),
                        read_only: Some(true),
                        ..Default::default()
                    },
                    VolumeMount {
                        name: "vm-secrets".to_string(),
                        mount_path: "/run/kletka-secrets".to_string(),
                        read_only: Some(true),
                        ..Default::default()
                    },
                ]),
                image_pull_policy: Some("IfNotPresent".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn pod_vm_status(pod: &Pod) -> Option<VmStatus> {
    let status = pod.status.as_ref()?;
    let phase = status.phase.as_deref()?;
    match phase {
        "Running" => {
            let ready = status
                .conditions
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True");
            Some(if ready {
                VmStatus::Running
            } else {
                VmStatus::Stopped
            })
        }
        "Succeeded" | "Failed" => Some(VmStatus::Failed),
        "Pending" => Some(VmStatus::Pending),
        _ => None,
    }
}

pub fn transition(current: VmStatus, observed: VmStatus) -> Option<VmStatus> {
    use VmStatus::*;
    match (observed, current) {
        (Running, Pending | Stopped | Rebasing | Failed) => Some(Running),
        (Stopped, Running) => Some(Stopped),
        (Failed, Failed | Stopped) => None,
        (Failed, _) => Some(Failed),
        _ => None,
    }
}

pub const PENDING_SWEEP_GRACE_SECS: i64 = 15 * 60;

pub fn sweep_candidate(status: &str, created_at: i64, now: i64) -> bool {
    match status {
        "running" | "rebasing" => true,
        "pending" => now.saturating_sub(created_at) >= PENDING_SWEEP_GRACE_SECS,
        _ => false,
    }
}

fn vm_id_of(pod: &Pod) -> Option<Uuid> {
    pod.labels().get(VM_ID_LABEL).and_then(|v| v.parse().ok())
}

pub struct K8sProvisioner {
    client: Client,
    pub(crate) config: K8sConfig,
    pub(crate) http: reqwest::Client,
}

fn kube_result<T>(result: Result<T, kube::Error>, what: &str) -> ApiResult<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(err) => {
            if let kube::Error::Api(status) = &err
                && (status.code == 409 || status.code == 404)
            {
                return Ok(None);
            }
            if let kube::Error::Api(status) = &err {
                return Err(ApiError::new(
                    http_status(status.code),
                    format!("{what}: {}", status.message),
                ));
            }
            Err(ApiError::internal(format!("{what}: {err}")))
        }
    }
}

async fn agent_reply(response: reqwest::Response, rejected: &str) -> ApiResult<serde_json::Value> {
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    if status.is_success() {
        return Ok(body);
    }
    let message = body
        .get("error")
        .and_then(|value| value.as_str())
        .unwrap_or(rejected);
    Err(ApiError::new(http_status(status.as_u16()), message))
}

fn warn_delete_failures(
    vm_id: &Uuid,
    results: impl IntoIterator<Item = (&'static str, Result<(), kube::Error>)>,
) {
    for (kind, result) in results {
        if let Err(err) = result
            && !is_not_found(&err)
        {
            tracing::warn!(vm = %vm_id, %err, kind, "delete failed (continuing)");
        }
    }
}

pub(crate) fn http_status(code: u16) -> axum::http::StatusCode {
    axum::http::StatusCode::from_u16(code).unwrap_or(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
}

impl K8sProvisioner {
    pub async fn connect(config: K8sConfig) -> Result<Self, kube::Error> {
        let client = Client::try_default().await?;
        Ok(Self {
            client,
            config,
            http: reqwest::Client::new(),
        })
    }

    #[cfg(any(test, feature = "pg-tests"))]
    pub fn for_tests(config: K8sConfig) -> Self {
        let namespace = config.namespace.clone();
        Self::for_tests_with_client(
            config,
            Client::new(
                tower::service_fn(|_req: axum::http::Request<kube::client::Body>| async move {
                    let error: tower::BoxError =
                        std::io::Error::other("no cluster in tests").into();
                    Err::<axum::http::Response<kube::client::Body>, tower::BoxError>(error)
                }),
                namespace,
            ),
        )
    }

    #[cfg(any(test, feature = "pg-tests"))]
    pub fn for_tests_with_client(config: K8sConfig, client: Client) -> Self {
        Self {
            client,
            config,
            http: reqwest::Client::new(),
        }
    }

    fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    fn secrets(&self) -> Api<Secret> {
        Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    fn pvcs(&self) -> Api<PersistentVolumeClaim> {
        Api::namespaced(self.client.clone(), &self.config.namespace)
    }

    fn cnps(&self) -> Api<DynamicObject> {
        Api::namespaced_with(self.client.clone(), &self.config.namespace, &cnp_resource())
    }

    fn guest_image_configmaps(&self, namespace: &str) -> Api<ConfigMap> {
        Api::namespaced(self.client.clone(), namespace)
    }

    pub async fn runtime_guest_images(&self) -> Option<BTreeMap<String, String>> {
        let configmap = self.config.guest_images_configmap.as_deref()?;
        let (namespace, name) = match split_configmap_ref(configmap) {
            Ok(parts) => parts,
            Err(err) => {
                tracing::warn!(%err, "ignoring guest-images configmap");
                return None;
            }
        };
        match self.guest_image_configmaps(namespace).get(name).await {
            Ok(cm) => cm.data.map(|data| {
                data.into_iter()
                    .filter(|(key, _)| key != "updated_at")
                    .filter(|(key, _)| !key.ends_with(".overlay_boot"))
                    .collect()
            }),
            Err(err) => {
                tracing::warn!(
                    %err, configmap = %configmap, "guest-images configmap unreadable; using static pins"
                );
                None
            }
        }
    }

    pub async fn guest_image(&self, image: &str) -> ApiResult<String> {
        if let Some(entries) = self.runtime_guest_images().await
            && let Some(reference) = entries.get(image)
        {
            return Ok(reference.clone());
        }
        self.config.guest_image(image)
    }

    pub async fn guest_image_overlay_boot(&self, image: &str) -> bool {
        if let Some(configmap) = self.config.guest_images_configmap.as_deref()
            && let Ok((namespace, name)) = split_configmap_ref(configmap)
            && let Ok(cm) = self.guest_image_configmaps(namespace).get(name).await
            && let Some(value) = cm
                .data
                .as_ref()
                .and_then(|data| data.get(&format!("{image}.overlay_boot")))
        {
            return value == "true";
        }
        self.config
            .guest_image_overlay_boots
            .get(image)
            .copied()
            .unwrap_or(false)
    }

    pub fn agent_image(&self, image: &str) -> ApiResult<String> {
        self.config.agent_image(image)
    }

    pub async fn pod_images(&self, image: &str) -> ApiResult<PodImages> {
        Ok(PodImages {
            agent: self.agent_image(image)?,
            guest: self.guest_image(image).await?,
        })
    }

    pub async fn pinned_guest_image(&self, vm_id: &Uuid, image: &str) -> ApiResult<String> {
        let claim = kube_result(
            self.pvcs().get(&data_claim_name(vm_id)).await,
            "reading vm data claim",
        )?;
        if let Some(pinned) = claim.as_ref().and_then(pinned_ref) {
            return Ok(pinned);
        }
        let current = self.guest_image(image).await?;
        if claim.is_some() {
            if let Err(err) = self.pin_guest_image(vm_id, &current).await {
                tracing::warn!(vm = %vm_id, %err, "could not pin legacy vm to its guest ref");
            } else {
                tracing::info!(vm = %vm_id, reference = %current, "pinned legacy vm to the current guest ref");
            }
        }
        Ok(current)
    }

    async fn pin_guest_image(&self, vm_id: &Uuid, reference: &str) -> ApiResult<()> {
        let patch = serde_json::json!({
            "metadata": { "annotations": { GUEST_REF_ANNOTATION: reference } }
        });
        self.pvcs()
            .patch(
                &data_claim_name(vm_id),
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .map_err(|err| ApiError::internal(format!("pinning guest image: {err}")))?;
        Ok(())
    }

    pub async fn create(
        &self,
        vm_id: &Uuid,
        owner_id: &Uuid,
        spec: &VmSpec,
        images: &PodImages,
        wireguard_config: Option<&str>,
        ssh_keys: Option<&str>,
    ) -> ApiResult<()> {
        let secrets = PodSecrets {
            wireguard_config,
            ssh_keys,
        };
        self.create_pod_resources(vm_id, owner_id, spec, images, PodIntent::Create, secrets)
            .await
    }

    async fn create_pod_resources(
        &self,
        vm_id: &Uuid,
        owner_id: &Uuid,
        spec: &VmSpec,
        images: &PodImages,
        intent: PodIntent,
        secrets: PodSecrets<'_>,
    ) -> ApiResult<()> {
        kube_result(
            self.pvcs()
                .create(
                    &PostParams::default(),
                    &build_data_claim(&self.config, vm_id, owner_id, spec, &images.guest),
                )
                .await,
            "creating vm data claim",
        )?;
        let secret = build_secret(
            vm_id,
            &self.config.namespace,
            &new_session_token(),
            secrets.wireguard_config,
            secrets.ssh_keys,
        );
        let created = self.secrets().create(&PostParams::default(), &secret).await;
        match &created {
            Err(kube::Error::Api(status)) if status.code == 409 => {
                self.ensure_secret_authorized_keys(vm_id).await?;
            }
            _ => {
                kube_result(created, "creating session token secret")?;
            }
        }
        let pod = build_pod(
            &self.config,
            vm_id,
            owner_id,
            spec,
            &images.agent,
            &images.guest,
            intent,
        );
        kube_result(
            self.pods().create(&PostParams::default(), &pod).await,
            "creating vm pod",
        )?;
        tracing::info!(vm = %vm_id, image = %spec.image, "vm pod created");
        Ok(())
    }

    async fn ensure_secret_authorized_keys(&self, vm_id: &Uuid) -> ApiResult<()> {
        let name = secret_name(vm_id);
        let mut secret = match self.secrets().get(&name).await {
            Ok(secret) => secret,
            Err(err) if is_not_found(&err) => return Ok(()),
            Err(err) => return Err(ApiError::internal(format!("reading vm secret: {err}"))),
        };
        let mut data = secret.data.take().unwrap_or_default();
        if data.contains_key("authorized_keys") {
            secret.data = Some(data);
            return Ok(());
        }
        data.insert("authorized_keys".to_string(), ByteString(Vec::new()));
        secret.data = Some(data);
        secret.string_data = None;
        kube_result(
            self.secrets()
                .replace(&name, &PostParams::default(), &secret)
                .await,
            "adding authorized_keys to vm secret",
        )?;
        Ok(())
    }

    pub async fn validate_rebase(&self, vm_id: &Uuid, image: &str) -> ApiResult<()> {
        self.pod_images(image).await?;
        if !self.guest_image_overlay_boot(image).await {
            return Err(ApiError::bad_request(format!(
                "guest image '{image}' does not support overlay boot; rebase would not preserve the vm disk"
            )));
        }
        self.pvcs()
            .get(&data_claim_name(vm_id))
            .await
            .map_err(|err| match err {
                err if is_not_found(&err) => {
                    ApiError::conflict("this VM has ephemeral storage and cannot be rebased safely")
                }
                other => ApiError::internal(format!("reading vm data claim: {other}")),
            })?;
        Ok(())
    }

    pub async fn rebase(&self, vm_id: &Uuid, owner_id: &Uuid, spec: &VmSpec) -> ApiResult<()> {
        let images = self.pod_images(&spec.image).await?;
        self.pin_guest_image(vm_id, &images.guest).await?;
        self.recreate_pod(vm_id, owner_id, spec, &images, PodIntent::Rebase)
            .await
    }

    async fn recreate_pod(
        &self,
        vm_id: &Uuid,
        owner_id: &Uuid,
        spec: &VmSpec,
        images: &PodImages,
        intent: PodIntent,
    ) -> ApiResult<()> {
        let pod = pod_name(vm_id);
        kube_result(
            self.pods().delete(&pod, &DeleteParams::default()).await,
            "deleting the old vm pod",
        )?;
        self.wait_pod_deleted(&pod).await?;
        self.create_pod_resources(vm_id, owner_id, spec, images, intent, PodSecrets::default())
            .await
    }

    async fn pinned_pod_images(&self, vm_id: &Uuid, image: &str) -> ApiResult<PodImages> {
        Ok(PodImages {
            agent: self.agent_image(image)?,
            guest: self.pinned_guest_image(vm_id, image).await?,
        })
    }

    async fn wait_pod_deleted(&self, pod: &str) -> ApiResult<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        loop {
            match self.pods().get(pod).await {
                Ok(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Ok(_) => {
                    return Err(ApiError::conflict("old vm pod did not terminate in time"));
                }
                Err(err) if is_not_found(&err) => return Ok(()),
                Err(err) => {
                    return Err(ApiError::internal(format!("waiting for old vm pod: {err}")));
                }
            }
        }
    }

    pub async fn delete_pod(&self, vm_id: &Uuid) -> ApiResult<()> {
        kube_result(
            self.pods()
                .delete(&pod_name(vm_id), &DeleteParams::default())
                .await,
            "deleting vm pod",
        )?;
        Ok(())
    }

    pub async fn set_wireguard_config(
        &self,
        vm_id: &Uuid,
        wireguard_config: Option<&str>,
    ) -> ApiResult<()> {
        let name = secret_name(vm_id);
        let mut secret = self.secrets().get(&name).await.map_err(|err| match err {
            err if is_not_found(&err) => ApiError::conflict("vm session secret is missing"),
            other => ApiError::internal(format!("reading vm session secret: {other}")),
        })?;
        let mut data = secret.data.take().unwrap_or_default();
        data.insert(
            "wireguard.conf".to_string(),
            ByteString(wireguard_config.unwrap_or_default().as_bytes().to_vec()),
        );
        secret.data = Some(data);
        secret.string_data = None;
        kube_result(
            self.secrets()
                .replace(&name, &PostParams::default(), &secret)
                .await,
            "updating vm WireGuard config",
        )?;
        Ok(())
    }

    pub async fn start_vm(&self, vm_id: &Uuid, owner_id: &Uuid, spec: &VmSpec) -> ApiResult<()> {
        let images = self.pinned_pod_images(vm_id, &spec.image).await?;
        self.recreate_pod(vm_id, owner_id, spec, &images, PodIntent::Start)
            .await
    }

    pub(crate) async fn wait_for_agent(&self, vm_id: &Uuid) -> ApiResult<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            if let Ok((addr, _)) = self.agent_endpoint(vm_id).await
                && let Ok(response) = self
                    .http
                    .get(agent_url(&addr, "/healthz"))
                    .timeout(Duration::from_secs(2))
                    .send()
                    .await
                && response.status().is_success()
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(ApiError::conflict(
                    "vm agent did not become reachable in time",
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn snapshot_vm(
        &self,
        vm_id: &Uuid,
        owner_id: &Uuid,
        spec: &VmSpec,
        maintenance: bool,
        body: kletka_types::SnapshotRequest,
    ) -> ApiResult<serde_json::Value> {
        if maintenance {
            let images = self.pinned_pod_images(vm_id, &spec.image).await?;
            self.create_pod_resources(
                vm_id,
                owner_id,
                spec,
                &images,
                PodIntent::Maintain,
                PodSecrets::default(),
            )
            .await?;
            self.wait_for_agent(vm_id).await?;
        }
        let result = self.snapshot_rpc(vm_id, &body).await;
        if maintenance && let Err(err) = self.delete_pod(vm_id).await {
            tracing::warn!(vm = %vm_id, %err, "maintenance pod delete failed");
        }
        result
    }

    pub async fn destroy(&self, vm_id: &Uuid) {
        let dp = DeleteParams::default();
        let what = [
            (
                "pod",
                self.pods().delete(&pod_name(vm_id), &dp).await.map(|_| ()),
            ),
            (
                "secret",
                self.secrets()
                    .delete(&secret_name(vm_id), &dp)
                    .await
                    .map(|_| ()),
            ),
            (
                "vm data claim",
                self.pvcs()
                    .delete(&data_claim_name(vm_id), &dp)
                    .await
                    .map(|_| ()),
            ),
            (
                "legacy egress policy",
                self.cnps().delete(&pod_name(vm_id), &dp).await.map(|_| ()),
            ),
        ];
        warn_delete_failures(vm_id, what);
    }

    async fn agent_rpc(
        &self,
        vm_id: &Uuid,
        method: reqwest::Method,
        path: &str,
        body: &impl serde::Serialize,
        timeout: Duration,
    ) -> ApiResult<serde_json::Value> {
        let (addr, token) = self.agent_endpoint(vm_id).await?;
        let response = self
            .http
            .request(method, agent_url(&addr, path))
            .header("x-node-secret", token)
            .json(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|err| {
                tracing::warn!(vm = %vm_id, path, err = %kletka_types::error_chain(&err), "vm agent unreachable");
                ApiError::conflict("the VM's agent is not reachable right now; try again shortly")
            })?;
        agent_reply(response, "the VM's agent rejected the request").await
    }

    pub async fn stop_guest(&self, vm_id: &Uuid) -> ApiResult<()> {
        let body = kletka_types::LifecycleRequest {
            op: kletka_types::LifecycleOp::Stop,
        };
        self.agent_rpc(
            vm_id,
            reqwest::Method::POST,
            "/internal/lifecycle",
            &body,
            Duration::from_secs(50),
        )
        .await
        .map(drop)
    }

    pub async fn wireguard_rpc(
        &self,
        vm_id: &Uuid,
        wireguard_config: Option<&str>,
    ) -> ApiResult<()> {
        let body = kletka_types::WireguardRequest {
            wireguard_config: wireguard_config.map(str::to_string),
        };
        self.agent_rpc(
            vm_id,
            reqwest::Method::PUT,
            "/internal/wireguard",
            &body,
            Duration::from_secs(60),
        )
        .await
        .map(drop)
    }

    async fn agent_endpoint(&self, vm_id: &Uuid) -> ApiResult<(String, String)> {
        let pod = self
            .pods()
            .get(&pod_name(vm_id))
            .await
            .map_err(|_| ApiError::conflict("vm pod not found"))?;
        let ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .ok_or_else(|| ApiError::conflict("vm pod has no ip yet"))?;
        let token = self
            .secrets()
            .get(&secret_name(vm_id))
            .await
            .ok()
            .and_then(|secret| secret_string(&secret, "token"))
            .ok_or_else(|| ApiError::conflict("vm session token not found"))?;
        Ok((ip, token))
    }

    pub async fn relay_target(&self, vm_id: &Uuid) -> ApiResult<(String, String, String)> {
        let (ip, token) = self.agent_endpoint(vm_id).await?;
        Ok((pod_name(vm_id), agent_url(&ip, ""), token))
    }

    pub async fn reserve_snapshot_capacity(&self, vm_id: &Uuid, disk_mib: usize) -> ApiResult<()> {
        let name = data_claim_name(vm_id);
        let claim = match self.pvcs().get(&name).await {
            Ok(claim) => claim,
            Err(err) if is_not_found(&err) => return Ok(()),
            Err(err) => return Err(ApiError::internal(format!("reading vm data claim: {err}"))),
        };
        let Some(current) = claim_request_mib(&claim) else {
            tracing::warn!(vm = %vm_id, "vm data claim size unreadable; skipping snapshot capacity growth");
            return Ok(());
        };
        let disk_mib = disk_mib.max(IMAGE_FLOOR_MIB);
        let ceiling = vm_storage_ceiling_mib(&self.config, disk_mib);
        let target = current.saturating_add(disk_mib).min(ceiling);
        if target <= current {
            return Ok(());
        }
        kube_result(
            self.pvcs()
                .patch(
                    &name,
                    &PatchParams::default(),
                    &Patch::Merge(&storage_patch(target)),
                )
                .await,
            "expanding vm data claim",
        )?;
        Ok(())
    }

    pub async fn resize_data_claim(&self, vm_id: &Uuid, spec: &VmSpec) -> ApiResult<()> {
        let name = data_claim_name(vm_id);
        let claim = match self.pvcs().get(&name).await {
            Ok(claim) => claim,
            Err(err) if is_not_found(&err) => {
                return Err(ApiError::conflict(
                    "this VM has ephemeral storage; its disk cannot be resized (recreate the \
                     VM on PVC storage)",
                ));
            }
            Err(err) => return Err(ApiError::internal(format!("reading vm data claim: {err}"))),
        };
        let Some(current) = claim_request_mib(&claim) else {
            return Err(ApiError::internal("vm data claim size unreadable"));
        };
        let target = vm_storage_mib(&self.config, spec).max(current);
        if target == current {
            return Ok(());
        }
        kube_result(
            self.pvcs()
                .patch(
                    &name,
                    &PatchParams::default(),
                    &Patch::Merge(&storage_patch(target)),
                )
                .await,
            "expanding vm data claim for disk resize",
        )?;
        Ok(())
    }

    const SNAPSHOT_RPC_TIMEOUT: Duration = Duration::from_secs(300);

    pub async fn snapshot_rpc(
        &self,
        vm_id: &Uuid,
        body: &kletka_types::SnapshotRequest,
    ) -> ApiResult<serde_json::Value> {
        self.agent_rpc(
            vm_id,
            reqwest::Method::POST,
            "/internal/snapshot",
            body,
            Self::SNAPSHOT_RPC_TIMEOUT,
        )
        .await
    }

    pub const CLONE_TRANSFER_TIMEOUT: Duration = Duration::from_secs(900);

    pub async fn clone_source_secrets(
        &self,
        src_vm_id: &Uuid,
    ) -> ApiResult<(String, Option<String>)> {
        let Some(claim) = kube_result(
            self.pvcs().get(&data_claim_name(src_vm_id)).await,
            "reading the source vm's data claim",
        )?
        else {
            return Err(ApiError::conflict(
                "the source VM has ephemeral storage; its disk cannot be cloned safely",
            ));
        };
        let pinned = pinned_ref(&claim).ok_or_else(|| {
            ApiError::conflict(
                "the source VM's disk is not pinned to a guest image yet; start it once, \
                 then clone",
            )
        })?;
        let secret = self
            .secrets()
            .get(&secret_name(src_vm_id))
            .await
            .map_err(|err| {
                ApiError::conflict(format!(
                    "the source VM's session secret is unreadable: {err}"
                ))
            })?;
        let keys = secret_string(&secret, "authorized_keys").filter(|keys| !keys.trim().is_empty());
        Ok((pinned, keys))
    }

    pub async fn start_clone(
        &self,
        dest_spec: &VmSpec,
        src_spec: &VmSpec,
        dest_vm_id: &Uuid,
        src_vm_id: &Uuid,
        owner_id: &Uuid,
    ) -> ApiResult<()> {
        let (pinned, ssh_keys) = self.clone_source_secrets(src_vm_id).await?;
        let agent = self.agent_image(&dest_spec.image)?;
        let dest_images = PodImages {
            agent: agent.clone(),
            guest: pinned,
        };
        let dest_secrets = PodSecrets {
            wireguard_config: None,
            ssh_keys: ssh_keys.as_deref(),
        };
        self.create_pod_resources(
            dest_vm_id,
            owner_id,
            dest_spec,
            &dest_images,
            PodIntent::Maintain,
            dest_secrets,
        )
        .await?;
        let src_images = PodImages {
            agent,
            guest: self.pinned_guest_image(src_vm_id, &src_spec.image).await?,
        };
        self.create_pod_resources(
            src_vm_id,
            owner_id,
            src_spec,
            &src_images,
            PodIntent::Maintain,
            PodSecrets::default(),
        )
        .await?;
        tracing::info!(
            source = %src_vm_id,
            target = %dest_vm_id,
            "clone maintenance pods created"
        );
        Ok(())
    }

    pub async fn disk_stream(&self, vm_id: &Uuid) -> ApiResult<reqwest::Response> {
        let (addr, token) = self.agent_endpoint(vm_id).await?;
        self.http
            .get(agent_url(&addr, "/internal/disk"))
            .header("x-node-secret", token)
            .timeout(Self::CLONE_TRANSFER_TIMEOUT)
            .send()
            .await
            .map_err(|err| {
                tracing::warn!(vm = %vm_id, err = %kletka_types::error_chain(&err), "clone disk read failed");
                ApiError::conflict("the source VM's agent is not reachable right now; try again shortly")
            })?
            .error_for_status()
            .map_err(|err| {
                ApiError::new(
                    http_status(err.status().map(|s| s.as_u16()).unwrap_or(500)),
                    "the source VM's agent refused the disk read",
                )
            })
    }

    pub async fn disk_push(&self, vm_id: &Uuid, body: reqwest::Body) -> ApiResult<u64> {
        let (addr, token) = self.agent_endpoint(vm_id).await?;
        let response = self
            .http
            .put(agent_url(&addr, "/internal/disk"))
            .header("x-node-secret", token)
            .header("content-type", "application/octet-stream")
            .timeout(Self::CLONE_TRANSFER_TIMEOUT)
            .body(body)
            .send()
            .await
            .map_err(|err| {
                tracing::warn!(vm = %vm_id, err = %kletka_types::error_chain(&err), "clone disk write failed");
                ApiError::conflict("the clone target's agent is not reachable right now; try again shortly")
            })?;
        let body = agent_reply(response, "the clone target's agent rejected the disk").await?;
        Ok(body
            .get("size")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0))
    }

    pub fn spawn_observer(
        self: Arc<Self>,
        db: sqlx::AnyPool,
        gate: std::sync::Arc<crate::leader::LeaderGate>,
    ) {
        tokio::spawn(async move {
            loop {
                gate.wait().await;
                tracing::info!(
                    namespace = %self.config.namespace,
                    "vm pod observer running"
                );
                let observer = tokio::spawn({
                    let this = self.clone();
                    let db = db.clone();
                    async move {
                        this.observe(db).await;
                    }
                });
                gate.lost().await;
                observer.abort();
                let _ = observer.await;
                tracing::info!("vm pod observer stood down");
            }
        });
    }

    async fn observe(&self, db: sqlx::AnyPool) {
        let selector = format!("{COMPONENT_LABEL}={COMPONENT_VM}");
        let stream =
            watcher(self.pods(), watcher::Config::default().labels(&selector)).default_backoff();
        let mut stream = Box::pin(stream);
        tracing::info!(namespace = %self.config.namespace, selector = %selector, "vm pod observer running");
        let mut init_batch: Vec<(Uuid, String)> = Vec::new();
        use kube::runtime::watcher::Event;
        while let Some(event) = futures_util::StreamExt::next(&mut stream).await {
            let event = match event {
                Ok(event) => event,
                Err(err) => {
                    tracing::warn!(%err, "vm pod watcher error");
                    continue;
                }
            };
            match event {
                Event::Init => init_batch.clear(),
                Event::InitApply(pod) => {
                    if let Some(vm_id) = vm_id_of(&pod) {
                        init_batch.push((vm_id, pod.name_any()));
                    }
                    self.apply_pod(&db, &pod).await;
                }
                Event::InitDone => {
                    self.gc_orphans(&db, &init_batch).await;
                    self.sweep_rows_without_pods(&db, &init_batch).await;
                    fail_stale_clones(&db).await;
                }
                Event::Apply(pod) => self.apply_pod(&db, &pod).await,
                Event::Delete(pod) => {
                    if let Some(vm_id) = vm_id_of(&pod) {
                        mark_failed(&db, &vm_id, "pod deleted").await;
                    }
                }
            }
        }
    }

    async fn apply_pod(&self, db: &sqlx::AnyPool, pod: &Pod) {
        let Some(vm_id) = vm_id_of(pod) else {
            return;
        };
        let Some(observed) = pod_vm_status(pod) else {
            return;
        };
        let row: Option<(String,)> =
            match crate::db::query_as("SELECT status FROM vms WHERE id = ?")
                .bind(vm_id.to_string())
                .fetch_optional(db)
                .await
            {
                Ok(row) => row,
                Err(err) => {
                    tracing::warn!(vm = %vm_id, %err, "status lookup failed");
                    return;
                }
            };
        let Some(current) = row.and_then(|(status,)| VmStatus::parse(&status)) else {
            return;
        };
        let Some(next) = transition(current, observed) else {
            return;
        };
        let result = crate::db::query("UPDATE vms SET status = ? WHERE id = ?")
            .bind(next.as_str())
            .bind(vm_id.to_string())
            .execute(db)
            .await;
        match result {
            Ok(_) => tracing::info!(
                vm = %vm_id,
                from = current.as_str(),
                to = next.as_str(),
                "vm status converged"
            ),
            Err(err) => tracing::warn!(vm = %vm_id, %err, "status update failed"),
        }
        if next == VmStatus::Failed {
            audit_failure(db, &vm_id, "the vm's pod failed").await;
        }
        if next == VmStatus::Running {
            let _ = crate::db::query(
                "UPDATE jobs SET state = 'running' WHERE vm_id = ? AND kind = 'create'",
            )
            .bind(vm_id.to_string())
            .execute(db)
            .await;
        }
    }

    async fn gc_orphans(&self, db: &sqlx::AnyPool, batch: &[(Uuid, String)]) {
        for (vm_id, pod) in batch {
            let row: Option<(String,)> =
                match crate::db::query_as("SELECT id FROM vms WHERE id = ?")
                    .bind(vm_id.to_string())
                    .fetch_optional(db)
                    .await
                {
                    Ok(row) => row,
                    Err(_) => continue,
                };
            if row.is_none() {
                tracing::warn!(
                    vm = %vm_id,
                    pod = %pod,
                    claim = %data_claim_name(vm_id),
                    "quarantining orphan vm pod (no vm row; data claim kept for review)"
                );
                self.quarantine_orphan(vm_id).await;
            }
        }
    }

    async fn quarantine_orphan(&self, vm_id: &Uuid) {
        let dp = DeleteParams::default();
        warn_delete_failures(
            vm_id,
            [
                (
                    "orphan pod",
                    self.pods().delete(&pod_name(vm_id), &dp).await.map(|_| ()),
                ),
                (
                    "orphan egress policy",
                    self.cnps().delete(&pod_name(vm_id), &dp).await.map(|_| ()),
                ),
            ],
        );
        let patch = json!({
            "metadata": {
                "annotations": { ORPHANED_ANNOTATION: kletka_types::time::now().to_string() }
            }
        });
        let name = data_claim_name(vm_id);
        match self
            .pvcs()
            .patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
            .await
        {
            Ok(_) => {
                tracing::warn!(vm = %vm_id, claim = %name, "orphan data claim kept; delete it once its data is confirmed unwanted")
            }
            Err(err) if is_not_found(&err) => {}
            Err(err) => tracing::warn!(vm = %vm_id, %err, "orphan claim annotation failed"),
        }
    }

    async fn sweep_rows_without_pods(&self, db: &sqlx::AnyPool, batch: &[(Uuid, String)]) {
        let rows: Vec<(String, String, i64)> = match crate::db::query_as(
            "SELECT id, status, created_at FROM vms \
             WHERE status IN ('running', 'pending', 'rebasing')",
        )
        .fetch_all(db)
        .await
        {
            Ok(rows) => rows,
            Err(err) => {
                tracing::warn!(%err, "startup sweep: row query failed");
                return;
            }
        };
        let seen: std::collections::HashSet<Uuid> = batch.iter().map(|(id, _)| *id).collect();
        let now = crate::db::now();
        for (id, status, created_at) in rows {
            let Ok(vm_id) = id.parse::<Uuid>() else {
                tracing::warn!(%id, "startup sweep: corrupt vm id");
                continue;
            };
            if !sweep_candidate(&status, created_at, now) || seen.contains(&vm_id) {
                continue;
            }
            match self.pods().get(&pod_name(&vm_id)).await {
                Ok(pod) => self.apply_pod(db, &pod).await,
                Err(err) if is_not_found(&err) => {
                    mark_failed(db, &vm_id, "pod missing after control-plane restart").await;
                }
                Err(err) => {
                    tracing::warn!(vm = %vm_id, %err, "startup sweep: pod lookup failed");
                }
            }
        }
    }
}

pub const CLONE_SWEEP_GRACE_SECS: i64 = 30 * 60;

async fn fail_stale_clones(db: &sqlx::AnyPool) {
    let stale: Vec<(String,)> = match crate::db::query_as(
        "SELECT id FROM vms WHERE status = 'cloning' \
         AND created_at < ?",
    )
    .bind(crate::db::now() - CLONE_SWEEP_GRACE_SECS)
    .fetch_all(db)
    .await
    {
        Ok(stale) => stale,
        Err(err) => {
            tracing::warn!(%err, "stale clone sweep query failed");
            return;
        }
    };
    for (id,) in stale {
        let Some(vm_id) = id.parse::<Uuid>().ok() else {
            continue;
        };
        mark_failed(db, &vm_id, "clone interrupted before it finished").await;
    }
}

async fn mark_failed(db: &sqlx::AnyPool, vm_id: &Uuid, why: &'static str) {
    match crate::db::query(
        "UPDATE vms SET status = 'failed' WHERE id = ? AND status NOT IN \
         ('failed', 'rebasing', 'stopped')",
    )
    .bind(vm_id.to_string())
    .execute(db)
    .await
    {
        Ok(result) if result.rows_affected() > 0 => {
            tracing::warn!(vm = %vm_id, why, "vm marked failed");
            audit_failure(db, vm_id, why).await;
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(vm = %vm_id, %err, "failed-status update error"),
    }
}

async fn audit_failure(db: &sqlx::AnyPool, vm_id: &Uuid, why: &str) {
    let row: Option<(String, String, String)> = match crate::db::query_as(
        "SELECT COALESCE(created_by, namespace_id), name, namespace_id FROM vms WHERE id = ?",
    )
    .bind(vm_id.to_string())
    .fetch_optional(db)
    .await
    {
        Ok(row) => row,
        Err(err) => {
            tracing::warn!(vm = %vm_id, %err, "cannot audit vm failure");
            return;
        }
    };
    let Some((owner, name, namespace)) = row else {
        return;
    };
    let Ok(owner) = owner.parse::<Uuid>() else {
        return;
    };
    crate::audit::record(
        db,
        crate::audit::Event::system(owner, "vm.failed")
            .vm(vm_id.to_string(), name)
            .namespace(namespace)
            .detail(json!({ "reason": why })),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> VmSpec {
        VmSpec {
            name: "vm-x".into(),
            image: "default".into(),
            vcpu: 2,
            memory_mib: 1024,
            disk_mib: 8192,
            nat: true,
        }
    }

    fn config() -> K8sConfig {
        K8sConfig::default()
    }

    #[test]
    fn pod_runs_as_the_configured_service_account() {
        let config = K8sConfig {
            vm_service_account: Some("kletka-vm".to_string()),
            ..config()
        };
        let pod = build_pod(
            &config,
            &Uuid::new_v4(),
            &Uuid::new_v4(),
            &spec(),
            "kletka-vm-agent:dev",
            "localhost:5000/kletka/guest/default:2026-11-17.1",
            PodIntent::Create,
        );
        let pod_spec = pod.spec.unwrap();
        assert_eq!(pod_spec.service_account_name.as_deref(), Some("kletka-vm"));
        assert!(!pod_spec.automount_service_account_token.unwrap());
    }

    #[test]
    fn pod_carries_the_vm_contract() {
        let vm_id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let pod = build_pod(
            &config(),
            &vm_id,
            &owner,
            &spec(),
            "kletka-vm-agent:dev",
            "ghcr.io/o/kletka-guest-default:2026-11-14.1",
            PodIntent::Create,
        );

        assert_eq!(
            pod.metadata.name.as_deref(),
            Some(pod_name(&vm_id).as_str())
        );
        let labels = pod.labels();
        assert_eq!(labels[VM_ID_LABEL], vm_id.to_string());
        assert_eq!(labels[USER_ID_LABEL], owner.to_string());
        assert_eq!(labels[COMPONENT_LABEL], "vm");

        let pod_spec = pod.spec.unwrap();
        assert!(!pod_spec.automount_service_account_token.unwrap());
        assert_eq!(pod_spec.service_account_name, None);
        assert_eq!(
            pod_spec.node_selector.unwrap()["kletka.dev/vm-node"],
            "true"
        );
        assert_eq!(
            pod_spec.tolerations.unwrap()[0].key.as_deref(),
            Some("kletka.dev/untrusted")
        );

        let container = &pod_spec.containers[0];
        let env: Vec<(&str, &str)> = container
            .env
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|e| e.value.as_deref().map(|v| (e.name.as_str(), v)))
            .collect();
        for expected in [
            ("KLETKA_VM_ID", vm_id.to_string().as_str()),
            ("KLETKA_VM_NAME", "vm-x"),
            ("KLETKA_VM_VCPU", "2"),
            ("KLETKA_VM_MEMORY_MIB", "1024"),
            ("KLETKA_VSOCK", "off"),
            ("KLETKA_GUEST_IMAGE_DIR", "/guest"),
            (
                "KLETKA_VM_IMAGE_REF",
                "ghcr.io/o/kletka-guest-default:2026-11-14.1",
            ),
            ("KLETKA_VM_REBASE", "false"),
            ("KLETKA_VM_AUTOSTART", "true"),
            (
                "KLETKA_WIREGUARD_CONFIG",
                "/run/kletka-secrets/wireguard.conf",
            ),
        ] {
            assert!(env.contains(&expected), "missing env {expected:?}: {env:?}");
        }
        assert!(
            container
                .env
                .as_ref()
                .unwrap()
                .iter()
                .any(|e| e.name == "KLETKA_SESSION_TOKEN" && e.value_from.is_some())
        );

        let resources = container.resources.as_ref().unwrap();
        let requests = resources.requests.as_ref().unwrap();
        assert_eq!(requests["cpu"].0, "2");
        assert_eq!(requests["memory"].0, "1280Mi");
        assert_eq!(requests[KVM_RESOURCE].0, "1");
        assert_eq!(requests[TUN_RESOURCE].0, "1");
        assert_eq!(resources.limits.as_ref().unwrap()["memory"].0, "1280Mi");

        let volumes = pod_spec.volumes.unwrap();
        assert_eq!(
            volumes[0]
                .persistent_volume_claim
                .as_ref()
                .unwrap()
                .claim_name,
            data_claim_name(&vm_id)
        );
        let guest = volumes
            .iter()
            .find(|v| v.name == "guest")
            .expect("guest image volume");
        assert_eq!(
            guest.image.as_ref().unwrap().reference.as_deref(),
            Some("ghcr.io/o/kletka-guest-default:2026-11-14.1")
        );
        let mounts = container.volume_mounts.as_ref().unwrap();
        let guest_mount = mounts
            .iter()
            .find(|m| m.name == "guest")
            .expect("guest mount");
        assert_eq!(guest_mount.mount_path, "/guest");
        assert_eq!(guest_mount.read_only, Some(true));
        let secrets_mount = mounts
            .iter()
            .find(|mount| mount.name == "vm-secrets")
            .expect("vm secret mount");
        assert_eq!(secrets_mount.mount_path, "/run/kletka-secrets");
        assert_eq!(secrets_mount.read_only, Some(true));
        assert_eq!(
            container
                .security_context
                .as_ref()
                .unwrap()
                .capabilities
                .as_ref()
                .unwrap()
                .drop,
            Some(vec!["ALL".to_string()])
        );
        assert_eq!(
            container.image_pull_policy.as_deref(),
            Some("IfNotPresent"),
            "vm pods must start from the node cache; a tag bump is the rollout"
        );
    }

    #[test]
    fn wireguard_config_is_kept_in_the_vm_secret() {
        let vm_id = Uuid::new_v4();
        let secret = build_secret(&vm_id, "kletka-vms", "token", Some("[Interface]\n"), None);
        let data = secret.string_data.unwrap();
        assert_eq!(data["token"], "token");
        assert_eq!(data["wireguard.conf"], "[Interface]\n");
    }

    #[test]
    fn ssh_keys_join_into_the_secret_and_default_to_empty() {
        let vm_id = Uuid::new_v4();
        let secret = build_secret(
            &vm_id,
            "kletka-vms",
            "token",
            None,
            Some("ssh-ed25519 AAAA one\nssh-ed25519 BBBB two"),
        );
        let data = secret.string_data.unwrap();
        assert_eq!(
            data["authorized_keys"],
            "ssh-ed25519 AAAA one\nssh-ed25519 BBBB two"
        );

        let bare = build_secret(&vm_id, "kletka-vms", "token", None, None);
        assert_eq!(bare.string_data.unwrap()["authorized_keys"], "");
    }

    fn pod_from_json(status: serde_json::Value) -> Pod {
        serde_json::from_value(serde_json::json!({
            "metadata": {
                "name": "vm-x",
                "labels": { COMPONENT_LABEL: "vm", VM_ID_LABEL: Uuid::new_v4().to_string() }
            },
            "status": status
        }))
        .unwrap()
    }

    #[test]
    fn pod_status_mapping() {
        let ready = pod_from_json(serde_json::json!({
            "phase": "Running",
            "podIP": "10.1.2.3",
            "conditions": [{ "type": "Ready", "status": "True" }]
        }));
        assert_eq!(pod_vm_status(&ready), Some(VmStatus::Running));

        let booting = pod_from_json(serde_json::json!({
            "phase": "Running",
            "conditions": [{ "type": "Ready", "status": "False" }]
        }));
        assert_eq!(pod_vm_status(&booting), Some(VmStatus::Stopped));

        let scheduling = pod_from_json(serde_json::json!({ "phase": "Pending" }));
        assert_eq!(pod_vm_status(&scheduling), Some(VmStatus::Pending));

        let dead = pod_from_json(serde_json::json!({ "phase": "Failed" }));
        assert_eq!(pod_vm_status(&dead), Some(VmStatus::Failed));

        let bare = pod_from_json(serde_json::json!({}));
        assert_eq!(pod_vm_status(&bare), None);
    }

    #[test]
    fn transitions_are_guarded() {
        assert_eq!(
            transition(VmStatus::Pending, VmStatus::Running),
            Some(VmStatus::Running)
        );
        assert_eq!(
            transition(VmStatus::Stopped, VmStatus::Running),
            Some(VmStatus::Running)
        );
        assert_eq!(
            transition(VmStatus::Rebasing, VmStatus::Running),
            Some(VmStatus::Running)
        );
        assert_eq!(
            transition(VmStatus::Failed, VmStatus::Running),
            Some(VmStatus::Running)
        );
        assert_eq!(transition(VmStatus::Running, VmStatus::Running), None);
        assert_eq!(
            transition(VmStatus::Running, VmStatus::Stopped),
            Some(VmStatus::Stopped)
        );
        assert_eq!(transition(VmStatus::Pending, VmStatus::Stopped), None);
        assert_eq!(transition(VmStatus::Running, VmStatus::Pending), None);
        assert_eq!(transition(VmStatus::Rebasing, VmStatus::Pending), None);
        assert_eq!(
            transition(VmStatus::Pending, VmStatus::Failed),
            Some(VmStatus::Failed)
        );
        assert_eq!(transition(VmStatus::Failed, VmStatus::Failed), None);
        assert_eq!(transition(VmStatus::Stopped, VmStatus::Failed), None);
    }

    #[test]
    fn startup_sweep_candidates() {
        let now = 10_000;
        assert!(sweep_candidate("running", now, now));
        assert!(sweep_candidate("rebasing", now - 1, now));
        assert!(!sweep_candidate(
            "pending",
            now - PENDING_SWEEP_GRACE_SECS + 1,
            now
        ));
        assert!(sweep_candidate(
            "pending",
            now - PENDING_SWEEP_GRACE_SECS,
            now
        ));
        assert!(!sweep_candidate("pending", now + 60, now));
        assert!(!sweep_candidate("stopped", 0, now));
        assert!(!sweep_candidate("failed", 0, now));
    }

    #[test]
    fn selector_parsing_ignores_garbage() {
        let parsed = parse_pairs("kletka.dev/vm-node=true, other=x");
        assert_eq!(parsed["kletka.dev/vm-node"], "true");
        assert_eq!(parsed["other"], "x");
        assert!(parse_pairs("no-equals-here").is_empty());
    }

    #[test]
    fn guest_overlay_capability_map_parses() {
        let parsed = parse_bool_map("default=true,legacy=false,bad=maybe,missing");
        assert_eq!(
            parsed,
            BTreeMap::from([("default".into(), true), ("legacy".into(), false)])
        );
    }

    #[test]
    fn unknown_guest_image_is_rejected_up_front() {
        let config = config();
        assert_eq!(
            config.agent_image("default").unwrap(),
            "kletka-vm-agent:dev"
        );
        let err = config.agent_image("nope").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("nope"));

        let err = config.guest_image("nope").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("nope"));
        let err = config.guest_image("default").unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST);
        assert!(err.message.contains("<none>"), "{}", err.message);
    }

    #[test]
    fn guest_images_configmap_ref_parses() {
        assert_eq!(
            split_configmap_ref("kletka-system/kletka-guest-images").unwrap(),
            ("kletka-system", "kletka-guest-images")
        );
        assert!(split_configmap_ref("kletka-guest-images").is_err());
        assert!(split_configmap_ref("/name").is_err());
        assert!(split_configmap_ref("ns/").is_err());
    }

    #[test]
    fn data_claim_pins_the_guest_ref() {
        let reference = "localhost:5000/kletka/guest/default:2026-11-17.1";
        let mut claim = build_data_claim(
            &config(),
            &Uuid::new_v4(),
            &Uuid::new_v4(),
            &spec(),
            reference,
        );
        assert_eq!(pinned_ref(&claim).as_deref(), Some(reference));

        claim.metadata.annotations = None;
        assert_eq!(pinned_ref(&claim), None);
        claim.metadata.annotations = Some(BTreeMap::from([(
            GUEST_REF_ANNOTATION.to_string(),
            " ".to_string(),
        )]));
        assert_eq!(pinned_ref(&claim), None);
    }

    #[test]
    fn data_claim_starts_at_disk_size_and_grows_to_a_snapshot_ceiling() {
        let config = config();
        let mut spec = spec();
        spec.disk_mib = 0;

        let claim = build_data_claim(&config, &Uuid::new_v4(), &Uuid::new_v4(), &spec, "g:1");
        let request = &claim.spec.unwrap().resources.unwrap().requests.unwrap()["storage"].0;
        assert_eq!(request, "8192Mi");
        assert_eq!(vm_storage_mib(&config, &spec), 8 * 1024);
        assert_eq!(vm_storage_ceiling_mib(&config, spec.disk_mib), 18 * 1024);
    }

    #[test]
    fn data_claim_reserves_overlay_snapshot_capacity() {
        let config = config();
        let vm_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let claim = build_data_claim(&config, &vm_id, &owner_id, &spec(), "g:1");
        assert_eq!(
            claim.metadata.name.as_deref(),
            Some(data_claim_name(&vm_id).as_str())
        );
        assert_eq!(
            claim.spec.unwrap().resources.unwrap().requests.unwrap()["storage"].0,
            "14336Mi"
        );
        assert_eq!(vm_storage_ceiling_mib(&config, spec().disk_mib), 54 * 1024);
    }

    #[test]
    fn claim_request_mib_parses_storage_quantities() {
        let claim = |quantity: &str| {
            serde_json::from_value::<PersistentVolumeClaim>(serde_json::json!({
                "spec": { "resources": { "requests": { "storage": quantity } } }
            }))
            .unwrap()
        };
        assert_eq!(claim_request_mib(&claim("14336Mi")), Some(14336));
        assert_eq!(claim_request_mib(&claim("66Gi")), Some(67584));
        assert_eq!(claim_request_mib(&claim("1048576Ki")), Some(1024));
        assert_eq!(claim_request_mib(&claim("1073741824")), Some(1024));
        assert_eq!(claim_request_mib(&claim("1Ti")), None);
    }

    #[test]
    fn rebasing_pod_carries_the_rebase_intent() {
        let vm_id = Uuid::new_v4();
        let pod = build_pod(
            &config(),
            &vm_id,
            &Uuid::new_v4(),
            &spec(),
            "kletka-vm-agent:dev",
            "ghcr.io/o/kletka-guest-default:2026-11-14.2",
            PodIntent::Rebase,
        );
        let env = pod.spec.unwrap().containers[0]
            .env
            .as_ref()
            .unwrap()
            .clone();
        assert!(env.iter().any(|value| {
            value.name == "KLETKA_VM_REBASE" && value.value.as_deref() == Some("true")
        }));
        assert!(env.iter().any(|value| {
            value.name == "KLETKA_VM_IMAGE_REF"
                && value.value.as_deref() == Some("ghcr.io/o/kletka-guest-default:2026-11-14.2")
        }));
    }

    #[test]
    fn maintenance_pod_boots_no_guest() {
        let pod = build_pod(
            &config(),
            &Uuid::new_v4(),
            &Uuid::new_v4(),
            &spec(),
            "kletka-vm-agent:dev",
            "ghcr.io/o/kletka-guest-default:2026-11-14.2",
            PodIntent::Maintain,
        );
        let env = pod.spec.unwrap().containers[0]
            .env
            .as_ref()
            .unwrap()
            .clone();
        assert!(env.iter().any(|value| {
            value.name == "KLETKA_VM_AUTOSTART" && value.value.as_deref() == Some("false")
        }));
    }
}
