use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use kletka_types::{
    CreateVmRequest, CreateVmResponse, MAX_VCPUS, MIN_MEMORY_MIB, RebaseVmRequest, ResizeVmRequest,
    Vm, VmSpec, VmStatus, WireguardRequest,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::audit::{self, Event, RequestMeta};
use crate::auth::UserContext;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use kletka_types::NamespaceRole;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct VmRow {
    pub id: String,
    pub namespace_id: String,
    pub created_by: Option<String>,
    pub name: String,
    pub image: String,
    pub vcpu: i64,
    pub memory_mib: i64,
    pub disk_mib: i64,
    pub nat: i64,
    pub status: String,
    pub assigned_node: Option<String>,
    pub created_at: i64,
    pub idle_timeout_secs: Option<i64>,
    pub last_active_at: Option<i64>,
}

fn non_negative(value: i64) -> usize {
    value.max(0) as usize
}

impl VmRow {
    pub fn uuid(&self) -> ApiResult<Uuid> {
        self.id
            .parse()
            .map_err(|_| ApiError::internal("corrupt vm id"))
    }

    pub fn namespace_uuid(&self) -> ApiResult<Uuid> {
        self.namespace_id
            .parse()
            .map_err(|_| ApiError::internal("corrupt namespace id"))
    }

    pub fn label_owner(&self) -> ApiResult<Uuid> {
        match self.created_by.as_deref().and_then(|id| id.parse().ok()) {
            Some(id) => Ok(id),
            None => self.namespace_uuid(),
        }
    }

    pub fn created_by_user(&self, user_id: &Uuid) -> bool {
        self.created_by.as_deref() == Some(user_id.to_string().as_str())
    }

    pub fn spec(&self) -> VmSpec {
        VmSpec {
            name: self.name.clone(),
            image: self.image.clone(),
            vcpu: non_negative(self.vcpu),
            memory_mib: non_negative(self.memory_mib),
            disk_mib: non_negative(self.disk_mib),
            nat: self.nat != 0,
        }
    }

    pub fn is_stopped_or_failed(&self) -> bool {
        matches!(self.status.as_str(), "stopped" | "failed")
    }

    fn reject_if_busy(&self) -> ApiResult<()> {
        match self.status.as_str() {
            "rebasing" => Err(ApiError::conflict("vm rebase is in progress")),
            "cloning" => Err(ApiError::conflict(
                "a clone of this VM is in progress; wait for it to finish",
            )),
            _ => Ok(()),
        }
    }
}

pub(crate) fn default_vm_name(vm_id: &Uuid) -> String {
    format!("vm-{:.8}", vm_id.to_string())
}

pub(crate) async fn list_owned(db: &sqlx::AnyPool, namespace: &Uuid) -> ApiResult<Vec<VmRow>> {
    Ok(
        crate::db::query_as("SELECT * FROM vms WHERE namespace_id = ? ORDER BY created_at")
            .bind(namespace.to_string())
            .fetch_all(db)
            .await?,
    )
}

pub(crate) fn vm_wire(row: &VmRow) -> ApiResult<Vm> {
    let spec = row.spec();
    Ok(Vm {
        id: row.uuid()?,
        name: spec.name,
        image: spec.image,
        vcpu: spec.vcpu,
        memory_mib: spec.memory_mib,
        disk_mib: spec.disk_mib,
        nat: spec.nat,
        status: VmStatus::parse(&row.status)
            .ok_or_else(|| ApiError::internal(format!("unknown vm status {}", row.status)))?,
        assigned_node: row.assigned_node.clone(),
        idle_timeout_secs: crate::idle::effective_timeout_secs(row.idle_timeout_secs),
        idle_timeout_default: row.idle_timeout_secs.is_none(),
        last_active_at: row.last_active_at.map(crate::db::timestamp),
    })
}

#[derive(Debug, Deserialize)]
pub struct UpdateVm {
    #[serde(default, deserialize_with = "present")]
    pub idle_timeout_secs: Option<Option<u64>>,
}

fn present<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

pub use kletka_types::MAX_VM_DISK_MIB as MAX_DISK_MIB;

const JOB_TTL_SECS: i64 = 24 * 60 * 60;

pub(crate) fn vm_spec_from_create(req: &CreateVmRequest, vm_id: &Uuid) -> VmSpec {
    let defaults = VmSpec::default();
    VmSpec {
        name: req
            .name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| default_vm_name(vm_id)),
        image: req.image.clone().unwrap_or(defaults.image),
        vcpu: req.vcpu.unwrap_or(defaults.vcpu),
        memory_mib: req.memory_mib.unwrap_or(defaults.memory_mib),
        disk_mib: req.disk_mib.unwrap_or(defaults.disk_mib),
        nat: req.nat.unwrap_or(defaults.nat),
    }
}

fn validate_wireguard_config(config: &str, nat: bool) -> ApiResult<()> {
    if config.len() > kletka_types::MAX_WIREGUARD_CONFIG_BYTES {
        return Err(ApiError::bad_request(
            "the WireGuard config is too large (max 64 KiB)",
        ));
    }
    if !nat {
        return Err(ApiError::bad_request(
            "WireGuard needs NAT networking; this VM was created without it",
        ));
    }
    if !has_full_tunnel_route(config) {
        return Err(ApiError::bad_request(
            "the WireGuard config must route all traffic through a peer (AllowedIPs = 0.0.0.0/0)",
        ));
    }
    Ok(())
}

fn has_full_tunnel_route(config: &str) -> bool {
    let mut in_peer = false;
    config.lines().any(|line| {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            in_peer = line == "[Peer]";
            return false;
        }
        if !in_peer {
            return false;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        key.trim() == "AllowedIPs"
            && value
                .split(',')
                .any(|network| network.trim() == "0.0.0.0/0")
    })
}

pub(crate) async fn fetch_vm(db: &sqlx::AnyPool, id: &str) -> ApiResult<Option<VmRow>> {
    Ok(crate::db::query_as("SELECT * FROM vms WHERE id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?)
}

pub async fn find_vm(db: &sqlx::AnyPool, user: &UserContext, key: &str) -> ApiResult<VmRow> {
    if key.parse::<Uuid>().is_ok()
        && let Some(row) = fetch_vm(db, key).await?
        && vm_role(db, user, &row).await?.is_some()
    {
        return Ok(row);
    }
    let by_name: Option<VmRow> =
        crate::db::query_as("SELECT * FROM vms WHERE name = ? AND namespace_id = ?")
            .bind(key)
            .bind(user.ns.id.to_string())
            .fetch_optional(db)
            .await?;
    by_name.ok_or_else(|| {
        ApiError::not_found(format!(
            "vm '{key}' not found in namespace '{}'",
            user.ns.name
        ))
    })
}

pub(crate) async fn vm_role(
    db: &sqlx::AnyPool,
    user: &UserContext,
    vm: &VmRow,
) -> ApiResult<Option<NamespaceRole>> {
    if vm.namespace_id == user.ns.id.to_string() {
        return Ok(Some(user.ns.role));
    }
    if user.platform_admin {
        return Ok(Some(NamespaceRole::Owner));
    }
    crate::namespaces::role_of(db, &vm.namespace_id, &user.user_id).await
}

fn idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub(crate) async fn create_vm_and_job(
    state: &AppState,
    user: &UserContext,
    req: &CreateVmRequest,
    idempotency_key: Option<&str>,
    meta: &RequestMeta,
) -> ApiResult<VmRow> {
    let user_id = &user.user_id;
    let namespace = &user.ns.id;
    if let Some(ref key) = idempotency_key {
        let existing: Option<(String, String)> = crate::db::query_as(
            "SELECT vm_id, id FROM jobs WHERE user_id = ? AND idempotency_key = ?",
        )
        .bind(user_id.to_string())
        .bind(key)
        .fetch_optional(&state.db)
        .await?;
        if let Some((vm_id, _job_id)) = existing {
            let vm: VmRow = crate::db::query_as("SELECT * FROM vms WHERE id = ?")
                .bind(&vm_id)
                .fetch_optional(&state.db)
                .await?
                .ok_or_else(|| ApiError::internal("idempotent job points at missing vm"))?;
            if vm.namespace_id != namespace.to_string() {
                return Err(ApiError::conflict(
                    "this idempotency key was already used for a VM in another namespace",
                ));
            }
            return Ok(vm);
        }
    }

    let vm_id = Uuid::new_v4();
    let spec = vm_spec_from_create(req, &vm_id);
    kletka_types::validate_vm_name(&spec.name).map_err(ApiError::bad_request)?;
    let wireguard_config = req
        .wireguard_config
        .as_deref()
        .filter(|config| !config.trim().is_empty());
    if let Some(config) = wireguard_config {
        validate_wireguard_config(config, spec.nat)?;
    }
    for key in &req.ssh_keys {
        kletka_types::validate_ssh_key(key.trim()).map_err(ApiError::bad_request)?;
    }
    let ssh_keys = (!req.ssh_keys.is_empty()).then(|| {
        req.ssh_keys
            .iter()
            .map(|key| key.trim())
            .collect::<Vec<_>>()
            .join("\n")
    });
    if let Some(timeout) = req.idle_timeout_secs {
        crate::idle::validate_timeout(timeout).map_err(ApiError::bad_request)?;
    }

    let images = state.provisioner.pod_images(&spec.image).await?;
    let placement = crate::k8s::pod_name(&vm_id);

    let mut tx = state.db.begin().await?;
    crate::quota::check_tx(&mut tx, namespace, spec.vcpu, spec.memory_mib, true).await?;
    let insert = crate::db::query(
        "INSERT INTO vms (id, namespace_id, created_by, name, image, vcpu, memory_mib, disk_mib, \
         nat, status, assigned_node, created_at, idle_timeout_secs, last_active_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)",
    )
    .bind(vm_id.to_string())
    .bind(namespace.to_string())
    .bind(user_id.to_string())
    .bind(&spec.name)
    .bind(&spec.image)
    .bind(spec.vcpu as i64)
    .bind(spec.memory_mib as i64)
    .bind(spec.disk_mib as i64)
    .bind(i64::from(spec.nat))
    .bind(&placement)
    .bind(crate::db::now())
    .bind(req.idle_timeout_secs.map(|secs| secs as i64))
    .bind(crate::db::now())
    .execute(&mut *tx)
    .await;
    if crate::db::is_unique_violation(&insert) {
        return Err(ApiError::conflict(format!(
            "a vm named '{}' already exists in namespace '{}'",
            spec.name, user.ns.name
        )));
    }
    insert?;

    let job_id = Uuid::new_v4();
    let spec_json = serde_json::to_string(&spec).expect("spec serializes");
    crate::db::query(
        "INSERT INTO jobs (id, vm_id, user_id, kind, spec_json, state, assigned_node, \
         assigned_at, idempotency_key, expires_at, created_at)
         VALUES (?, ?, ?, 'create', ?, 'assigned', ?, ?, ?, ?, ?)",
    )
    .bind(job_id.to_string())
    .bind(vm_id.to_string())
    .bind(user_id.to_string())
    .bind(spec_json)
    .bind(&placement)
    .bind(crate::db::now())
    .bind(idempotency_key)
    .bind(crate::db::now() + JOB_TTL_SECS)
    .bind(crate::db::now())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    if let Err(err) = state
        .provisioner
        .create(
            &vm_id,
            user_id,
            &spec,
            &images,
            wireguard_config,
            ssh_keys.as_deref(),
        )
        .await
    {
        let _ = crate::db::query("UPDATE vms SET status = 'failed' WHERE id = ?")
            .bind(vm_id.to_string())
            .execute(&state.db)
            .await;
        return Err(err);
    }

    let vm = fetch_vm(&state.db, &vm_id.to_string())
        .await?
        .ok_or_else(|| ApiError::conflict("the vm was destroyed while it was being created"))?;
    audit::record(
        &state.db,
        Event::user(*user_id, "vm.create", meta)
            .for_vm(&vm)
            .detail(serde_json::json!({
                "image": spec.image,
                "vcpu": spec.vcpu,
                "memory_mib": spec.memory_mib,
                "disk_mib": spec.disk_mib,
                "nat": spec.nat,
                "wireguard": wireguard_config.is_some(),
                "ssh_keys": req.ssh_keys.len(),
            })),
    )
    .await;
    Ok(vm)
}

pub async fn create(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    headers: HeaderMap,
    Json(req): Json<CreateVmRequest>,
) -> ApiResult<Json<CreateVmResponse>> {
    let key = idempotency_key(&headers);
    let vm = create_vm_and_job(&state, &user, &req, key.as_deref(), &meta).await?;
    Ok(Json(CreateVmResponse { vm: vm_wire(&vm)? }))
}

pub async fn list(State(state): State<AppState>, user: UserContext) -> ApiResult<Json<Vec<Vm>>> {
    list_owned(&state.db, &user.ns.id)
        .await?
        .iter()
        .map(vm_wire)
        .collect::<ApiResult<Vec<_>>>()
        .map(Json)
}

pub async fn show(
    State(state): State<AppState>,
    user: UserContext,
    Path(id): Path<String>,
) -> ApiResult<Json<Vm>> {
    Ok(Json(vm_wire(&find_vm(&state.db, &user, &id).await?)?))
}

pub async fn destroy(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let body = destroy_internal(&state, &user, &id, &meta).await?;
    Ok(Json(body))
}

pub(crate) async fn destroy_internal(
    state: &AppState,
    user: &UserContext,
    id: &str,
    meta: &RequestMeta,
) -> ApiResult<serde_json::Value> {
    let vm = find_vm(&state.db, user, id).await?;
    if !vm.created_by_user(&user.user_id)
        && vm_role(&state.db, user, &vm).await? < Some(NamespaceRole::Admin)
    {
        return Err(ApiError::forbidden(format!(
            "only the creator of '{}' or a namespace admin can destroy it",
            vm.name
        )));
    }
    if vm.status == "rebasing" {
        return Err(ApiError::conflict("vm rebase is in progress"));
    }
    let vm_id = vm.uuid()?;

    crate::db::query("DELETE FROM vms WHERE id = ?")
        .bind(vm_id.to_string())
        .execute(&state.db)
        .await?;
    state.provisioner.destroy(&vm_id).await;
    tracing::info!(vm = %vm.name, "destroyed (k8s objects deleted)");
    audit::record(
        &state.db,
        Event::user(user.user_id, "vm.destroy", meta).for_vm(&vm),
    )
    .await;
    Ok(serde_json::json!({
        "deleted": vm.name,
    }))
}

pub(crate) async fn start_vm(
    state: &AppState,
    user: &UserContext,
    id: &str,
    meta: &RequestMeta,
) -> ApiResult<VmRow> {
    let vm = find_vm(&state.db, user, id).await?;
    vm.reject_if_busy()?;
    match vm.status.as_str() {
        "running" => return Err(ApiError::conflict("vm is already running")),
        "pending" => return Err(ApiError::conflict("vm is already starting")),
        _ => {}
    }
    let vm_id = vm.uuid()?;
    let spec = vm.spec();
    crate::quota::claim_start(
        &state.db,
        &vm.namespace_uuid()?,
        &vm_id,
        spec.vcpu,
        spec.memory_mib,
    )
    .await?;
    if let Err(err) = state
        .provisioner
        .start_vm(&vm_id, &vm.label_owner()?, &spec)
        .await
    {
        let _ = crate::db::query(
            "UPDATE vms SET status = 'failed' WHERE id = ? AND status = 'pending'",
        )
        .bind(vm_id.to_string())
        .execute(&state.db)
        .await;
        return Err(err);
    }
    crate::db::query("UPDATE vms SET last_active_at = ? WHERE id = ?")
        .bind(crate::db::now())
        .bind(vm_id.to_string())
        .execute(&state.db)
        .await?;
    let row: Option<(String,)> = crate::db::query_as("SELECT status FROM vms WHERE id = ?")
        .bind(vm_id.to_string())
        .fetch_optional(&state.db)
        .await?;
    match row.map(|(status,)| status).as_deref() {
        Some("failed") => {
            crate::db::query(
                "UPDATE vms SET status = 'pending' WHERE id = ? AND status = 'failed'",
            )
            .bind(vm_id.to_string())
            .execute(&state.db)
            .await?;
        }
        Some("stopped") => {
            if let Err(err) = state.provisioner.delete_pod(&vm_id).await {
                tracing::warn!(vm = %vm.id, %err, "could not reap the pod of a cancelled start");
            }
        }
        _ => {}
    }
    audit::record(
        &state.db,
        Event::user(user.user_id, "vm.start", meta).for_vm(&vm),
    )
    .await;
    Ok(vm)
}

pub(crate) async fn stop_vm(
    state: &AppState,
    user: &UserContext,
    id: &str,
    meta: &RequestMeta,
) -> ApiResult<VmRow> {
    let vm = find_vm(&state.db, user, id).await?;
    stop_vm_with(state, vm, &user.user_id, StopCause::User(meta)).await
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum StopCause<'a> {
    User(&'a RequestMeta),
    Idle,
}

pub(crate) async fn stop_vm_with(
    state: &AppState,
    vm: VmRow,
    actor: &Uuid,
    cause: StopCause<'_>,
) -> ApiResult<VmRow> {
    vm.reject_if_busy()?;
    let vm_id = vm.uuid()?;
    let was_running = vm.status == "running";
    let was_starting = vm.status == "pending";
    let db = state.db.clone();
    let state = state.clone();
    tokio::spawn(async move {
        if was_running {
            state.provisioner.stop_guest(&vm_id).await?;
            crate::db::query("UPDATE vms SET status = 'stopped' WHERE id = ?")
                .bind(vm_id.to_string())
                .execute(&state.db)
                .await?;
        } else if was_starting {
            crate::db::query(
                "UPDATE vms SET status = 'stopped' WHERE id = ? AND status = 'pending'",
            )
            .bind(vm_id.to_string())
            .execute(&state.db)
            .await?;
        }
        state.provisioner.delete_pod(&vm_id).await
    })
    .await
    .map_err(|err| ApiError::internal(format!("stop task failed: {err}")))??;
    let event = match cause {
        StopCause::User(meta) => Event::user(*actor, "vm.stop", meta),
        StopCause::Idle => {
            Event::system(*actor, "vm.stop").detail(serde_json::json!({ "reason": "idle" }))
        }
    };
    audit::record(&db, event.for_vm(&vm)).await;
    Ok(vm)
}

fn transition_response(vm: &VmRow, op: &str) -> serde_json::Value {
    serde_json::json!({
        "vm": vm.name,
        "transition": op,
    })
}

pub async fn start(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let vm = start_vm(&state, &user, &id, &meta).await?;
    Ok(Json(transition_response(&vm, "start")))
}

pub async fn stop(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let vm = stop_vm(&state, &user, &id, &meta).await?;
    Ok(Json(transition_response(&vm, "stop")))
}

pub async fn update(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Json(req): Json<UpdateVm>,
) -> ApiResult<Json<Vm>> {
    let vm = find_vm(&state.db, &user, &id).await?;
    if let Some(timeout) = req.idle_timeout_secs {
        if let Some(secs) = timeout {
            crate::idle::validate_timeout(secs).map_err(ApiError::bad_request)?;
        }
        crate::db::query("UPDATE vms SET idle_timeout_secs = ?, last_active_at = ? WHERE id = ?")
            .bind(timeout.map(|secs| secs as i64))
            .bind(crate::db::now())
            .bind(&vm.id)
            .execute(&state.db)
            .await?;
        audit::record(
            &state.db,
            Event::user(user.user_id, "vm.configure", &meta)
                .for_vm(&vm)
                .detail(serde_json::json!({ "idle_timeout_secs": timeout })),
        )
        .await;
    }
    Ok(Json(vm_wire(&find_vm(&state.db, &user, &vm.id).await?)?))
}

pub async fn set_wireguard(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Json(req): Json<WireguardRequest>,
) -> ApiResult<Json<Vm>> {
    let vm = find_vm(&state.db, &user, &id).await?;
    if !matches!(vm.status.as_str(), "running" | "stopped" | "failed") {
        return Err(ApiError::conflict(format!(
            "vm '{}' is {}; wait for it to finish its current operation",
            vm.name, vm.status
        )));
    }
    let wireguard_config = req
        .wireguard_config
        .as_deref()
        .filter(|config| !config.trim().is_empty());
    if let Some(config) = wireguard_config {
        validate_wireguard_config(config, vm.spec().nat)?;
    }
    let vm_id = vm.uuid()?;
    state
        .provisioner
        .set_wireguard_config(&vm_id, wireguard_config)
        .await?;
    if vm.status == "running"
        && vm.spec().nat
        && let Err(err) = state
            .provisioner
            .wireguard_rpc(&vm_id, wireguard_config)
            .await
    {
        return Err(ApiError::conflict(format!(
            "WireGuard config was saved, but live apply failed: {err}"
        )));
    }
    audit::record(
        &state.db,
        Event::user(user.user_id, "vm.wireguard", &meta)
            .for_vm(&vm)
            .detail(serde_json::json!({ "configured": wireguard_config.is_some() })),
    )
    .await;
    Ok(Json(vm_wire(&vm)?))
}

pub async fn resize(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Json(req): Json<ResizeVmRequest>,
) -> ApiResult<Json<Vm>> {
    let vm = find_vm(&state.db, &user, &id).await?;
    if !vm.is_stopped_or_failed() {
        return Err(ApiError::conflict(format!(
            "vm '{}' is {}; stop it before resizing",
            vm.name, vm.status
        )));
    }
    let current = vm.spec();
    let vcpu = req.vcpu.unwrap_or(current.vcpu);
    let memory_mib = req.memory_mib.unwrap_or(current.memory_mib);
    let current_disk_mib = current.disk_mib;
    let disk_mib = req.disk_mib.unwrap_or(current_disk_mib);
    if !(1..=MAX_VCPUS).contains(&vcpu) {
        return Err(ApiError::bad_request(format!(
            "vcpu must be between 1 and {MAX_VCPUS}"
        )));
    }
    if memory_mib < MIN_MEMORY_MIB {
        return Err(ApiError::bad_request(format!(
            "memory must be at least {MIN_MEMORY_MIB} MiB"
        )));
    }
    if disk_mib != current_disk_mib
        && (disk_mib < current_disk_mib || disk_mib < crate::k8s::IMAGE_FLOOR_MIB)
    {
        return Err(ApiError::bad_request(format!(
            "disk size must be at least {} MiB — the VM's current size is {} MiB and disks can \
             only grow",
            crate::k8s::IMAGE_FLOOR_MIB.max(current_disk_mib),
            current_disk_mib
        )));
    }
    if disk_mib > MAX_DISK_MIB {
        return Err(ApiError::bad_request(format!(
            "disk size must be at most {MAX_DISK_MIB} MiB"
        )));
    }
    let quotas = crate::quota::quotas(&state.db, &vm.namespace_uuid()?).await?;
    if vcpu > quotas.max_vcpu {
        return Err(ApiError::quota(format!(
            "{vcpu} vCPUs exceed the namespace quota of {}",
            quotas.max_vcpu
        )));
    }
    if memory_mib > quotas.max_mem_mib {
        return Err(ApiError::quota(format!(
            "{memory_mib} MiB of memory exceed the namespace quota of {} MiB",
            quotas.max_mem_mib
        )));
    }

    let vm_id = vm.uuid()?;
    if disk_mib != current_disk_mib {
        let spec = VmSpec {
            disk_mib,
            ..current
        };
        state.provisioner.resize_data_claim(&vm_id, &spec).await?;
    }

    let updated = crate::db::query(
        "UPDATE vms SET vcpu = ?, memory_mib = ?, disk_mib = ? WHERE id = ? AND status IN \
         ('stopped', 'failed')",
    )
    .bind(vcpu as i64)
    .bind(memory_mib as i64)
    .bind(disk_mib as i64)
    .bind(&vm.id)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "vm lifecycle changed while resizing; try again",
        ));
    }
    tracing::info!(
        vm = %vm.name,
        from_vcpu = vm.vcpu,
        to_vcpu = vcpu,
        from_memory_mib = vm.memory_mib,
        to_memory_mib = memory_mib,
        from_disk_mib = vm.disk_mib,
        to_disk_mib = disk_mib,
        "vm resized"
    );
    audit::record(
        &state.db,
        Event::user(user.user_id, "vm.resize", &meta)
            .for_vm(&vm)
            .detail(serde_json::json!({
                "vcpu": vcpu,
                "memory_mib": memory_mib,
                "disk_mib": disk_mib,
                "from_vcpu": vm.vcpu,
                "from_memory_mib": vm.memory_mib,
                "from_disk_mib": vm.disk_mib,
            })),
    )
    .await;
    Ok(Json(vm_wire(&find_vm(&state.db, &user, &vm.id).await?)?))
}

pub async fn rebase(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Json(req): Json<RebaseVmRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let vm = find_vm(&state.db, &user, &id).await?;
    if !vm.is_stopped_or_failed() {
        return Err(ApiError::conflict(format!(
            "vm '{}' is {}; stop it before rebasing",
            vm.name, vm.status
        )));
    }
    let vm_id = vm.uuid()?;
    let image = req
        .image
        .filter(|image| !image.trim().is_empty())
        .unwrap_or_else(|| vm.image.clone());
    let spec = VmSpec {
        image: image.clone(),
        ..vm.spec()
    };

    state.provisioner.validate_rebase(&vm_id, &image).await?;
    let reserved = crate::db::query(
        "UPDATE vms SET image = ?, status = 'rebasing' WHERE id = ? AND status IN ('stopped', 'failed')",
    )
        .bind(&image)
        .bind(vm_id.to_string())
        .execute(&state.db)
        .await?;
    if reserved.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "vm lifecycle changed while preparing rebase",
        ));
    }

    if let Err(err) = state
        .provisioner
        .rebase(&vm_id, &vm.label_owner()?, &spec)
        .await
    {
        let _ = crate::db::query("UPDATE vms SET image = ?, status = 'failed' WHERE id = ?")
            .bind(&vm.image)
            .bind(vm_id.to_string())
            .execute(&state.db)
            .await;
        return Err(err);
    }

    audit::record(
        &state.db,
        Event::user(user.user_id, "vm.rebase", &meta)
            .for_vm(&vm)
            .detail(serde_json::json!({ "from": vm.image, "image": image })),
    )
    .await;
    Ok(Json(serde_json::json!({
        "vm": vm.name,
        "image": image,
        "status": "rebasing",
    })))
}

#[cfg(test)]
mod tests {
    use super::{CreateVmRequest, has_full_tunnel_route, vm_spec_from_create};
    use uuid::Uuid;

    #[test]
    fn wireguard_config_requires_a_full_ipv4_tunnel() {
        assert!(has_full_tunnel_route(
            "[Peer]\nAllowedIPs = 10.0.0.0/8, 0.0.0.0/0\n"
        ));
        assert!(!has_full_tunnel_route("[Peer]\nAllowedIPs = 10.0.0.0/8\n"));
        assert!(!has_full_tunnel_route(
            "[Interface]\nAllowedIPs = 0.0.0.0/0\n"
        ));
    }

    #[test]
    fn wireguard_config_is_not_serialized_into_vm_spec() {
        let req = CreateVmRequest {
            name: Some("vm".to_string()),
            image: None,
            vcpu: None,
            memory_mib: None,
            disk_mib: None,
            nat: None,
            wireguard_config: Some("PrivateKey = private".to_string()),
            idle_timeout_secs: None,
            ssh_keys: vec![],
        };
        let spec = vm_spec_from_create(&req, &Uuid::new_v4());
        let serialized = serde_json::to_string(&spec).unwrap();
        assert!(!serialized.contains("private"));
    }
}
