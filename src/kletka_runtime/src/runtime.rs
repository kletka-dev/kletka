use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use kletka::checkpoint::{CheckpointOperation, CheckpointRecord, CheckpointStore};
use kletka::fsutil::{disk_usage, ext4_size, grow_ext4, thin_copy};
use kletka::host_nat::{GUEST_IFACE, GUEST_IP_BOOT_ARG, allocate_loopback_addr, bring_up};
use kletka::image::{ImageStore, ResolvedImage};
use kletka::name_gen::generate_name;
use kletka::store::{Registry, VmNetworkConfig, VmRecord, VmState};
use kletka::system::KletkaPaths;
use kletka::vmm::firecracker::{FirecrackerVmm, Handle};
use kletka::vmm::{CreateParameters, NetworkConfig};
use kletka_types::VmSpec;

pub use crate::error::{RuntimeError, RuntimeResult};
use serde_json::Value;
use tokio::sync::Mutex;
use uuid::Uuid;

const DEFAULT_BOOT_ARGS: &str =
    "console=ttyS0 quiet audit=0 reboot=k panic=1 pci=off root=/dev/vda rw";

fn boot_config(nat: bool, id: Uuid) -> (String, Option<Vec<NetworkConfig>>) {
    if !nat {
        return (DEFAULT_BOOT_ARGS.to_string(), None);
    }
    let nic = NetworkConfig {
        interface_id: GUEST_IFACE.to_string(),
        host_device_name: "tap0".to_string(),
        guest_mac: Some(guest_mac(id)),
    };
    (
        format!("{DEFAULT_BOOT_ARGS} {GUEST_IP_BOOT_ARG}"),
        Some(vec![nic]),
    )
}

fn guest_mac(id: Uuid) -> String {
    let b = id.as_bytes();
    format!(
        "06:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4]
    )
}

#[derive(Debug, Clone)]
pub struct VmPlan {
    pub record: VmRecord,
    pub params: CreateParameters,
    pub instance_dir: PathBuf,
}

pub struct VmRuntime {
    paths: KletkaPaths,
    registry: Registry,
    vmm: FirecrackerVmm,
    running: Arc<Mutex<HashMap<Uuid, Handle>>>,
    vm_locks: Arc<Mutex<HashMap<Uuid, Arc<Mutex<()>>>>>,
    ssh_readiness: Arc<Mutex<HashMap<Uuid, SshReadiness>>>,
    boot_seq: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SshPhase {
    Waiting,
    Ready,
    GaveUp,
}

#[derive(Debug, Clone, Copy)]
struct SshReadiness {
    seq: u64,
    phase: SshPhase,
}

pub use kletka_types::{MAX_VCPUS, MIN_MEMORY_MIB};

const MIB: u64 = 1024 * 1024;

const SSH_READY_TIMEOUT: Duration = Duration::from_secs(90);

impl VmRuntime {
    pub fn new(paths: KletkaPaths) -> RuntimeResult<Self> {
        paths.ensure().map_err(|err| err.to_string())?;

        let firecracker = resolve_binary("KLETKA_FIRECRACKER", "firecracker");

        if !firecracker.is_file() {
            tracing::warn!(path = %firecracker.display(), "firecracker binary not found; creating vms will fail");
        }

        for binary in [
            "unshare",
            "python3",
            "ip",
            "slirp4netns",
            "ssh-keygen",
            "mkfs.ext4",
        ] {
            if !kletka::system::on_path(binary) {
                tracing::warn!(binary, "binary not found on PATH; creating vms will fail");
            }
        }

        let vmm = FirecrackerVmm::new(firecracker, paths.instances_path());
        let registry = Registry::open(&paths);

        let runtime = Self {
            paths,
            registry,
            vmm,
            running: Arc::new(Mutex::new(HashMap::new())),
            vm_locks: Arc::new(Mutex::new(HashMap::new())),
            ssh_readiness: Arc::new(Mutex::new(HashMap::new())),
            boot_seq: AtomicU64::new(0),
        };
        runtime.reconcile()?;
        Ok(runtime)
    }

    async fn vm_lock(&self, id: Uuid) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self.vm_locks.lock().await.entry(id).or_default().clone();
        lock.lock_owned().await
    }

    async fn locked_vm(
        &self,
        key: &str,
    ) -> RuntimeResult<(tokio::sync::OwnedMutexGuard<()>, VmRecord)> {
        let guard = self.vm_lock(self.find_vm(key)?.id).await;
        Ok((guard, self.find_vm(key)?))
    }

    fn allocate_vsock_cid(&self) -> RuntimeResult<Option<u32>> {
        if !Self::vsock_enabled() {
            return Ok(None);
        }
        self.registry
            .next_vsock_cid()
            .map(Some)
            .map_err(|err| err.to_string().into())
    }

    fn vsock_enabled() -> bool {
        !matches!(
            std::env::var("KLETKA_VSOCK").as_deref(),
            Ok("off" | "false" | "0")
        )
    }

    fn reconcile(&self) -> RuntimeResult<()> {
        let instances_path = self.paths.instances_path();
        let canonical =
            std::fs::canonicalize(&instances_path).unwrap_or_else(|_| instances_path.clone());

        for pid in find_instance_pids(&canonical, None) {
            tracing::warn!(
                pid,
                "reaping orphaned firecracker/slirp process from a previous runtime"
            );
            kletka::system::kill9(pid);
        }

        if let Ok(entries) = std::fs::read_dir(&instances_path) {
            for entry in entries.flatten() {
                let path = entry.path();

                if entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false) {
                    for socket in ["api.sock", "vsock.sock", "slirp.sock"] {
                        let _ = std::fs::remove_file(path.join(socket));
                    }

                    continue;
                }

                tracing::debug!(path = %path.display(), "removing stale file");
                let _ = std::fs::remove_file(&path);
            }
        }

        for mut record in self.registry.list().map_err(|err| err.to_string())? {
            if record.state == VmState::Running {
                tracing::warn!(id = %record.id, name = %record.name, "vm was running when the runtime died; marking stopped");
                record.mark_stopped();
                self.registry
                    .update(record)
                    .map_err(|err| err.to_string())?;
            }
        }

        Ok(())
    }

    async fn reap_orphaned_instance_processes(&self, instance_id: &Uuid) -> RuntimeResult<()> {
        let instances_path = self.paths.instances_path();
        let pids = find_instance_pids(&instances_path, Some(instance_id));
        for pid in pids {
            tracing::warn!(pid, instance = %instance_id, "reaping leaked vm process");
            kletka::system::kill9(pid);
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline
            && !find_instance_pids(&instances_path, Some(instance_id)).is_empty()
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if let Some(pid) = find_instance_pids(&instances_path, Some(instance_id)).first() {
            return Err(format!(
                "could not reap process {pid} for vm '{instance_id}'; refusing to start another vm on its disk"
            ).into());
        }
        Ok(())
    }

    pub fn list_vms(&self) -> RuntimeResult<Vec<VmRecord>> {
        self.registry.list().map_err(|err| err.to_string().into())
    }

    pub fn find_vm(&self, key: &str) -> RuntimeResult<VmRecord> {
        self.registry
            .find(key)
            .map_err(|err| err.to_string())?
            .ok_or_else(|| RuntimeError::VmNotFound(key.to_string()))
    }

    pub async fn guest_ssh_ready(&self, record: &VmRecord) -> bool {
        if record.ssh_addr.is_none() || record.ssh_port.is_none() {
            return true;
        }
        match self.ssh_readiness.lock().await.get(&record.id) {
            Some(entry) => entry.phase != SshPhase::Waiting,
            None => true,
        }
    }

    async fn begin_ssh_wait(&self, id: Uuid) -> u64 {
        let seq = self.boot_seq.fetch_add(1, Ordering::Relaxed) + 1;
        self.ssh_readiness.lock().await.insert(
            id,
            SshReadiness {
                seq,
                phase: SshPhase::Waiting,
            },
        );
        seq
    }

    async fn clear_ssh_readiness(&self, id: Uuid) {
        self.ssh_readiness.lock().await.remove(&id);
    }

    async fn track_ssh_readiness(&self, running: &VmRecord) {
        let (Some(addr), Some(port)) = (&running.ssh_addr, running.ssh_port) else {
            return;
        };
        let Ok(addr) = addr.parse::<std::net::Ipv4Addr>() else {
            return;
        };
        let seq = self.begin_ssh_wait(running.id).await;
        let readiness = Arc::clone(&self.ssh_readiness);
        let id = running.id;
        tokio::spawn(async move {
            let phase = if kletka::host_nat::wait_for_ssh(addr, port, SSH_READY_TIMEOUT)
                .await
                .is_ok()
            {
                SshPhase::Ready
            } else {
                SshPhase::GaveUp
            };
            commit_ssh_phase(&readiness, id, seq, phase).await;
        });
    }

    fn checkpoint_store(&self, record: &VmRecord) -> CheckpointStore {
        CheckpointStore::new(&self.paths.instance_dir(&record.id))
    }

    fn writable_disk_path(&self, record: &VmRecord) -> PathBuf {
        match &record.overlay_path {
            Some(overlay) => overlay.clone(),
            None => self.paths.instance_dir(&record.id).join("rootfs.ext4"),
        }
    }

    pub async fn checkpoint(&self, rpc: CheckpointOperation) -> RuntimeResult<Value> {
        match rpc {
            CheckpointOperation::List(key) => {
                let record = self.find_vm(&key)?;
                let records = self
                    .checkpoint_store(&record)
                    .list()
                    .map_err(|err| err.to_string())?;
                to_json(records)
            }
            CheckpointOperation::Create { vm, name, memory } => {
                self.create_checkpoint(&vm, &name, memory).await
            }
            CheckpointOperation::Delete { vm, name } => {
                let (_guard, record) = self.locked_vm(&vm).await?;
                if !self.checkpoint_store(&record).delete(&name)? {
                    return Err(RuntimeError::CheckpointNotFound(name));
                }

                tracing::info!(
                    id = %record.id,
                    name = %record.name,
                    snapshot = %name,
                    "checkpoint deleted"
                );
                Ok(serde_json::json!({ "deleted": name }))
            }
            CheckpointOperation::Rollback { vm, name } => {
                self.rollback_checkpoint(&vm, &name).await
            }
        }
    }

    async fn create_checkpoint(&self, key: &str, name: &str, memory: bool) -> RuntimeResult<Value> {
        if memory {
            return Err(
                "memory snapshots are not supported yet; create a disk-only snapshot (omit \
                 --memory)"
                    .to_string()
                    .into(),
            );
        }

        let (_guard, record) = self.locked_vm(key).await?;
        if record.state != VmState::Stopped {
            return Err(RuntimeError::not_stopped(
                &record.name,
                "creating a snapshot",
            ));
        }

        let disk = self.writable_disk_path(&record);
        if !disk.is_file() {
            return Err(format!(
                "vm '{}' has no disk to snapshot (it was never started)",
                record.name
            )
            .into());
        }

        let store = self.checkpoint_store(&record);
        let dir = store.create_dir(name)?;
        let disk_copy = store.rootfs_path(name);
        let copy = {
            let from = disk.clone();
            let to = disk_copy.clone();
            tokio::task::spawn_blocking(move || thin_copy(&from, &to)).await
        };
        if let Err(err) = copy {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(format!("cannot snapshot the disk of vm '{}': {err}", record.name).into());
        }

        let checkpoint = CheckpointRecord {
            name: name.to_string(),
            created_at: kletka_types::time::now(),
            size_bytes: disk_usage(&disk_copy).unwrap_or(0),
            with_memory: false,
        };
        if let Some(pruned) = store.insert(checkpoint.clone())? {
            tracing::info!(
                id = %record.id,
                snapshot = %pruned,
                "pruned oldest checkpoint (retention)"
            );
        }

        tracing::info!(
            id = %record.id,
            name = %record.name,
            snapshot = %name,
            "checkpoint created"
        );
        to_json(checkpoint)
    }

    async fn rollback_checkpoint(&self, key: &str, name: &str) -> RuntimeResult<Value> {
        let (_guard, record) = self.locked_vm(key).await?;
        if record.state != VmState::Stopped {
            return Err(RuntimeError::not_stopped(
                &record.name,
                "rolling back to a snapshot",
            ));
        }

        let store = self.checkpoint_store(&record);
        let checkpoint = store
            .get(name)
            .map_err(|err| err.to_string())?
            .ok_or_else(|| RuntimeError::CheckpointNotFound(name.to_string()))?;

        if checkpoint.with_memory {
            return Err(format!(
                "checkpoint '{name}' carries a memory snapshot; memory rollback is not \
                 supported yet"
            )
            .into());
        }

        let disk = self.writable_disk_path(&record);
        let staged = disk.with_extension(format!("rollback-{}", Uuid::new_v4().simple()));
        let copy = {
            let from = store.rootfs_path(name);
            let to = staged.clone();
            tokio::task::spawn_blocking(move || thin_copy(&from, &to)).await
        };
        if let Err(err) = copy {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "cannot restore snapshot '{name}' of vm '{}': {err}",
                record.name
            )
            .into());
        }
        if let Err(err) = std::fs::rename(&staged, &disk) {
            let _ = std::fs::remove_file(&staged);
            return Err(format!(
                "cannot swap the snapshot disk into place for vm '{}': {err}",
                record.name
            )
            .into());
        }

        tracing::info!(
            id = %record.id,
            name = %record.name,
            snapshot = %name,
            "vm rolled back to checkpoint"
        );
        Ok(serde_json::json!({ "rolled_back": name }))
    }

    fn allocate_ssh_addr(&self) -> RuntimeResult<std::net::Ipv4Addr> {
        let used: Vec<String> = self
            .registry
            .list()
            .map_err(|err| err.to_string())?
            .into_iter()
            .filter_map(|record| record.ssh_addr)
            .collect();

        Ok(allocate_loopback_addr(used))
    }

    pub async fn create_vm(
        &self,
        params: VmSpec,
        hostname: Option<&str>,
    ) -> RuntimeResult<VmRecord> {
        self.create_vm_with_wireguard(params, hostname, None, None)
            .await
    }

    pub async fn create_vm_with_wireguard(
        &self,
        params: VmSpec,
        hostname: Option<&str>,
        wireguard_config: Option<&str>,
        authorized_keys: Option<&str>,
    ) -> RuntimeResult<VmRecord> {
        let mut name = params.name.trim().to_string();

        if name.is_empty() {
            loop {
                name = generate_name();
                let taken = self
                    .registry
                    .find(&name)
                    .map_err(|err| err.to_string())?
                    .is_some();

                if !taken {
                    break;
                }
            }
        }

        if self
            .registry
            .find(&name)
            .map_err(|err| err.to_string())?
            .is_some()
        {
            return Err(format!("a vm named '{name}' already exists").into());
        }

        let image = if params.image.trim().is_empty() {
            "default".to_string()
        } else {
            params.image.trim().to_string()
        };

        let image_store = ImageStore::new(self.paths.images_path());
        let resolved = image_store.resolve(&image).map_err(|err| {
            format!(
                "{err}; ask the control plane to publish a guest image \
                 (the in-cluster image builder does this), or install one \
                 with `kletka image import`"
            )
        })?;

        let vsock_cid = self.allocate_vsock_cid()?;

        let plan = self.plan_vm(&params, &name, &image, &resolved, vsock_cid)?;
        let record = plan.record;
        let instance_dir = plan.instance_dir;

        self.registry
            .insert(record.clone())
            .map_err(|err| err.to_string())?;

        let hostname = hostname
            .map(str::trim)
            .filter(|hostname| !hostname.is_empty())
            .unwrap_or(&name);
        match self
            .launch(
                &record,
                plan.params,
                hostname,
                wireguard_config,
                authorized_keys,
            )
            .await
        {
            Ok(running) => {
                tracing::info!(id = %record.id, name = %record.name, cid = vsock_cid, "vm created and started");
                Ok(running)
            }
            Err(err) => {
                let _ = self.registry.remove(record.id);
                let _ = std::fs::remove_dir_all(&instance_dir);
                Err(err)
            }
        }
    }

    async fn launch(
        &self,
        record: &VmRecord,
        mut params: CreateParameters,
        hostname: &str,
        wireguard_config: Option<&str>,
        authorized_keys: Option<&str>,
    ) -> RuntimeResult<VmRecord> {
        let instance_dir = self.paths.instance_dir(&record.id);
        std::fs::create_dir_all(&instance_dir)
            .map_err(|err| format!("cannot create instance dir: {err}"))?;

        let ssh_addr = record
            .ssh_addr
            .as_deref()
            .map(str::parse::<std::net::Ipv4Addr>)
            .transpose()
            .map_err(|err| format!("vm '{}' has an invalid ssh address: {err}", record.name))?;
        if ssh_addr.is_some() {
            let dir = instance_dir.clone();
            let hostname = hostname.to_string();
            let wireguard = wireguard_config.map(str::to_string);
            let keys = authorized_keys.map(str::to_string);
            let seed = tokio::task::spawn_blocking(move || {
                build_seed_image_with_wireguard(
                    &dir,
                    &hostname,
                    wireguard.as_deref(),
                    keys.as_deref(),
                )
            })
            .await
            .map_err(|err| format!("seed build task failed: {err}"))??;
            params.seed_path = Some(seed);
        }

        let mut handle = self
            .vmm
            .create(&params)
            .await
            .map_err(|err| format!("failed to start vm '{}': {err}", record.name))?;

        let cp_dir = instance_dir.clone();
        match tokio::task::spawn_blocking(move || build_checkpoints_img(&cp_dir)).await {
            Ok(Ok(img)) => handle.params.checkpoints_path = Some(img),
            Ok(Err(err)) => tracing::warn!(%err, "checkpoint exposure image not attached"),
            Err(err) => tracing::warn!(%err, "checkpoint exposure build task panicked"),
        }

        if let Err(err) = self.vmm.start(handle.clone()).await {
            let _ = self.vmm.stop(handle).await;
            return Err(format!("failed to start vm '{}': {err}", record.name).into());
        }

        let mut ssh_port = None;
        if let Some(ssh_addr) = ssh_addr {
            match bring_up(handle.pid, &instance_dir, ssh_addr).await {
                Ok((slirp_pid, host_port)) => {
                    handle.slirp_pid = Some(slirp_pid);
                    ssh_port = Some(host_port);
                }
                Err(err) => {
                    let _ = self.vmm.stop(handle).await;
                    return Err(format!(
                        "failed to set up networking for '{}': {err}",
                        record.name
                    )
                    .into());
                }
            }
        }

        let mut running = record.clone();
        running.state = VmState::Running;
        running.fc_pid = Some(handle.pid);
        running.slirp_pid = handle.slirp_pid;
        running.ssh_port = ssh_port;

        self.track_ssh_readiness(&running).await;
        self.registry
            .update(running.clone())
            .map_err(|err| err.to_string())?;
        self.running.lock().await.insert(record.id, handle.clone());
        self.spawn_exit_watch(&running, &handle);

        Ok(running)
    }

    fn spawn_exit_watch(&self, running: &VmRecord, handle: &Handle) {
        let registry = self.registry.clone();
        let running_map = Arc::clone(&self.running);
        let vm_locks = Arc::clone(&self.vm_locks);
        let id = running.id;
        let pid = handle.pid;
        let mut exit = handle.exit.clone();
        tokio::spawn(async move {
            let _ = exit.changed().await;
            let lock = vm_locks.lock().await.entry(id).or_default().clone();
            let _guard = lock.lock_owned().await;
            let mut map = running_map.lock().await;
            if map.get(&id).is_some_and(|h| h.pid == pid) {
                map.remove(&id);
            }
            drop(map);
            if let Ok(Some(record)) = registry.find(&id.to_string())
                && record.state == VmState::Running
                && record.fc_pid == Some(pid)
            {
                let mut stopped = record;
                stopped.mark_stopped();
                match registry.update(stopped) {
                    Ok(()) => {
                        tracing::warn!(id = %id, pid, "vm process exited; state converged to stopped")
                    }
                    Err(err) => {
                        tracing::warn!(id = %id, %err, "vm process exited; state write failed")
                    }
                }
            }
        });
    }

    fn plan_vm(
        &self,
        params: &VmSpec,
        name: &str,
        image: &str,
        resolved: &ResolvedImage,
        vsock_cid: Option<u32>,
    ) -> RuntimeResult<VmPlan> {
        let id = Uuid::new_v4();
        let instance_dir = self.paths.instance_dir(&id);

        let image_fs_bytes = ext4_size(&resolved.rootfs_path).map_err(|err| {
            format!(
                "cannot read filesystem size of {}: {err}",
                resolved.rootfs_path.display()
            )
        })?;
        let disk_bytes = if params.disk_mib == 0 {
            None
        } else {
            let mib = u64::try_from(params.disk_mib).unwrap_or(u64::MAX);
            match mib.checked_mul(MIB) {
                Some(bytes) => Some(bytes),
                None => return Err(format!("disk size {mib}M is too large").into()),
            }
        };

        if let Some(target) = disk_bytes
            && target < image_fs_bytes
        {
            return Err(format!(
                "disk size {}M is smaller than the '{image}' image filesystem ({}M); disks can \
                 only grow, not shrink",
                params.disk_mib,
                image_fs_bytes.div_ceil(MIB)
            )
            .into());
        }

        let disk_mib = match disk_bytes {
            Some(bytes) => (bytes / MIB) as usize,
            None => (image_fs_bytes.div_ceil(MIB)) as usize,
        };

        let ssh_addr = if params.nat {
            Some(self.allocate_ssh_addr()?)
        } else {
            None
        };

        let (boot_args, network) = boot_config(params.nat, id);

        let overlay_path = resolved
            .overlay_boot()
            .then(|| instance_dir.join("overlay.ext4"));

        let record = VmRecord {
            id,
            name: name.to_string(),
            image: image.to_string(),
            state: VmState::Stopped,
            kernel_path: resolved.kernel_path.clone(),
            rootfs_path: resolved.rootfs_path.clone(),
            overlay_path: overlay_path.clone(),
            vsock_cid,
            network: Some(VmNetworkConfig { nat: params.nat }),
            fc_pid: None,
            slirp_pid: None,
            ssh_addr: ssh_addr.map(|addr| addr.to_string()),
            ssh_port: None,
            vcpu_count: params.vcpu.clamp(1, MAX_VCPUS) as u8,
            memory_mib: params.memory_mib,
            disk_mib,
            created_at: kletka_types::time::now(),
        };

        let create_parameters = CreateParameters {
            id,
            kernel_path: resolved.kernel_path.clone(),
            rootfs_path: resolved.rootfs_path.clone(),
            overlay_path,
            disk_bytes,
            vsock: vsock_cid.map(|cid| (instance_dir.join("vsock.sock"), cid)),
            seed_path: None,
            checkpoints_path: None,
            boot_args: Some(boot_args),
            network,
            memory_mb: params.memory_mib,
            vcpu_count: record.vcpu_count,
        };

        Ok(VmPlan {
            record,
            params: create_parameters,
            instance_dir,
        })
    }

    pub async fn start_vm(&self, key: &str) -> RuntimeResult<Value> {
        self.start_vm_with_wireguard(key, None, None, None).await
    }

    pub async fn start_vm_with_wireguard(
        &self,
        key: &str,
        hostname: Option<&str>,
        wireguard_config: Option<&str>,
        authorized_keys: Option<&str>,
    ) -> RuntimeResult<Value> {
        let (_guard, record) = self.locked_vm(key).await?;

        if self.running.lock().await.contains_key(&record.id) {
            return to_json(record);
        }

        self.reap_orphaned_instance_processes(&record.id).await?;

        let instance_dir = self.paths.instance_dir(&record.id);
        let staged_or = |staged: PathBuf, source: &Path| {
            if staged.is_file() || !source.is_file() {
                staged
            } else {
                source.to_path_buf()
            }
        };
        let kernel_path = staged_or(instance_dir.join("kernel"), &record.kernel_path);
        let rootfs_path = staged_or(instance_dir.join("rootfs.ext4"), &record.rootfs_path);

        let nat = record.nat();
        if nat && record.ssh_addr.is_none() {
            return Err(format!("vm '{}' has NAT but no ssh address", record.name).into());
        }
        let (boot_args, network) = boot_config(nat, record.id);

        let vsock_cid = match record.vsock_cid {
            Some(cid) => Some(cid),
            None => self.allocate_vsock_cid()?,
        };

        let params = CreateParameters {
            id: record.id,
            kernel_path,
            rootfs_path,
            overlay_path: record.overlay_path.clone(),
            disk_bytes: None,
            vsock: vsock_cid.map(|cid| (instance_dir.join("vsock.sock"), cid)),
            seed_path: None,
            checkpoints_path: None,
            boot_args: Some(boot_args),
            network,
            memory_mb: record.memory_mib,
            vcpu_count: record.vcpu_count,
        };

        let hostname = hostname.unwrap_or(&record.name);
        let running = self
            .launch(&record, params, hostname, wireguard_config, authorized_keys)
            .await?;
        tracing::info!(id = %record.id, name = %record.name, "vm started");
        to_json(running)
    }

    pub async fn stop_vm(&self, key: &str) -> RuntimeResult<Value> {
        let (_guard, record) = self.locked_vm(key).await?;

        let handle = self.running.lock().await.remove(&record.id);
        if let Some(handle) = handle {
            tracing::info!(id = %record.id, "stopping vm");

            guest_poweroff_impl(&record, &self.paths.instances_path()).await;

            if let Err(err) = self.vmm.stop(handle.clone()).await {
                let name = record.name.clone();
                if self
                    .reap_orphaned_instance_processes(&record.id)
                    .await
                    .is_err()
                {
                    self.running.lock().await.insert(record.id, handle);
                    return Err(format!("failed to stop vm '{name}': {err}").into());
                }
                tracing::warn!(id = %record.id, %err, "vm did not stop cleanly; force-killed");
            }
        } else {
            self.reap_orphaned_instance_processes(&record.id).await?;
        }

        let mut stopped = record.clone();
        stopped.mark_stopped();
        self.clear_ssh_readiness(record.id).await;
        self.registry
            .update(stopped.clone())
            .map_err(|err| err.to_string())?;

        to_json(stopped)
    }

    pub async fn delete_vm(&self, key: &str) -> RuntimeResult<Value> {
        let (_guard, record) = self.locked_vm(key).await?;

        let handle = self.running.lock().await.remove(&record.id);
        if let Some(handle) = handle {
            tracing::info!(id = %record.id, "stopping vm before delete");

            if let Err(err) = self.vmm.stop(handle).await {
                tracing::warn!(id = %record.id, %err, "vm did not stop cleanly; reaping before delete");
                self.reap_orphaned_instance_processes(&record.id).await?;
            }
        } else {
            self.reap_orphaned_instance_processes(&record.id).await?;
        }
        self.clear_ssh_readiness(record.id).await;

        self.registry
            .remove(record.id)
            .map_err(|err| err.to_string())?;

        let _ = std::fs::remove_dir_all(self.paths.instance_dir(&record.id));

        tracing::info!(id = %record.id, name = %record.name, "vm deleted");

        to_json(record)
    }

    pub fn resize_vm(&self, key: &str, vcpu: usize, memory_mib: usize) -> RuntimeResult<Value> {
        let record = self.find_vm(key)?;
        if record.state != VmState::Stopped {
            return Err(RuntimeError::not_stopped(&record.name, "resizing"));
        }
        let vcpu_count = (1..=MAX_VCPUS)
            .contains(&vcpu)
            .then_some(vcpu as u8)
            .ok_or_else(|| format!("vcpu count must be between 1 and {MAX_VCPUS}"))?;
        if memory_mib < MIN_MEMORY_MIB {
            return Err(format!("memory must be at least {MIN_MEMORY_MIB} MiB").into());
        }

        let mut resized = record.clone();
        resized.vcpu_count = vcpu_count;
        resized.memory_mib = memory_mib;
        self.registry
            .update(resized.clone())
            .map_err(|err| err.to_string())?;
        tracing::info!(
            id = %record.id,
            name = %record.name,
            from_vcpu = record.vcpu_count,
            to_vcpu = vcpu_count,
            from_memory_mib = record.memory_mib,
            to_memory_mib = memory_mib,
            "vm resized"
        );
        to_json(resized)
    }

    pub fn grow_disk(&self, key: &str, disk_mib: usize) -> RuntimeResult<Value> {
        let record = self.find_vm(key)?;
        if record.state != VmState::Stopped {
            return Err(RuntimeError::not_stopped(&record.name, "resizing its disk"));
        }
        if disk_mib == 0 || disk_mib == record.disk_mib {
            return to_json(record);
        }
        if disk_mib < record.disk_mib {
            return Err(format!(
                "disk size {disk_mib}M is below the VM's current {}M; disks can only grow",
                record.disk_mib
            )
            .into());
        }
        let target = u64::try_from(disk_mib)
            .ok()
            .and_then(|mib| mib.checked_mul(MIB))
            .ok_or_else(|| format!("disk size {disk_mib}M is too large"))?;
        let path = record
            .overlay_path
            .clone()
            .unwrap_or_else(|| record.rootfs_path.clone());
        grow_ext4(&path, target).map_err(|err| format!("cannot grow the vm disk: {err}"))?;
        let mut resized = record.clone();
        resized.disk_mib = disk_mib;
        self.registry
            .update(resized.clone())
            .map_err(|err| err.to_string())?;
        tracing::info!(
            id = %record.id,
            name = %record.name,
            from_disk_mib = record.disk_mib,
            to_disk_mib = disk_mib,
            path = %path.display(),
            "vm disk grown"
        );
        to_json(resized)
    }

    pub async fn rebase_vm(&self, key: &str, image: Option<&str>) -> RuntimeResult<Value> {
        let (_guard, record) = self.locked_vm(key).await?;

        if record.state != VmState::Stopped {
            return Err(format!(
                "vm '{}' is {}; stop it before rebasing",
                record.name,
                record.state.as_str()
            )
            .into());
        }
        if record.overlay_path.is_none() {
            return Err(format!(
                "vm '{}' has no CoW overlay; rebasing requires an overlay-enabled image",
                record.name
            )
            .into());
        }

        let image_name = image
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .unwrap_or(&record.image);

        let image_store = ImageStore::new(self.paths.images_path());
        let resolved = image_store.resolve(image_name).map_err(|err| {
            format!(
                "cannot resolve image '{image_name}' for vm '{}': {err}",
                record.name
            )
        })?;

        if !resolved.overlay_boot() {
            return Err(format!(
                "image '{image_name}' does not support overlay boot (its manifest lacks \
                 overlay_boot); rebasing vm '{}' onto it would drop its disk state",
                record.name
            )
            .into());
        }
        let overlay_path = record
            .overlay_path
            .as_ref()
            .ok_or_else(|| format!("vm '{}' has no CoW overlay", record.name))?;
        let image_size = ext4_size(&resolved.rootfs_path)
            .map_err(|err| format!("cannot inspect rebased image: {err}"))?;
        let overlay_size =
            ext4_size(overlay_path).map_err(|err| format!("cannot inspect vm overlay: {err}"))?;
        if image_size > overlay_size {
            let path = overlay_path.to_path_buf();
            tokio::task::spawn_blocking(move || grow_ext4(&path, image_size))
                .await
                .map_err(|err| format!("grow task: {err}"))?
                .map_err(|err| format!("cannot grow vm overlay for rebased image: {err}"))?;
        }
        let staged_kernel = self.paths.instance_dir(&record.id).join("kernel");
        if staged_kernel.exists() {
            std::fs::remove_file(&staged_kernel)
                .map_err(|err| format!("cannot remove old staged kernel: {err}"))?;
        }

        let mut rebased = record.clone();
        rebased.image = image_name.to_string();
        rebased.kernel_path = resolved.kernel_path;
        rebased.rootfs_path = resolved.rootfs_path;
        rebased.disk_mib = rebased
            .disk_mib
            .max(usize::try_from(image_size.div_ceil(MIB)).unwrap_or(usize::MAX));

        self.registry
            .update(rebased.clone())
            .map_err(|err| err.to_string())?;

        tracing::info!(
            id = %record.id,
            name = %record.name,
            image = %rebased.image,
            version = ?resolved.version,
            "vm rebased onto new image version"
        );

        to_json(rebased)
    }
}

fn to_json(value: impl serde::Serialize) -> RuntimeResult<Value> {
    serde_json::to_value(value).map_err(|err| err.to_string().into())
}

fn build_seed_image_with_wireguard(
    instance_dir: &Path,
    hostname: &str,
    wireguard_config: Option<&str>,
    authorized_keys: Option<&str>,
) -> Result<PathBuf, String> {
    let hostname = sanitize_hostname(hostname);
    let key_path = instance_dir.join("ssh_key");
    let pub_path = instance_dir.join("ssh_key.pub");

    if !key_path.is_file() || !pub_path.is_file() {
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&pub_path);
        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-q", "-N", "", "-C"])
            .arg(format!("kletka-{hostname}"))
            .args(["-f"])
            .arg(&key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("cannot run ssh-keygen: {err}"))?;

        if !status.success() {
            return Err("ssh-keygen failed to create the vm keypair".into());
        }
    }

    let public_key = std::fs::read_to_string(&pub_path)
        .map_err(|err| format!("cannot read the vm ssh public key: {err}"))?;

    let mut keys = public_key.trim_end().to_string();
    if let Some(extra) = authorized_keys
        .map(str::trim)
        .filter(|keys| !keys.is_empty())
    {
        keys.push('\n');
        keys.push_str(extra);
    }
    keys.push('\n');

    let seed_ext4 = instance_dir.join("seed.ext4");
    let seed_dir = instance_dir.join("seed.d");
    let _ = std::fs::remove_file(&seed_ext4);
    std::fs::create_dir_all(&seed_dir).map_err(|err| format!("cannot create seed dir: {err}"))?;

    std::fs::write(seed_dir.join("authorized_keys"), keys)
        .map_err(|err| format!("cannot write authorized_keys: {err}"))?;
    std::fs::write(seed_dir.join("hostname"), format!("{hostname}\n"))
        .map_err(|err| format!("cannot write hostname: {err}"))?;
    let path = seed_dir.join("wireguard.conf");
    std::fs::write(&path, wireguard_config.unwrap_or_default())
        .map_err(|err| format!("cannot write WireGuard config: {err}"))?;
    let mut permissions = std::fs::metadata(&path)
        .map_err(|err| format!("cannot inspect WireGuard config: {err}"))?
        .permissions();
    use std::os::unix::fs::PermissionsExt as _;
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)
        .map_err(|err| format!("cannot protect WireGuard config: {err}"))?;

    pack_dir_into_ext4(&seed_dir, &seed_ext4, "kletka-seed")?;

    Ok(seed_ext4)
}

fn build_checkpoints_img(instance_dir: &Path) -> Result<PathBuf, String> {
    let store = CheckpointStore::new(instance_dir);
    let img = instance_dir.join("checkpoints.img");
    let staging = instance_dir.join("checkpoints.d");
    let _ = std::fs::remove_file(&img);
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(|err| err.to_string())?;

    for cp in store.list().map_err(|err| err.to_string())? {
        let dir = staging.join(&cp.name);
        std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
        let meta = serde_json::to_string_pretty(&cp).map_err(|err| err.to_string())?;
        std::fs::write(dir.join("meta.json"), meta).map_err(|err| err.to_string())?;
    }

    pack_dir_into_ext4(&staging, &img, "kletka-checkpts")?;

    Ok(img)
}

fn pack_dir_into_ext4(dir: &Path, img: &Path, label: &str) -> Result<(), String> {
    let file =
        std::fs::File::create(img).map_err(|err| format!("cannot create {label} image: {err}"))?;
    file.set_len(4 * 1024 * 1024)
        .map_err(|err| format!("cannot size {label} image: {err}"))?;
    drop(file);

    let status = Command::new("mkfs.ext4")
        .args(["-q", "-F", "-L", label, "-d"])
        .arg(dir)
        .arg(img)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("cannot run mkfs.ext4: {err}"))?;

    let _ = std::fs::remove_dir_all(dir);

    if !status.success() {
        return Err(format!("mkfs.ext4 failed for {}", img.display()));
    }

    Ok(())
}

async fn commit_ssh_phase(
    readiness: &Mutex<HashMap<Uuid, SshReadiness>>,
    id: Uuid,
    seq: u64,
    phase: SshPhase,
) {
    let mut map = readiness.lock().await;
    if let Some(entry) = map.get_mut(&id)
        && entry.seq == seq
    {
        entry.phase = phase;
    }
}

fn sanitize_hostname(raw: &str) -> String {
    let collapsed: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();

    let trimmed = collapsed.trim_matches('-');
    let truncated = trimmed.chars().take(63).collect::<String>();
    let hostname = truncated.trim_end_matches('-');

    if hostname.is_empty() {
        "kletka".to_string()
    } else {
        hostname.to_string()
    }
}

async fn guest_poweroff_impl(record: &VmRecord, instances_path: &Path) {
    guest_ssh_impl(
        record,
        instances_path,
        "sudo systemctl reboot -i",
        Duration::from_secs(5),
    )
    .await;
}

async fn guest_ssh_impl(
    record: &VmRecord,
    instances_path: &Path,
    command: &str,
    timeout: Duration,
) {
    let (Some(ssh_addr), Some(port)) = (&record.ssh_addr, record.ssh_port) else {
        return;
    };

    let key = instances_path.join(record.id.to_string()).join("ssh_key");
    if !key.is_file() {
        return;
    }

    let mut cmd = tokio::process::Command::new("ssh");
    cmd.args(kletka::guest::ssh_common_args(&key, port, 2, 1))
        .arg(format!("user@{ssh_addr}"))
        .arg(command)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let _ = tokio::time::timeout(timeout, cmd.output()).await;
}

fn resolve_binary(env_var: &str, name: &str) -> PathBuf {
    std::env::var_os(env_var)
        .map(PathBuf::from)
        .or_else(|| kletka::system::which(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

fn find_instance_pids(instances_path: &Path, instance_id: Option<&Uuid>) -> Vec<u32> {
    let scope = instance_id.map(|id| instances_path.join(id.to_string()));
    let mut pids = Vec::new();

    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return pids,
    };

    for entry in entries.flatten() {
        let Some(file_name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };

        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };

        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };

        let args: Vec<String> = cmdline
            .split(|byte| *byte == 0)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .collect();

        let is_self = pid == std::process::id();
        let is_orphan = !is_self
            && args.iter().any(|arg| match &scope {
                Some(dir) => Path::new(arg).starts_with(dir),
                None => Path::new(arg).starts_with(instances_path),
            });

        if is_orphan {
            pids.push(pid);
        }
    }

    pids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;

    fn make_image(paths: &KletkaPaths, name: &str, version: &str, overlay_boot: bool) -> PathBuf {
        use kletka::image::{
            ArtifactInfo, ImageArtifacts, ImageManifest, ImageStore, MANIFEST_SCHEMA, ROOTFS_FILE,
        };

        let store = ImageStore::new(paths.images_path());
        let dir = store.root().join(name).join("versions").join(version);
        std::fs::create_dir_all(&dir).unwrap();

        std::fs::write(dir.join("vmlinux"), b"fake-kernel").unwrap();

        let rootfs = dir.join(ROOTFS_FILE);
        let file = std::fs::File::create(&rootfs).unwrap();
        file.set_len(16 * 1024 * 1024).unwrap();
        drop(file);
        let status = std::process::Command::new("mkfs.ext4")
            .args(["-q", "-F"])
            .arg(&rootfs)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mkfs.ext4 unavailable in test env");

        let manifest = ImageManifest {
            schema: MANIFEST_SCHEMA,
            name: name.to_string(),
            version: version.to_string(),
            created_at: kletka_types::time::Timestamp::UNIX_EPOCH,
            parent: None,
            source: kletka::image::ImageSource {
                git_sha: None,
                git_dirty: false,
                dockerfile: "docker/rootfs/Dockerfile".to_string(),
                dockerfile_sha256: "deadbeef".to_string(),
                base_image: None,
                updated: false,
                kernel_reused_from: None,
                rootfs_reused_from: None,
                embedded_version: None,
                kernel_inputs_sha256: None,
            },
            artifacts: ImageArtifacts {
                kernel: ArtifactInfo {
                    file: "vmlinux".to_string(),
                    size_bytes: 11,
                    sha256: kletka::image::sha256_file(&dir.join("vmlinux")).unwrap(),
                    used_bytes: Some(11),
                    fs_bytes: None,
                },
                kernel_config: None,
                rootfs: ArtifactInfo {
                    file: ROOTFS_FILE.to_string(),
                    size_bytes: 16 * 1024 * 1024,
                    sha256: kletka::image::sha256_file(&rootfs).unwrap(),
                    used_bytes: Some(16 * 1024 * 1024),
                    fs_bytes: Some(16 * 1024 * 1024),
                },
            },
            overlay_boot,
            labels: Default::default(),
        };
        kletka::image::write_manifest(&dir, &manifest).unwrap();
        store.set_current(name, version).unwrap();

        dir
    }

    async fn test_runtime(dir: &TempDir) -> VmRuntime {
        let paths = KletkaPaths::with_data_dir(dir.path());
        VmRuntime::new(paths).unwrap()
    }

    async fn running_nat_vm(paths: &KletkaPaths) -> VmRecord {
        let mut record = insert_vm(paths, "calm-fox", true).await;
        record.state = VmState::Running;
        record.ssh_addr = Some("127.42.0.2".into());
        record.ssh_port = Some(20_002);
        Registry::open(paths).update(record.clone()).unwrap();
        record
    }

    #[tokio::test]
    async fn ssh_readiness_tracks_boots_and_guards_stale_waiters() {
        let dir = TempDir::new("runtime-ssh-readiness");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let record = running_nat_vm(&paths).await;

        let first = runtime.begin_ssh_wait(record.id).await;
        assert!(!runtime.guest_ssh_ready(&record).await);

        commit_ssh_phase(&runtime.ssh_readiness, record.id, first, SshPhase::Ready).await;
        assert!(runtime.guest_ssh_ready(&record).await);

        let second = runtime.begin_ssh_wait(record.id).await;
        assert_ne!(first, second);
        assert!(!runtime.guest_ssh_ready(&record).await);

        commit_ssh_phase(&runtime.ssh_readiness, record.id, first, SshPhase::Ready).await;
        assert!(
            !runtime.guest_ssh_ready(&record).await,
            "a stale waiter must not ready a newer boot"
        );

        commit_ssh_phase(&runtime.ssh_readiness, record.id, second, SshPhase::GaveUp).await;
        assert!(
            runtime.guest_ssh_ready(&record).await,
            "a gave-up boot is ready: the console is the rescue path"
        );

        runtime.clear_ssh_readiness(record.id).await;
        assert!(
            runtime.guest_ssh_ready(&record).await,
            "a cleared entry falls back to the record's own state"
        );
    }

    #[tokio::test]
    async fn ssh_readiness_is_trivial_without_nat() {
        let dir = TempDir::new("runtime-ssh-no-nat");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let record = insert_vm(&paths, "bold-ox", true).await;
        assert!(runtime.guest_ssh_ready(&record).await);
    }

    #[test]
    fn instance_pid_scan_is_scoped() {
        let dir = TempDir::new("instance-scan");
        let instances = dir.path().join("instances");
        let mine = instances.join("11111111-1111-1111-1111-111111111111");
        let other = instances.join("22222222-2222-2222-2222-222222222222");
        std::fs::create_dir_all(&mine).unwrap();
        std::fs::create_dir_all(&other).unwrap();

        std::fs::write(mine.join("api.sock"), b"").unwrap();
        std::fs::write(other.join("api.sock"), b"").unwrap();
        let mut mine_child = std::process::Command::new("tail")
            .arg("-f")
            .arg(mine.join("api.sock"))
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut other_child = std::process::Command::new("tail")
            .arg("-f")
            .arg(other.join("api.sock"))
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let id: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let found = find_instance_pids(&instances, Some(&id));
        assert!(
            found.contains(&mine_child.id()),
            "own instance must match: {found:?}"
        );
        assert!(
            !found.contains(&other_child.id()),
            "another instance must not match: {found:?}"
        );

        let all = find_instance_pids(&instances, None);
        assert!(all.contains(&mine_child.id()) && all.contains(&other_child.id()));

        let outside_flag = dir.path().join("plain.flag");
        std::fs::write(&outside_flag, b"").unwrap();
        let mut outside = std::process::Command::new("tail")
            .arg("-f")
            .arg(&outside_flag)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!find_instance_pids(&instances, Some(&id)).contains(&outside.id()));

        let _ = mine_child.kill();
        let _ = mine_child.wait();
        let _ = other_child.kill();
        let _ = other_child.wait();
        let _ = outside.kill();
        let _ = outside.wait();
    }

    #[tokio::test]
    async fn plan_vm_overlay_mode_sets_record_fields() {
        let dir = TempDir::new("runtime-plan-overlay");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let base = make_image(&paths, "default", "2026-11-16.1", true);

        let resolved = ImageStore::new(paths.images_path())
            .resolve("default")
            .unwrap();
        assert!(resolved.overlay_boot());

        let params = VmSpec {
            name: "calm-fox".into(),
            image: "default".into(),
            disk_mib: 64,
            ..VmSpec::default()
        };
        let plan = runtime
            .plan_vm(&params, "calm-fox", "default", &resolved, Some(3))
            .unwrap();

        let expected_overlay = plan.instance_dir.join("overlay.ext4");
        assert_eq!(plan.record.overlay_path, Some(expected_overlay.clone()));
        assert_eq!(plan.record.rootfs_path, base.join("rootfs.ext4"));
        assert_eq!(plan.params.overlay_path, Some(expected_overlay));
        assert_eq!(plan.params.rootfs_path, base.join("rootfs.ext4"));
        assert_eq!(plan.params.disk_bytes, Some(64 * 1024 * 1024));
        assert_eq!(plan.record.disk_mib, 64);
    }

    #[tokio::test]
    async fn plan_vm_legacy_mode_keeps_staged_clone() {
        let dir = TempDir::new("runtime-plan-legacy");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let base = make_image(&paths, "default", "2026-11-16.1", false);

        let resolved = ImageStore::new(paths.images_path())
            .resolve("default")
            .unwrap();
        assert!(!resolved.overlay_boot());

        let params = VmSpec::default();
        let plan = runtime
            .plan_vm(&params, "bold-ox", "default", &resolved, None)
            .unwrap();

        assert_eq!(plan.record.overlay_path, None);
        assert_eq!(plan.params.overlay_path, None);
        assert_eq!(plan.params.rootfs_path, base.join("rootfs.ext4"));
        assert_eq!(plan.params.disk_bytes, None);
        assert_eq!(plan.record.disk_mib, 16);
    }

    #[tokio::test]
    async fn plan_vm_refuses_disk_shrink() {
        let dir = TempDir::new("runtime-plan-shrink");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        make_image(&paths, "default", "2026-11-16.1", true);

        let resolved = ImageStore::new(paths.images_path())
            .resolve("default")
            .unwrap();
        let params = VmSpec {
            disk_mib: 8,
            ..VmSpec::default()
        };
        let err = runtime
            .plan_vm(&params, "x", "default", &resolved, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("only grow, not shrink"), "{err}");
    }

    async fn insert_vm(paths: &KletkaPaths, name: &str, overlay: bool) -> VmRecord {
        let mut record = VmRecord {
            id: Uuid::new_v4(),
            name: name.to_string(),
            image: "default".to_string(),
            state: VmState::Stopped,
            kernel_path: paths.images_path().join("default/vmlinux"),
            rootfs_path: paths.images_path().join("default/rootfs.ext4"),
            overlay_path: None,
            vsock_cid: None,
            network: None,
            fc_pid: None,
            slirp_pid: None,
            ssh_addr: None,
            ssh_port: None,
            vcpu_count: 2,
            memory_mib: 512,
            disk_mib: 2048,
            created_at: kletka_types::time::Timestamp::UNIX_EPOCH,
        };
        if overlay {
            record.overlay_path = Some(
                paths
                    .instances_path()
                    .join(record.id.to_string())
                    .join("overlay.ext4"),
            );
        }
        Registry::open(paths).insert(record.clone()).unwrap();
        record
    }

    #[tokio::test]
    async fn rebase_stopped_vm_moves_base_and_keeps_overlay() {
        let dir = TempDir::new("runtime-rebase");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        make_image(&paths, "default", "2026-11-16.1", true);
        let newer = make_image(&paths, "default", "2026-11-16.2", true);
        grow_ext4(&newer.join("rootfs.ext4"), 32 * 1024 * 1024).unwrap();
        let mut record = insert_vm(&paths, "calm-fox", true).await;
        record.disk_mib = 16;
        Registry::open(&paths).update(record.clone()).unwrap();
        let overlay_path = record.overlay_path.as_ref().unwrap();
        std::fs::create_dir_all(overlay_path.parent().unwrap()).unwrap();
        let initial_base = ImageStore::new(paths.images_path())
            .resolve("default")
            .unwrap();
        thin_copy(&initial_base.rootfs_path, overlay_path).unwrap();

        let rebased = runtime
            .rebase_vm("calm-fox", Some("default"))
            .await
            .unwrap();
        assert_eq!(rebased["image"], "default");
        assert!(
            rebased["kernel_path"]
                .as_str()
                .unwrap()
                .contains("2026-11-16.2"),
            "kernel re-pinned to the new current version: {rebased}"
        );
        assert!(
            rebased["rootfs_path"]
                .as_str()
                .unwrap()
                .contains("2026-11-16.2"),
            "base re-pinned to the new current version: {rebased}"
        );
        assert_eq!(
            rebased["overlay_path"],
            serde_json::to_value(&record.overlay_path).unwrap(),
            "the overlay (disk state) is kept"
        );
        assert_eq!(rebased["state"], "stopped");
        assert_eq!(rebased["disk_mib"], 32);
        assert_eq!(
            ext4_size(record.overlay_path.as_ref().unwrap()).unwrap(),
            32 * 1024 * 1024
        );
    }

    #[tokio::test]
    async fn rebase_running_vm_is_refused() {
        let dir = TempDir::new("runtime-rebase-running");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        make_image(&paths, "default", "2026-11-16.1", true);
        let mut record = insert_vm(&paths, "calm-fox", true).await;
        record.state = VmState::Running;
        Registry::open(&paths).update(record).unwrap();

        let err = runtime
            .rebase_vm("calm-fox", None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("stop it before rebasing"), "{err}");
    }

    #[tokio::test]
    async fn rebase_unknown_image_errors() {
        let dir = TempDir::new("runtime-rebase-missing");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        make_image(&paths, "default", "2026-11-16.1", true);
        insert_vm(&paths, "calm-fox", true).await;

        let err = runtime
            .rebase_vm("calm-fox", Some("ghost"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("ghost"), "{err}");
    }

    #[tokio::test]
    async fn rebase_onto_non_overlay_image_is_refused_for_overlay_vms() {
        let dir = TempDir::new("runtime-rebase-noflag");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        make_image(&paths, "default", "2026-11-16.1", true);
        make_image(&paths, "old", "2026-11-15.1", false);
        insert_vm(&paths, "calm-fox", true).await;

        let err = runtime
            .rebase_vm("calm-fox", Some("old"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("overlay boot"), "{err}");
    }

    #[test]
    fn sanitize_hostname_table() {
        assert_eq!(sanitize_hostname("My VM!"), "my-vm");
        assert_eq!(sanitize_hostname("UPPER"), "upper");
        assert_eq!(sanitize_hostname("a_b"), "a-b");
        assert_eq!(sanitize_hostname("  spaced  name  "), "spaced--name");
        assert_eq!(sanitize_hostname("--x--"), "x");
        assert_eq!(sanitize_hostname("Ünïcode"), "n-code");
        let long = "a".repeat(80);
        assert_eq!(sanitize_hostname(&long), "a".repeat(63));
        let dashed = format!("{}b", "-".repeat(80));
        assert_eq!(sanitize_hostname(&dashed), "b");
        assert_eq!(sanitize_hostname(""), "kletka");
        assert_eq!(sanitize_hostname("???"), "kletka");
        assert_eq!(sanitize_hostname("---"), "kletka");
    }

    fn seed_file(img: &Path, file: &str) -> String {
        let output = std::process::Command::new("debugfs")
            .args(["-R", &format!("cat {file}")])
            .arg(img)
            .output()
            .expect("debugfs ships with mkfs.ext4 (e2fsprogs)");
        assert!(
            output.status.success(),
            "debugfs cat {file} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    #[tokio::test]
    async fn seed_image_carries_the_sanitized_hostname() {
        let dir = TempDir::new("runtime-seed-hostname");
        let _runtime = test_runtime(&dir).await;
        let instance = dir.path().join("instance");
        std::fs::create_dir_all(&instance).unwrap();

        let config = "[Interface]\nPrivateKey = private\n";
        let img = build_seed_image_with_wireguard(&instance, "My VM!", Some(config), None).unwrap();
        assert_eq!(seed_file(&img, "hostname"), "my-vm\n");
        assert!(seed_file(&img, "authorized_keys").contains("ssh-ed25519"));
        assert_eq!(seed_file(&img, "wireguard.conf"), config);
        let img = build_seed_image_with_wireguard(&instance, "My VM!", None, None).unwrap();
        assert_eq!(seed_file(&img, "wireguard.conf"), "");
    }

    #[tokio::test]
    async fn seed_image_carries_extra_authorized_keys() {
        let dir = TempDir::new("runtime-seed-keys");
        let _runtime = test_runtime(&dir).await;
        let instance = dir.path().join("instance");
        std::fs::create_dir_all(&instance).unwrap();

        let user_key = "ssh-ed25519 AAAAC3NzaC1lZDI1IE5leGFtcGxl me@laptop";
        let img =
            build_seed_image_with_wireguard(&instance, "My VM!", None, Some(user_key)).unwrap();
        let keys = seed_file(&img, "authorized_keys");
        assert!(keys.contains("ssh-ed25519"), "vm key dropped: {keys}");
        assert!(keys.contains(user_key), "user key dropped: {keys}");
        assert!(
            keys.ends_with('\n'),
            "sshd wants trailing newline: {keys:?}"
        );
        assert_eq!(keys.lines().count(), 2, "{keys}");

        let img = build_seed_image_with_wireguard(&instance, "My VM!", None, Some("  ")).unwrap();
        assert_eq!(seed_file(&img, "authorized_keys").lines().count(), 1);
    }

    async fn vm_with_disk(
        paths: &KletkaPaths,
        name: &str,
        overlay: bool,
        content: &[u8],
    ) -> VmRecord {
        let record = insert_vm(paths, name, overlay).await;
        let disk = match &record.overlay_path {
            Some(overlay) => overlay.clone(),
            None => paths
                .instances_path()
                .join(record.id.to_string())
                .join("rootfs.ext4"),
        };
        std::fs::create_dir_all(disk.parent().unwrap()).unwrap();
        std::fs::write(&disk, content).unwrap();
        record
    }

    #[tokio::test]
    async fn checkpoint_create_on_running_vm_is_refused() {
        let dir = TempDir::new("runtime-cp-running");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let mut record = vm_with_disk(&paths, "calm-fox", true, b"state").await;
        record.state = VmState::Running;
        let instance_dir = paths.instances_path().join(record.id.to_string());
        Registry::open(&paths).update(record).unwrap();

        let err = runtime
            .checkpoint(CheckpointOperation::Create {
                vm: "calm-fox".to_string(),
                name: "clean".to_string(),
                memory: false,
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not stopped"), "{err}");
        assert!(
            !instance_dir.join("checkpoints").exists(),
            "no checkpoint directory may appear"
        );
    }

    #[tokio::test]
    async fn checkpoint_roundtrip_on_stopped_overlay_vm() {
        let dir = TempDir::new("runtime-cp-roundtrip");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let record = vm_with_disk(&paths, "calm-fox", true, b"state-v1").await;
        let overlay = record.overlay_path.unwrap();

        let created = runtime
            .checkpoint(CheckpointOperation::Create {
                vm: "calm-fox".to_string(),
                name: "clean".to_string(),
                memory: false,
            })
            .await
            .unwrap();
        assert_eq!(created["name"], "clean");
        assert_eq!(created["with_memory"], false);
        assert!(
            created["size_bytes"].as_u64().unwrap() >= 8,
            "size_bytes is the copy's allocated usage (block-granular)"
        );

        let cp_disk = paths
            .instances_path()
            .join(record.id.to_string())
            .join("checkpoints/clean/rootfs.ext4");
        assert_eq!(std::fs::read(&cp_disk).unwrap(), b"state-v1");

        std::fs::write(&overlay, b"state-v2-with-more-writes").unwrap();

        runtime
            .checkpoint(CheckpointOperation::Rollback {
                vm: "calm-fox".to_string(),
                name: "clean".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(
            std::fs::read(&overlay).unwrap(),
            b"state-v1",
            "the live disk is the snapshot's content again"
        );
        assert_eq!(
            std::fs::read(&cp_disk).unwrap(),
            b"state-v1",
            "the snapshot survives the rollback"
        );
        let leaked = paths
            .instances_path()
            .join(record.id.to_string())
            .read_dir()
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("overlay.ext4.")
            });
        assert!(
            !leaked,
            "no rollback staging file may leak into the instance dir"
        );

        let list = runtime
            .checkpoint(CheckpointOperation::List("calm-fox".to_string()))
            .await
            .unwrap();
        let snapshots = list.as_array().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0]["name"], "clean");

        runtime
            .checkpoint(CheckpointOperation::Delete {
                vm: "calm-fox".to_string(),
                name: "clean".to_string(),
            })
            .await
            .unwrap();
        assert!(!cp_disk.exists());
        let err = runtime
            .checkpoint(CheckpointOperation::Delete {
                vm: "calm-fox".to_string(),
                name: "clean".to_string(),
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found"), "{err}");
    }

    #[tokio::test]
    async fn checkpoint_uses_staged_clone_for_legacy_vms() {
        let dir = TempDir::new("runtime-cp-legacy");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let record = vm_with_disk(&paths, "bold-ox", false, b"legacy-state").await;

        runtime
            .checkpoint(CheckpointOperation::Create {
                vm: "bold-ox".to_string(),
                name: "snap1".to_string(),
                memory: false,
            })
            .await
            .unwrap();

        let cp_disk = paths
            .instances_path()
            .join(record.id.to_string())
            .join("checkpoints/snap1/rootfs.ext4");
        assert_eq!(std::fs::read(&cp_disk).unwrap(), b"legacy-state");
    }

    #[tokio::test]
    async fn checkpoint_memory_flag_is_refused_clearly() {
        let dir = TempDir::new("runtime-cp-memory");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        vm_with_disk(&paths, "calm-fox", true, b"state").await;

        let err = runtime
            .checkpoint(CheckpointOperation::Create {
                vm: "calm-fox".to_string(),
                name: "clean".to_string(),
                memory: true,
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("memory snapshots are not supported"), "{err}");
    }

    #[test]
    fn guest_mac_is_stable_unicast_and_locally_administered() {
        let id = Uuid::parse_str("0123abcd-0000-0000-0000-000000000000").unwrap();
        assert_eq!(guest_mac(id), "06:01:23:ab:cd:00");
        let (_, nics) = boot_config(true, id);
        assert_eq!(
            nics.unwrap()[0].guest_mac.as_deref(),
            Some("06:01:23:ab:cd:00")
        );
        assert!(boot_config(false, id).1.is_none());
    }

    #[tokio::test]
    async fn resize_updates_a_stopped_vm_only() {
        let dir = TempDir::new("runtime-resize");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let mut record = insert_vm(&paths, "calm-fox", true).await;

        let resized = runtime.resize_vm("calm-fox", 4, 2048).unwrap();
        assert_eq!(resized["vcpu_count"], 4);
        assert_eq!(resized["memory_mib"], 2048);
        let stored = runtime.find_vm("calm-fox").unwrap();
        assert_eq!((stored.vcpu_count, stored.memory_mib), (4, 2048));

        assert!(runtime.resize_vm("calm-fox", 0, 2048).is_err());
        assert!(runtime.resize_vm("calm-fox", 33, 2048).is_err());
        assert!(runtime.resize_vm("calm-fox", 2, 64).is_err());

        record.state = VmState::Running;
        Registry::open(&paths).update(record).unwrap();
        let err = runtime
            .resize_vm("calm-fox", 2, 1024)
            .unwrap_err()
            .to_string();
        assert!(err.contains("stop it before resizing"), "{err}");
    }

    fn have_e2fsprogs() -> bool {
        ["mkfs.ext4", "resize2fs", "dumpe2fs"].iter().all(|binary| {
            std::env::var_os("PATH").is_some_and(|paths| {
                std::env::split_paths(&paths).any(|dir| dir.join(binary).is_file())
            })
        })
    }

    #[tokio::test]
    async fn grow_disk_grows_overlay_records_it_and_refuses_shrink() {
        if !have_e2fsprogs() {
            return;
        }
        let dir = TempDir::new("runtime-grow-disk");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        let record = vm_with_disk(&paths, "calm-fox", true, b"state").await;
        let overlay = record.overlay_path.clone().unwrap();

        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&overlay)
            .unwrap();
        file.set_len(2048 * 1024 * 1024).unwrap();
        drop(file);
        let status = std::process::Command::new("mkfs.ext4")
            .args(["-q", "-F"])
            .arg(&overlay)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(ext4_size(&overlay).unwrap(), 2048 * 1024 * 1024);

        runtime.grow_disk("calm-fox", 0).unwrap();
        runtime.grow_disk("calm-fox", 2048).unwrap();
        assert_eq!(runtime.find_vm("calm-fox").unwrap().disk_mib, 2048);

        let grown = runtime.grow_disk("calm-fox", 4096).unwrap();
        assert_eq!(grown["disk_mib"], 4096);
        assert_eq!(ext4_size(&overlay).unwrap(), 4096 * 1024 * 1024);
        assert_eq!(runtime.find_vm("calm-fox").unwrap().disk_mib, 4096);

        let err = runtime.grow_disk("calm-fox", 20).unwrap_err().to_string();
        assert!(err.contains("can only grow"), "{err}");

        let mut running = runtime.find_vm("calm-fox").unwrap();
        running.state = VmState::Running;
        Registry::open(&paths).update(running).unwrap();
        let err = runtime.grow_disk("calm-fox", 8192).unwrap_err().to_string();
        assert!(err.contains("stop it before resizing"), "{err}");
    }

    #[tokio::test]
    async fn checkpoint_retention_prunes_oldest() {
        let dir = TempDir::new("runtime-cp-retention");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;
        vm_with_disk(&paths, "calm-fox", true, b"state").await;

        for i in 0..6 {
            runtime
                .checkpoint(CheckpointOperation::Create {
                    vm: "calm-fox".to_string(),
                    name: format!("snap{i}"),
                    memory: false,
                })
                .await
                .unwrap();
        }

        let list = runtime
            .checkpoint(CheckpointOperation::List("calm-fox".to_string()))
            .await
            .unwrap();
        let snapshots = list.as_array().unwrap();
        assert_eq!(snapshots.len(), kletka::checkpoint::MAX_CHECKPOINTS);
        for snapshot in snapshots {
            let name = snapshot["name"].as_str().unwrap();
            assert!(name.starts_with("snap"), "{name}");
        }
    }

    #[tokio::test]
    async fn checkpoint_unknown_vm_and_missing_disk_are_errors() {
        let dir = TempDir::new("runtime-cp-missing");
        let paths = KletkaPaths::with_data_dir(dir.path());
        let runtime = test_runtime(&dir).await;

        let err = runtime
            .checkpoint(CheckpointOperation::List("ghost".to_string()))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not found"), "{err}");

        insert_vm(&paths, "calm-fox", true).await;
        let err = runtime
            .checkpoint(CheckpointOperation::Create {
                vm: "calm-fox".to_string(),
                name: "clean".to_string(),
                memory: false,
            })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no disk to snapshot"), "{err}");
    }
}
