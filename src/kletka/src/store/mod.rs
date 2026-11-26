use std::io;
use std::path::PathBuf;

use fslock::LockFile;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::system::KletkaPaths;

const FIRST_GUEST_CID: u32 = 3;

const MAX_GUEST_CID: u32 = 0xFFFF_FFFE;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("cannot lock registry at {path}: {source}")]
    Lock { path: PathBuf, source: io::Error },

    #[error("cannot read registry at {path}: {source}")]
    Read { path: PathBuf, source: io::Error },

    #[error("cannot write registry at {path}: {source}")]
    Write { path: PathBuf, source: io::Error },

    #[error("registry at {path} is corrupt: {source}")]
    Corrupt {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("a vm named '{0}' already exists")]
    NameTaken(String),

    #[error("vm '{0}' not found")]
    NotFound(String),

    #[error("no free vsock cid available")]
    NoFreeCid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmState {
    Running,
    #[serde(alias = "paused")]
    Stopped,
}

impl VmState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmNetworkConfig {
    pub nat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmRecord {
    pub id: Uuid,
    pub name: String,
    pub image: String,
    pub state: VmState,

    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub overlay_path: Option<PathBuf>,

    pub vsock_cid: Option<u32>,
    pub network: Option<VmNetworkConfig>,

    #[serde(default)]
    pub fc_pid: Option<u32>,

    #[serde(default)]
    pub slirp_pid: Option<u32>,

    #[serde(default)]
    pub ssh_addr: Option<String>,

    #[serde(default)]
    pub ssh_port: Option<u16>,

    pub vcpu_count: u8,
    pub memory_mib: usize,

    #[serde(default)]
    pub disk_mib: usize,

    #[serde(with = "kletka_types::time::rfc3339")]
    pub created_at: kletka_types::time::Timestamp,
}

impl VmRecord {
    pub fn mark_stopped(&mut self) {
        self.state = VmState::Stopped;
        self.fc_pid = None;
        self.slirp_pid = None;
    }

    pub fn nat(&self) -> bool {
        self.network.as_ref().is_some_and(|net| net.nat)
    }
}

struct RegistryGuard {
    file: LockFile,
}

impl RegistryGuard {
    fn acquire(path: &std::path::Path) -> Result<Self, RegistryError> {
        let mut file = LockFile::open(path).map_err(|source| RegistryError::Lock {
            path: path.to_path_buf(),
            source,
        })?;
        file.lock().map_err(|source| RegistryError::Lock {
            path: path.to_path_buf(),
            source,
        })?;

        Ok(Self { file })
    }
}

impl Drop for RegistryGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Debug, Clone)]
pub struct Registry {
    path: PathBuf,
    lock_path: PathBuf,
}

impl Registry {
    pub fn open(paths: &KletkaPaths) -> Self {
        Self {
            path: paths.registry_path(),
            lock_path: paths.registry_lock_path(),
        }
    }

    pub fn open_at(path: PathBuf, lock_path: PathBuf) -> Self {
        Self { path, lock_path }
    }

    pub fn list(&self) -> Result<Vec<VmRecord>, RegistryError> {
        let guard = RegistryGuard::acquire(&self.lock_path)?;
        self.load(&guard)
    }

    pub fn find(&self, key: &str) -> Result<Option<VmRecord>, RegistryError> {
        let guard = RegistryGuard::acquire(&self.lock_path)?;
        Ok(self
            .load(&guard)?
            .into_iter()
            .find(|record| record_matches(record, key)))
    }

    pub fn insert(&self, record: VmRecord) -> Result<(), RegistryError> {
        let guard = RegistryGuard::acquire(&self.lock_path)?;
        let mut records = self.load(&guard)?;

        if records.iter().any(|existing| existing.name == record.name) {
            return Err(RegistryError::NameTaken(record.name));
        }

        records.push(record);
        self.save(&guard, &records)
    }

    pub fn update(&self, record: VmRecord) -> Result<(), RegistryError> {
        let guard = RegistryGuard::acquire(&self.lock_path)?;
        let mut records = self.load(&guard)?;

        let slot = records
            .iter_mut()
            .find(|existing| existing.id == record.id)
            .ok_or_else(|| RegistryError::NotFound(record.name.clone()))?;

        *slot = record;
        self.save(&guard, &records)
    }

    pub fn remove(&self, id: Uuid) -> Result<Option<VmRecord>, RegistryError> {
        let guard = RegistryGuard::acquire(&self.lock_path)?;
        let mut records = self.load(&guard)?;

        let position = records.iter().position(|record| record.id == id);
        let removed = position.map(|at| records.remove(at));

        if position.is_some() {
            self.save(&guard, &records)?;
        }

        Ok(removed)
    }

    pub fn next_vsock_cid(&self) -> Result<u32, RegistryError> {
        let guard = RegistryGuard::acquire(&self.lock_path)?;
        let records = self.load(&guard)?;

        let mut candidate = FIRST_GUEST_CID;
        let mut used: Vec<u32> = records
            .iter()
            .filter_map(|record| record.vsock_cid)
            .collect();
        used.sort_unstable();

        for &taken in &used {
            if candidate == taken {
                candidate = taken
                    .checked_add(1)
                    .filter(|next| *next <= MAX_GUEST_CID)
                    .ok_or(RegistryError::NoFreeCid)?;
            }
        }

        Ok(candidate)
    }

    fn load(&self, _guard: &RegistryGuard) -> Result<Vec<VmRecord>, RegistryError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(source) => {
                return Err(RegistryError::Read {
                    path: self.path.clone(),
                    source,
                });
            }
        };

        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_slice(&bytes).map_err(|source| RegistryError::Corrupt {
            path: self.path.clone(),
            source,
        })
    }

    fn save(&self, _guard: &RegistryGuard, records: &[VmRecord]) -> Result<(), RegistryError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("registry path has no parent directory"))?;

        std::fs::create_dir_all(parent).map_err(|source| RegistryError::Write {
            path: parent.to_path_buf(),
            source,
        })?;

        let temporary = parent.join(format!(
            "{}.tmp-{}",
            self.path
                .file_name()
                .ok_or_else(|| io::Error::other("registry path has no file name"))?
                .to_string_lossy(),
            Uuid::new_v4()
        ));

        {
            let mut file =
                std::fs::File::create(&temporary).map_err(|source| RegistryError::Write {
                    path: temporary.clone(),
                    source,
                })?;
            serde_json::to_writer_pretty(&mut file, records)?;
            file.sync_all().map_err(|source| RegistryError::Write {
                path: temporary.clone(),
                source,
            })?;
        }

        std::fs::rename(&temporary, &self.path).map_err(|source| RegistryError::Write {
            path: self.path.clone(),
            source,
        })?;

        Ok(())
    }
}

fn record_matches(record: &VmRecord, key: &str) -> bool {
    record.name == key || record.id.to_string() == key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::test_util::TempDir;

    fn sample_record(name: &str) -> VmRecord {
        VmRecord {
            id: Uuid::new_v4(),
            name: name.to_string(),
            image: "default".to_string(),
            state: VmState::Stopped,
            kernel_path: PathBuf::from("/images/default/vmlinux"),
            rootfs_path: PathBuf::from("/images/default/rootfs.ext4"),
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
        }
    }

    #[test]
    fn empty_registry_is_empty() {
        let dir = TempDir::new("store-empty");
        let registry = Registry::open_at(
            dir.path().join("registry.json"),
            dir.path().join("registry.lock"),
        );

        assert!(registry.list().unwrap().is_empty());
        assert!(registry.find("anything").unwrap().is_none());
    }

    #[test]
    fn insert_update_remove_roundtrip() {
        let dir = TempDir::new("store-roundtrip");
        let registry = Registry::open_at(
            dir.path().join("registry.json"),
            dir.path().join("registry.lock"),
        );

        let mut record = sample_record("bold-ox");
        registry.insert(record.clone()).unwrap();

        assert!(registry.insert(sample_record("bold-ox")).is_err());

        record.state = VmState::Running;
        registry.update(record.clone()).unwrap();

        let found = registry.find("bold-ox").unwrap().unwrap();
        assert_eq!(found.state, VmState::Running);
        assert_eq!(found.id, record.id);

        let removed = registry.remove(record.id).unwrap();
        assert_eq!(removed.unwrap().name, "bold-ox");
        assert!(registry.find("bold-ox").unwrap().is_none());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = TempDir::new("store-reopen");
        let path = dir.path().join("registry.json");
        let lock = dir.path().join("registry.lock");

        {
            let registry = Registry::open_at(path.clone(), lock.clone());
            registry.insert(sample_record("keen-hawk")).unwrap();
        }

        let registry = Registry::open_at(path, lock);
        let records = registry.list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "keen-hawk");
    }

    #[test]
    fn finds_by_name_and_uuid() {
        let dir = TempDir::new("store-find");
        let registry = Registry::open_at(
            dir.path().join("registry.json"),
            dir.path().join("registry.lock"),
        );

        let record = sample_record("calm-fox");
        let id = record.id;
        registry.insert(record).unwrap();

        assert!(registry.find("calm-fox").unwrap().is_some());
        assert!(registry.find(&id.to_string()).unwrap().is_some());
        assert!(registry.find("wild-dog").unwrap().is_none());
    }

    #[test]
    fn overlay_path_roundtrips_through_the_registry() {
        let dir = TempDir::new("store-overlay");
        let registry = Registry::open_at(
            dir.path().join("registry.json"),
            dir.path().join("registry.lock"),
        );

        let mut record = sample_record("calm-fox");
        let overlay = dir.path().join("instances").join("overlay.ext4");
        record.overlay_path = Some(overlay.clone());
        registry.insert(record.clone()).unwrap();

        let found = registry.find("calm-fox").unwrap().unwrap();
        assert_eq!(found.overlay_path, Some(overlay));
    }

    #[test]
    fn allocates_lowest_free_cid() {
        let dir = TempDir::new("store-cid");
        let registry = Registry::open_at(
            dir.path().join("registry.json"),
            dir.path().join("registry.lock"),
        );

        assert_eq!(registry.next_vsock_cid().unwrap(), 3);

        let mut record = sample_record("snug-elk");
        record.vsock_cid = Some(3);
        registry.insert(record).unwrap();
        assert_eq!(registry.next_vsock_cid().unwrap(), 4);

        let mut record = sample_record("free-gull");
        record.vsock_cid = Some(5);
        registry.insert(record).unwrap();
        assert_eq!(registry.next_vsock_cid().unwrap(), 4);
    }

    #[test]
    fn permission_errors_name_the_path() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new("store-perm");
        let lock = dir.path().join("registry.lock");
        std::fs::write(&lock, b"").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o000)).unwrap();
        let registry = Registry::open_at(dir.path().join("registry.json"), lock.clone());
        let err = registry.list().unwrap_err().to_string();
        assert!(
            err.contains(&lock.display().to_string()),
            "error names the path: {err}"
        );
        assert!(err.contains("Permission denied"), "{err}");
    }
}
