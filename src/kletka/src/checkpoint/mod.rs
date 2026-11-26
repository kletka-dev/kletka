use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const MAX_CHECKPOINTS: usize = kletka_types::MAX_SNAPSHOTS_PER_VM;

pub fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("checkpoint name cannot be empty".to_string());
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("checkpoint name may only contain letters, digits, '-' and '_'".to_string());
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub enum CheckpointOperation {
    List(String),
    Create {
        vm: String,
        name: String,
        memory: bool,
    },
    Delete {
        vm: String,
        name: String,
    },
    Rollback {
        vm: String,
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRecord {
    pub name: String,
    #[serde(with = "kletka_types::time::rfc3339")]
    pub created_at: kletka_types::time::Timestamp,
    pub size_bytes: u64,
    pub with_memory: bool,
}

#[derive(Debug, Clone)]
pub struct CheckpointStore {
    dir: PathBuf,
}

impl CheckpointStore {
    pub fn new(instance_dir: &Path) -> Self {
        Self {
            dir: instance_dir.join("checkpoints"),
        }
    }

    fn checkpoint_dir(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn rootfs_path(&self, name: &str) -> PathBuf {
        self.checkpoint_dir(name).join("rootfs.ext4")
    }

    pub fn list(&self) -> std::io::Result<Vec<CheckpointRecord>> {
        let mut records = Vec::new();

        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(err) => return Err(err),
        };

        for entry in entries.flatten() {
            let meta = entry.path().join("meta.json");
            if let Ok(json) = std::fs::read_to_string(&meta)
                && let Ok(record) = serde_json::from_str::<CheckpointRecord>(&json)
            {
                records.push(record);
            }
        }

        records.sort_by_key(|record| record.created_at);
        Ok(records)
    }

    pub fn get(&self, name: &str) -> std::io::Result<Option<CheckpointRecord>> {
        Ok(self.list()?.into_iter().find(|record| record.name == name))
    }

    pub fn create_dir(&self, name: &str) -> Result<PathBuf, String> {
        validate_name(name)?;

        if self.get(name).map_err(|err| err.to_string())?.is_some()
            || self.checkpoint_dir(name).exists()
        {
            return Err(format!("checkpoint '{name}' already exists"));
        }

        let dir = self.checkpoint_dir(name);
        std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
        Ok(dir)
    }

    pub fn insert(&self, record: CheckpointRecord) -> Result<Option<String>, String> {
        let meta = serde_json::to_string_pretty(&record).map_err(|err| err.to_string())?;
        std::fs::write(self.checkpoint_dir(&record.name).join("meta.json"), meta)
            .map_err(|err| err.to_string())?;

        let mut records = self.list().map_err(|err| err.to_string())?;
        if records.len() <= MAX_CHECKPOINTS {
            return Ok(None);
        }

        if records.len() > MAX_CHECKPOINTS {
            let oldest = records.remove(0);
            self.delete(&oldest.name).map_err(|err| err.to_string())?;
            return Ok(Some(oldest.name));
        }

        Ok(None)
    }

    pub fn delete(&self, name: &str) -> Result<bool, String> {
        let dir = self.checkpoint_dir(name);
        if !dir.exists() {
            return Ok(false);
        }

        std::fs::remove_dir_all(&dir).map_err(|err| err.to_string())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::test_util::TempDir;

    fn store() -> (TempDir, CheckpointStore) {
        let dir = TempDir::new("cp");
        let store = CheckpointStore::new(dir.path());
        (dir, store)
    }

    fn record(name: &str, created_at: i64, size: u64) -> CheckpointRecord {
        CheckpointRecord {
            name: name.to_string(),
            created_at: kletka_types::time::from_unix(created_at),
            size_bytes: size,
            with_memory: false,
        }
    }

    #[test]
    fn name_validation() {
        assert!(validate_name("snap1").is_ok());
        assert!(validate_name("my-check_2").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("../etc").is_err());
        assert!(validate_name("has space").is_err());
    }

    #[test]
    fn create_list_delete_roundtrip() {
        let (_dir, store) = store();

        store.create_dir("snap1").unwrap();
        std::fs::write(store.rootfs_path("snap1"), b"x").unwrap();
        store.insert(record("snap1", 10, 1)).unwrap();

        store.create_dir("snap2").unwrap();
        store.insert(record("snap2", 20, 2)).unwrap();

        let list = store.list().unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "snap1");

        assert!(store.get("snap2").unwrap().is_some());
        assert!(store.get("nope").unwrap().is_none());

        assert!(store.delete("snap1").unwrap());
        assert!(!store.delete("snap1").unwrap());
        assert_eq!(store.list().unwrap().len(), 1);
    }

    #[test]
    fn duplicate_and_invalid_names_rejected() {
        let (_dir, store) = store();
        store.create_dir("snap1").unwrap();
        assert!(store.create_dir("snap1").is_err());
        assert!(store.create_dir("../escape").is_err());
    }

    #[test]
    fn retention_prunes_oldest() {
        let (_dir, store) = store();

        for i in 0..MAX_CHECKPOINTS {
            let name = format!("snap{i}");
            store.create_dir(&name).unwrap();
            store.insert(record(&name, i as i64, 1)).unwrap();
        }
        assert_eq!(store.list().unwrap().len(), MAX_CHECKPOINTS);

        store.create_dir("newest").unwrap();
        let pruned = store.insert(record("newest", 999, 1)).unwrap();
        assert_eq!(pruned.as_deref(), Some("snap0"));

        let list = store.list().unwrap();
        assert_eq!(list.len(), MAX_CHECKPOINTS);
        assert!(store.get("snap0").unwrap().is_none());
        assert!(store.get("snap1").unwrap().is_some());
    }

    #[test]
    fn missing_meta_is_skipped() {
        let (_dir, store) = store();
        store.create_dir("broken").unwrap();
        assert!(store.list().unwrap().is_empty());
    }
}
