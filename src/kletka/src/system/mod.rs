use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct KletkaPaths {
    data_dir: PathBuf,
}

impl KletkaPaths {
    pub fn with_data_dir(dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: dir.into(),
        }
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn registry_path(&self) -> PathBuf {
        self.data_dir.join("registry.json")
    }

    pub fn registry_lock_path(&self) -> PathBuf {
        self.data_dir.join("registry.lock")
    }

    pub fn instances_path(&self) -> PathBuf {
        self.data_dir.join("instances")
    }

    pub fn instance_dir(&self, id: &uuid::Uuid) -> PathBuf {
        self.instances_path().join(id.to_string())
    }

    pub fn images_path(&self) -> PathBuf {
        self.data_dir.join("images")
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        for dir in [
            self.data_dir.clone(),
            self.instances_path(),
            self.images_path(),
        ] {
            std::fs::create_dir_all(dir)?;
        }

        Ok(())
    }
}

pub fn which(binary: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.is_file())
}

pub fn on_path(binary: &str) -> bool {
    which(binary).is_some()
}

fn send_signal(pid: u32, signal: &str) {
    let _ = std::process::Command::new("kill")
        .arg(signal)
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

pub fn terminate(pid: u32) {
    send_signal(pid, "-TERM");
}

pub fn kill9(pid: u32) {
    send_signal(pid, "-KILL");
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        pub(crate) fn new(label: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("kletka-test-{label}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
