use std::fs;
use std::path::{Component, Path, PathBuf};

use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../docker/"]
struct DockerContext;

pub fn embedded_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn embedded_hash() -> String {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    let mut entries: Vec<_> = DockerContext::iter().collect();
    entries.sort();
    for path in entries {
        let file = DockerContext::get(&path).expect("iter() yields existing assets");
        hasher.update(path.as_bytes());
        hasher.update([0]);
        hasher.update(file.data.len().to_le_bytes());
        hasher.update(&file.data);
    }
    let hex = hex::encode(hasher.finalize());
    hex[..12].to_string()
}

pub fn embedded_repo_dir() -> PathBuf {
    std::env::temp_dir().join(format!("kletka-embedded-repo-{}", embedded_hash()))
}

pub fn extract_embedded_repo() -> Result<PathBuf, String> {
    let docker_dir = embedded_repo_dir().join("docker");
    for path in DockerContext::iter() {
        let file = DockerContext::get(&path).expect("iter() yields existing assets");
        let rel = Path::new(path.as_ref());
        if rel.components().any(|c| !matches!(c, Component::Normal(_))) {
            return Err(format!("embedded asset '{path}' has an unsafe path"));
        }
        let dest = docker_dir.join(rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
        }
        fs::write(&dest, &file.data)
            .map_err(|err| format!("cannot write {}: {err}", dest.display()))?;
    }
    Ok(embedded_repo_dir())
}

pub fn is_embedded_repo(repo: &Path) -> bool {
    let a = repo.canonicalize().unwrap_or_else(|_| repo.to_path_buf());
    let b = embedded_repo_dir()
        .canonicalize()
        .unwrap_or_else(|_| embedded_repo_dir());
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_full_docker_context() {
        let repo = extract_embedded_repo().unwrap();
        let docker = repo.join("docker");
        assert!(docker.join("kernel/Dockerfile").is_file());
        assert!(docker.join("kernel/microvm-kletka.config").is_file());
        assert!(docker.join("rootfs/Dockerfile").is_file());
        assert!(
            docker
                .join("rootfs/rootfs/usr/local/sbin/kletka-seed")
                .is_file()
        );
        assert!(
            docker
                .join("rootfs/rootfs/usr/lib/systemd/system/kletka-seed.service")
                .is_file()
        );
        assert!(is_embedded_repo(&repo));

        assert_eq!(extract_embedded_repo().unwrap(), repo);
        assert_eq!(embedded_repo_dir(), repo);
    }

    #[test]
    fn embedded_files_are_not_empty() {
        for path in DockerContext::iter() {
            let file = DockerContext::get(&path).unwrap();
            assert!(!file.data.is_empty(), "embedded asset '{path}' is empty");
        }
        assert!(!embedded_version().is_empty());
    }
}
