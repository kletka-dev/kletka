use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod build;
pub mod embedded;

use kletka_types::time::Timestamp;

pub const MANIFEST_SCHEMA: u32 = 1;

pub const LEGACY_VERSION: &str = "legacy";

pub const KERNEL_FILE: &str = "vmlinux";
pub const KERNEL_CONFIG_FILE: &str = "vmlinux.config";
pub const ROOTFS_FILE: &str = "rootfs.ext4";
pub const MANIFEST_FILE: &str = "manifest.json";

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("image '{name}' not found under {root}; available: {available}")]
    NotFound {
        name: String,
        root: PathBuf,
        available: String,
    },

    #[error("image '{name}' is incomplete: missing {missing} in {dir}")]
    Incomplete {
        name: String,
        missing: String,
        dir: PathBuf,
    },

    #[error("image manifest at {path} is corrupt: {source}")]
    CorruptManifest {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[error("unsupported manifest schema {schema} at {path} (expected {MANIFEST_SCHEMA})")]
    UnsupportedSchema { schema: u32, path: PathBuf },

    #[error("checksum mismatch for {file} in {dir}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        file: String,
        dir: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("version '{0}' of image '{1}' already exists")]
    VersionExists(String, String),

    #[error("invalid version '{0}': use letters, digits, '.', '-', '_' (no path separators)")]
    InvalidVersion(String),

    #[error("invalid image name '{0}': use letters, digits, '.', '-', '_' (no path separators)")]
    InvalidName(String),

    #[error("image '{0}' has no current version; build or import one first")]
    NoCurrent(String),

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub file: String,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
    #[serde(default)]
    pub git_dirty: bool,
    pub dockerfile: String,
    pub dockerfile_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_image: Option<String>,
    #[serde(default)]
    pub updated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_reused_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_reused_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedded_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_inputs_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageManifest {
    pub schema: u32,
    pub name: String,
    pub version: String,
    #[serde(with = "kletka_types::time::rfc3339")]
    pub created_at: Timestamp,
    #[serde(default)]
    pub overlay_boot: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub source: ImageSource,
    pub artifacts: ImageArtifacts,
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub labels: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageArtifacts {
    pub kernel: ArtifactInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_config: Option<ArtifactInfo>,
    pub rootfs: ArtifactInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    #[serde(with = "kletka_types::time::rfc3339")]
    pub created_at: Timestamp,
    pub size_bytes: u64,
    pub used_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default)]
    pub updated: bool,
    #[serde(default)]
    pub current: bool,
    #[serde(default)]
    pub legacy: bool,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSummary {
    pub name: String,
    pub current: Option<String>,
    pub versions: Vec<VersionInfo>,
}

#[derive(Debug, Clone)]
pub struct ResolvedImage {
    pub name: String,
    pub version: Option<String>,
    pub dir: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub manifest: Option<ImageManifest>,
}

impl ResolvedImage {
    pub fn overlay_boot(&self) -> bool {
        self.manifest.as_ref().is_some_and(|m| m.overlay_boot)
    }
}

#[derive(Debug, Clone)]
pub struct ImageStore {
    root: PathBuf,
}

impl ImageStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn image_dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn versions_dir(&self, name: &str) -> PathBuf {
        self.image_dir(name).join("versions")
    }

    fn version_dir(&self, name: &str, version: &str) -> PathBuf {
        self.versions_dir(name).join(version)
    }

    fn current_link(&self, name: &str) -> PathBuf {
        self.image_dir(name).join("current")
    }

    pub fn names(&self) -> Result<Vec<String>, ImageError> {
        let mut names = Vec::new();
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(names),
            Err(err) => return Err(err.into()),
        };
        for entry in entries.flatten() {
            if entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false) {
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort_unstable();
        Ok(names)
    }

    fn available_list(&self) -> String {
        match self.names() {
            Ok(names) if names.is_empty() => "<none>".to_string(),
            Ok(names) => names.join(", "),
            Err(_) => "<unreadable>".to_string(),
        }
    }

    fn require_name(name: &str) -> Result<(), ImageError> {
        validate_image_name(name).map_err(|_| ImageError::InvalidName(name.to_string()))
    }

    pub fn has_legacy(&self, name: &str) -> bool {
        let dir = self.image_dir(name);
        dir.join(KERNEL_FILE).is_file() && dir.join(ROOTFS_FILE).is_file()
    }

    pub fn versions(&self, name: &str) -> Result<Vec<VersionInfo>, ImageError> {
        Self::require_name(name)?;
        let current = self.current(name)?;
        let mut versions = Vec::new();

        let versions_dir = self.versions_dir(name);
        if let Ok(entries) = fs::read_dir(&versions_dir) {
            for entry in entries.flatten() {
                if !entry.file_type().map(|ty| ty.is_dir()).unwrap_or(false) {
                    continue;
                }
                let version = entry.file_name().to_string_lossy().into_owned();
                let dir = entry.path();
                if let Some(info) = self.version_info(&version, &dir, current.as_deref())? {
                    versions.push(info);
                }
            }
        }

        if self.has_legacy(name) {
            versions.push(VersionInfo {
                version: LEGACY_VERSION.to_string(),
                created_at: Timestamp::UNIX_EPOCH,
                size_bytes: dir_size(&self.image_dir(name)),
                used_bytes: dir_used(&self.image_dir(name)),
                parent: None,
                updated: false,
                current: current.is_none(),
                legacy: true,
                path: self.image_dir(name),
            });
        }

        versions.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then(a.version.cmp(&b.version))
        });
        Ok(versions)
    }

    fn version_info(
        &self,
        version: &str,
        dir: &Path,
        current: Option<&str>,
    ) -> Result<Option<VersionInfo>, ImageError> {
        if !dir.join(KERNEL_FILE).is_file() || !dir.join(ROOTFS_FILE).is_file() {
            return Ok(None);
        }
        let manifest = self.read_manifest(dir)?;
        let (created_at, parent, updated, mut size, mut used) = match &manifest {
            Some(m) => (
                m.created_at,
                m.parent.clone(),
                m.source.updated,
                m.artifacts.kernel.size_bytes
                    + m.artifacts.rootfs.size_bytes
                    + m.artifacts
                        .kernel_config
                        .as_ref()
                        .map_or(0, |a| a.size_bytes),
                m.artifacts.kernel.used_bytes.unwrap_or(0)
                    + m.artifacts.rootfs.used_bytes.unwrap_or(0)
                    + m.artifacts
                        .kernel_config
                        .as_ref()
                        .map_or(0, |a| a.used_bytes.unwrap_or(0)),
            ),
            None => (
                Timestamp::UNIX_EPOCH,
                None,
                false,
                dir_size(dir),
                dir_used(dir),
            ),
        };
        if manifest.is_none() {
            size = dir_size(dir);
            used = dir_used(dir);
        }
        Ok(Some(VersionInfo {
            version: version.to_string(),
            created_at,
            size_bytes: size,
            used_bytes: used,
            parent,
            updated,
            current: current == Some(version),
            legacy: false,
            path: dir.to_path_buf(),
        }))
    }

    pub fn current(&self, name: &str) -> Result<Option<String>, ImageError> {
        Self::require_name(name)?;
        let link = self.current_link(name);
        match fs::read_link(&link) {
            Ok(target) => {
                let version = target
                    .file_name()
                    .map(|v| v.to_string_lossy().into_owned())
                    .filter(|v| self.version_dir(name, v).is_dir());
                Ok(version)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if self.has_legacy(name) {
                    Ok(Some(LEGACY_VERSION.to_string()))
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    pub fn list(&self) -> Result<Vec<ImageSummary>, ImageError> {
        let mut images = Vec::new();
        for name in self.names()? {
            let current = self.current(&name)?;
            let versions = self.versions(&name)?;
            images.push(ImageSummary {
                name,
                current,
                versions,
            });
        }
        Ok(images)
    }

    pub fn show(&self, name: &str) -> Result<ImageSummary, ImageError> {
        Self::require_name(name)?;
        if !self.image_dir(name).is_dir() {
            return Err(ImageError::NotFound {
                name: name.to_string(),
                root: self.root.clone(),
                available: self.available_list(),
            });
        }
        Ok(ImageSummary {
            name: name.to_string(),
            current: self.current(name)?,
            versions: self.versions(name)?,
        })
    }

    fn read_manifest(&self, version_dir: &Path) -> Result<Option<ImageManifest>, ImageError> {
        let path = version_dir.join(MANIFEST_FILE);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let manifest: ImageManifest =
            serde_json::from_slice(&bytes).map_err(|source| ImageError::CorruptManifest {
                path: path.clone(),
                source,
            })?;
        if manifest.schema != MANIFEST_SCHEMA {
            return Err(ImageError::UnsupportedSchema {
                schema: manifest.schema,
                path,
            });
        }
        Ok(Some(manifest))
    }

    pub fn manifest(
        &self,
        name: &str,
        version: Option<&str>,
    ) -> Result<(PathBuf, Option<ImageManifest>), ImageError> {
        Self::require_name(name)?;
        let dir = match version {
            Some(v) => {
                validate_version(v).map_err(|_| ImageError::InvalidVersion(v.to_string()))?;
                let dir = self.version_dir(name, v);
                if !dir.is_dir() {
                    return Err(ImageError::NotFound {
                        name: format!("{name}@{v}"),
                        root: self.root.clone(),
                        available: self.available_list(),
                    });
                }
                dir
            }
            None => {
                let resolved = self.resolve(name)?;
                resolved.dir
            }
        };
        let manifest = self.read_manifest(&dir)?;
        Ok((dir, manifest))
    }

    pub fn resolve(&self, name: &str) -> Result<ResolvedImage, ImageError> {
        Self::require_name(name)?;
        let dir = self.image_dir(name);
        if !dir.is_dir() {
            return Err(ImageError::NotFound {
                name: name.to_string(),
                root: self.root.clone(),
                available: self.available_list(),
            });
        }

        if let Some(version) = self.current(name)? {
            if version == LEGACY_VERSION {
            } else {
                let vdir = self.version_dir(name, &version);
                let kernel_path = vdir.join(KERNEL_FILE);
                let rootfs_path = vdir.join(ROOTFS_FILE);
                if !kernel_path.is_file() || !rootfs_path.is_file() {
                    return Err(ImageError::Incomplete {
                        name: name.to_string(),
                        missing: if !kernel_path.is_file() {
                            KERNEL_FILE.to_string()
                        } else {
                            ROOTFS_FILE.to_string()
                        },
                        dir: vdir,
                    });
                }
                return Ok(ResolvedImage {
                    name: name.to_string(),
                    version: Some(version),
                    manifest: self.read_manifest(&vdir)?,
                    dir: vdir,
                    kernel_path,
                    rootfs_path,
                });
            }
        }

        let kernel_path = dir.join(KERNEL_FILE);
        let rootfs_path = dir.join(ROOTFS_FILE);
        if !kernel_path.is_file() || !rootfs_path.is_file() {
            return Err(ImageError::Incomplete {
                name: name.to_string(),
                missing: if !kernel_path.is_file() {
                    KERNEL_FILE.to_string()
                } else {
                    ROOTFS_FILE.to_string()
                },
                dir,
            });
        }
        Ok(ResolvedImage {
            name: name.to_string(),
            version: None,
            manifest: self.read_manifest(&dir)?,
            dir,
            kernel_path,
            rootfs_path,
        })
    }

    pub fn set_current(&self, name: &str, version: &str) -> Result<(), ImageError> {
        Self::require_name(name)?;
        validate_version(version).map_err(|_| ImageError::InvalidVersion(version.to_string()))?;
        if version == LEGACY_VERSION {
            if !self.has_legacy(name) {
                return Err(ImageError::Other(format!(
                    "image '{name}' has no legacy flat layout to point at"
                )));
            }
            let link = self.current_link(name);
            if link.symlink_metadata().is_ok() {
                fs::remove_file(&link)?;
            }
            return Ok(());
        }
        let vdir = self.version_dir(name, version);
        if !vdir.is_dir() {
            return Err(ImageError::NotFound {
                name: format!("{name}@{version}"),
                root: self.root.clone(),
                available: self.available_list(),
            });
        }
        let link = self.current_link(name);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        let temp = link.with_file_name(format!("current.tmp-{}", Uuid::new_v4()));
        let _ = fs::remove_file(&temp);
        std::os::unix::fs::symlink(format!("versions/{version}"), &temp)?;
        fs::rename(&temp, &link)?;
        Ok(())
    }

    pub fn publish(
        &self,
        name: &str,
        version: &str,
        staging: &Path,
    ) -> Result<PathBuf, ImageError> {
        Self::require_name(name)?;
        validate_version(version).map_err(|_| ImageError::InvalidVersion(version.to_string()))?;
        let target = self.version_dir(name, version);
        if target.exists() {
            return Err(ImageError::VersionExists(
                version.to_string(),
                name.to_string(),
            ));
        }
        fs::create_dir_all(self.versions_dir(name))?;
        fs::rename(staging, &target)?;
        Ok(target)
    }

    pub fn remove_version(&self, name: &str, version: &str) -> Result<(), ImageError> {
        Self::require_name(name)?;
        validate_version(version).map_err(|_| ImageError::InvalidVersion(version.to_string()))?;

        if version == LEGACY_VERSION {
            let dir = self.image_dir(name);
            for file in [KERNEL_FILE, KERNEL_CONFIG_FILE, ROOTFS_FILE, MANIFEST_FILE] {
                let _ = fs::remove_file(dir.join(file));
            }
            return Ok(());
        }

        let dir = self.version_dir(name, version);
        if !dir.is_dir() {
            return Err(ImageError::NotFound {
                name: format!("{name}@{version}"),
                root: self.root.clone(),
                available: self.available_list(),
            });
        }
        let was_current = self.current(name)?.as_deref() == Some(version);
        fs::remove_dir_all(&dir)?;
        if was_current {
            let remaining: Vec<String> = self
                .versions(name)?
                .into_iter()
                .filter(|v| !v.legacy)
                .map(|v| v.version)
                .collect();
            match remaining.first() {
                Some(newest) => self.set_current(name, newest)?,
                None => {
                    let link = self.current_link(name);
                    if link.symlink_metadata().is_ok() {
                        fs::remove_file(&link)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn remove_image(&self, name: &str) -> Result<(), ImageError> {
        Self::require_name(name)?;
        let dir = self.image_dir(name);
        if !dir.is_dir() {
            return Err(ImageError::NotFound {
                name: name.to_string(),
                root: self.root.clone(),
                available: self.available_list(),
            });
        }
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    pub fn verify(&self, name: &str, version: Option<&str>) -> Result<Vec<String>, ImageError> {
        let (dir, manifest) = self.manifest(name, version)?;
        let Some(manifest) = manifest else {
            return Ok(vec![format!(
                "{name}@{}: no manifest.json (legacy layout); checksums unavailable",
                version.unwrap_or("current")
            )]);
        };

        let mut issues = Vec::new();
        let artifacts = [
            ("kernel", &manifest.artifacts.kernel),
            ("rootfs", &manifest.artifacts.rootfs),
        ];
        for (label, artifact) in artifacts {
            let path = dir.join(&artifact.file);
            match sha256_file(&path) {
                Ok(actual) if actual == artifact.sha256 => {}
                Ok(actual) => issues.push(format!(
                    "{label} ({}): expected sha256 {}, got {actual}",
                    artifact.file, artifact.sha256
                )),
                Err(err) => issues.push(format!("{label} ({}): cannot read: {err}", artifact.file)),
            }
        }
        if let Some(config) = &manifest.artifacts.kernel_config {
            let path = dir.join(&config.file);
            match sha256_file(&path) {
                Ok(actual) if actual == config.sha256 => {}
                Ok(actual) => issues.push(format!(
                    "kernel_config ({}): expected sha256 {}, got {actual}",
                    config.file, config.sha256
                )),
                Err(err) => issues.push(format!(
                    "kernel_config ({}): cannot read: {err}",
                    config.file
                )),
            }
        }
        Ok(issues)
    }

    pub fn next_version(&self, name: &str, now: Timestamp) -> String {
        let today = kletka_types::time::date(now);
        let existing: Vec<String> = self
            .versions(name)
            .unwrap_or_default()
            .into_iter()
            .map(|v| v.version)
            .filter(|v| v.starts_with(&today))
            .collect();
        let max_n = existing
            .iter()
            .filter_map(|v| v.rsplit('.').next()?.parse::<u32>().ok())
            .max()
            .unwrap_or(0);
        format!("{today}.{}", max_n + 1)
    }

    pub fn export(
        &self,
        name: &str,
        version: Option<&str>,
        output: &Path,
    ) -> Result<ImageManifest, ImageError> {
        let (dir, manifest) = self.manifest(name, version)?;
        let manifest = manifest.ok_or_else(|| {
            ImageError::Other(format!(
                "image '{name}' has no manifest.json; only versioned images can be exported"
            ))
        })?;

        let mut files = vec![MANIFEST_FILE.to_string()];
        for artifact in [&manifest.artifacts.kernel, &manifest.artifacts.rootfs] {
            if !files.contains(&artifact.file) {
                files.push(artifact.file.clone());
            }
        }
        if let Some(config) = &manifest.artifacts.kernel_config
            && !files.contains(&config.file)
        {
            files.push(config.file.clone());
        }

        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(output)
            .arg("-C")
            .arg(&dir)
            .args(&files)
            .status()
            .map_err(|err| ImageError::Other(format!("cannot run tar to export image: {err}")))?;
        if !status.success() {
            return Err(ImageError::Other(format!(
                "tar failed exporting {name} to {}",
                output.display()
            )));
        }
        Ok(manifest)
    }

    pub fn import(
        &self,
        archive: &Path,
        name_override: Option<&str>,
        set_current: bool,
        force: bool,
    ) -> Result<ImageManifest, ImageError> {
        if let Some(name) = name_override {
            Self::require_name(name)?;
        }

        let staging = self.root.join(format!(".import-{}", Uuid::new_v4()));
        fs::create_dir_all(&staging)?;
        let result = self.import_inner(archive, name_override, set_current, force, &staging);
        let _ = fs::remove_dir_all(&staging);
        result
    }

    fn import_inner(
        &self,
        archive: &Path,
        name_override: Option<&str>,
        set_current: bool,
        force: bool,
        staging: &Path,
    ) -> Result<ImageManifest, ImageError> {
        let status = std::process::Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(staging)
            .status()
            .map_err(|err| ImageError::Other(format!("cannot run tar to import image: {err}")))?;
        if !status.success() {
            return Err(ImageError::Other(format!(
                "tar failed extracting {}",
                archive.display()
            )));
        }

        let manifest_path = staging.join(MANIFEST_FILE);
        let bytes = fs::read(&manifest_path).map_err(|err| {
            ImageError::Other(format!(
                "{}: not a kletka image archive (no manifest.json): {err}",
                archive.display()
            ))
        })?;
        let mut manifest: ImageManifest =
            serde_json::from_slice(&bytes).map_err(|source| ImageError::CorruptManifest {
                path: manifest_path.clone(),
                source,
            })?;
        if manifest.schema != MANIFEST_SCHEMA {
            return Err(ImageError::UnsupportedSchema {
                schema: manifest.schema,
                path: manifest_path,
            });
        }

        let name = match name_override {
            Some(name) => {
                manifest.name = name.to_string();
                name.to_string()
            }
            None => {
                Self::require_name(&manifest.name)?;
                manifest.name.clone()
            }
        };
        let version = manifest.version.clone();

        let mut artifacts = vec![
            manifest.artifacts.kernel.clone(),
            manifest.artifacts.rootfs.clone(),
        ];
        if let Some(config) = &manifest.artifacts.kernel_config {
            artifacts.push(config.clone());
        }
        for artifact in &artifacts {
            let path = staging.join(&artifact.file);
            let actual = sha256_file(&path).map_err(|err| {
                ImageError::Other(format!("imported artifact '{}': {err}", artifact.file))
            })?;
            if actual != artifact.sha256 {
                return Err(ImageError::ChecksumMismatch {
                    file: artifact.file.clone(),
                    dir: staging.to_path_buf(),
                    expected: artifact.sha256.clone(),
                    actual,
                });
            }
        }

        let bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|err| ImageError::Other(format!("cannot re-encode manifest: {err}")))?;
        fs::write(staging.join(MANIFEST_FILE), bytes)?;

        let target = self.version_dir(&name, &version);
        if target.exists() {
            if !force {
                return Err(ImageError::VersionExists(version, name));
            }
            fs::remove_dir_all(&target)?;
        }
        fs::create_dir_all(self.versions_dir(&name))?;
        fs::rename(staging, &target)?;

        let current = self.current(&name)?;
        if set_current || current.is_none() {
            self.set_current(&name, &version)?;
        }

        Ok(manifest)
    }
}

pub fn sha256_file(path: &Path) -> Result<String, ImageError> {
    use sha2::{Digest as _, Sha256};

    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn validate_image_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("image name cannot be empty".to_string());
    }
    if name.starts_with('.') {
        return Err("image name cannot start with '.'".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "invalid name '{name}': use letters, digits, '.', '-', '_'"
        ));
    }
    Ok(())
}

pub fn validate_version(version: &str) -> Result<(), String> {
    if version.is_empty() {
        return Err("version cannot be empty".to_string());
    }
    if !version
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(format!(
            "invalid version '{version}': use letters, digits, '.', '-', '_'"
        ));
    }
    Ok(())
}

fn dir_size(dir: &Path) -> u64 {
    [KERNEL_FILE, KERNEL_CONFIG_FILE, ROOTFS_FILE]
        .iter()
        .filter_map(|f| fs::metadata(dir.join(f)).ok())
        .map(|m| m.len())
        .sum()
}

fn dir_used(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    [KERNEL_FILE, KERNEL_CONFIG_FILE, ROOTFS_FILE]
        .iter()
        .filter_map(|f| fs::metadata(dir.join(f)).ok())
        .map(|m| m.blocks() * 512)
        .sum()
}

pub fn write_manifest(dir: &Path, manifest: &ImageManifest) -> Result<(), ImageError> {
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|err| ImageError::Other(format!("cannot encode manifest: {err}")))?;
    let path = dir.join(MANIFEST_FILE);
    let mut file = fs::File::create(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::test_util::TempDir;

    fn mkstore(dir: &TempDir) -> ImageStore {
        ImageStore::new(dir.path().join("images"))
    }

    fn make_version(
        store: &ImageStore,
        name: &str,
        version: &str,
        kernel: &[u8],
        rootfs: &[u8],
        created_at: i64,
    ) -> PathBuf {
        let dir = store.root().join(name).join("versions").join(version);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(KERNEL_FILE), kernel).unwrap();
        fs::write(dir.join(ROOTFS_FILE), rootfs).unwrap();
        let manifest = ImageManifest {
            schema: MANIFEST_SCHEMA,
            name: name.to_string(),
            version: version.to_string(),
            created_at: kletka_types::time::from_unix(created_at),
            parent: None,
            source: ImageSource {
                git_sha: Some("abc123".to_string()),
                git_dirty: false,
                dockerfile: "docker/rootfs/Dockerfile".to_string(),
                dockerfile_sha256: "deadbeef".to_string(),
                base_image: Some("fedora:44".to_string()),
                updated: false,
                kernel_reused_from: None,
                rootfs_reused_from: None,
                embedded_version: None,
                kernel_inputs_sha256: Some("cafebabe".to_string()),
            },
            artifacts: ImageArtifacts {
                kernel: ArtifactInfo {
                    file: KERNEL_FILE.to_string(),
                    size_bytes: kernel.len() as u64,
                    sha256: sha256_file(&dir.join(KERNEL_FILE)).unwrap(),
                    used_bytes: Some(kernel.len() as u64),
                    fs_bytes: None,
                },
                kernel_config: None,
                rootfs: ArtifactInfo {
                    file: ROOTFS_FILE.to_string(),
                    size_bytes: rootfs.len() as u64,
                    sha256: sha256_file(&dir.join(ROOTFS_FILE)).unwrap(),
                    used_bytes: Some(rootfs.len() as u64),
                    fs_bytes: Some(rootfs.len() as u64),
                },
            },
            overlay_boot: false,
            labels: Default::default(),
        };
        write_manifest(&dir, &manifest).unwrap();
        dir
    }

    #[test]
    fn sha256_known_vector() {
        let dir = TempDir::new("img-sha");
        let path = dir.path().join("f");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256_file(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn name_and_version_validation() {
        assert!(validate_image_name("default").is_ok());
        assert!(validate_image_name("web-2026.10").is_ok());
        assert!(validate_image_name("").is_err());
        assert!(validate_image_name(".hidden").is_err());
        assert!(validate_image_name("a/b").is_err());
        assert!(validate_image_name("a b").is_err());
        assert!(validate_version("2026-10-29.1").is_ok());
        assert!(validate_version("v1.2.3").is_ok());
        assert!(validate_version("../etc").is_err());
        assert!(validate_version("").is_err());
    }

    #[test]
    fn next_version_counts_per_day() {
        let dir = TempDir::new("img-nextver");
        let store = mkstore(&dir);
        let secs = 1_793_275_200;
        let now = kletka_types::time::from_unix(secs);
        assert_eq!(store.next_version("default", now), "2026-10-29.1");

        make_version(&store, "default", "2026-10-29.1", b"k", b"r", secs);
        assert_eq!(store.next_version("default", now), "2026-10-29.2");

        make_version(&store, "default", "2026-10-29.7", b"k", b"r", secs);
        assert_eq!(store.next_version("default", now), "2026-10-29.8");

        let later = kletka_types::time::from_unix(secs + 86_400 * 3);
        assert_eq!(store.next_version("default", later), "2026-11-01.1");
    }

    #[test]
    fn resolve_legacy_flat_layout() {
        let dir = TempDir::new("img-legacy");
        let store = mkstore(&dir);
        let img = store.root().join("default");
        fs::create_dir_all(&img).unwrap();
        fs::write(img.join(KERNEL_FILE), b"k").unwrap();
        fs::write(img.join(ROOTFS_FILE), b"r").unwrap();

        let resolved = store.resolve("default").unwrap();
        assert_eq!(resolved.version, None);
        assert_eq!(resolved.kernel_path, img.join(KERNEL_FILE));
        assert_eq!(
            store.current("default").unwrap().as_deref(),
            Some(LEGACY_VERSION)
        );

        let summary = store.show("default").unwrap();
        assert_eq!(summary.versions.len(), 1);
        assert!(summary.versions[0].legacy);
    }

    #[test]
    fn resolve_prefers_current_version() {
        let dir = TempDir::new("img-current");
        let store = mkstore(&dir);
        make_version(&store, "default", "2026-10-28.1", b"k1", b"r1", 100);
        make_version(&store, "default", "2026-10-29.1", b"k2", b"r2", 200);
        store.set_current("default", "2026-10-28.1").unwrap();

        let resolved = store.resolve("default").unwrap();
        assert_eq!(resolved.version.as_deref(), Some("2026-10-28.1"));
        assert!(
            resolved
                .kernel_path
                .ends_with("versions/2026-10-28.1/vmlinux")
        );
        assert_eq!(fs::read(&resolved.kernel_path).unwrap(), b"k1");

        store.set_current("default", "2026-10-29.1").unwrap();
        let resolved = store.resolve("default").unwrap();
        assert_eq!(fs::read(&resolved.kernel_path).unwrap(), b"k2");
    }

    #[test]
    fn resolve_missing_lists_available() {
        let dir = TempDir::new("img-missing");
        let store = mkstore(&dir);
        make_version(&store, "default", "2026-10-29.1", b"k", b"r", 1);
        store.set_current("default", "2026-10-29.1").unwrap();

        let err = store.resolve("ghost").unwrap_err().to_string();
        assert!(err.contains("'ghost' not found"), "{err}");
        assert!(err.contains("default"), "lists available: {err}");
    }

    #[test]
    fn manifest_overlay_boot_defaults_false_and_roundtrips() {
        let dir = TempDir::new("img-overlayflag");
        let store = mkstore(&dir);
        let vdir = make_version(&store, "default", "2026-10-29.1", b"k", b"r", 1);

        let path = vdir.join(MANIFEST_FILE);
        let bytes = fs::read(&path).unwrap();
        let stripped: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let stripped = match stripped {
            serde_json::Value::Object(mut map) => {
                map.remove("overlay_boot");
                serde_json::Value::Object(map)
            }
            other => other,
        };
        let manifest: ImageManifest = serde_json::from_value(stripped).unwrap();
        assert!(!manifest.overlay_boot);

        let mut flagged = manifest;
        flagged.overlay_boot = true;
        write_manifest(&vdir, &flagged).unwrap();
        let reread: ImageManifest = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(reread.overlay_boot);

        store.set_current("default", "2026-10-29.1").unwrap();
        assert!(store.resolve("default").unwrap().overlay_boot());
    }

    #[test]
    fn set_current_rejects_unknown_version() {
        let dir = TempDir::new("img-setcur");
        let store = mkstore(&dir);
        make_version(&store, "default", "2026-10-29.1", b"k", b"r", 1);
        let err = store.set_current("default", "9999-01-01.1").unwrap_err();
        assert!(err.to_string().contains("9999-01-01.1"), "{err}");
        assert!(store.set_current("default", "../evil").is_err());
    }

    #[test]
    fn remove_version_flips_current_to_newest_remaining() {
        let dir = TempDir::new("img-rmver");
        let store = mkstore(&dir);
        make_version(&store, "default", "2026-10-28.1", b"k", b"r", 100);
        make_version(&store, "default", "2026-10-29.1", b"k", b"r", 200);
        make_version(&store, "default", "2026-10-30.1", b"k", b"r", 300);
        store.set_current("default", "2026-10-30.1").unwrap();

        store.remove_version("default", "2026-10-30.1").unwrap();
        assert_eq!(
            store.current("default").unwrap().as_deref(),
            Some("2026-10-29.1")
        );
        assert!(!store.version_dir("default", "2026-10-30.1").exists());

        store.remove_version("default", "2026-10-29.1").unwrap();
        assert_eq!(
            store.current("default").unwrap().as_deref(),
            Some("2026-10-28.1")
        );

        store.remove_version("default", "2026-10-28.1").unwrap();
        assert_eq!(store.current("default").unwrap(), None);
    }

    #[test]
    fn remove_legacy_keeps_versioned_current() {
        let dir = TempDir::new("img-rmlegacy");
        let store = mkstore(&dir);
        let img = store.root().join("default");
        fs::create_dir_all(&img).unwrap();
        fs::write(img.join(KERNEL_FILE), b"k").unwrap();
        fs::write(img.join(ROOTFS_FILE), b"r").unwrap();
        make_version(&store, "default", "2026-10-29.1", b"k2", b"r2", 100);
        store.set_current("default", "2026-10-29.1").unwrap();

        store.remove_version("default", LEGACY_VERSION).unwrap();

        assert!(!img.join(ROOTFS_FILE).exists(), "flat files removed");
        assert_eq!(
            store.current("default").unwrap().as_deref(),
            Some("2026-10-29.1"),
            "current symlink to the version survives"
        );
        let resolved = store.resolve("default").unwrap();
        assert_eq!(resolved.version.as_deref(), Some("2026-10-29.1"));
        assert_eq!(fs::read(&resolved.rootfs_path).unwrap(), b"r2");
    }

    #[test]
    fn remove_image_deletes_everything() {
        let dir = TempDir::new("img-rmimg");
        let store = mkstore(&dir);
        make_version(&store, "default", "2026-10-29.1", b"k", b"r", 1);
        store.set_current("default", "2026-10-29.1").unwrap();
        store.remove_image("default").unwrap();
        assert!(!store.root().join("default").exists());
        assert!(store.resolve("default").is_err());
    }

    #[test]
    fn publish_is_atomic_and_rejects_duplicates() {
        let dir = TempDir::new("img-publish");
        let store = mkstore(&dir);
        let staging = store.root().join("default").join(".staging-1");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join(KERNEL_FILE), b"k").unwrap();
        fs::write(staging.join(ROOTFS_FILE), b"r").unwrap();

        let target = store.publish("default", "2026-10-29.1", &staging).unwrap();
        assert!(target.ends_with("versions/2026-10-29.1"));
        assert!(!staging.exists(), "staging dir was renamed away");

        let staging2 = store.root().join("default").join(".staging-2");
        fs::create_dir_all(&staging2).unwrap();
        let err = store
            .publish("default", "2026-10-29.1", &staging2)
            .unwrap_err();
        assert!(matches!(err, ImageError::VersionExists(_, _)), "{err}");
    }

    #[test]
    fn verify_detects_tampering() {
        let dir = TempDir::new("img-verify");
        let store = mkstore(&dir);
        let vdir = make_version(&store, "default", "2026-10-29.1", b"kernel", b"rootfs", 1);
        store.set_current("default", "2026-10-29.1").unwrap();

        assert!(store.verify("default", None).unwrap().is_empty());

        fs::write(vdir.join(ROOTFS_FILE), b"tampered").unwrap();
        let issues = store.verify("default", Some("2026-10-29.1")).unwrap();
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("rootfs"), "{}", issues[0]);
        assert!(issues[0].contains("expected sha256"), "{}", issues[0]);
    }

    fn have_tar() -> bool {
        std::env::var_os("PATH")
            .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join("tar").is_file()))
    }

    #[test]
    fn export_import_roundtrip_with_checksum_verification() {
        if !have_tar() {
            return;
        }
        let dir = TempDir::new("img-tar");
        let store = mkstore(&dir);
        make_version(
            &store,
            "default",
            "2026-10-29.1",
            b"kernel-bytes",
            b"rootfs-bytes",
            42,
        );
        store.set_current("default", "2026-10-29.1").unwrap();

        let archive = dir.path().join("default-2026-10-29.1.tar");
        let manifest = store.export("default", None, &archive).unwrap();
        assert_eq!(manifest.version, "2026-10-29.1");
        assert!(archive.is_file());

        let dir2 = TempDir::new("img-tar2");
        let store2 = mkstore(&dir2);
        let imported = store2.import(&archive, None, true, false).unwrap();
        assert_eq!(imported.version, "2026-10-29.1");
        assert_eq!(
            store2.current("default").unwrap().as_deref(),
            Some("2026-10-29.1")
        );
        let resolved = store2.resolve("default").unwrap();
        assert_eq!(fs::read(&resolved.kernel_path).unwrap(), b"kernel-bytes");
        assert_eq!(fs::read(&resolved.rootfs_path).unwrap(), b"rootfs-bytes");
        assert!(store2.verify("default", None).unwrap().is_empty());

        let err = store2.import(&archive, None, false, false).unwrap_err();
        assert!(matches!(err, ImageError::VersionExists(_, _)), "{err}");
        store2.import(&archive, None, false, true).unwrap();
    }

    #[test]
    fn import_rejects_tampered_archive() {
        if !have_tar() {
            return;
        }
        let dir = TempDir::new("img-tarbad");
        let store = mkstore(&dir);
        let vdir = make_version(&store, "default", "2026-10-29.1", b"k", b"r", 1);
        let archive = dir.path().join("img.tar");
        store
            .export("default", Some("2026-10-29.1"), &archive)
            .unwrap();

        fs::write(vdir.join(ROOTFS_FILE), b"evil").unwrap();
        let archive2 = dir.path().join("evil.tar");
        store
            .export("default", Some("2026-10-29.1"), &archive2)
            .unwrap();
        let work = dir.path().join("work");
        fs::create_dir_all(&work).unwrap();
        let status = std::process::Command::new("tar")
            .args(["-xf"])
            .arg(&archive)
            .arg("-C")
            .arg(&work)
            .status()
            .unwrap();
        assert!(status.success());
        fs::write(work.join(ROOTFS_FILE), b"evil").unwrap();
        let status = std::process::Command::new("tar")
            .args(["-cf"])
            .arg(&archive2)
            .arg("-C")
            .arg(&work)
            .args([MANIFEST_FILE, KERNEL_FILE, ROOTFS_FILE])
            .status()
            .unwrap();
        assert!(status.success());

        let dir2 = TempDir::new("img-tarbad2");
        let store2 = mkstore(&dir2);
        let err = store2.import(&archive2, None, false, false).unwrap_err();
        assert!(matches!(err, ImageError::ChecksumMismatch { .. }), "{err}");
        assert!(
            !store2
                .root()
                .join("default")
                .join("versions")
                .join("2026-10-29.1")
                .exists()
        );
    }

    #[test]
    fn import_with_name_override() {
        if !have_tar() {
            return;
        }
        let dir = TempDir::new("img-rename");
        let store = mkstore(&dir);
        make_version(&store, "default", "2026-10-29.1", b"k", b"r", 1);
        let archive = dir.path().join("img.tar");
        store
            .export("default", Some("2026-10-29.1"), &archive)
            .unwrap();

        let dir2 = TempDir::new("img-rename2");
        let store2 = mkstore(&dir2);
        let imported = store2
            .import(&archive, Some("golden"), false, false)
            .unwrap();
        assert_eq!(imported.name, "golden");
        assert_eq!(
            store2.current("golden").unwrap().as_deref(),
            Some("2026-10-29.1")
        );
        assert!(store2.resolve("golden").is_ok());
    }

    #[test]
    fn list_summarizes_all_images() {
        let dir = TempDir::new("img-list");
        let store = mkstore(&dir);
        make_version(&store, "default", "2026-10-29.1", b"k", b"rrrr", 100);
        make_version(&store, "default", "2026-10-28.1", b"k", b"r", 50);
        store.set_current("default", "2026-10-29.1").unwrap();

        let img = store.root().join("old");
        fs::create_dir_all(&img).unwrap();
        fs::write(img.join(KERNEL_FILE), b"k").unwrap();
        fs::write(img.join(ROOTFS_FILE), b"r").unwrap();

        let images = store.list().unwrap();
        assert_eq!(images.len(), 2);
        let default = images.iter().find(|i| i.name == "default").unwrap();
        assert_eq!(default.current.as_deref(), Some("2026-10-29.1"));
        assert_eq!(default.versions.len(), 2);
        assert!(default.versions[0].current, "newest first + current flag");
        assert_eq!(default.versions[0].version, "2026-10-29.1");
        let old = images.iter().find(|i| i.name == "old").unwrap();
        assert_eq!(old.current.as_deref(), Some(LEGACY_VERSION));
        assert!(old.versions[0].legacy);
    }

    #[test]
    fn manifest_roundtrip() {
        let dir = TempDir::new("img-manifest");
        let store = mkstore(&dir);
        let vdir = make_version(&store, "default", "2026-10-29.1", b"k", b"r", 7);
        let (dir2, manifest) = store.manifest("default", Some("2026-10-29.1")).unwrap();
        assert_eq!(dir2, vdir);
        let manifest = manifest.unwrap();
        assert_eq!(manifest.schema, MANIFEST_SCHEMA);
        assert_eq!(manifest.source.git_sha.as_deref(), Some("abc123"));
        assert_eq!(manifest.artifacts.rootfs.fs_bytes, Some(1));
    }
}
