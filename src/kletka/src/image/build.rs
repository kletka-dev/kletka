use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::embedded;
use super::{
    ArtifactInfo, ImageArtifacts, ImageManifest, ImageSource, ImageStore, KERNEL_CONFIG_FILE,
    KERNEL_FILE, MANIFEST_SCHEMA, ROOTFS_FILE, sha256_file, validate_image_name, validate_version,
    write_manifest,
};
use crate::fsutil::{disk_usage, ext4_size, thin_copy};
use crate::system::on_path;

pub const ROOTFS_DOCKERFILE: &str = "docker/rootfs/Dockerfile";
pub const KERNEL_DOCKERFILE_DIR: &str = "docker/kernel";
pub const ROOTFS_DOCKERFILE_DIR: &str = "docker/rootfs";

pub const OVERLAY_BASE_TAG: &str = "localhost/kletka-base:latest";
pub const OVERLAY_SHA_LABEL: &str = "kletka.image.definition.sha256";

pub const DEFAULT_SIZE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub images_root: PathBuf,
    pub name: String,
    pub version: Option<String>,
    pub size_bytes: u64,
    pub update: bool,
    pub skip_kernel: bool,
    pub skip_rootfs: bool,
    pub kernel_from: Option<PathBuf>,
    pub rootfs_overlay: Option<PathBuf>,
    pub repo: Option<PathBuf>,
    pub engine: Option<String>,
    pub set_current: bool,
    pub now: kletka_types::time::Timestamp,
}

#[derive(Debug, Clone)]
pub struct BuildResult {
    pub name: String,
    pub version: String,
    pub dir: PathBuf,
    pub manifest: ImageManifest,
    pub current: bool,
}

pub fn build(opts: &BuildOptions) -> Result<BuildResult, String> {
    validate_image_name(&opts.name).map_err(|err| format!("invalid image name: {err}"))?;
    if let Some(version) = &opts.version {
        validate_version(version).map_err(|err| format!("invalid version: {err}"))?;
    }
    if opts.skip_kernel && opts.skip_rootfs {
        return Err("nothing to build: --skip-kernel and --skip-rootfs are both set".to_string());
    }

    let store = ImageStore::new(opts.images_root.clone());
    let repo = resolve_repo(opts.repo.as_deref())?;
    let engine = resolve_engine(opts.engine.as_deref())?;
    let version = match &opts.version {
        Some(v) => v.clone(),
        None => store.next_version(&opts.name, opts.now),
    };
    if store
        .versions(&opts.name)
        .map(|vs| vs.iter().any(|v| v.version == version))
        .unwrap_or(false)
    {
        return Err(format!(
            "version '{version}' of image '{}' already exists; pass a new --version",
            opts.name
        ));
    }

    let previous = store.resolve(&opts.name).ok();
    let parent = previous.as_ref().and_then(|p| p.version.clone());

    let kernel_source_missing = opts.skip_kernel && opts.kernel_from.is_none();
    if (kernel_source_missing || opts.skip_rootfs) && previous.is_none() {
        return Err(format!(
            "image '{}' has no current version to reuse artifacts from; build without --skip-* \
             first",
            opts.name
        ));
    }

    let size_bytes = if opts.skip_rootfs {
        previous
            .as_ref()
            .and_then(|p| p.manifest.as_ref())
            .and_then(|m| m.artifacts.rootfs.fs_bytes)
            .unwrap_or(opts.size_bytes)
    } else {
        opts.size_bytes
    };

    let image_dir = store.root().join(&opts.name);
    fs::create_dir_all(&image_dir)
        .map_err(|err| format!("cannot create {}: {err}", image_dir.display()))?;
    let staging = image_dir.join(format!(".staging-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&staging).map_err(|err| format!("cannot create staging dir: {err}"))?;

    let result = build_inner(
        opts,
        &repo,
        &engine,
        &version,
        size_bytes,
        &previous,
        parent.clone(),
        &staging,
    );

    match result {
        Ok(manifest) => {
            let dir = store
                .publish(&opts.name, &version, &staging)
                .map_err(|err| err.to_string())?;
            let mut current = false;
            if opts.set_current {
                store
                    .set_current(&opts.name, &version)
                    .map_err(|err| err.to_string())?;
                current = true;
            }
            Ok(BuildResult {
                name: opts.name.clone(),
                version: version.clone(),
                dir,
                manifest,
                current,
            })
        }
        Err(err) => {
            let _ = fs::remove_dir_all(&staging);
            Err(err)
        }
    }
}

fn build_inner(
    opts: &BuildOptions,
    repo: &Path,
    engine: &str,
    version: &str,
    size_bytes: u64,
    previous: &Option<super::ResolvedImage>,
    parent: Option<String>,
    staging: &Path,
) -> Result<ImageManifest, String> {
    let prev_dir = previous.as_ref().map(|p| p.dir.clone());
    let prev_manifest = previous.as_ref().and_then(|p| p.manifest.clone());

    let (kernel_bytes, kernel_sha, kernel_reused_from, kernel_inputs_sha) = if opts.skip_kernel {
        let (kernel_dir, kernel_manifest) = match &opts.kernel_from {
            Some(dir) => (
                dir.clone(),
                ImageStore::new(opts.images_root.clone())
                    .read_manifest(dir)
                    .map_err(|err| format!("cannot read kernel source manifest: {err}"))?,
            ),
            None => (
                prev_dir.clone().expect("checked above"),
                prev_manifest.clone(),
            ),
        };
        let prev_dir = &kernel_dir;
        let prev_manifest = &kernel_manifest;
        let src = prev_dir.join(KERNEL_FILE);
        fs::copy(&src, staging.join(KERNEL_FILE))
            .map_err(|err| format!("cannot reuse kernel from {}: {err}", src.display()))?;
        if let Some(config) = prev_manifest
            .as_ref()
            .and_then(|m| m.artifacts.kernel_config.as_ref())
        {
            let config_src = prev_dir.join(&config.file);
            if config_src.is_file() {
                fs::copy(&config_src, staging.join(&config.file)).map_err(|err| {
                    format!("cannot reuse {} from {}: {err}", config.file, src.display())
                })?;
            }
        }
        let sha = sha256_file(&staging.join(KERNEL_FILE)).map_err(|err| err.to_string())?;
        let bytes = fs::metadata(staging.join(KERNEL_FILE))
            .map_err(|err| err.to_string())?
            .len();
        let reused = prev_manifest.as_ref().map(|m| {
            if m.name == opts.name {
                m.version.clone()
            } else {
                format!("{}:{}", m.name, m.version)
            }
        });
        let inputs = prev_manifest
            .as_ref()
            .and_then(|m| m.source.kernel_inputs_sha256.clone())
            .or_else(|| hash_kernel_inputs(repo));
        (bytes, sha, reused, inputs)
    } else {
        eprintln!("==> building kernel container ({engine})");
        let out = staging.join("kernel-out");
        run(
            Command::new(engine)
                .arg("build")
                .arg("--output")
                .arg(format!("type=local,dest={}", out.display()))
                .arg("-t")
                .arg("kletka-kernel:dev")
                .arg(repo.join(KERNEL_DOCKERFILE_DIR)),
            "kernel container build",
        )?;
        fs::copy(out.join(KERNEL_FILE), staging.join(KERNEL_FILE))
            .map_err(|err| format!("kernel build produced no vmlinux: {err}"))?;
        let config_src = out.join("kernel.config");
        if config_src.is_file() {
            fs::copy(&config_src, staging.join(KERNEL_CONFIG_FILE))
                .map_err(|err| format!("cannot copy kernel.config: {err}"))?;
        }
        let _ = fs::remove_dir_all(&out);
        let sha = sha256_file(&staging.join(KERNEL_FILE)).map_err(|err| err.to_string())?;
        let bytes = fs::metadata(staging.join(KERNEL_FILE))
            .map_err(|err| err.to_string())?
            .len();
        let inputs = hash_kernel_inputs(repo);
        (bytes, sha, None, inputs)
    };

    let (rootfs_bytes, rootfs_sha, rootfs_used, rootfs_fs, rootfs_reused_from) = if opts.skip_rootfs
    {
        let prev_dir = prev_dir.as_ref().expect("checked above");
        let src = prev_dir.join(ROOTFS_FILE);
        thin_copy(&src, &staging.join(ROOTFS_FILE)).map_err(|err| err.to_string())?;
        let sha = sha256_file(&staging.join(ROOTFS_FILE)).map_err(|err| err.to_string())?;
        let meta = fs::metadata(staging.join(ROOTFS_FILE)).map_err(|err| err.to_string())?;
        let fs_bytes = ext4_size(&staging.join(ROOTFS_FILE)).map_err(|err| err.to_string())?;
        (
            meta.len(),
            sha,
            disk_usage(&staging.join(ROOTFS_FILE)).map_err(|err| err.to_string())?,
            fs_bytes,
            prev_manifest.as_ref().map(|m| m.version.clone()),
        )
    } else {
        eprintln!("==> building rootfs container ({engine})");
        let mut cmd = Command::new(engine);
        cmd.arg("build").arg("-t").arg("kletka-rootfs:dev");
        if opts.rootfs_overlay.is_some() {
            cmd.arg("-t").arg(OVERLAY_BASE_TAG);
        }
        if opts.update {
            cmd.arg("--build-arg").arg("KLETKA_UPDATE=1");
        }
        cmd.arg(repo.join(ROOTFS_DOCKERFILE_DIR));
        run(&mut cmd, "rootfs container build")?;

        let rootfs_tag = if let Some(overlay) = &opts.rootfs_overlay {
            eprintln!("==> building image definition '{}' ({engine})", opts.name);
            run(
                Command::new(engine)
                    .arg("build")
                    .arg("-t")
                    .arg("kletka-rootfs-overlay:dev")
                    .arg("--build-arg")
                    .arg(format!("KLETKA_BASE={OVERLAY_BASE_TAG}"))
                    .arg(overlay),
                "image definition build",
            )?;
            "kletka-rootfs-overlay:dev"
        } else {
            "kletka-rootfs:dev"
        };

        eprintln!("==> exporting container filesystem");
        let tar_path = staging.join("rootfs.tar");
        let tree = staging.join("tree");
        fs::create_dir_all(&tree).map_err(|err| err.to_string())?;

        let ctr = {
            let output = Command::new(engine)
                .args(["create", rootfs_tag])
                .output()
                .map_err(|err| format!("cannot run {engine} create: {err}"))?;
            if !output.status.success() {
                return Err(format!(
                    "{engine} create failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        };

        let export = Command::new(engine)
            .arg("export")
            .arg(&ctr)
            .stdout(fs::File::create(&tar_path).map_err(|err| err.to_string())?)
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("cannot run {engine} export: {err}"))?;
        let _ = Command::new(engine)
            .args(["rm", &ctr])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !export.success() {
            return Err(format!("{engine} export failed for container {ctr}"));
        }

        eprintln!(
            "==> packing sparse rootfs.ext4 ({} max)",
            human_bytes(size_bytes)
        );
        let rootfs_path = staging.join(ROOTFS_FILE);
        let script = format!(
            "set -e\ntar -xpf '{tar}' -C '{tree}'\nchmod -R u+rwX '{tree}'\ntruncate -s {size} \
             '{rootfs}'\nmkfs.ext4 -q -F -L rootfs -d '{tree}' '{rootfs}'\n",
            tar = tar_path.display(),
            tree = tree.display(),
            size = size_bytes,
            rootfs = rootfs_path.display(),
        );
        let is_root = std::os::unix::fs::MetadataExt::uid(
            &std::fs::metadata("/proc/self")
                .map_err(|err| format!("cannot stat /proc/self: {err}"))?,
        ) == 0;
        let packing_result = if is_root {
            run(
                Command::new("bash").arg("-c").arg(&script),
                "rootfs packing (mkfs.ext4)",
            )
        } else {
            if !on_path("fakeroot") {
                return Err(
                    "fakeroot not found on PATH; it is required to build images as non-root"
                        .to_string(),
                );
            }
            let state = staging.join("fakeroot.state");
            run(
                Command::new("fakeroot")
                    .arg("-s")
                    .arg(&state)
                    .arg("--")
                    .arg("bash")
                    .arg("-c")
                    .arg(&script),
                "rootfs packing (fakeroot + mkfs.ext4)",
            )
        };
        packing_result?;
        let _ = fs::remove_file(&tar_path);
        let _ = fs::remove_dir_all(&tree);

        let sha = sha256_file(&rootfs_path).map_err(|err| err.to_string())?;
        let meta = fs::metadata(&rootfs_path).map_err(|err| err.to_string())?;
        let fs_bytes = ext4_size(&rootfs_path).map_err(|err| err.to_string())?;
        let used = disk_usage(&rootfs_path).map_err(|err| err.to_string())?;
        (meta.len(), sha, used, fs_bytes, None)
    };

    let kernel_config = if opts.skip_kernel {
        let path = staging.join(KERNEL_CONFIG_FILE);
        if path.is_file() {
            prev_manifest
                .as_ref()
                .and_then(|m| m.artifacts.kernel_config.clone())
        } else {
            None
        }
    } else {
        let path = staging.join(KERNEL_CONFIG_FILE);
        if path.is_file() {
            let sha = sha256_file(&path).map_err(|err| err.to_string())?;
            let bytes = fs::metadata(&path).map_err(|err| err.to_string())?.len();
            Some(ArtifactInfo {
                file: KERNEL_CONFIG_FILE.to_string(),
                size_bytes: bytes,
                sha256: sha,
                used_bytes: Some(bytes),
                fs_bytes: None,
            })
        } else {
            None
        }
    };

    let (git_sha, git_dirty) = git_info(repo);
    let embedded_version = if embedded::is_embedded_repo(repo) {
        Some(embedded::embedded_version().to_string())
    } else {
        None
    };
    let dockerfile_path = repo.join(ROOTFS_DOCKERFILE);
    let dockerfile_sha256 = sha256_file(&dockerfile_path)
        .map_err(|err| format!("cannot hash {}: {err}", dockerfile_path.display()))?;
    let base_image = parse_base_image(&dockerfile_path);

    let manifest = ImageManifest {
        schema: MANIFEST_SCHEMA,
        name: opts.name.clone(),
        version: version.to_string(),
        created_at: opts.now,
        overlay_boot: true,
        parent,
        source: ImageSource {
            git_sha,
            git_dirty,
            dockerfile: ROOTFS_DOCKERFILE.to_string(),
            dockerfile_sha256,
            base_image,
            updated: opts.update,
            kernel_reused_from,
            rootfs_reused_from,
            embedded_version,
            kernel_inputs_sha256: kernel_inputs_sha,
        },
        artifacts: ImageArtifacts {
            kernel: ArtifactInfo {
                file: KERNEL_FILE.to_string(),
                size_bytes: kernel_bytes,
                sha256: kernel_sha,
                used_bytes: Some(kernel_bytes),
                fs_bytes: None,
            },
            kernel_config,
            rootfs: ArtifactInfo {
                file: ROOTFS_FILE.to_string(),
                size_bytes: rootfs_bytes,
                sha256: rootfs_sha,
                used_bytes: Some(rootfs_used),
                fs_bytes: Some(rootfs_fs),
            },
        },
        labels: {
            let mut labels: std::collections::BTreeMap<String, String> = [
                ("kletka.image.name".to_string(), opts.name.clone()),
                ("kletka.image.version".to_string(), version.to_string()),
                (
                    "kletka.image.updated".to_string(),
                    if opts.update { "true" } else { "false" }.to_string(),
                ),
            ]
            .into_iter()
            .collect();
            if let Some(overlay) = &opts.rootfs_overlay {
                let dockerfile = overlay.join("Dockerfile");
                let sha = sha256_file(&dockerfile)
                    .map_err(|err| format!("cannot hash {}: {err}", dockerfile.display()))?;
                labels.insert(OVERLAY_SHA_LABEL.to_string(), sha);
            }
            labels
        },
    };
    write_manifest(staging, &manifest).map_err(|err| err.to_string())?;

    eprintln!(
        "==> published {}:{} ({})",
        opts.name,
        version,
        human_bytes(rootfs_used)
    );

    Ok(manifest)
}

pub fn hash_kernel_inputs(repo: &Path) -> Option<String> {
    use sha2::{Digest as _, Sha256};

    let dockerfile = repo.join(KERNEL_DOCKERFILE_DIR).join("Dockerfile");
    if !dockerfile.is_file() {
        return None;
    }
    let mut hasher = Sha256::new();
    for path in [
        dockerfile,
        repo.join(KERNEL_DOCKERFILE_DIR)
            .join("microvm-kletka.config"),
    ] {
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Some(hex::encode(hasher.finalize()))
}

fn run(cmd: &mut Command, what: &str) -> Result<(), String> {
    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd.status().map_err(|err| {
        format!(
            "cannot run {} ({}): {err}",
            cmd.get_program().to_string_lossy(),
            what
        )
    })?;
    if !status.success() {
        return Err(format!(
            "{what} failed (exit {})",
            status.code().unwrap_or(1)
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoOrigin {
    Disk,
    Embedded,
}

pub fn resolve_repo(explicit: Option<&Path>) -> Result<PathBuf, String> {
    Ok(resolve_repo_ex(explicit)?.0)
}

pub fn resolve_repo_ex(explicit: Option<&Path>) -> Result<(PathBuf, RepoOrigin), String> {
    let cwd = std::env::current_dir().map_err(|err| format!("cannot get CWD: {err}"))?;
    resolve_repo_at(explicit, Some(&cwd))
}

fn resolve_repo_at(
    explicit: Option<&Path>,
    cwd: Option<&Path>,
) -> Result<(PathBuf, RepoOrigin), String> {
    if let Some(repo) = explicit {
        if repo.join(ROOTFS_DOCKERFILE).is_file() {
            return Ok((repo.to_path_buf(), RepoOrigin::Disk));
        }
        return Err(format!(
            "{} does not look like the kletka repo (missing {})",
            repo.display(),
            ROOTFS_DOCKERFILE
        ));
    }
    if let Some(repo) = std::env::var_os("KLETKA_REPO") {
        let repo = PathBuf::from(repo);
        if repo.join(ROOTFS_DOCKERFILE).is_file() {
            return Ok((repo, RepoOrigin::Disk));
        }
        return Err(format!(
            "KLETKA_REPO={} does not look like the kletka repo (missing {})",
            repo.display(),
            ROOTFS_DOCKERFILE
        ));
    }
    if let Some(cwd) = cwd {
        for ancestor in cwd.ancestors() {
            if ancestor.join(ROOTFS_DOCKERFILE).is_file() {
                return Ok((ancestor.to_path_buf(), RepoOrigin::Disk));
            }
        }
    }
    let repo = embedded::extract_embedded_repo()?;
    Ok((repo, RepoOrigin::Embedded))
}

pub fn resolve_engine(explicit: Option<&str>) -> Result<String, String> {
    if let Some(engine) = explicit {
        return Ok(engine.to_string());
    }
    if let Some(engine) = std::env::var_os("KLETKA_CONTAINER_ENGINE") {
        return Ok(engine.to_string_lossy().into_owned());
    }
    for candidate in ["podman", "docker"] {
        if on_path(candidate) {
            return Ok(candidate.to_string());
        }
    }
    Err(
        "no container engine found: install podman or docker (or set KLETKA_CONTAINER_ENGINE)"
            .to_string(),
    )
}

fn git_info(repo: &Path) -> (Option<String>, bool) {
    let sha = Command::new("git")
        .args(["-C"])
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string());
    let dirty = Command::new("git")
        .args(["-C"])
        .arg(repo)
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| !String::from_utf8_lossy(&out.stdout).trim().is_empty())
        .unwrap_or(false);
    (sha, dirty)
}

fn parse_base_image(dockerfile: &Path) -> Option<String> {
    let text = fs::read_to_string(dockerfile).ok()?;
    let mut arg_version = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ARG FEDORA_VERSION=") {
            arg_version = Some(rest.trim().to_string());
        }
    }
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("FROM ") {
            let image = rest.split_whitespace().next()?;
            if let Some(version) = &arg_version {
                return Some(image.replace("${FEDORA_VERSION}", version));
            }
            return Some(image.to_string());
        }
    }
    None
}

pub fn parse_size_bytes(raw: &str) -> Result<u64, String> {
    const MIB: u64 = 1024 * 1024;
    let trimmed = raw.trim();
    let (digits, multiplier) = match trimmed.chars().next_back() {
        Some('k' | 'K') => (1, 1024u64),
        Some('m' | 'M') => (1, MIB),
        Some('g' | 'G') => (1, MIB * 1024),
        Some('t' | 'T') => (1, MIB * 1024 * 1024),
        Some(_) => (0, MIB),
        None => return Err("size cannot be empty".to_string()),
    };
    let digits = &trimmed[..trimmed.len() - digits];
    let value: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("invalid size '{raw}' (expected e.g. '20G' or '512M')"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size '{raw}' is too large"))
}

pub fn human_bytes(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.0} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{} KiB", bytes / 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::ImageStore;
    use crate::system::test_util::TempDir;

    #[test]
    fn parse_size_bytes_suffixes() {
        assert_eq!(parse_size_bytes("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size_bytes("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_size_bytes("100g").unwrap(), 100 * 1024 * 1024 * 1024);
        assert_eq!(parse_size_bytes("64K").unwrap(), 64 * 1024);
        assert_eq!(parse_size_bytes("2048").unwrap(), 2048 * 1024 * 1024);
        assert!(parse_size_bytes("").is_err());
        assert!(parse_size_bytes("abc").is_err());
        assert!(parse_size_bytes("10T").is_ok());
    }

    #[test]
    fn base_image_parse_from_dockerfile() {
        let dir = TempDir::new("build-base");
        let df = dir.path().join("Dockerfile");
        fs::write(
            &df,
            "ARG FEDORA_VERSION=44\nFROM registry.fedoraproject.org/fedora:${FEDORA_VERSION}\nRUN \
             true\n",
        )
        .unwrap();
        assert_eq!(
            parse_base_image(&df).as_deref(),
            Some("registry.fedoraproject.org/fedora:44")
        );
    }

    #[test]
    fn repo_detection_walks_up() {
        let dir = TempDir::new("build-repo");
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join("docker/rootfs")).unwrap();
        fs::write(repo.join("docker/rootfs/Dockerfile"), "FROM x\n").unwrap();
        let nested = repo.join("a/b/c");
        fs::create_dir_all(&nested).unwrap();

        assert_eq!(resolve_repo(Some(&repo)).unwrap(), repo);
        assert!(resolve_repo(Some(dir.path())).is_err());
    }

    #[test]
    fn resolve_repo_falls_back_to_embedded_tree() {
        if std::env::var_os("KLETKA_REPO").is_some() {
            return;
        }
        let dir = TempDir::new("build-embedded");
        let (repo, origin) = resolve_repo_at(None, Some(dir.path())).unwrap();
        assert_eq!(origin, RepoOrigin::Embedded);
        assert!(
            repo.join(ROOTFS_DOCKERFILE).is_file(),
            "embedded tree materialized at {}",
            repo.display()
        );
        assert!(embedded::is_embedded_repo(&repo));
        let real = dir.path().join("repo");
        fs::create_dir_all(real.join("docker/rootfs")).unwrap();
        fs::write(real.join("docker/rootfs/Dockerfile"), "FROM x\n").unwrap();
        let (repo, origin) = resolve_repo_at(None, Some(&real.join("sub").join("x"))).unwrap();
        assert_eq!(origin, RepoOrigin::Disk);
        assert_eq!(repo, real);
        assert!(resolve_repo_at(Some(dir.path()), None).is_err());
    }

    #[test]
    fn build_rejects_both_skips() {
        let dir = TempDir::new("build-skip");
        let opts = BuildOptions {
            images_root: dir.path().join("images"),
            name: "default".into(),
            version: None,
            size_bytes: DEFAULT_SIZE_BYTES,
            update: false,
            skip_kernel: true,
            skip_rootfs: true,
            kernel_from: None,
            rootfs_overlay: None,
            repo: None,
            engine: Some("true".into()),
            set_current: true,
            now: kletka_types::time::from_unix(1_793_275_200),
        };
        let err = build(&opts).unwrap_err();
        assert!(err.contains("nothing to build"), "{err}");
    }

    #[test]
    fn build_rejects_duplicate_version() {
        let dir = TempDir::new("build-dup");
        let store = ImageStore::new(dir.path().join("images"));
        let vdir = store.root().join("default/versions/2026-10-29.1");
        fs::create_dir_all(&vdir).unwrap();
        fs::write(vdir.join(KERNEL_FILE), b"k").unwrap();
        fs::write(vdir.join(ROOTFS_FILE), b"r").unwrap();

        let opts = BuildOptions {
            images_root: dir.path().join("images"),
            name: "default".into(),
            version: Some("2026-10-29.1".into()),
            size_bytes: DEFAULT_SIZE_BYTES,
            update: false,
            skip_kernel: true,
            skip_rootfs: false,
            kernel_from: None,
            rootfs_overlay: None,
            repo: Some(dir.path().to_path_buf()),
            engine: Some("true".into()),
            set_current: true,
            now: kletka_types::time::from_unix(1_793_275_200),
        };
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join("docker/rootfs")).unwrap();
        fs::write(repo.join("docker/rootfs/Dockerfile"), "FROM scratch\n").unwrap();
        let opts = BuildOptions {
            repo: Some(repo),
            ..opts
        };
        let err = build(&opts).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
    }

    #[test]
    fn skip_without_previous_version_errors() {
        let dir = TempDir::new("build-noprev");
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join("docker/rootfs")).unwrap();
        fs::write(repo.join("docker/rootfs/Dockerfile"), "FROM scratch\n").unwrap();
        let opts = BuildOptions {
            images_root: dir.path().join("images"),
            name: "default".into(),
            version: None,
            size_bytes: DEFAULT_SIZE_BYTES,
            update: false,
            skip_kernel: true,
            skip_rootfs: false,
            kernel_from: None,
            rootfs_overlay: None,
            repo: Some(repo),
            engine: Some("true".into()),
            set_current: true,
            now: kletka_types::time::from_unix(1_793_275_200),
        };
        let err = build(&opts).unwrap_err();
        assert!(err.contains("no current version to reuse"), "{err}");
    }
}
