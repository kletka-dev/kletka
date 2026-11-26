use std::path::{Path, PathBuf};
use std::process::Stdio;

use kletka::fsutil::{disk_usage, ext4_size, thin_copy};
use kletka::image::{
    ArtifactInfo, ImageArtifacts, ImageManifest, ImageSource, ImageStore, MANIFEST_SCHEMA,
    ROOTFS_FILE, sha256_file, write_manifest,
};
use kletka::system::KletkaPaths;
use tokio::process::Command;

pub const OVERLAY_INIT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docker/rootfs/rootfs/usr/local/sbin/kletka-overlay-init"
));

pub fn have_prerequisites() -> bool {
    for binary in [
        "firecracker",
        "slirp4netns",
        "unshare",
        "ssh",
        "debugfs",
        "mkfs.ext4",
    ] {
        if on_host_path(binary) {
            continue;
        }
        eprintln!("skipping: {binary} not on PATH");
        return false;
    }
    if !Path::new("/dev/kvm").exists() {
        eprintln!("skipping: /dev/kvm missing");
        return false;
    }
    true
}

pub fn source_image() -> Option<PathBuf> {
    let root = dirs_home()?.join(".local/share/kletka/images/default/versions");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(&root)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|dir| dir.join("vmlinux").is_file() && dir.join(ROOTFS_FILE).is_file())
        .collect();
    versions.sort();
    versions.pop()
}

pub fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

pub fn make_overlay_image(data_dir: &Path, source: &Path) -> PathBuf {
    let store = ImageStore::new(data_dir.join("images"));
    let dir = store.root().join("default").join("versions").join("e2e.1");
    std::fs::create_dir_all(&dir).unwrap();

    thin_copy(&source.join("vmlinux"), &dir.join("vmlinux")).unwrap();
    thin_copy(&source.join(ROOTFS_FILE), &dir.join(ROOTFS_FILE)).unwrap();

    inject_overlay_init(&dir.join(ROOTFS_FILE));

    let manifest = ImageManifest {
        schema: MANIFEST_SCHEMA,
        name: "default".to_string(),
        version: "e2e.1".to_string(),
        created_at: kletka_types::time::Timestamp::UNIX_EPOCH,
        parent: None,
        source: ImageSource {
            git_sha: None,
            git_dirty: false,
            dockerfile: "docker/rootfs/Dockerfile".to_string(),
            dockerfile_sha256: "e2e".to_string(),
            base_image: None,
            updated: false,
            kernel_reused_from: None,
            rootfs_reused_from: None,
            embedded_version: None,
            kernel_inputs_sha256: None,
        },
        artifacts: ImageArtifacts {
            kernel: artifact(&dir, "vmlinux", None),
            kernel_config: None,
            rootfs: artifact(
                &dir,
                ROOTFS_FILE,
                Some(ext4_size(&dir.join(ROOTFS_FILE)).unwrap()),
            ),
        },
        overlay_boot: true,
        labels: Default::default(),
    };
    write_manifest(&dir, &manifest).unwrap();
    store.set_current("default", "e2e.1").unwrap();

    dir
}

pub fn artifact(dir: &Path, file: &str, fs_bytes: Option<u64>) -> ArtifactInfo {
    let path = dir.join(file);
    ArtifactInfo {
        file: file.to_string(),
        size_bytes: std::fs::metadata(&path).unwrap().len(),
        sha256: sha256_file(&path).unwrap(),
        used_bytes: Some(disk_usage(&path).unwrap()),
        fs_bytes,
    }
}

pub fn inject_overlay_init(rootfs: &Path) {
    let script = std::env::temp_dir().join(format!("kletka-overlay-init-{}", std::process::id()));
    std::fs::write(&script, OVERLAY_INIT).unwrap();

    let commands = std::env::temp_dir().join(format!("kletka-overlay-cmds-{}", std::process::id()));
    std::fs::write(
        &commands,
        format!(
            "write {} /usr/local/sbin/kletka-overlay-init\nsif /usr/local/sbin/kletka-overlay-init \
             mode 0100755\n",
            script.display()
        ),
    )
    .unwrap();

    let status = std::process::Command::new("debugfs")
        .args(["-w", "-f"])
        .arg(&commands)
        .arg(rootfs)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "debugfs injection failed");

    let _ = std::fs::remove_file(&script);
    let _ = std::fs::remove_file(&commands);
}

pub async fn guest_ssh(
    paths: &KletkaPaths,
    vm: &kletka::store::VmRecord,
    command: &str,
) -> Result<Option<String>, String> {
    let key = paths
        .instances_path()
        .join(vm.id.to_string())
        .join("ssh_key");
    let port = vm.ssh_port.ok_or("vm has no ssh port")?;
    let target = format!(
        "user@{}",
        vm.ssh_addr.as_deref().ok_or("vm has no ssh address")?
    );

    let output = Command::new("ssh")
        .args(ssh_common_args(&key, port, "-p"))
        .arg(&target)
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|err| err.to_string())?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

pub fn ssh_common_args(key: &Path, port: u16, port_flag: &str) -> Vec<String> {
    [
        "-i",
        &key.display().to_string(),
        port_flag,
        &port.to_string(),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
    ]
    .iter()
    .map(ToString::to_string)
    .collect()
}

pub fn on_host_path(binary: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(binary))
                .any(|candidate| candidate.is_file())
        })
        .unwrap_or(false)
}

pub async fn guest_ssh_ok(
    paths: &KletkaPaths,
    vm: &kletka::store::VmRecord,
    command: &str,
) -> Result<String, String> {
    guest_ssh(paths, vm, command)
        .await?
        .ok_or_else(|| format!("ssh '{command}' failed"))
}

pub fn dump_serial_tail(paths: &KletkaPaths, vm_id: &str) {
    let log = paths.instances_path().join(vm_id).join("serial.log");
    if let Ok(content) = std::fs::read_to_string(&log) {
        eprintln!("---- serial.log tail ----");
        let tail: String = content
            .lines()
            .rev()
            .take(40)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        eprintln!("{tail}");
    }
}
