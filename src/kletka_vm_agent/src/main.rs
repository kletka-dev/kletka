mod config;
mod file;
mod internal;
mod pty;
mod reply;
mod session;

use kletka::image;
use kletka::system::KletkaPaths;
use kletka_runtime::error::RuntimeError;
use kletka_runtime::runtime::VmRuntime;
use session::SessionState;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

use crate::config::Config;
use crate::internal::InternalState;

const BAKED_GUEST_BASE: &str = "/usr/share/kletka/guest";

const VERSION: &str = match option_env!("KLETKA_VERSION") {
    Some(version) => version,
    None => "dev",
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("kletka-vm-agent: bad config: {err}");
            std::process::exit(1);
        }
    };
    tracing::info!(
        version = VERSION,
        vm = %config.vm_id,
        image = %config.image,
        vcpu = config.vcpu,
        memory_mib = config.memory_mib,
        nat = config.nat,
        data_dir = %config.data_dir.display(),
        "kletka-vm-agent starting"
    );

    let paths = KletkaPaths::with_data_dir(config.data_dir.clone());
    if let Err(err) = paths.ensure() {
        tracing::error!(%err, "cannot prepare data dir");
        std::process::exit(1);
    }
    if let Err(err) = stage_guest_image(&config, &paths) {
        tracing::error!(%err, "guest image staging failed");
        std::process::exit(1);
    }

    let runtime = match VmRuntime::new(paths.clone()) {
        Ok(runtime) => Arc::new(runtime),
        Err(err) => {
            tracing::error!(%err, "cannot initialize VM runtime");
            std::process::exit(1);
        }
    };

    let state = InternalState {
        session: SessionState {
            node_secret: config.session_token.clone(),
            node_id: config.vm_id.to_string(),
            data_dir: config.data_dir.clone(),
        },
        vm_id: config.vm_id,
        runtime: runtime.clone(),
    };
    let app = session::router(state.session.clone())
        .merge(file::router(state.session.clone()))
        .merge(internal::router(state));
    let bind = config.bind;
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(bind).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::error!(%err, "agent server bind failed");
                std::process::exit(1);
            }
        };
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(%err, "agent server exited");
        }
    });

    if let Err(err) = ensure_vm(&runtime, &config).await {
        tracing::error!(%err, "vm never came up; exiting so the pod retries");
        std::process::exit(1);
    }

    wait_for_terminate().await;
    tracing::info!(vm = %config.vm_id, "shutdown requested; stopping guest");
    if let Err(err) = runtime.stop_vm(&config.vm_id.to_string()).await {
        tracing::warn!(%err, "guest did not stop cleanly");
    }
    tracing::info!("bye");
}

async fn ensure_vm(runtime: &Arc<VmRuntime>, config: &Config) -> Result<(), RuntimeError> {
    let name = config.vm_id.to_string();
    match runtime.find_vm(&name) {
        Ok(record) if record.state == kletka::store::VmState::Running => Ok(()),
        Ok(_) if !config.autostart => Ok(()),
        Ok(record) => {
            if usize::from(record.vcpu_count) != config.vcpu
                || record.memory_mib != config.memory_mib
            {
                runtime.resize_vm(&name, config.vcpu, config.memory_mib)?;
            }
            let grow = config.disk_mib != 0 && config.disk_mib != record.disk_mib;
            if grow {
                let runtime = Arc::clone(runtime);
                let name = name.clone();
                let disk_mib = config.disk_mib;
                tokio::task::spawn_blocking(move || runtime.grow_disk(&name, disk_mib))
                    .await
                    .map_err(|err| format!("disk grow task: {err}"))??;
            }
            if config.rebase {
                runtime.rebase_vm(&name, Some(&config.image)).await?;
                let record = runtime.find_vm(&name)?;
                if let Some(base_dir) = record.rootfs_path.parent() {
                    prune_staged_images(&config.data_dir.join("images"), base_dir)
                        .map_err(|err| format!("cannot prune old guest images: {err}"))?;
                }
            }
            runtime
                .start_vm_with_wireguard(
                    &name,
                    config.vm_name.as_deref(),
                    config.wireguard_config.as_deref(),
                    config.authorized_keys(),
                )
                .await
                .map(|_| ())
        }
        Err(RuntimeError::VmNotFound(_)) => {
            if !config.autostart {
                return Ok(());
            }
            runtime
                .create_vm_with_wireguard(
                    config.spec(),
                    config.vm_name.as_deref(),
                    config.wireguard_config.as_deref(),
                    config.authorized_keys(),
                )
                .await
                .map(|_| ())
        }
        Err(err) => Err(err),
    }
}

fn prune_staged_images(images_dir: &Path, keep_version: &Path) -> std::io::Result<()> {
    let keep_image = keep_version
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| std::io::Error::other("guest image version has no image directory"))?;

    for image in std::fs::read_dir(images_dir)? {
        let image = image?.path();
        if image != keep_image {
            std::fs::remove_dir_all(image)?;
            continue;
        }
        let versions = image.join("versions");
        for version in std::fs::read_dir(versions)? {
            let version = version?.path();
            if version != keep_version {
                std::fs::remove_dir_all(version)?;
            }
        }
    }
    Ok(())
}

fn stage_guest_image(config: &Config, paths: &KletkaPaths) -> Result<(), String> {
    let src = config
        .guest_image_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from(BAKED_GUEST_BASE).join(&config.image));
    if !src.is_dir() {
        return Err(format!(
            "no guest image for '{}': set KLETKA_GUEST_IMAGE_DIR or bake one into the image ({})",
            config.image,
            src.display()
        ));
    }
    let store = image::ImageStore::new(paths.images_path());
    let reference = config.guest_image_ref.as_deref().unwrap_or("development");
    let version = hex::encode(Sha256::digest(reference.as_bytes()));
    let dst = store
        .root()
        .join(&config.image)
        .join("versions")
        .join(&version);
    if dst.join(image::KERNEL_FILE).is_file() && dst.join(image::ROOTFS_FILE).is_file() {
        store
            .set_current(&config.image, &version)
            .map_err(|err| err.to_string())?;
        tracing::debug!(image = %config.image, "guest image already staged");
        return Ok(());
    }
    std::fs::create_dir_all(&dst).map_err(|err| format!("mkdir {}: {err}", dst.display()))?;
    for file in [image::KERNEL_FILE, image::ROOTFS_FILE] {
        let from = src.join(file);
        if !from.is_file() {
            return Err(format!(
                "guest image dir {} is missing {file}",
                src.display()
            ));
        }
        relink(&from, &dst.join(file))?;
    }
    let manifest = src.join(image::MANIFEST_FILE);
    if manifest.is_file() {
        relink(&manifest, &dst.join(image::MANIFEST_FILE))?;
    }
    store
        .set_current(&config.image, &version)
        .map_err(|err| err.to_string())?;
    tracing::info!(image = %config.image, dir = %dst.display(), "guest image staged");
    Ok(())
}

fn relink(from: &Path, to: &Path) -> Result<(), String> {
    let _ = std::fs::remove_file(to);
    std::os::unix::fs::symlink(from, to).map_err(|err| format!("link {}: {err}", from.display()))
}

async fn wait_for_terminate() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");
    tokio::select! {
        _ = sigterm.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::*;

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("kletka-vm-agent-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn stages_guest_image_by_reference_and_idempotently() {
        let guest = TempDir::new();
        std::fs::write(guest.0.join(image::KERNEL_FILE), b"kernel").unwrap();
        std::fs::write(guest.0.join(image::ROOTFS_FILE), b"rootfs").unwrap();

        let data = TempDir::new();
        let paths = KletkaPaths::with_data_dir(&data.0);
        paths.ensure().unwrap();

        let mut config = crate::config::test_config();
        config.guest_image_dir = Some(guest.0.clone());
        config.guest_image_ref = Some("registry/guest:v1".into());

        stage_guest_image(&config, &paths).expect("staging works");
        let store = image::ImageStore::new(paths.images_path());
        let staged = store.resolve("default").unwrap().dir;
        assert!(staged.join(image::KERNEL_FILE).is_file());
        assert!(staged.join(image::ROOTFS_FILE).is_file());
        assert!(
            staged
                .join(image::ROOTFS_FILE)
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );

        stage_guest_image(&config, &paths).expect("restaging works");
        assert_eq!(store.resolve("default").unwrap().dir, staged);

        std::fs::write(guest.0.join(image::ROOTFS_FILE), b"new-rootfs").unwrap();
        config.guest_image_ref = Some("registry/guest:v2".into());
        stage_guest_image(&config, &paths).expect("new ref stages a new image version");
        let rebased = store.resolve("default").unwrap();
        assert_ne!(rebased.dir, staged);
        assert_eq!(std::fs::read(rebased.rootfs_path).unwrap(), b"new-rootfs");
        assert_eq!(
            std::fs::read(staged.join(image::ROOTFS_FILE)).unwrap(),
            b"new-rootfs"
        );
    }

    #[test]
    fn missing_guest_image_is_an_error() {
        let data = TempDir::new();
        let paths = KletkaPaths::with_data_dir(&data.0);
        paths.ensure().unwrap();
        let mut config = crate::config::test_config();
        config.guest_image_dir = Some(data.0.join("nonexistent"));
        assert!(stage_guest_image(&config, &paths).is_err());
    }
}
