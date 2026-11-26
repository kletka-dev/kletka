use std::path::PathBuf;

use uuid::Uuid;

pub mod api;
pub mod error;
pub mod firecracker;

pub use error::FirecrackerError;
pub use firecracker::{FirecrackerVmm, Handle};

pub const OVERLAY_INIT_PATH: &str = "/usr/local/sbin/kletka-overlay-init";

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub interface_id: String,
    pub host_device_name: String,
    pub guest_mac: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CreateParameters {
    pub id: Uuid,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,

    pub overlay_path: Option<PathBuf>,

    pub disk_bytes: Option<u64>,
    pub vsock: Option<(PathBuf, u32)>,

    pub seed_path: Option<PathBuf>,
    pub checkpoints_path: Option<PathBuf>,

    pub boot_args: Option<String>,
    pub network: Option<Vec<NetworkConfig>>,

    pub memory_mb: usize,
    pub vcpu_count: u8,
}
