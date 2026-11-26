use std::time::Duration;

use kletka::fsutil::disk_usage;
use kletka::image::{ROOTFS_FILE, sha256_file};
use kletka::system::KletkaPaths;
use kletka_runtime::runtime::VmRuntime;
use kletka_types::VmSpec;

mod common;
use common::*;

#[tokio::test]
#[ignore = "requires firecracker, /dev/kvm and a prebuilt guest image"]
async fn overlay_boot_end_to_end() {
    if !have_prerequisites() {
        return;
    }
    let Some(source) = source_image() else {
        eprintln!("skipping: no prebuilt image under ~/.local/share/kletka/images/default");
        return;
    };

    let data = std::env::temp_dir().join(format!("kletka-e2e-overlay-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    let paths = KletkaPaths::with_data_dir(&data);
    paths.ensure().unwrap();

    let base_dir = make_overlay_image(&data, &source);
    let base_rootfs = base_dir.join(ROOTFS_FILE);
    let base_sha_before = sha256_file(&base_rootfs).unwrap();

    let runtime = VmRuntime::new(paths.clone()).unwrap();

    let vm = runtime
        .create_vm(
            VmSpec {
                name: "overlay-e2e".to_string(),
                image: "default".to_string(),
                ..VmSpec::default()
            },
            Some("overlay-e2e"),
        )
        .await
        .unwrap_or_else(|err| {
            panic!("create failed: {err}");
        });
    let instance_dir = paths.instances_path().join(vm.id.to_string());

    assert_eq!(vm.rootfs_path, base_rootfs);
    let overlay_path = vm
        .overlay_path
        .clone()
        .expect("overlay-capable image must set overlay_path");
    assert_eq!(overlay_path, instance_dir.join("overlay.ext4"));
    assert!(
        overlay_path.is_file(),
        "overlay file must exist after create"
    );

    let hostname = tokio::time::timeout(
        Duration::from_secs(30),
        guest_ssh_ok(&paths, &vm, "hostname"),
    )
    .await
    .unwrap_or_else(|_| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("ssh timed out after boot");
    })
    .unwrap_or_else(|err| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("hostname failed: {err}");
    });
    println!("guest hostname: {hostname}");
    assert!(!hostname.trim().is_empty());

    let overlay_usage_before = disk_usage(&overlay_path).unwrap();

    tokio::time::timeout(
        Duration::from_secs(30),
        guest_ssh_ok(&paths, &vm, "echo overlay-proof > /home/user/proof.txt"),
    )
    .await
    .unwrap()
    .unwrap();
    let overlay_usage_after_write = disk_usage(&overlay_path).unwrap();
    println!(
        "overlay disk usage: {} -> {} after guest write",
        overlay_usage_before, overlay_usage_after_write
    );
    assert!(
        overlay_usage_after_write > overlay_usage_before,
        "overlay must grow with guest writes"
    );

    runtime.stop_vm(&vm.name).await.unwrap();

    let started = runtime.start_vm(&vm.name).await.unwrap();
    let vm: kletka::store::VmRecord = serde_json::from_value(started).unwrap();

    let proof = tokio::time::timeout(
        Duration::from_secs(60),
        guest_ssh_ok(&paths, &vm, "cat /home/user/proof.txt"),
    )
    .await
    .unwrap_or_else(|_| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("ssh timed out after restart");
    })
    .unwrap_or_else(|err| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("cat after restart failed: {err}");
    });
    println!("proof file after restart: {proof}");
    assert_eq!(proof, "overlay-proof");

    assert_eq!(
        sha256_file(&base_rootfs).unwrap(),
        base_sha_before,
        "the read-only base rootfs must be byte-identical after guest writes"
    );

    let root_fstype = tokio::time::timeout(
        Duration::from_secs(30),
        guest_ssh_ok(&paths, &vm, "findmnt -n -o FSTYPE /"),
    )
    .await
    .unwrap()
    .unwrap();
    println!("guest root fstype: {root_fstype}");
    assert_eq!(root_fstype, "overlay");

    runtime.delete_vm(&vm.name).await.unwrap();

    let _ = std::fs::remove_dir_all(&data);
}
