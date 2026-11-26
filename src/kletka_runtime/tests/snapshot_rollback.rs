use std::time::Duration;

use kletka::checkpoint::CheckpointOperation;
use kletka::fsutil::{disk_usage, ext4_size};
use kletka::image::{ROOTFS_FILE, sha256_file};
use kletka::system::KletkaPaths;
use kletka_runtime::runtime::VmRuntime;
use kletka_types::VmSpec;

mod common;
use common::*;

#[tokio::test]
#[ignore = "requires firecracker, /dev/kvm and a prebuilt guest image"]
async fn snapshot_rollback_end_to_end() {
    if !have_prerequisites() {
        return;
    }
    let Some(source) = source_image() else {
        eprintln!("skipping: no prebuilt image under ~/.local/share/kletka/images/default");
        return;
    };

    let data = std::env::temp_dir().join(format!("kletka-e2e-snapshot-{}", std::process::id()));
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
                name: "snapshot-e2e".to_string(),
                image: "default".to_string(),
                ..VmSpec::default()
            },
            Some("snapshot-e2e"),
        )
        .await
        .unwrap_or_else(|err| panic!("create failed: {err}"));
    let instance_dir = paths.instances_path().join(vm.id.to_string());
    let overlay_path = vm
        .overlay_path
        .clone()
        .expect("overlay-capable image must set overlay_path");

    tokio::time::timeout(
        Duration::from_secs(30),
        guest_ssh_ok(&paths, &vm, "echo base-state > /home/user/base.txt"),
    )
    .await
    .unwrap()
    .unwrap_or_else(|err| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("pre-snapshot write failed: {err}");
    });

    runtime.stop_vm(&vm.name).await.unwrap();

    let snapshot_before = disk_usage(&overlay_path).unwrap();
    let created = runtime
        .checkpoint(CheckpointOperation::Create {
            vm: vm.name.clone(),
            name: "clean".to_string(),
            memory: false,
        })
        .await
        .unwrap_or_else(|err| panic!("snapshot create failed: {err}"));
    println!("snapshot record: {created}");
    assert_eq!(created["name"], "clean");
    assert_eq!(created["with_memory"], false);

    let cp_disk = instance_dir.join("checkpoints/clean/rootfs.ext4");
    assert!(cp_disk.is_file(), "the snapshot's disk copy must exist");
    let snapshot_size = created["size_bytes"].as_u64().unwrap();
    let base_fs_bytes = ext4_size(&base_rootfs).unwrap();
    println!(
        "snapshot size: {snapshot_size} bytes (overlay usage before: {snapshot_before}, base fs: \
         {base_fs_bytes})"
    );
    assert!(
        snapshot_size < base_fs_bytes / 2,
        "the snapshot must carry the overlay only, not the shared base"
    );

    let started = runtime
        .start_vm(&vm.name)
        .await
        .unwrap_or_else(|err| panic!("restart after snapshot failed: {err}"));
    let vm: kletka::store::VmRecord = serde_json::from_value(started).unwrap();

    tokio::time::timeout(
        Duration::from_secs(30),
        guest_ssh_ok(&paths, &vm, "echo marker-state > /home/user/marker.txt"),
    )
    .await
    .unwrap()
    .unwrap_or_else(|err| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("marker write failed: {err}");
    });
    let overlay_usage_after_marker = disk_usage(&overlay_path).unwrap();
    println!("overlay usage after marker write: {overlay_usage_after_marker}");

    runtime.stop_vm(&vm.name).await.unwrap();

    let rolled = runtime
        .checkpoint(CheckpointOperation::Rollback {
            vm: vm.name.clone(),
            name: "clean".to_string(),
        })
        .await
        .unwrap_or_else(|err| panic!("rollback failed: {err}"));
    println!("rollback record: {rolled}");
    assert_eq!(rolled["rolled_back"], "clean");

    let started = runtime
        .start_vm(&vm.name)
        .await
        .unwrap_or_else(|err| panic!("restart after rollback failed: {err}"));
    let vm: kletka::store::VmRecord = serde_json::from_value(started).unwrap();

    let marker = tokio::time::timeout(
        Duration::from_secs(60),
        guest_ssh(&paths, &vm, "cat /home/user/marker.txt"),
    )
    .await
    .unwrap_or_else(|_| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("ssh timed out after rollback restart");
    })
    .unwrap_or_else(|err| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("marker check failed: {err}");
    });
    println!("marker after rollback: {marker:?}");
    assert!(marker.is_none(), "the marker must be gone after rollback");

    let base_file = tokio::time::timeout(
        Duration::from_secs(30),
        guest_ssh_ok(&paths, &vm, "cat /home/user/base.txt"),
    )
    .await
    .unwrap_or_else(|_| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("ssh timed out reading the pre-snapshot file");
    })
    .unwrap_or_else(|err| {
        dump_serial_tail(&paths, &vm.id.to_string());
        panic!("pre-snapshot file check failed: {err}");
    });
    println!("pre-snapshot file after rollback: {base_file}");
    assert_eq!(base_file, "base-state");

    let listed = runtime
        .checkpoint(CheckpointOperation::List(vm.name.clone()))
        .await
        .unwrap_or_else(|err| panic!("snapshot list failed: {err}"));
    println!("snapshot list: {listed}");
    let snapshots = listed.as_array().expect("list is an array");
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0]["name"], "clean");
    assert_eq!(snapshots[0]["with_memory"], false);
    assert!(cp_disk.is_file(), "the snapshot must survive the rollback");

    assert_eq!(
        sha256_file(&base_rootfs).unwrap(),
        base_sha_before,
        "the read-only base rootfs must be byte-identical after snapshot + rollback"
    );

    runtime.delete_vm(&vm.name).await.unwrap();

    let _ = std::fs::remove_dir_all(&data);
}
