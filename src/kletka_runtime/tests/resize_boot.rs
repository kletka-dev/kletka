use std::time::Duration;

use kletka::store::VmRecord;
use kletka::system::KletkaPaths;
use kletka_runtime::runtime::VmRuntime;
use kletka_types::VmSpec;

mod common;
use common::*;

async fn wait_ready(runtime: &VmRuntime, vm: &VmRecord) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    while !runtime.guest_ssh_ready(vm).await {
        assert!(
            tokio::time::Instant::now() < deadline,
            "guest ssh never became ready"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn ssh_ok(paths: &KletkaPaths, vm: &VmRecord, command: &str) -> String {
    tokio::time::timeout(Duration::from_secs(60), guest_ssh_ok(paths, vm, command))
        .await
        .unwrap_or_else(|_| Err(format!("ssh '{command}' timed out")))
        .unwrap_or_else(|err| {
            dump_serial_tail(paths, &vm.id.to_string());
            panic!("{err}");
        })
}

async fn guest_size(paths: &KletkaPaths, vm: &VmRecord) -> (usize, usize) {
    let cpus = ssh_ok(paths, vm, "nproc").await.parse().unwrap();
    let mem_kib: usize = ssh_ok(paths, vm, "awk '/^MemTotal:/ {print $2}' /proc/meminfo")
        .await
        .parse()
        .unwrap();
    (cpus, mem_kib / 1024)
}

#[tokio::test]
#[ignore = "requires firecracker, /dev/kvm and a prebuilt guest image"]
async fn resize_end_to_end() {
    if !have_prerequisites() {
        return;
    }
    let Some(source) = source_image() else {
        eprintln!("skipping: no prebuilt image under ~/.local/share/kletka/images/default");
        return;
    };

    let data = std::env::temp_dir().join(format!("kletka-e2e-resize-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    let paths = KletkaPaths::with_data_dir(&data);
    paths.ensure().unwrap();
    make_overlay_image(&data, &source);
    let runtime = VmRuntime::new(paths.clone()).unwrap();

    let vm = runtime
        .create_vm(
            VmSpec {
                name: "resize-e2e".to_string(),
                image: "default".to_string(),
                vcpu: 1,
                memory_mib: 512,
                ..VmSpec::default()
            },
            Some("resize-e2e"),
        )
        .await
        .unwrap_or_else(|err| panic!("create failed: {err}"));
    wait_ready(&runtime, &vm).await;
    let (cpus, mem) = guest_size(&paths, &vm).await;
    println!("before: {cpus} cpu, {mem} MiB");
    assert_eq!(cpus, 1);
    ssh_ok(&paths, &vm, "echo kept > /home/user/state.txt && sync").await;

    assert!(runtime.resize_vm(&vm.name, 2, 1024).is_err());

    runtime.stop_vm(&vm.name).await.unwrap();
    runtime.resize_vm(&vm.name, 2, 1024).unwrap();
    let started = runtime.start_vm(&vm.name).await.unwrap();
    let vm: VmRecord = serde_json::from_value(started).unwrap();
    wait_ready(&runtime, &vm).await;

    let (cpus, mem) = guest_size(&paths, &vm).await;
    println!("after: {cpus} cpu, {mem} MiB");
    assert_eq!(cpus, 2);
    assert!(mem > 512 && mem <= 1024, "guest sees {mem} MiB");
    assert_eq!(
        ssh_ok(&paths, &vm, "cat /home/user/state.txt").await,
        "kept",
        "the disk survives a resize"
    );

    runtime.delete_vm(&vm.name).await.unwrap();
    let _ = std::fs::remove_dir_all(&data);
}
