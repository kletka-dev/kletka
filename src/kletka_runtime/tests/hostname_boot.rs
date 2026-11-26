use std::time::Duration;

use kletka::system::KletkaPaths;
use kletka_runtime::runtime::VmRuntime;
use kletka_types::VmSpec;

mod common;
use common::*;

#[tokio::test]
#[ignore = "requires firecracker, /dev/kvm and a prebuilt guest image"]
async fn guest_hostname_is_the_vm_name() {
    if !have_prerequisites() {
        return;
    }
    let Some(source) = source_image() else {
        eprintln!("skipping: no prebuilt image under ~/.local/share/kletka/images/default");
        return;
    };

    let data = std::env::temp_dir().join(format!("kletka-e2e-hostname-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    let paths = KletkaPaths::with_data_dir(&data);
    paths.ensure().unwrap();

    make_overlay_image(&data, &source);

    let runtime = VmRuntime::new(paths.clone()).unwrap();

    let vm = runtime
        .create_vm(
            VmSpec {
                name: "hostname-check".to_string(),
                image: "default".to_string(),
                ..VmSpec::default()
            },
            Some("hostname-check"),
        )
        .await
        .unwrap_or_else(|err| {
            panic!("create failed: {err}");
        });

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
    assert_eq!(hostname, "hostname-check");

    let hostname_file = tokio::time::timeout(
        Duration::from_secs(30),
        guest_ssh_ok(&paths, &vm, "cat /etc/hostname"),
    )
    .await
    .unwrap()
    .unwrap();
    println!("guest /etc/hostname: {hostname_file}");
    assert_eq!(hostname_file, "hostname-check");

    runtime.delete_vm(&vm.name).await.unwrap();

    let _ = std::fs::remove_dir_all(&data);
}
