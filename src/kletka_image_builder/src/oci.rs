use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kletka::image::{ImageStore, MANIFEST_FILE};
use kube::api::{Api, Patch, PatchParams, PostParams};

fn guest_artifacts(dir: &Path) -> Result<Vec<String>, String> {
    let mut files = vec![MANIFEST_FILE.to_string()];
    for name in ["vmlinux", "rootfs.ext4", "vmlinux.config"] {
        if dir.join(name).is_file() {
            files.push(name.to_string());
        }
    }
    for required in ["vmlinux", "rootfs.ext4"] {
        if !files.iter().any(|f| f == required) {
            return Err(format!(
                "version dir {} is missing {required}",
                dir.display()
            ));
        }
    }
    Ok(files)
}

fn pack(engine: &str, dir: &Path, reference: &str) -> Result<(), String> {
    let files = guest_artifacts(dir)?;
    let dockerfile = std::env::temp_dir().join(format!(
        "kletka-image-pack-{}-Dockerfile",
        uuid::Uuid::new_v4()
    ));
    fs::write(&dockerfile, pack_dockerfile(&files))
        .map_err(|err| format!("cannot write {}: {err}", dockerfile.display()))?;

    let result = {
        let dockerfile_arg = dockerfile.to_string_lossy().into_owned();
        let ctx_arg = dir.to_string_lossy().into_owned();
        run_engine(
            engine,
            &["build", "-f", &dockerfile_arg, "-t", reference, &ctx_arg],
            "image pack (engine build)",
        )
    };
    let _ = fs::remove_file(&dockerfile);
    result
}

fn pack_dockerfile(files: &[String]) -> String {
    format!("FROM scratch\nCOPY {} /\n", files.join(" "))
}

pub fn tls_args(engine: &str, tls_verify: bool) -> &'static [&'static str] {
    let is_podman = Path::new(engine)
        .file_name()
        .is_some_and(|name| name == "podman");
    if !tls_verify && is_podman {
        &["--tls-verify=false"]
    } else {
        &[]
    }
}

pub fn push_version(
    engine: &str,
    store: &ImageStore,
    name: &str,
    version: &str,
    reference: &str,
    tls_verify: bool,
) -> Result<(), String> {
    let (dir, _) = store
        .manifest(name, Some(version))
        .map_err(|err| err.to_string())?;
    pack(engine, &dir, reference)?;
    let mut args = vec!["push"];
    args.extend_from_slice(tls_args(engine, tls_verify));
    args.push(reference);
    run_engine(engine, &args, &format!("image push to {reference}"))?;

    let _ = Command::new(engine)
        .args(["rmi", reference])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    tracing::info!(image = %name, version, %reference, "guest image pushed");
    Ok(())
}

pub fn pull_ref(
    engine: &str,
    store: &ImageStore,
    reference: &str,
    name: &str,
    tls_verify: bool,
) -> Result<String, String> {
    let mut args = vec!["pull"];
    args.extend_from_slice(tls_args(engine, tls_verify));
    args.push(reference);
    run_engine(engine, &args, &format!("image pull from {reference}"))?;

    let output = Command::new(engine)
        .args(["create", "--entrypoint", "/bin/true", reference])
        .output()
        .map_err(|err| format!("cannot run {engine} create: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{engine} create failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let ctr = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let archive =
        std::env::temp_dir().join(format!("kletka-image-pull-{}.tar", uuid::Uuid::new_v4()));
    let export = Command::new(engine)
        .args(["export", "-o"])
        .arg(&archive)
        .arg(&ctr)
        .status()
        .map_err(|err| format!("cannot run {engine} export: {err}"))?;
    let _ = Command::new(engine)
        .args(["rm", "-f", &ctr])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if !export.success() {
        let _ = fs::remove_file(&archive);
        return Err(format!("{engine} export failed for container {ctr}"));
    }

    let imported = store
        .import(&archive, Some(name), true, true)
        .map_err(|err| err.to_string());
    let _ = fs::remove_file(&archive);
    let _ = Command::new(engine)
        .args(["rmi", reference])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let manifest = imported?;
    tracing::info!(image = %manifest.name, version = %manifest.version, %reference, "guest image pulled");
    Ok(manifest.version)
}

pub fn gc(store: &ImageStore, name: &str, keep_versions: usize) {
    let Ok(versions) = store.versions(name) else {
        return;
    };
    let current = store.current(name).ok().flatten();
    let doomed: Vec<&kletka::image::VersionInfo> = versions
        .iter()
        .enumerate()
        .filter(|(index, version)| {
            if Some(version.version.as_str()) == current.as_deref() {
                return false;
            }
            *index >= keep_versions - 1
        })
        .map(|(_, version)| version)
        .collect();
    for version in doomed {
        match store.remove_version(name, &version.version) {
            Ok(()) => tracing::info!(image = %name, version = %version.version, "gc: pruned"),
            Err(err) => {
                tracing::warn!(image = %name, version = %version.version, %err, "gc failed")
            }
        }
    }
}

pub fn parse_configmap_ref(configmap_ref: &str) -> Result<(&str, &str), String> {
    kletka_types::parse_configmap_ref(configmap_ref)
}

pub async fn announce(
    configmap_ref: &str,
    image: &str,
    reference: &str,
    overlay_boot: bool,
) -> Result<(), String> {
    let (namespace, name) = parse_configmap_ref(configmap_ref)
        .map_err(|err| format!("KLETKA_BUILDER_CONFIGMAP: {err}"))?;

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("kube client: {err}"))?;
    let maps: Api<ConfigMap> = Api::namespaced(client, namespace);

    let data = BTreeMap::from([
        (image.to_string(), reference.to_string()),
        (format!("{image}.overlay_boot"), overlay_boot.to_string()),
    ]);
    let cm = ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    match maps.create(&PostParams::default(), &cm).await {
        Ok(_) => {
            tracing::info!(configmap = %configmap_ref, image, %reference, "announced (created)");
            return Ok(());
        }
        Err(kube::Error::Api(status)) if status.code == 409 => {}
        Err(err) => return Err(format!("creating {configmap_ref}: {err}")),
    }
    let mut data = serde_json::Map::new();
    data.insert(image.to_string(), serde_json::json!(reference));
    data.insert(
        format!("{image}.overlay_boot"),
        serde_json::json!(overlay_boot.to_string()),
    );
    let patch = serde_json::json!({ "data": data });
    maps.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|err| format!("patching {configmap_ref}: {err}"))?;
    tracing::info!(configmap = %configmap_ref, image, %reference, "announced (patched)");
    Ok(())
}

fn run_engine(engine: &str, args: &[&str], what: &str) -> Result<(), String> {
    let status = Command::new(engine)
        .args(args)
        .status()
        .map_err(|err| format!("cannot run {engine} ({what}): {err}"))?;
    if !status.success() {
        return Err(format!(
            "{what} failed (exit {})",
            status.code().unwrap_or(1)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_dockerfile_puts_artifacts_at_the_root() {
        let dockerfile = pack_dockerfile(&[
            "manifest.json".to_string(),
            "vmlinux".to_string(),
            "rootfs.ext4".to_string(),
        ]);
        assert_eq!(
            dockerfile,
            "FROM scratch\nCOPY manifest.json vmlinux rootfs.ext4 /\n"
        );
    }

    #[test]
    fn guest_artifacts_requires_kernel_and_rootfs() {
        let dir = std::env::temp_dir().join(format!("kletka-oci-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        assert!(guest_artifacts(&dir).is_err());
        fs::write(dir.join("rootfs.ext4"), b"x").unwrap();
        assert!(guest_artifacts(&dir).is_err());
        fs::write(dir.join("vmlinux"), b"x").unwrap();
        fs::write(dir.join("manifest.json"), b"{}").unwrap();
        let files = guest_artifacts(&dir).unwrap();
        assert_eq!(files, vec!["manifest.json", "vmlinux", "rootfs.ext4"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn tls_skip_is_podman_only() {
        assert_eq!(tls_args("podman", false), &["--tls-verify=false"]);
        assert_eq!(tls_args("/usr/bin/podman", false), &["--tls-verify=false"]);
        assert!(tls_args("podman", true).is_empty());
        assert!(tls_args("docker", false).is_empty());
    }

    #[test]
    fn configmap_ref_needs_namespace_and_name() {
        assert_eq!(
            parse_configmap_ref("kletka-system/kletka-guest-images").unwrap(),
            ("kletka-system", "kletka-guest-images")
        );
        assert!(parse_configmap_ref("no-slash").is_err());
        assert!(parse_configmap_ref("/name").is_err());
        assert!(parse_configmap_ref("ns/").is_err());
    }

    #[test]
    fn pack_builds_with_the_version_dir_as_context() {
        let dir = std::env::temp_dir().join(format!("kletka-pack-test-{}", uuid::Uuid::new_v4()));
        let version_dir = dir.join("default/versions/2026-11-14.1");
        fs::create_dir_all(&version_dir).unwrap();
        fs::write(version_dir.join("manifest.json"), b"{}").unwrap();
        fs::write(version_dir.join("vmlinux"), b"kernel").unwrap();
        fs::write(version_dir.join("rootfs.ext4"), b"rootfs").unwrap();
        fs::write(version_dir.join("vmlinux.config"), b"config").unwrap();

        let engine = dir.join("fake-engine");
        fs::write(
            &engine,
            "#!/usr/bin/env bash\n\
             set -eu\n\
             # args: build -f <dockerfile> -t <ref> <context>\n\
             dockerfile=\"$3\"; context=\"$6\"\n\
             for f in $(sed -n 's/^COPY \\(.*\\) \\/$/\\1/p' \"$dockerfile\"); do\n\
               [ -f \"$context/$f\" ] || { echo \"context missing $f\" >&2; exit 42; }\n\
             done\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755)).unwrap();

        pack(engine.to_str().unwrap(), &version_dir, "test:1").unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
