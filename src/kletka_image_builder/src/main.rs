mod definitions;
mod oci;
mod retention;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use kletka::image::ImageStore;
use kletka::image::build::{BuildOptions, build, hash_kernel_inputs, resolve_engine, resolve_repo};

use crate::definitions::ImageDefinition;
use crate::oci::{announce, gc, pull_ref, push_version, tls_args};

const DEFAULT_KEEP_VERSIONS: usize = 3;
const DEFAULT_REPOSITORY_PREFIX: &str = "kletka/guest";

struct Config {
    data_dir: PathBuf,
    images_file: Option<PathBuf>,
    fallback_image_name: String,
    skip_kernel: bool,
    full_build_day: u8,
    seed_ref: Option<String>,
    prune_engine: bool,
    registry: Option<Registry>,
    configmap: Option<String>,
    keep_versions: usize,
    registry_retention: usize,
    vm_namespace: Option<String>,
}

struct Registry {
    push: String,
    pull: String,
    prefix: String,
    tls_verify: bool,
    user: Option<String>,
    token: Option<String>,
}

impl Registry {
    fn reference(base: &str, prefix: &str, image: &str, version: &str) -> String {
        let base = base.trim_end_matches('/');
        let prefix = prefix.trim_matches('/');
        if prefix.is_empty() {
            format!("{base}/{image}:{version}")
        } else {
            format!("{base}/{prefix}/{image}:{version}")
        }
    }

    fn push_ref(&self, image: &str, version: &str) -> String {
        Self::reference(&self.push, &self.prefix, image, version)
    }

    fn pull_ref(&self, image: &str, version: &str) -> String {
        Self::reference(&self.pull, &self.prefix, image, version)
    }

    fn host(&self) -> &str {
        self.push.split('/').next().unwrap_or(&self.push)
    }

    fn api_repository(&self, image: &str) -> String {
        let push_path = self
            .push
            .split_once('/')
            .map(|(_, path)| path)
            .unwrap_or("");
        [push_path, self.prefix.as_str(), image]
            .iter()
            .map(|part| part.trim_matches('/'))
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/")
    }
}

use kletka_types::{env_bool, env_parse, env_var as env};

impl Config {
    fn from_env() -> Result<Self, String> {
        let data_dir = env("KLETKA_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/kletka"));
        let registry = env("KLETKA_BUILDER_PUSH_REGISTRY").map(|push| Registry {
            pull: env("KLETKA_BUILDER_PULL_REGISTRY").unwrap_or_else(|| push.clone()),
            push,
            prefix: env("KLETKA_BUILDER_REPOSITORY_PREFIX")
                .unwrap_or_else(|| DEFAULT_REPOSITORY_PREFIX.to_string()),
            tls_verify: env_bool("KLETKA_BUILDER_REGISTRY_TLS_VERIFY", true),
            user: env("KLETKA_REGISTRY_USER"),
            token: env("KLETKA_REGISTRY_TOKEN"),
        });
        if env("KLETKA_BUILDER_PUSH_REF_BASE").is_some() {
            return Err(
                "KLETKA_BUILDER_PUSH_REF_BASE was replaced by KLETKA_BUILDER_PUSH_REGISTRY \
                 (+ _PULL_REGISTRY, _REPOSITORY_PREFIX); see charts/kletka"
                    .to_string(),
            );
        }
        Ok(Self {
            data_dir,
            images_file: env("KLETKA_BUILDER_IMAGES").map(PathBuf::from),
            fallback_image_name: env("KLETKA_BUILDER_IMAGE_NAME")
                .unwrap_or_else(|| "default".to_string()),
            skip_kernel: env_bool("KLETKA_BUILDER_SKIP_KERNEL", true),
            full_build_day: env_parse("KLETKA_BUILDER_FULL_BUILD_DAY").unwrap_or(0),
            seed_ref: env("KLETKA_BUILDER_SEED_REF"),
            prune_engine: env_bool("KLETKA_BUILDER_PRUNE_ENGINE", false),
            registry,
            configmap: env("KLETKA_BUILDER_CONFIGMAP"),
            keep_versions: env_parse("KLETKA_BUILDER_KEEP_VERSIONS")
                .unwrap_or(DEFAULT_KEEP_VERSIONS)
                .max(1),
            registry_retention: env_parse("KLETKA_BUILDER_REGISTRY_RETENTION").unwrap_or(0),
            vm_namespace: env("KLETKA_BUILDER_VM_NAMESPACE"),
        })
    }
}

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
            tracing::error!(%err, "bad config");
            std::process::exit(2);
        }
    };
    if let Err(err) = run(config).await {
        tracing::error!(%err, "image builder failed");
        std::process::exit(1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KernelPlan {
    Build,
    ReuseOwn,
    ReuseFrom(PathBuf),
}

fn plan_kernel(
    built_this_run: Option<&Path>,
    force_build: bool,
    own_matches: bool,
    shared: Option<&Path>,
) -> KernelPlan {
    if let Some(dir) = built_this_run {
        return KernelPlan::ReuseFrom(dir.to_path_buf());
    }
    if force_build {
        return KernelPlan::Build;
    }
    if own_matches {
        return KernelPlan::ReuseOwn;
    }
    match shared {
        Some(dir) => KernelPlan::ReuseFrom(dir.to_path_buf()),
        None => KernelPlan::Build,
    }
}

fn current_kernel(store: &ImageStore, name: &str) -> Option<(PathBuf, Option<String>)> {
    let resolved = store.resolve(name).ok()?;
    let inputs = resolved
        .manifest
        .as_ref()
        .and_then(|m| m.source.kernel_inputs_sha256.clone());
    Some((resolved.dir, inputs))
}

fn find_shared_kernel(store: &ImageStore, inputs: Option<&str>) -> Option<PathBuf> {
    let inputs = inputs?;
    let names = store.names().ok()?;
    names.iter().find_map(|name| {
        let (dir, recorded) = current_kernel(store, name)?;
        (recorded.as_deref() == Some(inputs)).then_some(dir)
    })
}

async fn run(config: Config) -> Result<(), String> {
    let definitions =
        definitions::load(config.images_file.as_deref(), &config.fallback_image_name)?;
    tracing::info!(
        version = option_env!("KLETKA_VERSION").unwrap_or("dev"),
        images = ?definitions.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        "image builder running"
    );
    let paths = kletka::system::KletkaPaths::with_data_dir(config.data_dir.clone());
    paths
        .ensure()
        .map_err(|err| format!("cannot prepare data dir: {err}"))?;
    let store = ImageStore::new(paths.images_path());
    let contexts_dir = config.data_dir.join("definitions");

    let engine = resolve_engine(None)?;
    tracing::info!(%engine, "container engine resolved");
    if config.prune_engine {
        prune_engine_storage(&engine);
    }

    if let Some(registry) = &config.registry {
        registry_login(&engine, registry)?;
    } else {
        tracing::warn!("KLETKA_BUILDER_PUSH_REGISTRY unset; images are built but not published");
    }

    let full_build = config.full_build_day > 0
        && config.full_build_day == weekday_utc(kletka_types::time::now());
    if full_build {
        tracing::info!(
            day = config.full_build_day,
            "scheduled full build (kernel included)"
        );
    }
    let force_kernel = full_build || !config.skip_kernel;
    let kernel_inputs = hash_kernel_inputs(&resolve_repo(None)?);

    if !force_kernel
        && find_shared_kernel(&store, kernel_inputs.as_deref()).is_none()
        && let Some(seed_ref) = &config.seed_ref
    {
        let target = &definitions[0].name;
        let tls_verify = config.registry.as_ref().is_none_or(|r| r.tls_verify);
        let engine = engine.clone();
        let seeded = {
            let seed_ref = seed_ref.clone();
            let store = store.clone();
            let target = target.clone();
            tokio::task::spawn_blocking(move || {
                pull_ref(&engine, &store, &seed_ref, &target, tls_verify)
            })
            .await
            .map_err(|err| format!("pull task failed: {err}"))
            .and_then(|result| result)
        };
        match &seeded {
            Ok(version) => tracing::info!(%version, seed_ref = %seed_ref, "seeded store"),
            Err(err) => {
                tracing::warn!(%err, seed_ref = %seed_ref, "seed ref unavailable; building the kernel")
            }
        }
    }

    let mut built_kernel: Option<PathBuf> = None;
    let mut failed = Vec::new();
    for def in &definitions {
        let own = current_kernel(&store, &def.name);
        let own_matches = own
            .as_ref()
            .is_some_and(|(_, recorded)| kernel_inputs.is_some() && *recorded == kernel_inputs);
        let shared = find_shared_kernel(&store, kernel_inputs.as_deref());
        let plan = plan_kernel(
            built_kernel.as_deref(),
            force_kernel,
            own_matches,
            shared.as_deref(),
        );
        tracing::info!(image = %def.name, kernel = ?plan, "building");

        match build_one(&config, &engine, &store, &paths, &contexts_dir, def, &plan).await {
            Ok(dir) => {
                if plan == KernelPlan::Build {
                    built_kernel = Some(dir);
                }
            }
            Err(err) => {
                tracing::error!(image = %def.name, %err, "image failed");
                failed.push(def.name.clone());
            }
        }
    }

    for def in &definitions {
        gc(&store, &def.name, config.keep_versions);
    }

    if config.prune_engine {
        prune_engine_storage(&engine);
    }

    let names: Vec<String> = definitions.iter().map(|d| d.name.clone()).collect();
    if let Err(err) = prune_registry(&config, &names).await {
        tracing::warn!(%err, "registry retention skipped");
    }

    if failed.is_empty() {
        tracing::info!("image builder done");
        Ok(())
    } else {
        Err(format!("images failed: {}", failed.join(", ")))
    }
}

async fn prune_registry(config: &Config, defined: &[String]) -> Result<(), String> {
    let keep = config.registry_retention;
    let (Some(registry), Some(configmap), Some(vm_namespace)) =
        (&config.registry, &config.configmap, &config.vm_namespace)
    else {
        return Ok(());
    };
    if keep == 0 {
        return Ok(());
    }
    if registry.tls_verify {
        return Err("retention only prunes plain-HTTP registries (the chart's own)".into());
    }

    let client = kube::Client::try_default()
        .await
        .map_err(|err| format!("kube client: {err}"))?;
    let announced = retention::announced_refs(&client, configmap).await?;
    let in_use = retention::in_use_refs(&client, vm_namespace).await?;

    let mut protected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for reference in announced.values().chain(in_use.iter()) {
        if let Some((repo, tag)) = retention::split_ref(reference, &registry.pull) {
            protected.entry(repo).or_default().insert(tag);
        }
    }

    let names: BTreeSet<&str> = defined
        .iter()
        .map(String::as_str)
        .chain(announced.keys().map(String::as_str))
        .collect();
    let api = retention::RegistryApi::new(registry.host());
    for name in names {
        let probe = Registry::reference(&registry.pull, &registry.prefix, name, "probe");
        let pull_repo = retention::split_ref(&probe, &registry.pull)
            .map(|(repo, _)| repo)
            .unwrap_or_default();
        let tags = protected.get(&pull_repo).cloned().unwrap_or_default();
        let repo = registry.api_repository(name);
        match retention::prune_repository(&api, &repo, keep, &tags).await {
            Ok(deleted) if !deleted.is_empty() => tracing::info!(
                image = name,
                pruned = deleted.len(),
                pinned = tags.len(),
                "registry retention applied"
            ),
            Ok(_) => {}
            Err(err) => tracing::warn!(image = name, %err, "registry retention failed"),
        }
    }
    Ok(())
}

async fn build_one(
    config: &Config,
    engine: &str,
    store: &ImageStore,
    paths: &kletka::system::KletkaPaths,
    contexts_dir: &Path,
    def: &ImageDefinition,
    plan: &KernelPlan,
) -> Result<PathBuf, String> {
    let rootfs_overlay = def.write_context(contexts_dir)?;
    let opts = BuildOptions {
        images_root: paths.images_path(),
        name: def.name.clone(),
        version: None,
        size_bytes: def.size_bytes()?,
        update: def.update(),
        skip_kernel: *plan != KernelPlan::Build,
        skip_rootfs: false,
        kernel_from: match plan {
            KernelPlan::ReuseFrom(dir) => Some(dir.clone()),
            _ => None,
        },
        rootfs_overlay,
        repo: None,
        engine: Some(engine.to_string()),
        set_current: true,
        now: kletka_types::time::now(),
    };
    let result = tokio::task::spawn_blocking(move || build(&opts))
        .await
        .map_err(|err| format!("build task failed: {err}"))??;
    tracing::info!(
        image = %result.name,
        version = %result.version,
        updated = result.manifest.source.updated,
        "built new guest image version"
    );

    let Some(registry) = &config.registry else {
        return Ok(result.dir);
    };
    let push_ref = registry.push_ref(&def.name, &result.version);
    {
        let engine = engine.to_string();
        let store = store.clone();
        let name = def.name.clone();
        let version = result.version.clone();
        let push_ref = push_ref.clone();
        let tls_verify = registry.tls_verify;
        tokio::task::spawn_blocking(move || {
            push_version(&engine, &store, &name, &version, &push_ref, tls_verify)
        })
        .await
        .map_err(|err| format!("push task failed: {err}"))??;
    }

    let pull_ref = registry.pull_ref(&def.name, &result.version);
    match &config.configmap {
        Some(configmap) => {
            announce(
                configmap,
                &def.name,
                &pull_ref,
                result.manifest.overlay_boot,
            )
            .await?
        }
        None => tracing::warn!("KLETKA_BUILDER_CONFIGMAP unset; not announcing {pull_ref}"),
    }
    Ok(result.dir)
}

fn prune_engine_storage(engine: &str) {
    let status = Command::new(engine)
        .args(["system", "prune", "--all", "--force"])
        .stdout(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => tracing::info!(%engine, "engine storage pruned"),
        Ok(status) => tracing::warn!(%engine, code = ?status.code(), "engine storage prune failed"),
        Err(err) => tracing::warn!(%engine, %err, "cannot run engine storage prune"),
    }
}

fn weekday_utc(now: kletka_types::time::Timestamp) -> u8 {
    kletka_types::time::utc(now)
        .weekday()
        .to_monday_one_offset() as u8
}

fn registry_login(engine: &str, registry: &Registry) -> Result<(), String> {
    let (Some(user), Some(token)) = (&registry.user, &registry.token) else {
        tracing::info!(registry = %registry.host(), "no registry credentials; pushing anonymously");
        return Ok(());
    };
    let host = registry.host();
    let mut args = vec!["login"];
    args.extend_from_slice(tls_args(engine, registry.tls_verify));
    args.extend_from_slice(&[host, "--password-stdin", "-u", user]);
    let mut child = Command::new(engine)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("cannot run {engine} login: {err}"))?;
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(token.as_bytes())
            .map_err(|err| format!("{engine} login: {err}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("{engine} login: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "{engine} login to {host} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weekday_matches_date_plus_u() {
        assert_eq!(weekday_utc(kletka_types::time::from_unix(0)), 4);
        assert_eq!(weekday_utc(kletka_types::time::from_unix(1_792_203_200)), 6);
        assert_eq!(weekday_utc(kletka_types::time::from_unix(1_792_289_600)), 7);
    }

    #[test]
    fn push_and_pull_refs_share_the_repository_path() {
        let registry = Registry {
            push: "kletka-registry.kletka-system.svc.cluster.local:5000".into(),
            pull: "localhost:5000/".into(),
            prefix: "/kletka/guest/".into(),
            tls_verify: false,
            user: None,
            token: None,
        };
        assert_eq!(
            registry.push_ref("python", "2026-11-17.1"),
            "kletka-registry.kletka-system.svc.cluster.local:5000/kletka/guest/python:2026-11-17.1"
        );
        assert_eq!(
            registry.pull_ref("python", "2026-11-17.1"),
            "localhost:5000/kletka/guest/python:2026-11-17.1"
        );
        assert_eq!(
            registry.host(),
            "kletka-registry.kletka-system.svc.cluster.local:5000"
        );

        let ghcr = Registry {
            push: "ghcr.io/acme".into(),
            pull: "ghcr.io/acme".into(),
            prefix: "".into(),
            tls_verify: true,
            user: None,
            token: None,
        };
        assert_eq!(ghcr.push_ref("default", "v1"), "ghcr.io/acme/default:v1");
        assert_eq!(ghcr.api_repository("default"), "acme/default");
        assert_eq!(registry.api_repository("python"), "kletka/guest/python");
        assert_eq!(ghcr.host(), "ghcr.io");
    }

    #[test]
    fn kernel_is_compiled_at_most_once_per_run() {
        let built = PathBuf::from("/store/default/versions/2");
        let shared = PathBuf::from("/store/other/versions/1");
        assert_eq!(
            plan_kernel(Some(&built), true, true, Some(&shared)),
            KernelPlan::ReuseFrom(built.clone())
        );
        assert_eq!(
            plan_kernel(None, true, true, Some(&shared)),
            KernelPlan::Build
        );
        assert_eq!(
            plan_kernel(None, false, true, Some(&shared)),
            KernelPlan::ReuseOwn
        );
        assert_eq!(
            plan_kernel(None, false, false, Some(&shared)),
            KernelPlan::ReuseFrom(shared)
        );
        assert_eq!(plan_kernel(None, false, false, None), KernelPlan::Build);
    }
}
