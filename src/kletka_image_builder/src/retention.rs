use std::collections::{BTreeMap, BTreeSet};

use k8s_openapi::api::core::v1::{ConfigMap, PersistentVolumeClaim, Pod};
use kube::api::{Api, ListParams};

use crate::oci::parse_configmap_ref;
pub use kletka_types::GUEST_REF_ANNOTATION;

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
                               application/vnd.docker.distribution.manifest.v2+json, \
                               application/vnd.oci.image.index.v1+json, \
                               application/vnd.docker.distribution.manifest.list.v2+json";

fn version_key(tag: &str) -> (String, u64) {
    match tag.rsplit_once('.') {
        Some((head, n)) if !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()) => {
            (head.to_string(), n.parse().unwrap_or(0))
        }
        _ => (tag.to_string(), 0),
    }
}

pub fn select_doomed(tags: &[String], keep: usize, protected: &BTreeSet<String>) -> Vec<String> {
    let mut sorted: Vec<&String> = tags.iter().collect();
    sorted.sort_by_key(|tag| std::cmp::Reverse(version_key(tag)));
    sorted
        .into_iter()
        .skip(keep)
        .filter(|tag| !protected.contains(*tag))
        .cloned()
        .collect()
}

pub fn split_ref(reference: &str, base: &str) -> Option<(String, String)> {
    let base = base.trim_end_matches('/');
    let rest = reference.strip_prefix(base)?.strip_prefix('/')?;
    let rest = rest.split('@').next().unwrap_or(rest);
    let (repo, tag) = rest.rsplit_once(':')?;
    if repo.is_empty() || tag.is_empty() || tag.contains('/') {
        return None;
    }
    Some((repo.to_string(), tag.to_string()))
}

pub async fn in_use_refs(
    client: &kube::Client,
    namespace: &str,
) -> Result<BTreeSet<String>, String> {
    let mut refs = BTreeSet::new();
    let claims: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), namespace);
    let claims = claims
        .list(&ListParams::default())
        .await
        .map_err(|err| format!("listing vm data claims: {err}"))?;
    for claim in claims {
        if let Some(reference) = claim
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(GUEST_REF_ANNOTATION))
        {
            refs.insert(reference.clone());
        }
    }
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pods = pods
        .list(&ListParams::default())
        .await
        .map_err(|err| format!("listing vm pods: {err}"))?;
    for pod in pods {
        let volumes = pod.spec.and_then(|spec| spec.volumes).unwrap_or_default();
        for volume in volumes {
            if let Some(reference) = volume.image.and_then(|image| image.reference) {
                refs.insert(reference);
            }
        }
    }
    Ok(refs)
}

pub async fn announced_refs(
    client: &kube::Client,
    configmap_ref: &str,
) -> Result<BTreeMap<String, String>, String> {
    let (namespace, name) = parse_configmap_ref(configmap_ref)?;
    let maps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let cm = maps
        .get_opt(name)
        .await
        .map_err(|err| format!("reading {configmap_ref}: {err}"))?;
    Ok(cm
        .and_then(|cm| cm.data)
        .unwrap_or_default()
        .into_iter()
        .filter(|(key, _)| !key.ends_with(".overlay_boot"))
        .collect())
}

pub struct RegistryApi {
    base: String,
    http: reqwest::Client,
}

impl RegistryApi {
    pub fn new(host: &str) -> Self {
        Self {
            base: format!("http://{}", host.trim_end_matches('/')),
            http: reqwest::Client::new(),
        }
    }

    pub async fn tags(&self, repo: &str) -> Result<Vec<String>, String> {
        let url = format!("{}/v2/{repo}/tags/list?n=10000", self.base);
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|err| format!("GET {url}: {err}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Vec::new());
        }
        if !response.status().is_success() {
            return Err(format!("GET {url}: {}", response.status()));
        }
        let body = response
            .text()
            .await
            .map_err(|err| format!("GET {url}: {err}"))?;
        let parsed: serde_json::Value =
            serde_json::from_str(&body).map_err(|err| format!("GET {url}: {err}"))?;
        Ok(parsed["tags"]
            .as_array()
            .map(|tags| {
                tags.iter()
                    .filter_map(|tag| tag.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    pub async fn digest(&self, repo: &str, tag: &str) -> Result<String, String> {
        let url = format!("{}/v2/{repo}/manifests/{tag}", self.base);
        let response = self
            .http
            .head(&url)
            .header(reqwest::header::ACCEPT, MANIFEST_ACCEPT)
            .send()
            .await
            .map_err(|err| format!("HEAD {url}: {err}"))?;
        if !response.status().is_success() {
            return Err(format!("HEAD {url}: {}", response.status()));
        }
        response
            .headers()
            .get("docker-content-digest")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| format!("HEAD {url}: no Docker-Content-Digest header"))
    }

    pub async fn delete(&self, repo: &str, digest: &str) -> Result<(), String> {
        let url = format!("{}/v2/{repo}/manifests/{digest}", self.base);
        let response = self
            .http
            .delete(&url)
            .send()
            .await
            .map_err(|err| format!("DELETE {url}: {err}"))?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(format!("DELETE {url}: {}", response.status()))
        }
    }
}

pub async fn prune_repository(
    api: &RegistryApi,
    repo: &str,
    keep: usize,
    protected: &BTreeSet<String>,
) -> Result<Vec<String>, String> {
    let tags = api.tags(repo).await?;
    let doomed = select_doomed(&tags, keep, protected);
    if doomed.is_empty() {
        return Ok(Vec::new());
    }
    let mut kept_digests = BTreeSet::new();
    for tag in tags.iter().filter(|tag| !doomed.contains(tag)) {
        kept_digests.insert(api.digest(repo, tag).await?);
    }
    let mut deleted = Vec::new();
    for tag in doomed {
        let digest = api.digest(repo, &tag).await?;
        if kept_digests.contains(&digest) {
            tracing::warn!(%repo, %tag, %digest, "shares a digest with a kept tag; not deleting");
            continue;
        }
        api.delete(repo, &digest).await?;
        tracing::info!(%repo, %tag, %digest, "pruned guest image version");
        deleted.push(tag);
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Router;
    use axum::extract::{Path, State};
    use axum::http::{HeaderMap, Method, StatusCode};
    use axum::routing::any;

    use super::*;

    fn tags(list: &[&str]) -> Vec<String> {
        list.iter().map(|t| t.to_string()).collect()
    }

    #[test]
    fn versions_sort_by_date_then_build_number() {
        let doomed = select_doomed(
            &tags(&[
                "2026-11-17.9",
                "2026-11-16.1",
                "2026-11-17.10",
                "2026-11-15.3",
            ]),
            2,
            &BTreeSet::new(),
        );
        assert_eq!(doomed, tags(&["2026-11-16.1", "2026-11-15.3"]));
    }

    #[test]
    fn protected_versions_survive() {
        let protected = BTreeSet::from(["2026-11-01.1".to_string()]);
        let doomed = select_doomed(
            &tags(&[
                "2026-11-01.1",
                "2026-11-02.1",
                "2026-11-03.1",
                "2026-11-04.1",
            ]),
            2,
            &protected,
        );
        assert_eq!(doomed, tags(&["2026-11-02.1"]));
        assert!(select_doomed(&tags(&["a"]), 2, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn refs_split_relative_to_the_pull_registry() {
        assert_eq!(
            split_ref(
                "localhost:5000/kletka/guest/default:2026-11-17.1",
                "localhost:5000"
            ),
            Some(("kletka/guest/default".into(), "2026-11-17.1".into()))
        );
        assert_eq!(
            split_ref(
                "localhost:5000/kletka/guest/py:v1@sha256:abc",
                "localhost:5000/"
            ),
            Some(("kletka/guest/py".into(), "v1".into()))
        );
        assert_eq!(
            split_ref("ghcr.io/o/kletka-guest-default:v1", "localhost:5000"),
            None
        );
        assert_eq!(split_ref("localhost:50001/a:b", "localhost:5000"), None);
        assert_eq!(split_ref("localhost:5000/untagged", "localhost:5000"), None);
    }

    #[derive(Clone)]
    struct Fake {
        digests: Arc<BTreeMap<String, String>>,
        deleted: Arc<Mutex<Vec<String>>>,
    }

    async fn handle(
        State(fake): State<Fake>,
        method: Method,
        headers: HeaderMap,
        Path(path): Path<String>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut out = HeaderMap::new();
        if let Some(repo) = path.strip_suffix("/tags/list") {
            assert_eq!(repo, "kletka/guest/default");
            let tags: Vec<&String> = fake.digests.keys().collect();
            return (
                StatusCode::OK,
                out,
                serde_json::json!({ "tags": tags }).to_string(),
            );
        }
        let (_, reference) = path.split_once("/manifests/").expect("manifest path");
        match method {
            Method::HEAD => {
                assert!(
                    headers["accept"]
                        .to_str()
                        .unwrap()
                        .contains("application/vnd.oci.image.manifest.v1+json")
                );
                let digest = &fake.digests[reference];
                out.insert("docker-content-digest", digest.parse().unwrap());
                (StatusCode::OK, out, String::new())
            }
            Method::DELETE => {
                fake.deleted.lock().unwrap().push(reference.to_string());
                (StatusCode::ACCEPTED, out, String::new())
            }
            _ => (StatusCode::METHOD_NOT_ALLOWED, out, String::new()),
        }
    }

    #[tokio::test]
    async fn prunes_unreferenced_versions_by_digest() {
        let fake = Fake {
            digests: Arc::new(BTreeMap::from([
                ("2026-11-14.1".to_string(), "sha256:14".to_string()),
                ("2026-11-15.1".to_string(), "sha256:15".to_string()),
                ("2026-11-16.1".to_string(), "sha256:16".to_string()),
                ("2026-11-17.1".to_string(), "sha256:17".to_string()),
                ("2026-11-13.1".to_string(), "sha256:17".to_string()),
            ])),
            deleted: Arc::default(),
        };
        let app = Router::new()
            .route("/v2/{*path}", any(handle))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let api = RegistryApi::new(&addr.to_string());
        let protected = BTreeSet::from(["2026-11-14.1".to_string()]);
        let deleted = prune_repository(&api, "kletka/guest/default", 2, &protected)
            .await
            .unwrap();
        assert_eq!(deleted, tags(&["2026-11-15.1"]));
        assert_eq!(*fake.deleted.lock().unwrap(), vec!["sha256:15".to_string()]);
    }
}
