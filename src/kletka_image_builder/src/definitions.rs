use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use kletka::image::build::{DEFAULT_SIZE_BYTES, parse_size_bytes};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageDefinition {
    pub name: String,
    #[serde(default)]
    pub size: Option<String>,
    #[serde(default)]
    pub update: Option<bool>,
    #[serde(default)]
    pub dockerfile: Option<String>,
    #[serde(default)]
    pub files: BTreeMap<String, String>,
}

impl ImageDefinition {
    pub fn builtin(name: &str) -> Self {
        Self {
            name: name.to_string(),
            size: None,
            update: None,
            dockerfile: None,
            files: BTreeMap::new(),
        }
    }

    pub fn size_bytes(&self) -> Result<u64, String> {
        match &self.size {
            Some(raw) => {
                parse_size_bytes(raw).map_err(|err| format!("image '{}': {err}", self.name))
            }
            None => Ok(DEFAULT_SIZE_BYTES),
        }
    }

    pub fn update(&self) -> bool {
        self.update.unwrap_or(true)
    }

    pub fn write_context(&self, parent: &Path) -> Result<Option<PathBuf>, String> {
        let Some(dockerfile) = &self.dockerfile else {
            return Ok(None);
        };
        let dir = parent.join(&self.name);
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .map_err(|err| format!("cannot clear {}: {err}", dir.display()))?;
        }
        fs::create_dir_all(&dir)
            .map_err(|err| format!("cannot create {}: {err}", dir.display()))?;
        fs::write(dir.join("Dockerfile"), dockerfile)
            .map_err(|err| format!("cannot write Dockerfile for '{}': {err}", self.name))?;
        for (rel, contents) in &self.files {
            let dest = dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| format!("cannot create {}: {err}", parent.display()))?;
            }
            fs::write(&dest, contents)
                .map_err(|err| format!("cannot write {}: {err}", dest.display()))?;
        }
        Ok(Some(dir))
    }
}

fn validate_name(name: &str) -> Result<(), String> {
    kletka::image::validate_image_name(name)?;
    let first_ok = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let all_ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.'));
    if !first_ok || !all_ok || name.contains("..") {
        return Err(format!(
            "invalid image name '{name}': use lowercase letters, digits, '.', '-', '_' \
             (starting with a letter or digit)"
        ));
    }
    Ok(())
}

fn validate_file_path(image: &str, rel: &str) -> Result<(), String> {
    let path = Path::new(rel);
    let safe = !rel.is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if !safe {
        return Err(format!(
            "image '{image}': file '{rel}' must be a relative path inside the build context"
        ));
    }
    if rel == "Dockerfile" {
        return Err(format!(
            "image '{image}': set the Dockerfile via 'dockerfile', not 'files'"
        ));
    }
    Ok(())
}

pub fn parse(json: &str) -> Result<Vec<ImageDefinition>, String> {
    let defs: Vec<ImageDefinition> =
        serde_json::from_str(json).map_err(|err| format!("invalid image definitions: {err}"))?;
    if defs.is_empty() {
        return Err("image definitions list is empty".to_string());
    }
    let mut seen = std::collections::BTreeSet::new();
    for def in &defs {
        validate_name(&def.name)?;
        if !seen.insert(def.name.as_str()) {
            return Err(format!("image '{}' is defined twice", def.name));
        }
        def.size_bytes()?;
        if def.dockerfile.is_none() && !def.files.is_empty() {
            return Err(format!(
                "image '{}': 'files' need a 'dockerfile' to use them",
                def.name
            ));
        }
        for rel in def.files.keys() {
            validate_file_path(&def.name, rel)?;
        }
    }
    Ok(defs)
}

pub fn load(path: Option<&Path>, fallback_name: &str) -> Result<Vec<ImageDefinition>, String> {
    match path {
        Some(path) => {
            let json = fs::read_to_string(path)
                .map_err(|err| format!("cannot read {}: {err}", path.display()))?;
            parse(&json)
        }
        None => {
            validate_name(fallback_name)?;
            Ok(vec![ImageDefinition::builtin(fallback_name)])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_builtin_and_layered_definitions() {
        let defs = parse(
            r#"[
              {"name": "default"},
              {"name": "python", "size": "4G", "update": false,
               "dockerfile": "ARG KLETKA_BASE\nFROM ${KLETKA_BASE}\n",
               "files": {"etc/motd": "hi\n"}}
            ]"#,
        )
        .unwrap();
        assert_eq!(defs.len(), 2);
        assert_eq!(defs[0], ImageDefinition::builtin("default"));
        assert!(defs[0].update());
        assert_eq!(defs[0].size_bytes().unwrap(), DEFAULT_SIZE_BYTES);
        assert_eq!(defs[1].size_bytes().unwrap(), 4 * 1024 * 1024 * 1024);
        assert!(!defs[1].update());
    }

    #[test]
    fn rejects_bad_definitions() {
        for (json, needle) in [
            ("[]", "empty"),
            (r#"[{"name": "Py"}]"#, "lowercase"),
            (r#"[{"name": "a/b"}]"#, "invalid"),
            (r#"[{"name": "a"}, {"name": "a"}]"#, "twice"),
            (r#"[{"name": "a", "size": "lots"}]"#, "invalid size"),
            (
                r#"[{"name": "a", "files": {"x": ""}}]"#,
                "need a 'dockerfile'",
            ),
            (
                r#"[{"name": "a", "dockerfile": "FROM x", "files": {"../x": ""}}]"#,
                "relative path",
            ),
            (
                r#"[{"name": "a", "dockerfile": "FROM x", "files": {"/etc/x": ""}}]"#,
                "relative path",
            ),
            (
                r#"[{"name": "a", "dockerfile": "FROM x", "files": {"Dockerfile": ""}}]"#,
                "via 'dockerfile'",
            ),
            (r#"[{"name": "a", "bogus": 1}]"#, "unknown field"),
        ] {
            let err = parse(json).unwrap_err();
            assert!(err.contains(needle), "{json}: {err}");
        }
    }

    #[test]
    fn writes_a_fresh_context() {
        let parent = std::env::temp_dir().join(format!("kletka-defs-{}", uuid::Uuid::new_v4()));
        let def =
            parse(r#"[{"name": "py", "dockerfile": "FROM x\n", "files": {"conf/a.txt": "a"}}]"#)
                .unwrap()
                .remove(0);
        fs::create_dir_all(parent.join("py")).unwrap();
        fs::write(parent.join("py/stale"), "old").unwrap();

        let dir = def.write_context(&parent).unwrap().unwrap();
        assert_eq!(
            fs::read_to_string(dir.join("Dockerfile")).unwrap(),
            "FROM x\n"
        );
        assert_eq!(fs::read_to_string(dir.join("conf/a.txt")).unwrap(), "a");
        assert!(!dir.join("stale").exists());

        assert!(
            ImageDefinition::builtin("default")
                .write_context(&parent)
                .unwrap()
                .is_none()
        );
        let _ = fs::remove_dir_all(&parent);
    }

    #[test]
    fn load_falls_back_to_one_builtin_image() {
        assert_eq!(
            load(None, "default").unwrap(),
            vec![ImageDefinition::builtin("default")]
        );
        assert!(load(None, "Bad").is_err());
    }
}
