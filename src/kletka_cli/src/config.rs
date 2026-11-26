use std::path::PathBuf;

use crate::error::{CliError, CliResult, io_error};

const DEFAULT_CONTROL_URL: &str = "http://127.0.0.1:8080";

fn config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config/kletka"))
}

fn credentials_path() -> Option<PathBuf> {
    config_dir().map(|dir| dir.join("credentials"))
}

fn read_key(path: Option<PathBuf>, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path?).ok()?;
    parse_key(&text, key)
}

fn parse_key(text: &str, key: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.starts_with('['))
        .filter_map(|line| line.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, value)| value.trim().trim_matches(['"', '\'']).trim().to_string())
        .filter(|value| !value.is_empty())
}

use kletka_types::env_var as env;

pub fn control_url(flag: Option<&str>) -> String {
    flag.map(str::to_string)
        .or_else(|| env("KLETKA_CONTROL_URL"))
        .or_else(|| read_key(config_dir().map(|d| d.join("config.toml")), "control_url"))
        .or_else(|| read_key(credentials_path(), "control_url"))
        .unwrap_or_else(|| DEFAULT_CONTROL_URL.to_string())
        .trim_end_matches('/')
        .to_string()
}

pub fn namespace(flag: Option<&str>) -> Option<String> {
    flag.map(str::to_string)
        .or_else(|| env("KLETKA_NAMESPACE"))
        .or_else(|| read_key(config_dir().map(|d| d.join("config.toml")), "namespace"))
        .map(|ns| ns.trim().to_string())
        .filter(|ns| !ns.is_empty())
}

pub fn token() -> CliResult<String> {
    env("KLETKA_TOKEN")
        .or_else(|| read_key(credentials_path(), "token"))
        .ok_or_else(|| {
            CliError::new("not logged in")
                .hint("run `kletka login --control <url>` (or set KLETKA_TOKEN)")
        })
}

pub fn save_credentials(control_url: &str, token: &str) -> CliResult<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    let path = credentials_path().ok_or("cannot locate your home directory ($HOME is unset)")?;
    let parent = path.parent().expect("credentials path has a parent");
    std::fs::create_dir_all(parent).map_err(|err| io_error(parent.display(), err))?;
    let write = || -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        writeln!(file, "control_url = \"{control_url}\"")?;
        writeln!(file, "token = \"{token}\"")
    };
    write().map_err(|err| {
        io_error(
            format!("cannot save credentials to {}", path.display()),
            err,
        )
    })
}

pub fn clear_credentials() -> CliResult<bool> {
    let Some(path) = credentials_path() else {
        return Ok(false);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error(path.display(), err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_key_values() {
        let text = "# comment\n[section]\ncontrol_url = \"https://x\"\ntoken='abc'\nempty = \"\"\n";
        assert_eq!(parse_key(text, "control_url").as_deref(), Some("https://x"));
        assert_eq!(parse_key(text, "token").as_deref(), Some("abc"));
        assert_eq!(parse_key(text, "empty"), None);
        assert_eq!(parse_key(text, "missing"), None);
    }

    #[test]
    fn credentials_roundtrip_with_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("kletka-creds-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let old_home = std::env::var_os("HOME");
        unsafe { std::env::set_var("HOME", &dir) };

        save_credentials("http://ctl:8080", "tok123").unwrap();
        assert_eq!(
            read_key(credentials_path(), "token").as_deref(),
            Some("tok123")
        );
        assert_eq!(
            read_key(credentials_path(), "control_url").as_deref(),
            Some("http://ctl:8080")
        );
        let mode = std::fs::metadata(dir.join(".config/kletka/credentials"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        assert!(clear_credentials().unwrap());
        assert!(!clear_credentials().unwrap());

        unsafe {
            match old_home {
                Some(home) => std::env::set_var("HOME", home),
                None => std::env::remove_var("HOME"),
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
