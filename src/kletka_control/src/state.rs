use std::net::SocketAddr;
use std::sync::Arc;

use crate::k8s::{K8sConfig, K8sProvisioner};
use crate::oauth::OAuthSettings;
use crate::ratelimit::RateLimits;
use kletka_types::QuotaInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreationPolicy {
    Everyone,
    PlatformAdmins,
}

impl CreationPolicy {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "everyone" | "all" | "users" => Some(Self::Everyone),
            "admins" | "platform-admins" | "platform_admins" => Some(Self::PlatformAdmins),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Everyone => "everyone",
            Self::PlatformAdmins => "admins",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NamespaceSettings {
    pub creation: CreationPolicy,
    pub max_per_user: usize,
    pub default_quotas: QuotaInfo,
    pub platform_admins: Vec<String>,
}

impl Default for NamespaceSettings {
    fn default() -> Self {
        Self {
            creation: CreationPolicy::Everyone,
            max_per_user: 3,
            default_quotas: QuotaInfo {
                max_vms: 10,
                max_vcpu: 16,
                max_mem_mib: 16384,
            },
            platform_admins: Vec::new(),
        }
    }
}

impl NamespaceSettings {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        let creation = match kletka_types::env_var("KLETKA_NAMESPACE_CREATION") {
            Some(raw) => CreationPolicy::parse(&raw).unwrap_or_else(|| {
                tracing::warn!(
                    value = %raw,
                    "KLETKA_NAMESPACE_CREATION must be 'everyone' or 'admins'; using 'admins'"
                );
                CreationPolicy::PlatformAdmins
            }),
            None => defaults.creation,
        };
        Self {
            creation,
            max_per_user: kletka_types::env_parse("KLETKA_MAX_NAMESPACES_PER_USER")
                .unwrap_or(defaults.max_per_user),
            default_quotas: QuotaInfo {
                max_vms: kletka_types::env_parse("KLETKA_NAMESPACE_DEFAULT_MAX_VMS")
                    .unwrap_or(defaults.default_quotas.max_vms),
                max_vcpu: kletka_types::env_parse("KLETKA_NAMESPACE_DEFAULT_MAX_VCPU")
                    .unwrap_or(defaults.default_quotas.max_vcpu),
                max_mem_mib: kletka_types::env_parse("KLETKA_NAMESPACE_DEFAULT_MAX_MEM_MIB")
                    .unwrap_or(defaults.default_quotas.max_mem_mib),
            },
            platform_admins: parse_email_list(
                &kletka_types::env_var("KLETKA_PLATFORM_ADMINS").unwrap_or_default(),
            ),
        }
    }

    pub fn is_configured_admin(&self, email: &str) -> bool {
        let email = email.trim();
        self.platform_admins
            .iter()
            .any(|admin| admin.eq_ignore_ascii_case(email))
    }
}

pub fn parse_email_list(raw: &str) -> Vec<String> {
    raw.split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[derive(Debug, Clone)]
pub struct AuthSettings {
    pub password: bool,
    pub oauth: OAuthSettings,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            password: true,
            oauth: OAuthSettings::default(),
        }
    }
}

impl AuthSettings {
    pub fn from_env() -> Self {
        Self {
            password: kletka_types::env_bool("KLETKA_AUTH_PASSWORD", true),
            oauth: OAuthSettings::from_env(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.password && !self.oauth.has_any() {
            return Err(
                "KLETKA_AUTH_PASSWORD=false requires at least one OAuth provider; \
                 set KLETKA_OAUTH_GITHUB_CLIENT_ID/SECRET, \
                 KLETKA_OAUTH_GITLAB_CLIENT_ID/SECRET, or KLETKA_OAUTH_STEAM_ENABLED=true"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn oauth_enabled(&self) -> Vec<crate::oauth::ProviderId> {
        self.oauth.enabled()
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::AnyPool,
    pub admin_token: String,
    pub provisioner: Arc<K8sProvisioner>,
    pub rate_limits: RateLimits,
    pub namespaces: Arc<NamespaceSettings>,
    pub auth: Arc<AuthSettings>,
}

impl AppState {
    pub fn new(
        db: sqlx::AnyPool,
        provisioner: Arc<K8sProvisioner>,
        admin_token: String,
        rate_limits: RateLimits,
        namespaces: NamespaceSettings,
        auth: AuthSettings,
    ) -> Self {
        Self {
            db,
            admin_token,
            provisioner,
            rate_limits,
            namespaces: Arc::new(namespaces),
            auth: Arc::new(auth),
        }
    }
}

#[cfg(test)]
impl AppState {
    pub fn test(db: sqlx::AnyPool) -> Self {
        Self::test_with_config(db, K8sConfig::default())
    }

    pub fn test_with_config(db: sqlx::AnyPool, config: K8sConfig) -> Self {
        Self::test_with_config_and_limits(db, config, RateLimits::disabled())
    }

    pub fn test_with_config_and_limits(
        db: sqlx::AnyPool,
        config: K8sConfig,
        rate_limits: RateLimits,
    ) -> Self {
        Self {
            db,
            admin_token: "test-admin".to_string(),
            provisioner: Arc::new(crate::k8s::K8sProvisioner::for_tests(config)),
            rate_limits,
            namespaces: Arc::new(NamespaceSettings::default()),
            auth: Arc::new(AuthSettings {
                password: true,
                oauth: OAuthSettings::default(),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: SocketAddr,
    pub admin_token: String,
    pub k8s: K8sConfig,
    pub rate_limits: RateLimits,
    pub namespaces: NamespaceSettings,
    pub auth: AuthSettings,
}

impl Config {
    pub fn from_env() -> Self {
        let database_url = kletka_types::env_var("KLETKA_DATABASE_URL")
            .unwrap_or_else(|| "sqlite:/var/lib/kletka/control.db?mode=rwc".to_string());
        let bind: SocketAddr = kletka_types::env_parse("KLETKA_BIND_ADDR")
            .unwrap_or_else(|| "127.0.0.1:8080".parse().expect("default bind addr"));
        let admin_token = kletka_types::env_var("KLETKA_ADMIN_TOKEN").unwrap_or_default();
        Self {
            database_url,
            bind,
            admin_token,
            k8s: K8sConfig::from_env(),
            rate_limits: RateLimits::from_env(),
            namespaces: NamespaceSettings::from_env(),
            auth: AuthSettings::from_env(),
        }
    }
}
