use serde::Deserialize;
use serde_json::Value;

use kletka_types::urlencode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderId {
    GitHub,
    GitLab,
    Steam,
}

impl ProviderId {
    pub const ALL: [Self; 3] = [Self::GitHub, Self::GitLab, Self::Steam];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
            Self::Steam => "steam",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::GitHub => "GitHub",
            Self::GitLab => "GitLab",
            Self::Steam => "Steam",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.as_str().eq_ignore_ascii_case(raw.trim()))
    }
}

#[derive(Debug, Clone)]
pub struct OAuth2Client {
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone)]
pub struct GitLabClient {
    pub base: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Default)]
pub struct SteamClient {
    pub api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OAuthSettings {
    pub public_url: String,
    pub github: Option<OAuth2Client>,
    pub gitlab: Option<GitLabClient>,
    pub steam: Option<SteamClient>,
    http: reqwest::Client,
}

impl Default for OAuthSettings {
    fn default() -> Self {
        Self {
            public_url: String::new(),
            github: None,
            gitlab: None,
            steam: None,
            http: reqwest::Client::new(),
        }
    }
}

impl OAuthSettings {
    pub fn from_env() -> Self {
        Self {
            public_url: kletka_types::env_var("KLETKA_PUBLIC_URL")
                .map(|url| url.trim_end_matches('/').to_string())
                .unwrap_or_default(),
            github: oauth2_client("GITHUB"),
            gitlab: {
                let client_id = env_secret("KLETKA_OAUTH_GITLAB_CLIENT_ID");
                let client_secret = env_secret("KLETKA_OAUTH_GITLAB_CLIENT_SECRET");
                (!client_id.is_empty() && !client_secret.is_empty()).then(|| GitLabClient {
                    base: kletka_types::env_var("KLETKA_OAUTH_GITLAB_URL")
                        .map(|url| url.trim_end_matches('/').to_string())
                        .unwrap_or_else(|| "https://gitlab.com".to_string()),
                    client_id,
                    client_secret,
                })
            },
            steam: kletka_types::env_bool("KLETKA_OAUTH_STEAM_ENABLED", false).then(|| SteamClient {
                api_key: kletka_types::env_var("KLETKA_OAUTH_STEAM_API_KEY"),
            }),
            http: reqwest::Client::new(),
        }
    }

    pub fn enabled(&self) -> Vec<ProviderId> {
        ProviderId::ALL
            .into_iter()
            .filter(|provider| self.is_enabled(*provider))
            .collect()
    }

    pub fn is_enabled(&self, provider: ProviderId) -> bool {
        match provider {
            ProviderId::GitHub => self.github.is_some(),
            ProviderId::GitLab => self.gitlab.is_some(),
            ProviderId::Steam => self.steam.is_some(),
        }
    }

    pub fn has_any(&self) -> bool {
        self.github.is_some() || self.gitlab.is_some() || self.steam.is_some()
    }

    pub fn callback_url(&self, provider: ProviderId) -> String {
        format!("{}/login/oauth/{}/callback", self.public_url, provider.as_str())
    }

    pub fn authorize_url(&self, provider: ProviderId, state: &str) -> String {
        let redirect = urlencode(&self.callback_url(provider));
        let state = urlencode(state);
        match provider {
            ProviderId::GitHub => {
                let client_id = urlencode(&self.github.as_ref().expect("enabled").client_id);
                format!(
                    "https://github.com/login/oauth/authorize?client_id={client_id}\
                     &redirect_uri={redirect}&state={state}&scope=read:user%20user:email"
                )
            }
            ProviderId::GitLab => {
                let gitlab = self.gitlab.as_ref().expect("enabled");
                let client_id = urlencode(&gitlab.client_id);
                format!(
                    "{}/oauth/authorize?client_id={client_id}\
                     &redirect_uri={redirect}&state={state}&response_type=code&scope=read_user",
                    gitlab.base
                )
            }
            ProviderId::Steam => self.steam_authorize_url(&self.callback_url(provider), &state),
        }
    }

    pub fn steam_authorize_url(&self, callback: &str, state: &str) -> String {
        let return_to = format!("{callback}?state={state}");
        format!(
            "https://steamcommunity.com/openid/login?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0\
             &openid.mode=checkid_setup&openid.return_to={}&openid.realm={}\
             &openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select\
             &openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select",
            urlencode(&return_to),
            urlencode(&origin_of(callback)),
        )
    }

    pub async fn exchange_code(&self, provider: ProviderId, code: &str) -> Result<Profile, String> {
        match provider {
            ProviderId::GitHub => self.github_profile(code).await,
            ProviderId::GitLab => self.gitlab_profile(code).await,
            ProviderId::Steam => Err("Steam uses OpenID, not OAuth code exchange".to_string()),
        }
    }

    pub async fn verify_steam(&self, openid: &[(String, String)]) -> Result<Profile, String> {
        let steam = self.steam.as_ref().expect("enabled");
        let mut form: Vec<(String, String)> = openid
            .iter()
            .filter(|(key, _)| key.starts_with("openid."))
            .cloned()
            .collect();
        form.retain(|(key, _)| key != "openid.mode");
        form.push(("openid.mode".into(), "check_authentication".into()));
        let body = self
            .http
            .post("https://steamcommunity.com/openid/login")
            .form(&form)
            .send()
            .await
            .map_err(|err| format!("cannot reach Steam: {err}"))?
            .text()
            .await
            .map_err(|err| format!("cannot read Steam's verification reply: {err}"))?;
        if !body.contains("is_valid:true") {
            return Err("Steam did not verify this sign-in".to_string());
        }
        let claimed = openid
            .iter()
            .find(|(key, _)| key == "openid.claimed_id")
            .map(|(_, value)| value.as_str())
            .unwrap_or_default();
        let steamid = claimed
            .rsplit('/')
            .next()
            .filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_digit()))
            .ok_or("Steam returned an unexpected identity")?;
        let email = format!("{steamid}@steam.local");
        let name = match steam.api_key.as_deref().filter(|key| !key.is_empty()) {
            Some(key) => self.steam_name(key, steamid).await,
            None => String::new(),
        };
        Ok(Profile {
            provider: ProviderId::Steam,
            uid: steamid.to_string(),
            email,
            name,
        })
    }

    async fn steam_name(&self, key: &str, steamid: &str) -> String {
        #[derive(Deserialize)]
        struct Reply {
            #[serde(default)]
            response: Option<ReplyResponse>,
        }
        #[derive(Deserialize)]
        struct ReplyResponse {
            #[serde(default)]
            players: Vec<ReplyPlayer>,
        }
        #[derive(Deserialize)]
        struct ReplyPlayer {
            #[serde(default)]
            personaname: Option<String>,
        }
        let Ok(response) = self
            .http
            .get("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/")
            .query(&[("key", key), ("steamids", steamid)])
            .send()
            .await
        else {
            return String::new();
        };
        match response.json::<Reply>().await {
            Ok(reply) => reply
                .response
                .and_then(|response| response.players.into_iter().next())
                .and_then(|player| player.personaname)
                .unwrap_or_default(),
            Err(_) => String::new(),
        }
    }

    async fn github_token(&self, code: &str) -> Result<String, String> {
        let client = self.github.as_ref().expect("enabled");
        let redirect = self.callback_url(ProviderId::GitHub);
        let form = [
            ("client_id", client.client_id.as_str()),
            ("client_secret", client.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect.as_str()),
            ("grant_type", "authorization_code"),
        ];
        token_from(
            &self.http,
            "https://github.com/login/oauth/access_token",
            &form,
        )
        .await
    }

    async fn github_profile(&self, code: &str) -> Result<Profile, String> {
        let token = self.github_token(code).await?;
        let user: Value = self
            .http
            .get("https://api.github.com/user")
            .bearer_auth(&token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "kletka")
            .send()
            .await
            .map_err(|err| format!("cannot read the GitHub profile: {err}"))?
            .json()
            .await
            .map_err(|err| format!("GitHub sent an unexpected profile: {err}"))?;
        let uid = user
            .get("id")
            .and_then(Value::as_i64)
            .ok_or("GitHub profile has no id")?;
        let login = user
            .get("login")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let email = user
            .get("email")
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
            .map(str::to_string);
        let email = match email {
            Some(email) => email,
            None => {
                let primary = self.github_primary_email(&token).await;
                if primary.is_empty() {
                    format!("{login}@users.noreply.github.com")
                } else {
                    primary
                }
            }
        };
        Ok(Profile {
            provider: ProviderId::GitHub,
            uid: uid.to_string(),
            email,
            name: login.to_string(),
        })
    }

    async fn github_primary_email(&self, token: &str) -> String {
        let Ok(response) = self
            .http
            .get("https://api.github.com/user/emails")
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "kletka")
            .send()
            .await
        else {
            return String::new();
        };
        let Ok(emails) = response.json::<Value>().await else {
            return String::new();
        };
        for entry in emails.as_array().map(Vec::as_slice).unwrap_or(&[]) {
            let primary = entry.get("primary").and_then(Value::as_bool) == Some(true);
            let verified = entry.get("verified").and_then(Value::as_bool) != Some(false);
            if primary
                && verified
                && let Some(email) = entry.get("email").and_then(Value::as_str)
            {
                return email.to_string();
            }
        }
        String::new()
    }

    async fn gitlab_token(&self, code: &str) -> Result<String, String> {
        let gitlab = self.gitlab.as_ref().expect("enabled");
        let redirect = self.callback_url(ProviderId::GitLab);
        let form = [
            ("client_id", gitlab.client_id.as_str()),
            ("client_secret", gitlab.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect.as_str()),
            ("grant_type", "authorization_code"),
        ];
        token_from(&self.http, &format!("{}/oauth/token", gitlab.base), &form).await
    }

    async fn gitlab_profile(&self, code: &str) -> Result<Profile, String> {
        let gitlab = self.gitlab.as_ref().expect("enabled");
        let token = self.gitlab_token(code).await?;
        let user: Value = self
            .http
            .get(format!("{}/api/v4/user", gitlab.base))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|err| format!("cannot read the GitLab profile: {err}"))?
            .json()
            .await
            .map_err(|err| format!("GitLab sent an unexpected profile: {err}"))?;
        let uid = user
            .get("id")
            .and_then(Value::as_i64)
            .ok_or("GitLab profile has no id")?;
        let username = user
            .get("username")
            .and_then(Value::as_str)
            .unwrap_or("user")
            .to_string();
        let email = user
            .get("email")
            .and_then(Value::as_str)
            .filter(|email| !email.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{username}@users.gitlab"));
        Ok(Profile {
            provider: ProviderId::GitLab,
            uid: uid.to_string(),
            email,
            name: username,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub provider: ProviderId,
    pub uid: String,
    pub email: String,
    pub name: String,
}

async fn token_from(
    http: &reqwest::Client,
    token_url: &str,
    form: &[(&str, &str); 5],
) -> Result<String, String> {
    let reply: Value = http
        .post(token_url)
        .header("Accept", "application/json")
        .form(form)
        .send()
        .await
        .map_err(|err| format!("cannot reach the token endpoint: {err}"))?
        .json()
        .await
        .map_err(|err| format!("token endpoint sent an unexpected reply: {err}"))?;
    reply
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            reply
                .get("error_description")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| "the provider did not issue an access token".to_string())
}

fn oauth2_client(name: &str) -> Option<OAuth2Client> {
    let client_id = env_secret(&format!("KLETKA_OAUTH_{name}_CLIENT_ID"));
    let client_secret = env_secret(&format!("KLETKA_OAUTH_{name}_CLIENT_SECRET"));
    (!client_id.is_empty() && !client_secret.is_empty()).then_some(OAuth2Client {
        client_id,
        client_secret,
    })
}

fn env_secret(name: &str) -> String {
    kletka_types::env_var(name).unwrap_or_default()
}

fn origin_of(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let rest = &url[scheme_end + 3..];
    let end = rest.find('/').unwrap_or(rest.len());
    url[..scheme_end + 3 + end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_parse_and_round_trip() {
        for provider in ProviderId::ALL {
            assert_eq!(ProviderId::parse(provider.as_str()), Some(provider));
        }
        assert_eq!(ProviderId::parse("GITHUB"), Some(ProviderId::GitHub));
        assert_eq!(ProviderId::parse("gitlab "), Some(ProviderId::GitLab));
        assert_eq!(ProviderId::parse("sso"), None);
        assert_eq!(ProviderId::GitHub.label(), "GitHub");
        assert_eq!(ProviderId::Steam.label(), "Steam");
    }

    #[test]
    fn settings_enable_each_provider_from_env() {
        const KEYS: [&str; 8] = [
            "KLETKA_OAUTH_GITHUB_CLIENT_ID",
            "KLETKA_OAUTH_GITHUB_CLIENT_SECRET",
            "KLETKA_OAUTH_GITLAB_CLIENT_ID",
            "KLETKA_OAUTH_GITLAB_CLIENT_SECRET",
            "KLETKA_OAUTH_GITLAB_URL",
            "KLETKA_OAUTH_STEAM_ENABLED",
            "KLETKA_OAUTH_STEAM_API_KEY",
            "KLETKA_PUBLIC_URL",
        ];
        for key in KEYS {
            unsafe { std::env::remove_var(key) };
        }
        let settings = OAuthSettings::from_env();
        assert!(!settings.has_any());
        assert_eq!(settings.enabled(), Vec::<ProviderId>::new());

        unsafe {
            std::env::set_var("KLETKA_PUBLIC_URL", "https://control.example.com");
            std::env::set_var("KLETKA_OAUTH_GITHUB_CLIENT_ID", "abc");
            std::env::set_var("KLETKA_OAUTH_GITHUB_CLIENT_SECRET", "shh");
            std::env::set_var("KLETKA_OAUTH_GITLAB_CLIENT_ID", "abc");
            std::env::set_var("KLETKA_OAUTH_GITLAB_CLIENT_SECRET", "shh");
            std::env::set_var("KLETKA_OAUTH_GITLAB_URL", "https://git.example.com/");
            std::env::set_var("KLETKA_OAUTH_STEAM_ENABLED", "true");
        }
        let settings = OAuthSettings::from_env();
        assert_eq!(
            settings.enabled(),
            vec![ProviderId::GitHub, ProviderId::GitLab, ProviderId::Steam]
        );

        let authorize = settings.authorize_url(ProviderId::GitLab, "st");
        assert!(
            authorize.starts_with("https://git.example.com/oauth/authorize?"),
            "{authorize}"
        );
        assert!(authorize.contains("redirect_uri="), "{authorize}");
        assert!(authorize.contains("state=st"), "{authorize}");
        let authorize = settings.authorize_url(ProviderId::GitHub, "st");
        assert!(
            authorize.starts_with("https://github.com/login/oauth/authorize?"),
            "{authorize}"
        );
        let callback = settings.callback_url(ProviderId::Steam);
        assert_eq!(
            callback,
            "https://control.example.com/login/oauth/steam/callback"
        );
        let steam = settings.authorize_url(ProviderId::Steam, "st123");
        assert!(
            steam.contains("openid.return_to=https%3A//control.example.com/login/oauth/steam/callback%3Fstate%3Dst123"),
            "{steam}"
        );
        assert!(
            steam.contains("openid.realm=https%3A//control.example.com"),
            "{steam}"
        );

        for key in KEYS {
            unsafe { std::env::remove_var(key) };
        }
    }

    #[test]
    fn origins_strip_paths() {
        assert_eq!(
            origin_of("https://control.example.com/login/oauth/steam/callback"),
            "https://control.example.com"
        );
        assert_eq!(origin_of("http://127.0.0.1:8123/"), "http://127.0.0.1:8123");
    }
}
