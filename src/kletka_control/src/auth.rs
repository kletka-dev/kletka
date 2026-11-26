use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::namespaces::NsAccess;
use crate::state::AppState;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub use kletka_types::secrets_equal;

pub const TOKEN_COOKIE: &str = "kletka_token";

pub fn token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(header) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(token) = header.strip_prefix("Bearer ")
    {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }
    let cookies = headers.get_all(axum::http::header::COOKIE);
    for value in cookies {
        let Ok(raw) = value.to_str() else { continue };
        for part in raw.split(';') {
            let part = part.trim();
            let Some((key, val)) = part.split_once('=') else {
                continue;
            };
            if key.trim() == TOKEN_COOKIE {
                let token = val.trim().trim_matches('"').to_string();
                if !token.is_empty() {
                    return Some(token);
                }
            }
        }
    }
    None
}

pub fn set_token_cookie(token: &str) -> String {
    format!("{TOKEN_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000")
}

pub fn clear_token_cookie() -> String {
    format!("{TOKEN_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
}

fn raw_token_hex() -> (String, String) {
    let raw: [u8; 32] = rand::random();
    let shown: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    (shown.clone(), sha256_hex(shown.as_bytes()))
}

pub async fn mint_token(db: &sqlx::AnyPool, user_id: &Uuid) -> Result<String, sqlx::Error> {
    let (shown, hash) = raw_token_hex();
    crate::db::query("INSERT INTO tokens (token_hash, user_id, created_at) VALUES (?, ?, ?)")
        .bind(hash)
        .bind(user_id.to_string())
        .bind(crate::db::now())
        .execute(db)
        .await?;
    Ok(shown)
}

pub async fn lookup_token(state: &AppState, token: &str) -> Option<Identity> {
    identity_for_token(state, token).await.ok().flatten()
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub user_id: Uuid,
    pub email: String,
    pub platform_admin: bool,
}

impl Identity {
    pub async fn in_namespace(
        self,
        db: &sqlx::AnyPool,
        selector: Option<&str>,
    ) -> ApiResult<UserContext> {
        let ns = crate::namespaces::resolve(
            db,
            &self.user_id,
            &self.email,
            self.platform_admin,
            selector,
        )
        .await?;
        Ok(UserContext {
            user_id: self.user_id,
            email: self.email,
            platform_admin: self.platform_admin,
            ns,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UserContext {
    pub user_id: Uuid,
    pub email: String,
    pub platform_admin: bool,
    pub ns: NsAccess,
}

impl UserContext {
    pub fn identity(&self) -> Identity {
        Identity {
            user_id: self.user_id,
            email: self.email.clone(),
            platform_admin: self.platform_admin,
        }
    }
}

pub async fn is_platform_admin(state: &AppState, user_id: &Uuid) -> ApiResult<bool> {
    let row: Option<(String, i64)> =
        crate::db::query_as("SELECT email, is_platform_admin FROM users WHERE id = ?")
            .bind(user_id.to_string())
            .fetch_optional(&state.db)
            .await?;
    Ok(row.is_some_and(|(email, flag)| flag != 0 || state.namespaces.is_configured_admin(&email)))
}

async fn identity_for_token(state: &AppState, token: &str) -> ApiResult<Option<Identity>> {
    let hash = sha256_hex(token.as_bytes());
    let row: Option<(String, String, i64)> = crate::db::query_as(
        "SELECT users.id, users.email, users.is_platform_admin FROM tokens \
         JOIN users ON users.id = tokens.user_id WHERE tokens.token_hash = ?",
    )
    .bind(hash)
    .fetch_optional(&state.db)
    .await?;
    Ok(row.and_then(|(id, email, flag)| {
        let platform_admin = flag != 0 || state.namespaces.is_configured_admin(&email);
        Some(Identity {
            user_id: id.parse().ok()?,
            email,
            platform_admin,
        })
    }))
}

pub const NAMESPACE_COOKIE: &str = "kletka_ns";

pub fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|raw| raw.split(';'))
        .filter_map(|part| part.trim().split_once('='))
        .find(|(key, _)| key.trim() == name)
        .map(|(_, value)| value.trim().trim_matches('"').to_string())
        .filter(|value| !value.is_empty())
}

pub enum Selector {
    Explicit(String),
    Cookie(String),
    Default,
}

pub fn namespace_selector(parts: &Parts) -> Selector {
    if let Some(value) = parts
        .headers
        .get(kletka_types::NAMESPACE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        return Selector::Explicit(value.to_string());
    }
    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            if let Some(("namespace", value)) = pair.split_once('=')
                && !value.is_empty()
            {
                return Selector::Explicit(value.to_string());
            }
        }
    }
    match cookie_value(&parts.headers, NAMESPACE_COOKIE) {
        Some(value) => Selector::Cookie(value),
        None => Selector::Default,
    }
}

impl FromRequestParts<AppState> for Identity {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let Some(token) = token_from_headers(&parts.headers) else {
            return Err(ApiError::unauthorized(
                "missing Authorization: Bearer <token>",
            ));
        };
        identity_for_token(state, &token)
            .await?
            .ok_or_else(|| ApiError::unauthorized("invalid token"))
    }
}

impl FromRequestParts<AppState> for UserContext {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let identity = Identity::from_request_parts(parts, state).await?;
        match namespace_selector(parts) {
            Selector::Explicit(key) => identity.in_namespace(&state.db, Some(&key)).await,
            Selector::Cookie(key) => {
                match identity.clone().in_namespace(&state.db, Some(&key)).await {
                    Ok(user) => Ok(user),
                    Err(_) => identity.in_namespace(&state.db, None).await,
                }
            }
            Selector::Default => identity.in_namespace(&state.db, None).await,
        }
    }
}
