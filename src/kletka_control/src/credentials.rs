use uuid::Uuid;

use crate::audit::{self, Event, RequestMeta};
use crate::auth::mint_token;
use crate::password;
use kletka_types::AuthResponse;

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthError {
    #[error("invalid email")]
    InvalidEmail,
    #[error("password is required (min 8 characters)")]
    WeakPassword,
    #[error("email already registered; log in instead")]
    EmailTaken,
    #[error("unknown email; sign up first")]
    UnknownEmail,
    #[error("password not set for this account; ask an admin to reset it")]
    PasswordUnset,
    #[error("wrong password")]
    WrongPassword,
    #[error("database error: {0}")]
    Internal(String),
}

impl AuthError {
    pub(crate) fn status(&self) -> axum::http::StatusCode {
        match self {
            Self::InvalidEmail | Self::WeakPassword => axum::http::StatusCode::BAD_REQUEST,
            Self::EmailTaken => axum::http::StatusCode::CONFLICT,
            Self::UnknownEmail => axum::http::StatusCode::NOT_FOUND,
            Self::PasswordUnset | Self::WrongPassword => axum::http::StatusCode::UNAUTHORIZED,
            Self::Internal(_) => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<sqlx::Error> for AuthError {
    fn from(err: sqlx::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<AuthError> for crate::error::ApiError {
    fn from(err: AuthError) -> Self {
        Self::new(err.status(), err.to_string())
    }
}

pub(crate) fn valid_email(email: &str) -> bool {
    let mut parts = email.split('@');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(user), Some(domain), None) => !user.is_empty() && domain.contains('.'),
        _ => false,
    }
}

pub(crate) fn check_password(password: Option<&str>) -> Result<String, AuthError> {
    password
        .filter(|password| password.trim().len() >= 8)
        .map(str::to_string)
        .ok_or(AuthError::WeakPassword)
}

pub(crate) async fn hash_blocking(password: String) -> Result<String, AuthError> {
    tokio::task::spawn_blocking(move || password::hash(&password))
        .await
        .map_err(|err| AuthError::Internal(err.to_string()))?
        .map_err(AuthError::Internal)
}

async fn verify_blocking(password: String, stored: String) -> Result<bool, AuthError> {
    tokio::task::spawn_blocking(move || password::verify(&password, &stored))
        .await
        .map_err(|err| AuthError::Internal(err.to_string()))
}

fn audit_event(
    user_id: Uuid,
    action: &'static str,
    meta: &RequestMeta,
    via: Option<&str>,
) -> Event {
    let event = Event::user(user_id, action, meta);
    match via {
        Some(via) => event.detail(serde_json::json!({ "via": via })),
        None => event,
    }
}

pub(crate) async fn signup(
    db: &sqlx::AnyPool,
    email: &str,
    password: Option<&str>,
    meta: &RequestMeta,
    via: Option<&str>,
) -> Result<AuthResponse, AuthError> {
    let email = email.trim().to_string();
    if !valid_email(&email) {
        return Err(AuthError::InvalidEmail);
    }
    let password = check_password(password)?;
    let exists: Option<(String,)> = crate::db::query_as("SELECT id FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(db)
        .await?;
    if exists.is_some() {
        return Err(AuthError::EmailTaken);
    }
    let hash = hash_blocking(password).await?;
    let user_id = Uuid::new_v4();
    let insert = crate::db::query(
        "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(user_id.to_string())
    .bind(&email)
    .bind(&hash)
    .bind(crate::db::now())
    .execute(db)
    .await;
    if crate::db::is_unique_violation(&insert) {
        return Err(AuthError::EmailTaken);
    }
    insert?;
    crate::namespaces::ensure_personal(db, &user_id, &email)
        .await
        .map_err(|err| AuthError::Internal(err.message))?;
    let token = mint_token(db, &user_id).await?;
    audit::record(db, audit_event(user_id, "account.signup", meta, via)).await;
    Ok(AuthResponse { user_id, token })
}

pub(crate) async fn login(
    db: &sqlx::AnyPool,
    email: &str,
    password: Option<&str>,
    meta: &RequestMeta,
    via: Option<&str>,
) -> Result<AuthResponse, AuthError> {
    let email = email.trim().to_string();
    let password = password.map(str::to_string).unwrap_or_default();
    let row: Option<(String, Option<String>)> =
        crate::db::query_as("SELECT id, password_hash FROM users WHERE email = ?")
            .bind(&email)
            .fetch_optional(db)
            .await?;
    let Some((id, stored)) = row else {
        let _ = tokio::task::spawn_blocking({
            let password = password.clone();
            move || password::dummy_verify(&password)
        })
        .await;
        return Err(AuthError::UnknownEmail);
    };
    let Some(stored) = stored else {
        return Err(AuthError::PasswordUnset);
    };
    let user_id: Uuid = id
        .parse()
        .map_err(|_| AuthError::Internal("corrupt user id".into()))?;
    let event = audit_event(user_id, "account.login", meta, via);
    if !verify_blocking(password, stored).await? {
        audit::record(db, event.denied()).await;
        return Err(AuthError::WrongPassword);
    }
    let token = mint_token(db, &user_id).await?;
    audit::record(db, event).await;
    Ok(AuthResponse { user_id, token })
}
