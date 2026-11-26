use axum::{Json, extract::State};
use serde::Deserialize;
use uuid::Uuid;

use kletka_types::AuthResponse;

use crate::audit::RequestMeta;
use crate::auth::UserContext;
use crate::credentials;
use crate::error::{ApiError, ApiResult};
use crate::quota;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub email: String,
    pub password: Option<String>,
}

pub async fn signup(
    State(state): State<AppState>,
    meta: RequestMeta,
    Json(req): Json<AuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    credentials::signup(&state.db, &req.email, req.password.as_deref(), &meta, None)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn login(
    State(state): State<AppState>,
    meta: RequestMeta,
    Json(req): Json<AuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    credentials::login(&state.db, &req.email, req.password.as_deref(), &meta, None)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn set_password(db: &sqlx::AnyPool, email: &str, new_password: &str) -> ApiResult<Uuid> {
    let new_password = credentials::check_password(Some(new_password)).map_err(ApiError::from)?;
    let row: Option<(String,)> = crate::db::query_as("SELECT id FROM users WHERE email = ?")
        .bind(email)
        .fetch_optional(db)
        .await?;
    let Some((id,)) = row else {
        return Err(ApiError::not_found(format!("unknown email '{email}'")));
    };
    let hash = credentials::hash_blocking(new_password)
        .await
        .map_err(ApiError::from)?;
    crate::db::query("UPDATE users SET password_hash = ? WHERE id = ?")
        .bind(hash)
        .bind(&id)
        .execute(db)
        .await?;
    id.parse()
        .map_err(|_| ApiError::internal("corrupt user id"))
}

pub async fn me(
    State(state): State<AppState>,
    user: UserContext,
) -> ApiResult<Json<kletka_types::AccountInfo>> {
    Ok(Json(quota::account(&state.db, &user).await?))
}
