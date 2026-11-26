use axum::Json;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use uuid::Uuid;

use crate::audit::{self, Actor, Event, RequestMeta};
use crate::auth::{Identity, secrets_equal, token_from_headers};
use crate::error::{ApiError, ApiResult};
use crate::namespaces;
use crate::quota;
use crate::state::AppState;
use kletka_types::{AccountInfo, QuotaInfo, UpdateUserRequest, UserSummary};

#[derive(Debug, Clone)]
pub enum AdminCaller {
    Token,
    User(Identity),
}

impl AdminCaller {
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::Token => None,
            Self::User(identity) => Some(identity.user_id),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Token => "admin-token".to_string(),
            Self::User(identity) => identity.email.clone(),
        }
    }
}

impl FromRequestParts<AppState> for AdminCaller {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        if let Some(got) = parts
            .headers
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
        {
            if state.admin_token.is_empty() {
                return Err(ApiError::forbidden(
                    "admin token disabled (KLETKA_ADMIN_TOKEN unset); use a platform admin account",
                ));
            }
            if !secrets_equal(got, &state.admin_token) {
                return Err(ApiError::unauthorized("bad admin token"));
            }
            return Ok(Self::Token);
        }
        if token_from_headers(&parts.headers).is_none() {
            return Err(ApiError::unauthorized(
                "admin credentials required: X-Admin-Token or a platform admin's bearer token",
            ));
        }
        let identity = Identity::from_request_parts(parts, state).await?;
        if !identity.platform_admin {
            return Err(ApiError::forbidden("this needs a platform admin"));
        }
        Ok(Self::User(identity))
    }
}

pub(crate) async fn account_for(
    state: &AppState,
    user_id: Uuid,
    email: String,
) -> ApiResult<AccountInfo> {
    let platform_admin = crate::auth::is_platform_admin(state, &user_id).await?;
    let user = Identity {
        user_id,
        email,
        platform_admin,
    }
    .in_namespace(&state.db, None)
    .await?;
    Ok(quota::account(&state.db, &user).await?)
}

pub async fn show_user(
    State(state): State<AppState>,
    _admin: AdminCaller,
    Path(key): Path<String>,
) -> ApiResult<Json<AccountInfo>> {
    let (user_id, email) = namespaces::user_by_key(&state.db, &key).await?;
    Ok(Json(account_for(&state, user_id, email).await?))
}

pub async fn set_quota(
    State(state): State<AppState>,
    admin: AdminCaller,
    meta: RequestMeta,
    Path(key): Path<String>,
    Json(req): Json<QuotaInfo>,
) -> ApiResult<Json<AccountInfo>> {
    let (user_id, email) = namespaces::user_by_key(&state.db, &key).await?;
    set_user_quota(&state, &admin, &meta, user_id, req).await?;
    Ok(Json(account_for(&state, user_id, email).await?))
}

pub(crate) async fn set_user_quota(
    state: &AppState,
    _admin: &AdminCaller,
    meta: &RequestMeta,
    user_id: Uuid,
    limits: QuotaInfo,
) -> ApiResult<QuotaInfo> {
    let quotas = quota::set_quotas(&state.db, &user_id, &limits).await?;
    audit::record(
        &state.db,
        Event::user(user_id, "account.quota", meta)
            .actor(Actor::Admin)
            .namespace(user_id)
            .detail(serde_json::to_value(limits).unwrap_or_default()),
    )
    .await;
    Ok(quotas)
}

pub async fn user_audit(
    State(state): State<AppState>,
    _admin: AdminCaller,
    Path(key): Path<String>,
    Query(query): Query<crate::routes::audit::AuditQuery>,
) -> ApiResult<Json<audit::AuditPage>> {
    let (user_id, _) = namespaces::user_by_key(&state.db, &key).await?;
    Ok(Json(
        query.fetch(&state.db, audit::Scope::User(user_id)).await?,
    ))
}

pub(crate) async fn user_summaries(state: &AppState) -> ApiResult<Vec<UserSummary>> {
    let rows: Vec<(String, String, i64, Option<i64>, i64, i64)> = crate::db::query_as(
        "SELECT u.id, u.email, u.is_platform_admin, u.max_namespaces, u.created_at, \
                (SELECT COUNT(*) FROM namespace_members m \
                   JOIN namespaces n ON n.id = m.namespace_id \
                  WHERE m.user_id = u.id AND m.role = 'owner' AND n.personal_user_id IS NULL) \
         FROM users u ORDER BY u.email",
    )
    .fetch_all(&state.db)
    .await?;
    rows.into_iter()
        .map(|(id, email, flag, max, created, owned)| {
            Ok(UserSummary {
                user_id: id
                    .parse()
                    .map_err(|_| ApiError::internal("corrupt user id"))?,
                platform_admin: flag != 0 || state.namespaces.is_configured_admin(&email),
                email,
                max_namespaces: max.map(|max| max.max(0) as usize),
                namespaces_owned: owned.max(0) as usize,
                created_at: crate::db::timestamp(created),
            })
        })
        .collect()
}

pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminCaller,
) -> ApiResult<Json<Vec<UserSummary>>> {
    Ok(Json(user_summaries(&state).await?))
}

pub async fn update_user(
    State(state): State<AppState>,
    admin: AdminCaller,
    meta: RequestMeta,
    Path(key): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> ApiResult<Json<UserSummary>> {
    let (user_id, _) = namespaces::user_by_key(&state.db, &key).await?;
    apply_user_update(&state, &admin, &meta, user_id, &req).await?;
    user_summaries(&state)
        .await?
        .into_iter()
        .find(|user| user.user_id == user_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("user vanished"))
}

pub(crate) async fn apply_user_update(
    state: &AppState,
    admin: &AdminCaller,
    meta: &RequestMeta,
    user_id: Uuid,
    req: &UpdateUserRequest,
) -> ApiResult<()> {
    if let Some(flag) = req.platform_admin {
        if !flag && admin.user_id() == Some(user_id) {
            return Err(ApiError::bad_request(
                "you cannot revoke your own platform admin role; ask another platform admin",
            ));
        }
        crate::db::query("UPDATE users SET is_platform_admin = ? WHERE id = ?")
            .bind(i64::from(flag))
            .bind(user_id.to_string())
            .execute(&state.db)
            .await?;
        audit::record(
            &state.db,
            Event::user(user_id, "account.platform_admin", meta)
                .actor(Actor::Admin)
                .detail(serde_json::json!({ "platform_admin": flag, "by": admin.label() })),
        )
        .await;
    }
    if let Some(max) = req.max_namespaces {
        crate::db::query("UPDATE users SET max_namespaces = ? WHERE id = ?")
            .bind(max.map(|max| max as i64))
            .bind(user_id.to_string())
            .execute(&state.db)
            .await?;
        audit::record(
            &state.db,
            Event::user(user_id, "account.namespace_allowance", meta)
                .actor(Actor::Admin)
                .detail(serde_json::json!({ "max_namespaces": max, "by": admin.label() })),
        )
        .await;
    }
    Ok(())
}
