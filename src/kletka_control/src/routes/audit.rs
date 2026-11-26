use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;

use crate::audit::{self, AuditPage};
use crate::auth::Identity;
use crate::error::ApiResult;
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub vm: Option<String>,
    #[serde(default)]
    pub before: Option<i64>,
    #[serde(default)]
    pub limit: Option<usize>,
}

impl AuditQuery {
    pub async fn fetch(
        &self,
        db: &sqlx::AnyPool,
        scope: audit::Scope,
    ) -> Result<AuditPage, sqlx::Error> {
        audit::list(
            db,
            scope,
            self.vm.as_deref(),
            self.before,
            self.limit.unwrap_or(audit::DEFAULT_PAGE),
        )
        .await
    }
}

pub async fn list(
    State(state): State<AppState>,
    user: Identity,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<AuditPage>> {
    Ok(Json(
        query
            .fetch(&state.db, audit::Scope::User(user.user_id))
            .await?,
    ))
}
