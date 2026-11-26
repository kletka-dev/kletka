use axum::Json;
use kletka_types::VersionInfo;

use crate::VERSION;
use crate::auth::UserContext;
use crate::error::ApiResult;

pub async fn version(_user: UserContext) -> ApiResult<Json<VersionInfo>> {
    Ok(Json(VersionInfo {
        version: VERSION.to_string(),
    }))
}
