use axum::Json;
use axum::extract::State;
use kletka_types::ImageInfo;

use crate::auth::UserContext;
use crate::error::ApiResult;
use crate::state::AppState;

pub async fn list(
    State(state): State<AppState>,
    _user: UserContext,
) -> ApiResult<Json<Vec<ImageInfo>>> {
    let mut images = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    if let Some(entries) = state.provisioner.runtime_guest_images().await {
        for (name, reference) in entries {
            seen.insert(name.clone());
            images.push(ImageInfo {
                name,
                reference,
                source: "builder".to_string(),
            });
        }
    }
    for (name, reference) in &state.provisioner.config.guest_images {
        if seen.contains(name) {
            continue;
        }
        images.push(ImageInfo {
            name: name.clone(),
            reference: reference.clone(),
            source: "pin".to_string(),
        });
    }
    Ok(Json(images))
}
