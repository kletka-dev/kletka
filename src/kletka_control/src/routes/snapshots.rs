use axum::Json;
use axum::extract::{Path, State};
use kletka_types::{CreateSnapshotRequest, SnapshotInfo, SnapshotOp, SnapshotRequest};
use uuid::Uuid;

use crate::audit::{self, Event, RequestMeta};
use crate::auth::UserContext;
use crate::error::{ApiError, ApiResult};
use crate::routes::vms::{VmRow, find_vm};
use crate::state::AppState;

async fn snapshot_op(
    state: &AppState,
    vm: &VmRow,
    body: SnapshotRequest,
) -> ApiResult<serde_json::Value> {
    let vm_id = vm.uuid()?;
    let owner_id: Uuid = vm.label_owner()?;
    state
        .provisioner
        .snapshot_vm(
            &vm_id,
            &owner_id,
            &vm.spec(),
            vm.is_stopped_or_failed(),
            body,
        )
        .await
}

pub async fn list(
    State(state): State<AppState>,
    user: UserContext,
    Path(id): Path<String>,
) -> ApiResult<Json<Vec<SnapshotInfo>>> {
    let vm = find_vm(&state.db, &user, &id).await?;
    let body = snapshot_op(
        &state,
        &vm,
        SnapshotRequest {
            op: SnapshotOp::List,
            name: None,
            memory: false,
        },
    )
    .await?;
    let snapshots: Vec<SnapshotInfo> =
        serde_json::from_value(body.get("snapshots").cloned().unwrap_or_default())
            .map_err(|_| ApiError::internal("vm agent returned a malformed snapshot list"))?;
    Ok(Json(snapshots))
}

pub async fn create(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Json(req): Json<CreateSnapshotRequest>,
) -> ApiResult<Json<SnapshotInfo>> {
    let vm = find_vm(&state.db, &user, &id).await?;
    let vm_id = vm.uuid()?;
    state
        .provisioner
        .reserve_snapshot_capacity(&vm_id, vm.spec().disk_mib)
        .await?;
    let body = snapshot_op(
        &state,
        &vm,
        SnapshotRequest {
            op: SnapshotOp::Create,
            name: Some(req.name.clone()),
            memory: req.memory,
        },
    )
    .await?;
    let snapshot: SnapshotInfo = serde_json::from_value(
        body.get("snapshot")
            .cloned()
            .ok_or_else(|| ApiError::internal("vm agent returned no snapshot record"))?,
    )
    .map_err(|_| ApiError::internal("vm agent returned a malformed snapshot record"))?;
    audit::record(
        &state.db,
        Event::user(user.user_id, "snapshot.create", &meta)
            .for_vm(&vm)
            .detail(serde_json::json!({ "snapshot": req.name })),
    )
    .await;
    Ok(Json(snapshot))
}

async fn named_snapshot_op(
    state: &AppState,
    user: &UserContext,
    meta: &RequestMeta,
    id: &str,
    name: &str,
    op: SnapshotOp,
    action: &'static str,
) -> ApiResult<serde_json::Value> {
    let vm = find_vm(&state.db, user, id).await?;
    let body = snapshot_op(
        state,
        &vm,
        SnapshotRequest {
            op,
            name: Some(name.to_string()),
            memory: false,
        },
    )
    .await?;
    audit::record(
        &state.db,
        Event::user(user.user_id, action, meta)
            .for_vm(&vm)
            .detail(serde_json::json!({ "snapshot": name })),
    )
    .await;
    Ok(body)
}

pub async fn delete(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        named_snapshot_op(
            &state,
            &user,
            &meta,
            &id,
            &name,
            SnapshotOp::Delete,
            "snapshot.delete",
        )
        .await?,
    ))
}

pub async fn rollback(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path((id, name)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(
        named_snapshot_op(
            &state,
            &user,
            &meta,
            &id,
            &name,
            SnapshotOp::Rollback,
            "snapshot.rollback",
        )
        .await?,
    ))
}

#[cfg(test)]
mod tests {
    use crate::testing::{call, json_req, signup, test_state};
    use axum::http::StatusCode;

    async fn insert_vm_row(db: &sqlx::AnyPool, owner_id: &str, name: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, \
             status, assigned_node, created_at)
             VALUES (?, ?, ?, 'default', 2, 512, 2048, 1, 'running', 'vm-x', 0)",
        )
        .bind(&id)
        .bind(owner_id)
        .bind(name)
        .execute(db)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn snapshot_routes_require_auth_and_ownership() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state.clone());

        let (status, _) = call(
            app.clone(),
            json_req("GET", "/v1/vms/x/snapshots", None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (token, owner_id) = signup(&app, "snap-owner@example.com").await;
        let (attacker_token, _) = signup(&app, "snap-attacker@example.com").await;

        let vm_id = insert_vm_row(&state.db, &owner_id, "mine").await;

        let (status, body) = call(
            app.clone(),
            json_req(
                "GET",
                "/v1/vms/ghost/snapshots",
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let foreign = [
            (
                "GET",
                format!("/v1/vms/{vm_id}/snapshots"),
                serde_json::json!({}),
            ),
            (
                "POST",
                format!("/v1/vms/{vm_id}/snapshots"),
                serde_json::json!({"name": "clean"}),
            ),
            (
                "DELETE",
                format!("/v1/vms/{vm_id}/snapshots/clean"),
                serde_json::json!({}),
            ),
            (
                "POST",
                format!("/v1/vms/{vm_id}/snapshots/clean/rollback"),
                serde_json::json!({}),
            ),
        ];
        for (method, uri, body_json) in foreign {
            let (status, body) = call(
                app.clone(),
                json_req(method, &uri, Some(&attacker_token), body_json),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {body}");
        }
    }

    #[tokio::test]
    async fn snapshot_routes_surface_agent_dial_failures() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state.clone());

        let (token, owner_id) = signup(&app, "dial@example.com").await;
        let vm_id = insert_vm_row(&state.db, &owner_id, "mine").await;

        let (status, body) = call(
            app.clone(),
            json_req(
                "GET",
                &format!("/v1/vms/{vm_id}/snapshots"),
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"].as_str().unwrap().contains("vm pod not found"),
            "{body}"
        );
    }
}
