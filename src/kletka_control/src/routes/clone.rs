use axum::Json;
use axum::extract::{Path, State};
use kletka_types::{CloneVmRequest, Vm, VmSpec};
use uuid::Uuid;

use crate::audit::{self, Event, RequestMeta};
use crate::auth::UserContext;
use crate::error::{ApiError, ApiResult};
use crate::routes::vms::{default_vm_name, fetch_vm, find_vm, vm_wire};
use crate::state::AppState;

#[derive(Debug, Clone)]
struct CloneJob {
    actor: Uuid,
    namespace_id: Uuid,
    label_owner: Uuid,
    src_id: Uuid,
    src_spec: VmSpec,
    dest_spec: VmSpec,
    dest_id: Uuid,
    dest_name: String,
    meta: RequestMeta,
}

pub(crate) async fn clone_internal(
    state: &AppState,
    user: &UserContext,
    id: &str,
    req: &CloneVmRequest,
    meta: &RequestMeta,
) -> ApiResult<Vm> {
    let src = find_vm(&state.db, user, id).await?;
    let namespace_id = src.namespace_uuid()?;
    if src.status == "cloning" {
        return Err(ApiError::conflict(
            "this VM is the target of a clone; wait for it to finish",
        ));
    }
    if src.status != "stopped" {
        return Err(ApiError::conflict(format!(
            "vm '{}' is {}; stop it before cloning",
            src.name, src.status
        )));
    }
    if !state.provisioner.guest_image_overlay_boot(&src.image).await {
        return Err(ApiError::conflict(format!(
            "guest image '{}' does not support overlay boot; a clone would not preserve \
             the vm disk",
            src.image
        )));
    }
    let src_spec = src.spec();
    let src_id = src.uuid()?;

    let dest_id = Uuid::new_v4();
    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| default_vm_name(&dest_id));
    kletka_types::validate_vm_name(&name).map_err(ApiError::bad_request)?;
    let dest_spec = VmSpec {
        name: name.clone(),
        ..src_spec.clone()
    };

    let mut tx = state.db.begin().await?;
    crate::quota::check_tx(
        &mut tx,
        &namespace_id,
        dest_spec.vcpu,
        dest_spec.memory_mib,
        true,
    )
    .await?;
    let insert = crate::db::query(
        "INSERT INTO vms (id, namespace_id, created_by, name, image, vcpu, memory_mib, disk_mib, \
         nat, status, assigned_node, created_at, idle_timeout_secs, last_active_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'cloning', ?, ?, ?, ?)",
    )
    .bind(dest_id.to_string())
    .bind(namespace_id.to_string())
    .bind(user.user_id.to_string())
    .bind(&name)
    .bind(&dest_spec.image)
    .bind(dest_spec.vcpu as i64)
    .bind(dest_spec.memory_mib as i64)
    .bind(dest_spec.disk_mib as i64)
    .bind(i64::from(dest_spec.nat))
    .bind(crate::k8s::pod_name(&dest_id))
    .bind(crate::db::now())
    .bind(src.idle_timeout_secs)
    .bind(crate::db::now())
    .execute(&mut *tx)
    .await;
    if crate::db::is_unique_violation(&insert) {
        return Err(ApiError::conflict(format!(
            "a vm named '{name}' already exists"
        )));
    }
    insert?;
    tx.commit().await?;

    let job = CloneJob {
        actor: user.user_id,
        namespace_id,
        label_owner: user.user_id,
        src_id,
        src_spec,
        dest_spec,
        dest_id,
        dest_name: name.clone(),
        meta: meta.clone(),
    };
    if let Err(err) = state
        .provisioner
        .start_clone(
            &job.dest_spec,
            &job.src_spec,
            &job.dest_id,
            &job.src_id,
            &job.label_owner,
        )
        .await
    {
        rollback_clone(state, &job, &err.message).await;
        return Err(err);
    }

    let task_state = state.clone();
    let task_job = job.clone();
    tokio::spawn(async move {
        run_clone(task_state, task_job).await;
    });
    tracing::info!(from = %src.name, into = %name, "clone started");
    vm_wire(
        &fetch_vm(&state.db, &dest_id.to_string())
            .await?
            .ok_or_else(|| ApiError::conflict("the clone was rolled back before it started"))?,
    )
}

pub async fn clone(
    State(state): State<AppState>,
    user: UserContext,
    meta: RequestMeta,
    Path(id): Path<String>,
    Json(req): Json<CloneVmRequest>,
) -> ApiResult<Json<Vm>> {
    Ok(Json(clone_internal(&state, &user, &id, &req, &meta).await?))
}

async fn run_clone(state: AppState, job: CloneJob) {
    match copy_disk(&state, &job).await {
        Ok(copied) => {
            let finalized = crate::db::query(
                "UPDATE vms SET status = 'stopped' WHERE id = ? AND status = 'cloning'",
            )
            .bind(job.dest_id.to_string())
            .execute(&state.db)
            .await
            .map(|result| result.rows_affected())
            .unwrap_or(0);
            src_maintenance_pod_reap(&state, &job).await;
            if let Err(err) = state.provisioner.delete_pod(&job.dest_id).await {
                tracing::warn!(vm = %job.dest_id, %err, "clone target maintenance pod delete failed");
            }
            if finalized == 0 {
                tracing::info!(
                    vm = %job.dest_id,
                    "clone copy finished against a destroyed row; nothing to settle"
                );
                return;
            }
            tracing::info!(
                from = %job.src_spec.name,
                into = %job.dest_name,
                copied,
                "clone landed"
            );
            audit::record(
                &state.db,
                Event::user(job.actor, "vm.clone", &job.meta)
                    .vm(job.dest_id.to_string(), &job.dest_name)
                    .namespace(job.namespace_id)
                    .detail(serde_json::json!({
                        "from": job.src_spec.name,
                        "copied": copied,
                        "stored": true,
                    })),
            )
            .await;
        }
        Err(err) => {
            tracing::warn!(
                into = %job.dest_name,
                err = %err,
                "clone copy failed; rolling the destination back"
            );
            rollback_clone(&state, &job, &err.message).await;
            src_maintenance_pod_reap(&state, &job).await;
        }
    }
}

async fn copy_disk(state: &AppState, job: &CloneJob) -> ApiResult<u64> {
    state.provisioner.wait_for_agent(&job.src_id).await?;
    state.provisioner.wait_for_agent(&job.dest_id).await?;

    let source = state.provisioner.disk_stream(&job.src_id).await?;
    let expected = source.content_length();
    let bytes = reqwest::Body::wrap_stream(source.bytes_stream());
    let written = state.provisioner.disk_push(&job.dest_id, bytes).await?;
    if expected.is_some_and(|announced| announced != written) {
        return Err(ApiError::conflict(format!(
            "the disk copy did not complete: the source announced {decoded} bytes, the \
             target wrote {written}",
            decoded = expected.unwrap_or(0)
        )));
    }
    Ok(written)
}

async fn rollback_clone(state: &AppState, job: &CloneJob, why: &str) {
    let rolled =
        crate::db::query("DELETE FROM vms WHERE id = ? AND status IN ('cloning', 'failed')")
            .bind(job.dest_id.to_string())
            .execute(&state.db)
            .await
            .map(|result| result.rows_affected())
            .unwrap_or(0);
    if rolled == 0 {
        return;
    }
    state.provisioner.destroy(&job.dest_id).await;
    audit::record(
        &state.db,
        Event::user(job.actor, "vm.clone", &job.meta)
            .vm(job.dest_id.to_string(), &job.dest_name)
            .namespace(job.namespace_id)
            .detail(serde_json::json!({ "denied": why }))
            .denied(),
    )
    .await;
}

async fn src_maintenance_pod_reap(state: &AppState, job: &CloneJob) {
    let status: Option<(String,)> = match crate::db::query_as("SELECT status FROM vms WHERE id = ?")
        .bind(job.src_id.to_string())
        .fetch_optional(&state.db)
        .await
    {
        Ok(status) => status,
        Err(err) => {
            tracing::warn!(%err, "clone cleanup: source status lookup failed");
            return;
        }
    };
    if status.map(|(status,)| status) != Some("stopped".to_string()) {
        return;
    }
    if let Err(err) = state.provisioner.delete_pod(&job.src_id).await {
        tracing::warn!(vm = %job.src_id, %err, "clone source maintenance pod delete failed");
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use kletka_types::VmSpec;
    use uuid::Uuid;

    use crate::k8s::K8sConfig;
    use crate::testing::{call, json_req, signup, test_state, test_state_with_config};

    async fn insert_vm_row(db: &sqlx::AnyPool, owner_id: &str, name: &str, status: &str) -> String {
        let id = Uuid::new_v4().to_string();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, \
             status, assigned_node, created_at) \
             VALUES (?, ?, ?, 'default', 2, 512, 2048, 1, ?, 'vm-x', 0)",
        )
        .bind(&id)
        .bind(owner_id)
        .bind(name)
        .bind(status)
        .execute(db)
        .await
        .unwrap();
        id
    }

    fn overlay_config() -> K8sConfig {
        let mut config = K8sConfig::default();
        config
            .guest_image_overlay_boots
            .insert("default".into(), true);
        config
    }

    #[tokio::test]
    async fn clone_validates_the_source() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state.clone());
        let (token_v, _) = signup(&app, "clone-owner@example.com").await;

        let (status, _) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/vms/ghost/clone",
                Some(&token_v),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let vm_id = insert_vm_row(
            &state.db,
            &signup(&app, "real-owner@example.com").await.1,
            "research",
            "running",
        )
        .await;
        let (status, _) = call(
            app.clone(),
            json_req(
                "POST",
                &format!("/v1/vms/{vm_id}/clone"),
                Some(&token_v),
                serde_json::json!({"name": "copy"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (_, owner) = signup(&app, "clone-real@example.com").await;
        let running = insert_vm_row(&state.db, &owner, "labs", "running").await;
        let (status, _) = call(
            app.clone(),
            json_req(
                "POST",
                &format!("/v1/vms/{running}/clone"),
                Some(&token_v),
                serde_json::json!({"name": "copy"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let owner_token = {
            let (status, body) = call(
                app.clone(),
                json_req(
                    "POST",
                    "/v1/auth/login",
                    None,
                    serde_json::json!({"email": "clone-real@example.com", "password": "test-password-123"}),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            body["token"].as_str().unwrap().to_string()
        };
        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                &format!("/v1/vms/{running}/clone"),
                Some(&owner_token),
                serde_json::json!({"name": "copy"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body["error"].as_str().unwrap().contains("stop it"));

        crate::db::query("UPDATE vms SET status = 'stopped' WHERE id = ?")
            .bind(&running)
            .execute(&state.db)
            .await
            .unwrap();
        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                &format!("/v1/vms/{running}/clone"),
                Some(&owner_token),
                serde_json::json!({"name": "copy"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("does not support overlay boot"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn clone_sync_failures_leave_no_row_behind() {
        let (state, _guard) = test_state_with_config(overlay_config()).await;
        let app = crate::router(state.clone());
        let (token, owner) = signup(&app, "clone-fail@example.com").await;
        let src = insert_vm_row(&state.db, &owner, "research", "stopped").await;

        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                &format!("/v1/vms/{src}/clone"),
                Some(&token),
                serde_json::json!({"name": "copy"}),
            ),
        )
        .await;
        assert!(
            status == StatusCode::CONFLICT || status == StatusCode::INTERNAL_SERVER_ERROR,
            "{status} {body}"
        );
        let names: Vec<(String,)> =
            crate::db::query_as("SELECT name FROM vms WHERE namespace_id = ?")
                .bind(&owner)
                .fetch_all(&state.db)
                .await
                .unwrap();
        assert_eq!(names, vec![("research".to_string(),)]);
    }

    #[tokio::test]
    async fn clone_rejects_bad_names_and_over_quota() {
        let (state, _guard) = test_state_with_config(overlay_config()).await;
        let app = crate::router(state.clone());
        let (token, owner) = signup(&app, "clone-plain@example.com").await;
        let src = insert_vm_row(&state.db, &owner, "research", "stopped").await;
        let clone = |body: serde_json::Value| {
            call(
                app.clone(),
                json_req("POST", &format!("/v1/vms/{src}/clone"), Some(&token), body),
            )
        };

        let (status, _) = clone(serde_json::json!({"name": "NoGo"})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        crate::db::query("UPDATE users SET quota_max_vcpu = 1 WHERE id = ?")
            .bind(&owner)
            .execute(&state.db)
            .await
            .unwrap();
        let (status, body) = clone(serde_json::json!({"name": "copy"})).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
    }

    #[test]
    fn dest_spec_copies_the_source_but_the_name() {
        let spec = VmSpec {
            name: "research".into(),
            image: "default".into(),
            vcpu: 4,
            memory_mib: 2048,
            disk_mib: 20480,
            nat: true,
        };
        let dest = VmSpec {
            name: "copy".into(),
            ..spec.clone()
        };
        assert_eq!(dest.name, "copy");
        assert_eq!(dest.vcpu, spec.vcpu);
        assert_eq!(dest.disk_mib, spec.disk_mib);
        assert_eq!(dest.nat, spec.nat);
    }
}
