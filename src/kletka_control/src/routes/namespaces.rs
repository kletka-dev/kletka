use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;

use crate::audit::{self, Actor, AuditPage, Event, RequestMeta};
use crate::auth::Identity;
use crate::error::{ApiError, ApiResult};
use crate::namespaces::{self, NamespaceRow, NsAccess};
use crate::routes::admin::AdminCaller;
use crate::state::AppState;
use kletka_types::{
    AddMemberRequest, CreateNamespaceRequest, NamespaceInfo, NamespaceMember,
    NamespaceRole as Role, QuotaInfo, UpdateMemberRequest, UpdateNamespaceRequest,
};

pub(crate) async fn open(
    state: &AppState,
    user: &Identity,
    key: &str,
) -> ApiResult<(NamespaceRow, NsAccess)> {
    let not_found = || ApiError::not_found(format!("namespace '{key}' not found"));
    let row = namespaces::find(&state.db, key)
        .await?
        .ok_or_else(not_found)?;
    let access = namespaces::access(&state.db, &user.user_id, user.platform_admin, &row)
        .await?
        .ok_or_else(not_found)?;
    Ok((row, access))
}

fn ns_event(user: &Identity, action: &'static str, meta: &RequestMeta, ns: &NsAccess) -> Event {
    let event = Event::user(user.user_id, action, meta).namespace(ns.id);
    if !ns.member {
        event.actor(Actor::Admin)
    } else {
        event
    }
}

pub(crate) async fn create_ns(
    state: &AppState,
    user: &Identity,
    meta: &RequestMeta,
    name: &str,
) -> ApiResult<NamespaceRow> {
    let row = namespaces::create(
        &state.db,
        &state.namespaces,
        &user.user_id,
        user.platform_admin,
        name,
    )
    .await?;
    audit::record(
        &state.db,
        Event::user(user.user_id, "namespace.create", meta)
            .namespace(&row.id)
            .detail(serde_json::json!({ "name": row.name })),
    )
    .await;
    Ok(row)
}

pub(crate) async fn rename_ns(
    state: &AppState,
    user: &Identity,
    meta: &RequestMeta,
    ns: &NsAccess,
    name: &str,
) -> ApiResult<()> {
    namespaces::rename(&state.db, ns, name).await?;
    audit::record(
        &state.db,
        ns_event(user, "namespace.rename", meta, ns)
            .detail(serde_json::json!({ "from": ns.name, "name": name.trim() })),
    )
    .await;
    Ok(())
}

pub(crate) async fn delete_ns(
    state: &AppState,
    user: &Identity,
    meta: &RequestMeta,
    ns: &NsAccess,
) -> ApiResult<()> {
    namespaces::delete(&state.db, ns).await?;
    audit::record(
        &state.db,
        ns_event(user, "namespace.delete", meta, ns).detail(serde_json::json!({ "name": ns.name })),
    )
    .await;
    Ok(())
}

pub(crate) async fn add_member_op(
    state: &AppState,
    user: &Identity,
    meta: &RequestMeta,
    ns: &NsAccess,
    email: &str,
    role: Role,
) -> ApiResult<()> {
    let (_, email) = namespaces::add_member(&state.db, ns, email, role).await?;
    audit::record(
        &state.db,
        ns_event(user, "namespace.member.add", meta, ns)
            .detail(serde_json::json!({ "member": email, "role": role })),
    )
    .await;
    Ok(())
}

pub(crate) async fn set_role_op(
    state: &AppState,
    user: &Identity,
    meta: &RequestMeta,
    ns: &NsAccess,
    member: &str,
    role: Role,
) -> ApiResult<()> {
    let (target, email) = namespaces::user_by_key(&state.db, member).await?;
    let from = namespaces::set_role(&state.db, ns, &target, role).await?;
    audit::record(
        &state.db,
        ns_event(user, "namespace.member.role", meta, ns)
            .detail(serde_json::json!({ "member": email, "from": from, "role": role })),
    )
    .await;
    Ok(())
}

pub(crate) async fn remove_member_op(
    state: &AppState,
    user: &Identity,
    meta: &RequestMeta,
    ns: &NsAccess,
    member: &str,
) -> ApiResult<()> {
    let (target, email) = namespaces::user_by_key(&state.db, member).await?;
    let role = namespaces::remove_member(&state.db, ns, &user.user_id, &target).await?;
    audit::record(
        &state.db,
        ns_event(user, "namespace.member.remove", meta, ns)
            .detail(serde_json::json!({ "member": email, "role": role })),
    )
    .await;
    Ok(())
}

pub(crate) async fn set_quota_op(
    state: &AppState,
    admin: &AdminCaller,
    meta: &RequestMeta,
    row: &NamespaceRow,
    limits: Option<QuotaInfo>,
) -> ApiResult<QuotaInfo> {
    let quotas = namespaces::set_quota(&state.db, &state.namespaces, row, limits).await?;
    audit::record(
        &state.db,
        Event::user(admin.user_id().unwrap_or_default(), "namespace.quota", meta)
            .actor(Actor::Admin)
            .namespace(&row.id)
            .detail(serde_json::json!({
                "quotas": quotas,
                "reset": limits.is_none(),
                "by": admin.label(),
            })),
    )
    .await;
    Ok(quotas)
}

async fn info_for(
    state: &AppState,
    row: &NamespaceRow,
    access: &NsAccess,
) -> ApiResult<NamespaceInfo> {
    namespaces::info(&state.db, row, access.member.then_some(access.role)).await
}

#[derive(Debug, Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub all: bool,
}

pub async fn list(
    State(state): State<AppState>,
    user: Identity,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Vec<NamespaceInfo>>> {
    namespaces::ensure_personal(&state.db, &user.user_id, &user.email).await?;
    let mut out = Vec::new();
    if query.all {
        if !user.platform_admin {
            return Err(ApiError::forbidden(
                "listing every namespace needs a platform admin",
            ));
        }
        for row in namespaces::list_all(&state.db).await? {
            let role = namespaces::role_of(&state.db, &row.id, &user.user_id).await?;
            out.push(namespaces::info(&state.db, &row, role).await?);
        }
    } else {
        for (row, role) in namespaces::list_for_user(&state.db, &user.user_id).await? {
            out.push(namespaces::info(&state.db, &row, Some(role)).await?);
        }
    }
    Ok(Json(out))
}

pub async fn create(
    State(state): State<AppState>,
    user: Identity,
    meta: RequestMeta,
    Json(req): Json<CreateNamespaceRequest>,
) -> ApiResult<Json<NamespaceInfo>> {
    let row = create_ns(&state, &user, &meta, &req.name).await?;
    Ok(Json(
        namespaces::info(&state.db, &row, Some(Role::Owner)).await?,
    ))
}

pub async fn show(
    State(state): State<AppState>,
    user: Identity,
    Path(key): Path<String>,
) -> ApiResult<Json<NamespaceInfo>> {
    let (row, access) = open(&state, &user, &key).await?;
    Ok(Json(info_for(&state, &row, &access).await?))
}

pub async fn update(
    State(state): State<AppState>,
    user: Identity,
    meta: RequestMeta,
    Path(key): Path<String>,
    Json(req): Json<UpdateNamespaceRequest>,
) -> ApiResult<Json<NamespaceInfo>> {
    let (_, access) = open(&state, &user, &key).await?;
    if let Some(name) = req.name.as_deref() {
        rename_ns(&state, &user, &meta, &access, name).await?;
    }
    let (row, access) = open(&state, &user, &access.id.to_string()).await?;
    Ok(Json(info_for(&state, &row, &access).await?))
}

pub async fn delete(
    State(state): State<AppState>,
    user: Identity,
    meta: RequestMeta,
    Path(key): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let (_, access) = open(&state, &user, &key).await?;
    delete_ns(&state, &user, &meta, &access).await?;
    Ok(Json(serde_json::json!({ "deleted": access.name })))
}

pub async fn members(
    State(state): State<AppState>,
    user: Identity,
    Path(key): Path<String>,
) -> ApiResult<Json<Vec<NamespaceMember>>> {
    let (_, access) = open(&state, &user, &key).await?;
    Ok(Json(namespaces::members(&state.db, &access.id).await?))
}

pub async fn add_member(
    State(state): State<AppState>,
    user: Identity,
    meta: RequestMeta,
    Path(key): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<Json<Vec<NamespaceMember>>> {
    let (_, access) = open(&state, &user, &key).await?;
    add_member_op(&state, &user, &meta, &access, &req.email, req.role).await?;
    Ok(Json(namespaces::members(&state.db, &access.id).await?))
}

pub async fn update_member(
    State(state): State<AppState>,
    user: Identity,
    meta: RequestMeta,
    Path((key, member)): Path<(String, String)>,
    Json(req): Json<UpdateMemberRequest>,
) -> ApiResult<Json<Vec<NamespaceMember>>> {
    let (_, access) = open(&state, &user, &key).await?;
    set_role_op(&state, &user, &meta, &access, &member, req.role).await?;
    Ok(Json(namespaces::members(&state.db, &access.id).await?))
}

pub async fn remove_member(
    State(state): State<AppState>,
    user: Identity,
    meta: RequestMeta,
    Path((key, member)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let (_, access) = open(&state, &user, &key).await?;
    remove_member_op(&state, &user, &meta, &access, &member).await?;
    Ok(Json(
        serde_json::json!({ "removed": member, "namespace": access.name }),
    ))
}

async fn admin_open(state: &AppState, key: &str) -> ApiResult<NamespaceRow> {
    namespaces::find(&state.db, key)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("namespace '{key}' not found")))
}

pub async fn set_quota(
    State(state): State<AppState>,
    admin: AdminCaller,
    meta: RequestMeta,
    Path(key): Path<String>,
    Json(req): Json<QuotaInfo>,
) -> ApiResult<Json<NamespaceInfo>> {
    let row = admin_open(&state, &key).await?;
    set_quota_op(&state, &admin, &meta, &row, Some(req)).await?;
    Ok(Json(namespaces::info(&state.db, &row, None).await?))
}

pub async fn reset_quota(
    State(state): State<AppState>,
    admin: AdminCaller,
    meta: RequestMeta,
    Path(key): Path<String>,
) -> ApiResult<Json<NamespaceInfo>> {
    let row = admin_open(&state, &key).await?;
    set_quota_op(&state, &admin, &meta, &row, None).await?;
    Ok(Json(namespaces::info(&state.db, &row, None).await?))
}

pub async fn audit_log(
    State(state): State<AppState>,
    user: Identity,
    Path(key): Path<String>,
    Query(query): Query<crate::routes::audit::AuditQuery>,
) -> ApiResult<Json<AuditPage>> {
    let (_, access) = open(&state, &user, &key).await?;
    access.require(Role::Admin, "reading the namespace activity log")?;
    Ok(Json(
        query
            .fetch(&state.db, audit::Scope::Namespace(access.id))
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::{Value, json};

    use crate::state::{CreationPolicy, NamespaceSettings};
    use crate::testing::{call, json_req, signup, test_state};

    async fn vm_in(state: &crate::state::AppState, ns: &str, creator: &str, name: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, created_by, name, image, vcpu, memory_mib, \
             disk_mib, nat, status, created_at) \
             VALUES (?, ?, ?, ?, 'default', 2, 1024, 0, 1, 'stopped', 1)",
        )
        .bind(&id)
        .bind(ns)
        .bind(creator)
        .bind(name)
        .execute(&state.db)
        .await
        .unwrap();
        id
    }

    async fn req(
        app: &Router,
        method: &str,
        uri: &str,
        token: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        call(app.clone(), json_req(method, uri, Some(token), body)).await
    }

    fn admin_req(method: &str, uri: &str, body: Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-admin-token", "test-admin")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn roles_gate_membership_and_vm_access() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state.clone());
        let (alice, alice_id) = signup(&app, "alice@example.com").await;
        let (bob, bob_id) = signup(&app, "bob@example.com").await;
        let (carol, _) = signup(&app, "carol@example.com").await;

        let (status, me) = req(&app, "GET", "/v1/auth/me", &alice, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(me["namespace"], "alice");

        let (status, ns) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &alice,
            json!({"name": "acme"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{ns}");
        assert_eq!(
            (ns["role"].as_str(), ns["personal"].as_bool()),
            (Some("owner"), Some(false))
        );
        let ns_id = ns["id"].as_str().unwrap().to_string();
        let (status, _) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &bob,
            json!({"name": "acme"}),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let (status, body) = req(
            &app,
            "POST",
            "/v1/namespaces/acme/members",
            &alice,
            json!({"email": "BOB@example.com"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().unwrap().len(), 2);

        let alice_vm = vm_in(&state, &ns_id, &alice_id, "shared").await;
        let bob_vm = vm_in(&state, &ns_id, &bob_id, "bobs").await;

        let (status, list) = req(&app, "GET", "/v1/vms?namespace=acme", &bob, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{list}");
        assert_eq!(list.as_array().unwrap().len(), 2);
        let (_, mine) = req(&app, "GET", "/v1/vms", &bob, json!({})).await;
        assert_eq!(
            mine.as_array().unwrap().len(),
            0,
            "personal namespace is the default"
        );
        let (status, _) = req(&app, "GET", &format!("/v1/vms/{alice_vm}"), &bob, json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "members reach VMs by id from any namespace"
        );

        for uri in [
            "/v1/vms?namespace=acme".to_string(),
            format!("/v1/vms/{alice_vm}"),
            "/v1/namespaces/acme".to_string(),
        ] {
            let (status, _) = req(&app, "GET", &uri, &carol, json!({})).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{uri} must not leak to outsiders"
            );
        }

        let (status, _) = req(
            &app,
            "POST",
            "/v1/namespaces/acme/members",
            &bob,
            json!({"email": "carol@example.com"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "members cannot invite");
        let (status, body) = req(
            &app,
            "DELETE",
            &format!("/v1/vms/{alice_vm}"),
            &bob,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, _) = req(
            &app,
            "DELETE",
            &format!("/v1/vms/{bob_vm}"),
            &bob,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "creators may destroy their own VMs");

        let (status, _) = req(
            &app,
            "PATCH",
            "/v1/namespaces/acme/members/bob@example.com",
            &alice,
            json!({"role": "admin"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(
            &app,
            "PATCH",
            &format!("/v1/namespaces/acme/members/{bob_id}"),
            &bob,
            json!({"role": "owner"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "admins cannot make owners");
        let (status, _) = req(&app, "GET", "/v1/namespaces/acme/audit", &bob, json!({})).await;
        assert_eq!(status, StatusCode::OK, "admins read the namespace log");

        let (status, body) = req(
            &app,
            "DELETE",
            &format!("/v1/namespaces/acme/members/{alice_id}"),
            &alice,
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the last owner cannot leave: {body}"
        );
        let (status, _) = req(
            &app,
            "PATCH",
            "/v1/namespaces/acme/members/bob@example.com",
            &alice,
            json!({"role": "owner"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(&app, "DELETE", "/v1/namespaces/acme", &bob, json!({})).await;
        assert_eq!(status, StatusCode::CONFLICT, "namespaces with VMs stay");
        let (status, _) = req(
            &app,
            "DELETE",
            &format!("/v1/vms/{alice_vm}"),
            &bob,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owners destroy anyone's VMs");
        let (status, _) = req(
            &app,
            "DELETE",
            &format!("/v1/namespaces/acme/members/{alice_id}"),
            &alice,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "a non-last owner can leave");
        let (status, _) = req(&app, "GET", "/v1/namespaces/acme", &alice, json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let (status, _) = req(
            &app,
            "PATCH",
            "/v1/namespaces/acme",
            &bob,
            json!({"name": "acme-2"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(&app, "DELETE", "/v1/namespaces/acme-2", &bob, json!({})).await;
        assert_eq!(status, StatusCode::OK);

        let (_, log) = req(&app, "GET", "/v1/audit", &alice, json!({})).await;
        let actions: Vec<&str> = log["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap())
            .collect();
        assert!(actions.contains(&"namespace.create"), "{actions:?}");
        assert!(actions.contains(&"namespace.member.role"), "{actions:?}");
    }

    #[tokio::test]
    async fn stale_namespace_cookies_fall_back_but_explicit_selectors_fail() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state);
        let (token, _) = signup(&app, "cookie@example.com").await;
        let (_, ns) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &token,
            json!({"name": "gone"}),
        )
        .await;
        let gone = ns["id"].as_str().unwrap().to_string();
        let (status, _) = req(&app, "DELETE", "/v1/namespaces/gone", &token, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        let me = |selector: (&str, String)| {
            Request::builder()
                .uri("/v1/auth/me")
                .header("authorization", format!("Bearer {token}"))
                .header(selector.0, selector.1)
                .body(Body::empty())
                .unwrap()
        };
        let (status, body) = call(app.clone(), me(("cookie", format!("kletka_ns={gone}")))).await;
        assert_eq!(
            (status, body["namespace"].as_str()),
            (StatusCode::OK, Some("cookie"))
        );
        let (status, _) = call(app, me((kletka_types::NAMESPACE_HEADER, gone))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn personal_namespaces_cannot_be_shared_or_deleted() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state);
        let (dana, _) = signup(&app, "dana.smith@example.com").await;
        signup(&app, "eve@example.com").await;
        let (_, list) = req(&app, "GET", "/v1/namespaces", &dana, json!({})).await;
        assert_eq!(list[0]["name"], "dana-smith");
        assert_eq!(list[0]["personal"], true);
        let (status, _) = req(
            &app,
            "POST",
            "/v1/namespaces/dana-smith/members",
            &dana,
            json!({"email": "eve@example.com"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = req(
            &app,
            "DELETE",
            "/v1/namespaces/dana-smith",
            &dana,
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = req(
            &app,
            "PATCH",
            "/v1/namespaces/dana-smith",
            &dana,
            json!({"name": "dana"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "personal namespaces can be renamed");
    }

    #[tokio::test]
    async fn creation_policy_allowances_and_platform_admins() {
        let (mut state, _guard) = test_state().await;
        state.namespaces = std::sync::Arc::new(NamespaceSettings {
            creation: CreationPolicy::PlatformAdmins,
            platform_admins: vec!["root@example.com".into()],
            ..NamespaceSettings::default()
        });
        let app = crate::router(state.clone());
        let (user, user_id) = signup(&app, "user@example.com").await;
        let (root, _) = signup(&app, "Root@Example.com").await;

        let (status, _) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &user,
            json!({"name": "team"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = req(&app, "GET", "/v1/users", &user, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, me) = req(&app, "GET", "/v1/auth/me", &root, json!({})).await;
        assert_eq!(
            (status, me["platform_admin"].as_bool()),
            (StatusCode::OK, Some(true))
        );
        let (status, _) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &root,
            json!({"name": "ops"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "platform admins always may create");
        let (status, users) = req(&app, "GET", "/v1/users", &root, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(users.as_array().unwrap().len(), 2);
        let (status, _) = req(&app, "GET", "/v1/namespaces/ops", &user, json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, all) = req(&app, "GET", "/v1/namespaces?all=true", &root, json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(all.as_array().unwrap().len(), 3);
        let (status, _) = req(&app, "GET", "/v1/namespaces/user", &root, json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "platform admins see every namespace"
        );

        let (status, body) = call(
            app.clone(),
            admin_req(
                "PATCH",
                &format!("/v1/users/{user_id}"),
                json!({"max_namespaces": 1}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["max_namespaces"], 1);
        let (status, _) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &user,
            json!({"name": "team"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a per-user allowance overrides the policy"
        );
        let (status, _) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &user,
            json!({"name": "team-2"}),
        )
        .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);

        let (status, _) = req(
            &app,
            "PATCH",
            &format!("/v1/users/{user_id}"),
            &root,
            json!({"platform_admin": true}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = req(&app, "GET", "/v1/users", &user, json!({})).await;
        assert_eq!(status, StatusCode::OK, "the DB flag grants platform admin");
        let (status, _) = req(
            &app,
            "PATCH",
            &format!("/v1/users/{user_id}"),
            &user,
            json!({"platform_admin": false}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "no self-demotion");
    }

    #[tokio::test]
    async fn quotas_are_per_namespace() {
        let mut k8s = crate::k8s::K8sConfig::default();
        k8s.guest_images
            .insert("default".into(), "kletka-guest-default:dev".into());
        let (state, _guard) = crate::testing::test_state_with_config(k8s).await;
        let app = crate::router(state.clone());
        let (owner, owner_id) = signup(&app, "q@example.com").await;
        let (_, ns) = req(
            &app,
            "POST",
            "/v1/namespaces",
            &owner,
            json!({"name": "lab"}),
        )
        .await;
        let ns_id = ns["id"].as_str().unwrap().to_string();
        assert_eq!(
            ns["quotas"]["max_vms"], 10,
            "new namespaces get the configured defaults"
        );

        let (status, body) = call(
            app.clone(),
            admin_req(
                "PATCH",
                "/v1/namespaces/lab/quota",
                json!({"max_vms": 1, "max_vcpu": 2, "max_mem_mib": 2048}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        vm_in(&state, &ns_id, &owner_id, "one").await;

        let (status, body) = req(
            &app,
            "POST",
            "/v1/vms?namespace=lab",
            &owner,
            json!({"name": "two"}),
        )
        .await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED, "{body}");
        let (_, me) = req(&app, "GET", "/v1/auth/me?namespace=lab", &owner, json!({})).await;
        assert_eq!(
            (
                me["usage"]["vms"].as_u64(),
                me["quotas"]["max_vms"].as_u64()
            ),
            (Some(1), Some(1))
        );
        let (_, me) = req(&app, "GET", "/v1/auth/me", &owner, json!({})).await;
        assert_eq!(
            (
                me["usage"]["vms"].as_u64(),
                me["quotas"]["max_vms"].as_u64()
            ),
            (Some(0), Some(5))
        );

        let (status, body) = call(
            app.clone(),
            admin_req("DELETE", "/v1/namespaces/lab/quota", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["quotas"]["max_vms"], 10);

        let (status, body) = call(
            app.clone(),
            admin_req(
                "PATCH",
                "/v1/namespaces/q/quota",
                json!({"max_vms": 2, "max_vcpu": 2, "max_mem_mib": 2048}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, user) = call(
            app,
            Request::builder()
                .uri(format!("/v1/users/{owner_id}"))
                .header("x-admin-token", "test-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            user["quotas"]["max_vms"], 2,
            "personal namespace quota is the user's quota"
        );
    }
}
