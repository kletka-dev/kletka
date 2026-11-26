pub mod audit;
pub mod auth;
pub mod credentials;
pub mod db;
pub mod error;
pub mod idle;
pub mod k8s;
pub mod leader;
pub mod namespaces;
pub mod oauth;
pub mod password;
pub mod quota;
pub mod ratelimit;
pub mod routes;
pub mod state;
#[cfg(test)]
pub(crate) mod testing;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(routes::web::index))
        .route(
            "/login",
            get(routes::web::login_page).post(routes::web::login_submit),
        )
        .route(
            "/register",
            get(routes::web::register_page).post(routes::web::register_submit),
        )
        .route("/login/oauth/{provider}", get(routes::oauth::start))
        .route("/login/oauth/{provider}/callback", get(routes::oauth::callback))
        .route("/logout", post(routes::web::logout))
        .route(
            "/vms",
            get(routes::web::vms_page).post(routes::web::vms_create),
        )
        .route("/vms/table", get(routes::web::vms_table))
        .route("/vms/{id}", get(routes::web::vm_detail))
        .route("/vms/{id}/start", post(routes::web::vm_start))
        .route("/vms/{id}/stop", post(routes::web::vm_stop))
        .route("/vms/{id}/delete", post(routes::web::vm_delete))
        .route("/vms/{id}/terminal", get(routes::web::vm_terminal))
        .route(
            "/namespaces",
            get(routes::web_namespaces::namespaces_list)
                .post(routes::web_namespaces::namespaces_create),
        )
        .route("/ns/switch", post(routes::web_namespaces::switch))
        .route(
            "/namespaces/{ns}",
            get(routes::web_namespaces::namespace_detail),
        )
        .route(
            "/namespaces/{ns}/rename",
            post(routes::web_namespaces::namespace_rename),
        )
        .route(
            "/namespaces/{ns}/delete",
            post(routes::web_namespaces::namespace_delete),
        )
        .route(
            "/namespaces/{ns}/quota",
            post(routes::web_namespaces::namespace_quota),
        )
        .route(
            "/namespaces/{ns}/members",
            post(routes::web_namespaces::member_add),
        )
        .route(
            "/namespaces/{ns}/members/{member}/role",
            post(routes::web_namespaces::member_role),
        )
        .route(
            "/namespaces/{ns}/members/{member}/remove",
            post(routes::web_namespaces::member_remove),
        )
        .route("/admin", get(routes::web_namespaces::admin_index))
        .route(
            "/admin/users/{id}",
            post(routes::web_namespaces::admin_user_update),
        )
        .route("/assets/{*path}", get(assets))
        .route("/v1/auth/signup", post(routes::auth::signup))
        .route("/v1/auth/login", post(routes::auth::login))
        .route("/v1/auth/me", get(routes::auth::me))
        .route("/v1/auth/methods", get(routes::oauth::methods))
        .route("/v1/auth/oauth/cli/start", post(routes::oauth::cli_start))
        .route("/v1/auth/oauth/poll/{state}", get(routes::oauth::poll))
        .route("/v1/vms", get(routes::vms::list).post(routes::vms::create))
        .route(
            "/v1/vms/{id}",
            get(routes::vms::show)
                .delete(routes::vms::destroy)
                .patch(routes::vms::update),
        )
        .route("/v1/vms/{id}/start", post(routes::vms::start))
        .route("/v1/vms/{id}/stop", post(routes::vms::stop))
        .route("/v1/vms/{id}/clone", post(routes::clone::clone))
        .route("/v1/vms/{id}/rebase", post(routes::vms::rebase))
        .route("/v1/vms/{id}/resize", post(routes::vms::resize))
        .route("/v1/vms/{id}/wireguard", put(routes::vms::set_wireguard))
        .route("/vms/{id}/clone", post(routes::web::vm_clone))
        .route(
            "/v1/vms/{id}/snapshots",
            get(routes::snapshots::list).post(routes::snapshots::create),
        )
        .route(
            "/v1/vms/{id}/snapshots/{name}",
            axum::routing::delete(routes::snapshots::delete),
        )
        .route(
            "/v1/vms/{id}/snapshots/{name}/rollback",
            post(routes::snapshots::rollback),
        )
        .route("/v1/vms/{id}/console", get(routes::relay::console))
        .route("/v1/vms/{id}/exec", get(routes::relay::exec))
        .route("/v1/vms/{id}/proxy", get(routes::relay::proxy))
        .route("/v1/vms/{id}/file/push", post(routes::relay::file_push))
        .route("/v1/vms/{id}/file/pull", get(routes::relay::file_pull))
        .route("/v1/images", get(routes::images::list))
        .route("/v1/audit", get(routes::audit::list))
        .route("/v1/users", get(routes::admin::list_users))
        .route("/v1/users/{id}/audit", get(routes::admin::user_audit))
        .route(
            "/v1/users/{id}",
            get(routes::admin::show_user).patch(routes::admin::update_user),
        )
        .route("/v1/users/{id}/quota", patch(routes::admin::set_quota))
        .route(
            "/v1/namespaces",
            get(routes::namespaces::list).post(routes::namespaces::create),
        )
        .route(
            "/v1/namespaces/{ns}",
            get(routes::namespaces::show)
                .patch(routes::namespaces::update)
                .delete(routes::namespaces::delete),
        )
        .route(
            "/v1/namespaces/{ns}/members",
            get(routes::namespaces::members).post(routes::namespaces::add_member),
        )
        .route(
            "/v1/namespaces/{ns}/members/{member}",
            patch(routes::namespaces::update_member).delete(routes::namespaces::remove_member),
        )
        .route(
            "/v1/namespaces/{ns}/quota",
            patch(routes::namespaces::set_quota).delete(routes::namespaces::reset_quota),
        )
        .route(
            "/v1/namespaces/{ns}/audit",
            get(routes::namespaces::audit_log),
        )
        .route("/healthz", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            ratelimit::rate_limit,
        ))
        .with_state(state)
}

async fn assets(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    const ASSETS: &[(&str, &str, &[u8])] = &[
        (
            "tailwind.js",
            "application/javascript",
            include_bytes!("../assets/tailwind.js"),
        ),
        (
            "htmx.min.js",
            "application/javascript",
            include_bytes!("../assets/htmx.min.js"),
        ),
        (
            "panel.css",
            "text/css",
            include_bytes!("../assets/panel.css"),
        ),
        (
            "fonts/jetbrains-mono-latin-400-normal.woff2",
            "font/woff2",
            include_bytes!("../assets/fonts/jetbrains-mono-latin-400-normal.woff2"),
        ),
        (
            "fonts/jetbrains-mono-latin-500-normal.woff2",
            "font/woff2",
            include_bytes!("../assets/fonts/jetbrains-mono-latin-500-normal.woff2"),
        ),
        (
            "fonts/jetbrains-mono-latin-700-normal.woff2",
            "font/woff2",
            include_bytes!("../assets/fonts/jetbrains-mono-latin-700-normal.woff2"),
        ),
        (
            "xterm.min.js",
            "application/javascript",
            include_bytes!("../assets/xterm.min.js"),
        ),
        (
            "xterm-addon-fit.min.js",
            "application/javascript",
            include_bytes!("../assets/xterm-addon-fit.min.js"),
        ),
        (
            "xterm.min.css",
            "text/css",
            include_bytes!("../assets/xterm.min.css"),
        ),
    ];
    if path.contains("..") || path.contains('\\') {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some((mime, bytes)) = ASSETS
        .iter()
        .find(|(name, _, _)| *name == path)
        .map(|(_, mime, bytes)| (*mime, *bytes))
    {
        return asset_response(mime, axum::body::Body::from(bytes));
    }
    if let Some(name) = path.strip_prefix("flavor/")
        && let Some((mime, bytes)) = flavor_asset(name)
    {
        return asset_response(mime, axum::body::Body::from(bytes));
    }
    StatusCode::NOT_FOUND.into_response()
}

fn asset_response(mime: &'static str, bytes: axum::body::Body) -> Response {
    (
        [
            (axum::http::header::CONTENT_TYPE, mime),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        bytes,
    )
        .into_response()
}

fn flavor_asset(name: &str) -> Option<(&'static str, Vec<u8>)> {
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return None;
    }
    let entries = std::fs::read_dir("assets/flavor").ok()?;
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy() == name {
            let mime = match entry.path().extension()?.to_str()? {
                "png" => "image/png",
                "svg" => "image/svg+xml",
                "webp" => "image/webp",
                "gif" => "image/gif",
                "jpg" | "jpeg" => "image/jpeg",
                _ => return None,
            };
            return Some((mime, std::fs::read(entry.path()).ok()?));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::router;
    use crate::testing::{TEST_PASSWORD, call, json_req, signup, test_state};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    #[tokio::test]
    async fn healthz_is_unauthenticated() {
        let (state, _guard) = test_state().await;
        let app = router(state);
        let (status, _) = call(
            app,
            json_req("GET", "/healthz", None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn signup_login_and_me_roundtrip() {
        let (state, _guard) = test_state().await;
        let app = router(state);
        let (token, user_id) = signup(&app, "a@example.com").await;
        assert!(!token.is_empty());
        assert!(!user_id.is_empty());

        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/auth/login",
                None,
                serde_json::json!({"email": "a@example.com", "password": TEST_PASSWORD}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            app.clone(),
            json_req("GET", "/v1/auth/me", Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["user_id"].as_str(), Some(user_id.as_str()));
    }

    #[tokio::test]
    async fn unknown_image_lists_the_alternatives() {
        let (state, _guard) = test_state().await;
        let app = router(state);
        let (token, _) = signup(&app, "img@example.com").await;
        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/vms",
                Some(&token),
                serde_json::json!({"name": "x", "image": "nope"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("available images: default"),
            "{}",
            body
        );
    }

    #[tokio::test]
    async fn images_listing_is_read_only_and_authenticated() {
        let (state, _guard) = test_state().await;
        let app = router(state);
        let (status, _) = call(
            app.clone(),
            json_req("GET", "/v1/images", None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (token, _) = signup(&app, "list@example.com").await;
        let (status, body) = call(
            app.clone(),
            json_req("GET", "/v1/images", Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let entries = body.as_array().unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[tokio::test]
    async fn me_reports_quotas_and_usage() {
        let (state, _guard) = test_state().await;
        let app = router(state.clone());
        let (token, owner_id) = signup(&app, "usage@example.com").await;

        let (status, body) = call(
            app.clone(),
            json_req("GET", "/v1/auth/me", Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            (body["user_id"].as_str(), body["email"].as_str()),
            (Some(owner_id.as_str()), Some("usage@example.com")),
            "{body}"
        );
        assert_eq!(body["usage"]["vms"], 0);
        assert_eq!(
            (
                body["quotas"]["max_vms"].as_u64(),
                body["quotas"]["max_vcpu"].as_u64()
            ),
            (Some(5), Some(8))
        );
        assert_eq!(body["quotas"]["max_mem_mib"].as_u64(), Some(8192));

        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, status, \
             created_at) VALUES
             (?, ?, 'active', 'default', 4, 4096, 0, 1, 'running', 1),
             (?, ?, 'shelved', 'default', 8, 8192, 0, 1, 'stopped', 1)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner_id)
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&owner_id)
        .execute(&state.db)
        .await
        .unwrap();

        let (status, body) = call(
            app.clone(),
            json_req("GET", "/v1/auth/me", Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["usage"]["vms"], 2);
        assert_eq!(body["usage"]["vcpu"], 4);
        assert_eq!(body["usage"]["mem_mib"], 4096);

        let (status, _) = call(
            app.clone(),
            json_req("GET", "/v1/auth/me", None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_user_route_returns_the_account_shape() {
        let (state, _guard) = test_state().await;
        let app = router(state.clone());
        let (_, user_id) = signup(&app, "admin-shown@example.com").await;
        crate::db::query("UPDATE users SET quota_max_vcpu = 3 WHERE id = ?")
            .bind(&user_id)
            .execute(&state.db)
            .await
            .unwrap();

        let request = Request::builder()
            .uri(format!("/v1/users/{user_id}"))
            .header("x-admin-token", "test-admin")
            .body(Body::empty())
            .unwrap();
        let (status, body) = call(app, request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            (body["email"].as_str(), body["user_id"].as_str()),
            (Some("admin-shown@example.com"), Some(user_id.as_str()))
        );
        assert_eq!(body["quotas"]["max_vcpu"], 3);
        assert_eq!(body["usage"]["vms"], 0);
    }

    #[tokio::test]
    async fn me_includes_the_caller_only() {
        let (state, _guard) = test_state().await;
        let app = router(state);
        let (token, _) = signup(&app, "me@example.com").await;
        let (_, _) = signup(&app, "other@example.com").await;
        let (_, body) = call(
            app,
            json_req("GET", "/v1/auth/me", Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(body["email"], "me@example.com");
    }

    #[tokio::test]
    async fn resize_requires_a_stopped_vm_within_quota() {
        let (state, _guard) = test_state().await;
        let app = router(state.clone());
        let (token, owner_id) = signup(&app, "resize@example.com").await;
        let vm_id = uuid::Uuid::new_v4();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, \
             status, created_at) VALUES (?, ?, 'sized', 'default', 2, 1024, 0, 1, 'running', 1)",
        )
        .bind(vm_id.to_string())
        .bind(&owner_id)
        .execute(&state.db)
        .await
        .unwrap();
        let uri = format!("/v1/vms/{vm_id}/resize");
        let resize = |body: serde_json::Value| json_req("POST", &uri, Some(&token), body);

        let (status, body) = call(app.clone(), resize(serde_json::json!({"vcpu": 4}))).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body["error"].as_str().unwrap().contains("stop it"));

        crate::db::query("UPDATE vms SET status = 'stopped' WHERE id = ?")
            .bind(vm_id.to_string())
            .execute(&state.db)
            .await
            .unwrap();

        let (status, body) = call(app.clone(), resize(serde_json::json!({"vcpu": 4}))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["vcpu"], 4);
        assert_eq!(body["memory_mib"], 1024);

        let (status, body) =
            call(app.clone(), resize(serde_json::json!({"memory_mib": 2048}))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            (body["vcpu"].as_u64(), body["memory_mib"].as_u64()),
            (Some(4), Some(2048))
        );

        let (status, _) = call(app.clone(), resize(serde_json::json!({"vcpu": 9}))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let (status, _) = call(app.clone(), resize(serde_json::json!({"memory_mib": 9000}))).await;
        assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        let (status, _) = call(app.clone(), resize(serde_json::json!({"vcpu": 0}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = call(app.clone(), resize(serde_json::json!({"memory_mib": 64}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (_, log) = call(
            app,
            json_req(
                "GET",
                "/v1/audit?vm=sized",
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        let resizes: Vec<_> = log["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|event| event["action"] == "vm.resize")
            .collect();
        assert_eq!(resizes.len(), 2);
        assert_eq!(resizes[0]["detail"]["memory_mib"], 2048);
        assert_eq!(resizes[0]["detail"]["from_memory_mib"], 1024);
    }

    #[tokio::test]
    async fn idle_timeout_is_validated_and_patchable() {
        let (state, _guard) = test_state().await;
        let app = router(state.clone());
        let (token, owner_id) = signup(&app, "idle@example.com").await;

        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/vms",
                Some(&token),
                serde_json::json!({"name": "x", "idle_timeout_secs": 5}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"].as_str().unwrap().contains("idle timeout"));

        let vm_id = uuid::Uuid::new_v4();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, status, created_at, last_active_at) \
             VALUES (?, ?, 'idle-vm', 'running', 1, 1)",
        )
        .bind(vm_id.to_string())
        .bind(&owner_id)
        .execute(&state.db)
        .await
        .unwrap();
        let uri = format!("/v1/vms/{vm_id}");

        let (status, body) = call(
            app.clone(),
            json_req("GET", &uri, Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["idle_timeout_default"], true);
        assert_eq!(
            body["idle_timeout_secs"].as_u64(),
            Some(crate::idle::default_timeout_secs())
        );

        let (status, body) = call(
            app.clone(),
            json_req(
                "PATCH",
                &uri,
                Some(&token),
                serde_json::json!({"idle_timeout_secs": 0}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["idle_timeout_secs"], 0);
        assert_eq!(body["idle_timeout_default"], false);
        let last_active: kletka_types::time::Timestamp =
            body["last_active_at"].as_str().unwrap().parse().unwrap();
        assert!(last_active > kletka_types::time::from_unix(1));

        let (_, body) = call(
            app.clone(),
            json_req("PATCH", &uri, Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(body["idle_timeout_secs"], 0);
        let (_, body) = call(
            app.clone(),
            json_req(
                "PATCH",
                &uri,
                Some(&token),
                serde_json::json!({"idle_timeout_secs": null}),
            ),
        )
        .await;
        assert_eq!(body["idle_timeout_default"], true);

        let (_, log) = call(
            app.clone(),
            json_req(
                "GET",
                "/v1/audit?vm=idle-vm",
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        let configured: Vec<_> = log["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["detail"]["idle_timeout_secs"].clone())
            .collect();
        assert_eq!(
            configured,
            vec![serde_json::Value::Null, serde_json::json!(0)]
        );

        let (status, _) = call(
            app,
            json_req(
                "PATCH",
                &uri,
                Some(&token),
                serde_json::json!({"idle_timeout_secs": 10}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn audit_log_records_account_events_for_their_owner_only() {
        let (state, _guard) = test_state().await;
        let app = router(state.clone());
        let (token, user_id) = signup(&app, "audited@example.com").await;
        let (other_token, _) = signup(&app, "other@example.com").await;

        let login = |password: &str| {
            json_req(
                "POST",
                "/v1/auth/login",
                None,
                serde_json::json!({"email": "audited@example.com", "password": password}),
            )
        };
        let (status, _) = call(app.clone(), login("not-the-password")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, _) = call(app.clone(), login(TEST_PASSWORD)).await;
        assert_eq!(status, StatusCode::OK);

        let request = Request::builder()
            .method("PATCH")
            .uri(format!("/v1/users/{user_id}/quota"))
            .header("content-type", "application/json")
            .header("x-admin-token", "test-admin")
            .body(Body::from(
                r#"{"max_vms": 3, "max_vcpu": 4, "max_mem_mib": 4096}"#,
            ))
            .unwrap();
        let (status, body) = call(app.clone(), request).await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            app.clone(),
            json_req("GET", "/v1/audit", Some(&token), serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let events = body["events"].as_array().unwrap();
        let summary: Vec<(String, String, String)> = events
            .iter()
            .map(|event| {
                (
                    event["action"].as_str().unwrap().to_string(),
                    event["actor"].as_str().unwrap().to_string(),
                    event["outcome"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let expect = |action: &str, actor: &str, outcome: &str| {
            (action.to_string(), actor.to_string(), outcome.to_string())
        };
        assert_eq!(
            summary,
            vec![
                expect("account.quota", "admin", "ok"),
                expect("account.login", "user", "ok"),
                expect("account.login", "user", "denied"),
                expect("account.signup", "user", "ok"),
            ],
            "newest first"
        );
        assert_eq!(events[0]["detail"]["max_vcpu"], 4);

        let (_, page) = call(
            app.clone(),
            json_req(
                "GET",
                "/v1/audit?limit=3",
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(page["events"].as_array().unwrap().len(), 3);
        let before = page["next_before"].as_i64().unwrap();
        let (_, rest) = call(
            app.clone(),
            json_req(
                "GET",
                &format!("/v1/audit?before={before}"),
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(rest["events"].as_array().unwrap().len(), 1);
        assert!(rest["next_before"].is_null());

        let (_, theirs) = call(
            app.clone(),
            json_req(
                "GET",
                "/v1/audit",
                Some(&other_token),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(theirs["events"].as_array().unwrap().len(), 1);

        let admin_read = |admin: Option<&str>| {
            let mut builder = Request::builder()
                .method("GET")
                .uri("/v1/users/audited@example.com/audit");
            if let Some(admin) = admin {
                builder = builder.header("x-admin-token", admin);
            }
            builder.body(Body::empty()).unwrap()
        };
        let (status, body) = call(app.clone(), admin_read(Some("test-admin"))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["events"].as_array().unwrap().len(), 4);
        let (status, _) = call(app, admin_read(None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_rejects_invalid_names_and_copies_nothing() {
        let (state, _guard) = test_state().await;
        let app = router(state.clone());
        let (token, _) = signup(&app, "names@example.com").await;

        for name in ["UPPER", "trailing-", "-leading", &"x".repeat(33), "spa ce"] {
            let (status, body) = call(
                app.clone(),
                json_req(
                    "POST",
                    "/v1/vms",
                    Some(&token),
                    serde_json::json!({ "name": name }),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
            assert!(
                body["error"].as_str().unwrap().contains("invalid vm name"),
                "{body}"
            );
            let (_, list) = call(
                app.clone(),
                json_req("GET", "/v1/vms", Some(&token), serde_json::json!({})),
            )
            .await;
            assert_eq!(list.as_array().unwrap().len(), 0, "{name}");
        }

        let vm_id = uuid::Uuid::new_v4();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, status, created_at) \
             VALUES (?, ?, 'LegacyName', 'stopped', 1)",
        )
        .bind(vm_id.to_string())
        .bind(
            sqlx::query_scalar::<_, String>(
                "SELECT id FROM users WHERE email = 'names@example.com'",
            )
            .fetch_one(&state.db)
            .await
            .unwrap(),
        )
        .execute(&state.db)
        .await
        .unwrap();
        let (status, body) = call(
            app,
            json_req(
                "GET",
                "/v1/vms/LegacyName",
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn rebase_requires_a_stopped_owned_vm() {
        let (state, _guard) = test_state().await;
        let app = router(state.clone());
        let (token, owner_id) = signup(&app, "rebase@example.com").await;
        let vm_id = uuid::Uuid::new_v4();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, \
             status, created_at) VALUES (?, ?, ?, 'default', 2, 1024, 0, 1, 'running', 1)",
        )
        .bind(vm_id.to_string())
        .bind(owner_id)
        .bind("rebasing-vm")
        .execute(&state.db)
        .await
        .unwrap();

        let (status, body) = call(
            app,
            json_req(
                "POST",
                &format!("/v1/vms/{vm_id}/rebase"),
                Some(&token),
                serde_json::json!({}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body["error"].as_str().unwrap().contains("stop it"));
    }
}
