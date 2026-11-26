use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;

use kletka_control::k8s::{K8sConfig, K8sProvisioner};
use kletka_control::quota;
use kletka_control::ratelimit::RateLimits;
use kletka_control::state::AppState;
use kletka_control::{db, router};
use uuid::Uuid;

fn env_url() -> Option<String> {
    std::env::var("KLETKA_TEST_DATABASE_URL").ok()
}

struct Pg {
    url: String,
    #[allow(dead_code)]
    suffix: String,
}

async fn setup() -> Pg {
    let Some(url) = env_url() else {
        eprintln!("KLETKA_TEST_DATABASE_URL unset; skipping postgres suite");
        return Pg {
            url: String::new(),
            suffix: String::new(),
        };
    };
    let suffix = Uuid::new_v4().simple().to_string();
    Pg { url, suffix }
}

fn state(pool: sqlx::AnyPool) -> (AppState, Router) {
    let state = AppState {
        db: pool,
        admin_token: "test-admin".to_string(),
        provisioner: Arc::new(K8sProvisioner::for_tests(K8sConfig::default())),
        rate_limits: RateLimits::disabled(),
        namespaces: Default::default(),
        auth: Default::default(),
    };
    let app = router(state.clone());
    (state, app)
}

fn json_req(
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn call(app: Router, request: Request<Body>) -> (StatusCode, serde_json::Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::String(
            String::from_utf8_lossy(&bytes).into_owned(),
        ))
    };
    (status, body)
}

async fn signup(app: &Router, email: &str) -> (String, String) {
    let (status, body) = call(
        app.clone(),
        json_req(
            "POST",
            "/v1/auth/signup",
            None,
            serde_json::json!({"email": email, "password": "test-password-123"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["token"].as_str().unwrap().to_string();
    let user_id = body["user_id"].as_str().unwrap().to_string();
    (token, user_id)
}

#[tokio::test]
async fn signup_login_me_and_audit_over_postgres() {
    let pg = setup().await;
    if pg.url.is_empty() {
        return;
    }
    let pool = db::connect(&pg.url).await.unwrap();
    let (_state, app) = state(pool);

    let (token, login_id) = signup(&app, &format!("pg-login-{}@example.com", pg.suffix)).await;

    let (status, body) = call(
        app.clone(),
        json_req(
            "POST",
            "/v1/auth/login",
            None,
            serde_json::json!({
                "email": format!("pg-login-{}@example.com", pg.suffix),
                "password": "test-password-123"
            }),
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
    assert_eq!(body["user_id"].as_str(), Some(login_id.as_str()));
    assert_eq!(body["quotas"]["max_vms"].as_u64(), Some(5));
    assert_eq!(body["usage"]["vms"].as_u64(), Some(0));

    let (status, _) = call(
        app.clone(),
        json_req(
            "POST",
            "/v1/auth/signup",
            None,
            serde_json::json!({
                "email": format!("pg-login-{}@example.com", pg.suffix),
                "password": "test-password-123"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn vm_rows_lifecycle_and_quota_claims_over_postgres() {
    let pg = setup().await;
    if pg.url.is_empty() {
        return;
    }
    let pool = db::connect(&pg.url).await.unwrap();
    let (state, app) = state(pool);
    let (token, owner_id) = signup(&app, &format!("pg-vm-{}@example.com", pg.suffix)).await;
    let owner_id: Uuid = owner_id.parse().unwrap();

    let vm_id = Uuid::new_v4();
    db::query(
        "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, status, \
         created_at, last_active_at) \
         VALUES (?, ?, ?, 'default', 4, 4096, 0, 1, 'stopped', ?, ?)",
    )
    .bind(vm_id.to_string())
    .bind(owner_id.to_string())
    .bind(format!("pg-row-{}", pg.suffix))
    .bind(1_i64)
    .bind(1_i64)
    .execute(&state.db)
    .await
    .unwrap();

    let (status, body) = call(
        app.clone(),
        json_req(
            "GET",
            &format!("/v1/vms/{}", vm_id),
            Some(&token),
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["vcpu"].as_u64(), Some(4));
    assert_eq!(body["status"], "stopped");

    quota::claim_start(&state.db, &owner_id, &vm_id, 4, 4096)
        .await
        .unwrap();

    let (status, body) = call(
        app.clone(),
        json_req("GET", "/v1/auth/me", Some(&token), serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["usage"]["vms"].as_u64(), Some(1));
    assert_eq!(body["usage"]["vcpu"].as_u64(), Some(4));
    assert_eq!(body["usage"]["mem_mib"].as_u64(), Some(4096));

    let (status, body) = call(
        app.clone(),
        json_req(
            "PATCH",
            &format!("/v1/vms/{}", vm_id),
            Some(&token),
            serde_json::json!({"idle_timeout_secs": 0}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["idle_timeout_secs"].as_u64(), Some(0));
}

#[tokio::test]
async fn audit_pages_and_retention_over_postgres() {
    let pg = setup().await;
    if pg.url.is_empty() {
        return;
    }
    let pool = db::connect(&pg.url).await.unwrap();
    let (_state, app) = state(pool);
    let (token, _) = signup(&app, &format!("pg-audit-{}@example.com", pg.suffix)).await;
    let (status, _) = call(
        app.clone(),
        json_req(
            "POST",
            "/v1/auth/login",
            None,
            serde_json::json!({
                "email": format!("pg-audit-{}@example.com", pg.suffix),
                "password": "test-password-123"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(
        app.clone(),
        json_req("GET", "/v1/audit", Some(&token), serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(events.len(), 2, "signup + login");
    assert_eq!(events[0]["action"], "account.login");
    assert_eq!(events[1]["action"], "account.signup");
    assert!(
        events[0]["id"].as_i64().unwrap() > events[1]["id"].as_i64().unwrap(),
        "identity columns order audit pages"
    );

    let (status, body) = call(
        app.clone(),
        json_req(
            "GET",
            "/v1/audit?limit=1",
            Some(&token),
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["events"].as_array().unwrap().len(), 1);
    let next_before = body["next_before"].as_i64().unwrap();
    let (status, body) = call(
        app.clone(),
        json_req(
            "GET",
            &format!("/v1/audit?before={next_before}"),
            Some(&token),
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["events"].as_array().unwrap().len(), 1);
    assert_eq!(body["events"][0]["action"], "account.signup");
    assert!(body["next_before"].is_null());
}

#[tokio::test]
async fn vm_name_unique_violation_is_a_conflict_over_postgres() {
    let pg = setup().await;
    if pg.url.is_empty() {
        return;
    }
    let pool = db::connect(&pg.url).await.unwrap();
    let (state, app) = state(pool);
    let (_, owner_id) = signup(&app, &format!("pg-name-{}@example.com", pg.suffix)).await;
    let owner_id: Uuid = owner_id.parse().unwrap();

    db::query(
        "INSERT INTO vms (id, namespace_id, name, status, created_at) VALUES (?, ?, ?, 'stopped', 1)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(owner_id.to_string())
    .bind(format!("pg-taken-{}", pg.suffix))
    .execute(&state.db)
    .await
    .unwrap();

    let insert = db::query(
        "INSERT INTO vms (id, namespace_id, name, status, created_at) VALUES (?, ?, ?, 'stopped', 1)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(owner_id.to_string())
    .bind(format!("pg-taken-{}", pg.suffix))
    .execute(&state.db)
    .await;
    assert!(db::is_unique_violation(&insert), "{insert:?}");
}

#[tokio::test]
async fn advisory_lock_elects_one_leader_with_failover() {
    use kletka_control::leader::LeaderGate;
    use std::time::Duration;

    let pg = setup().await;
    if pg.url.is_empty() {
        return;
    }
    let pool_a = db::connect(&pg.url).await.unwrap();
    let pool_b = db::connect(&pg.url).await.unwrap();
    let a = LeaderGate::start(pool_a.clone());
    let b = LeaderGate::start(pool_b.clone());

    let a_won = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::select! {
            _ = a.wait() => true,
            _ = b.wait() => false,
        }
    })
    .await
    .expect("one gate wins the advisory lock within 20s");
    let (leader, leader_pool, follower) = if a_won {
        (a, pool_a, b)
    } else {
        (b, pool_b, a)
    };
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(leader.is_leader());
    assert!(!follower.is_leader(), "only one gate leads at a time");

    drop(leader);
    leader_pool.close().await;
    let takeover = tokio::time::timeout(Duration::from_secs(20), follower.wait()).await;
    assert!(
        takeover.is_ok(),
        "the follower takes over once the leader's connection is gone"
    );
    assert!(follower.is_leader());
}

#[tokio::test]
async fn namespaces_members_and_quotas_over_postgres() {
    let pg = setup().await;
    if pg.url.is_empty() {
        return;
    }
    let pool = db::connect(&pg.url).await.unwrap();
    let (state, app) = state(pool);
    let (owner, owner_id) = signup(&app, &format!("pg-ns-owner-{}@example.com", pg.suffix)).await;
    let member_email = format!("pg-ns-member-{}@example.com", pg.suffix);
    let (member, _) = signup(&app, &member_email).await;
    let ns_name = format!("pg-{}", &pg.suffix[..12]);
    let get = |uri: &str, token: &str| json_req("GET", uri, Some(token), serde_json::json!({}));

    let (status, body) = call(
        app.clone(),
        json_req(
            "POST",
            "/v1/namespaces",
            Some(&owner),
            serde_json::json!({ "name": ns_name }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ns_id = body["id"].as_str().unwrap().to_string();

    let (status, body) = call(
        app.clone(),
        json_req(
            "POST",
            &format!("/v1/namespaces/{ns_name}/members"),
            Some(&owner),
            serde_json::json!({ "email": member_email, "role": "admin" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    db::query(
        "INSERT INTO vms (id, namespace_id, created_by, name, image, vcpu, memory_mib, disk_mib, \
         nat, status, created_at) VALUES (?, ?, ?, 'pg-vm', 'default', 2, 1024, 0, 1, 'running', 1)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&ns_id)
    .bind(&owner_id)
    .execute(&state.db)
    .await
    .unwrap();

    let (status, body) = call(
        app.clone(),
        get(&format!("/v1/vms?namespace={ns_name}"), &member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.as_array().unwrap().len(), 1);
    let (_, body) = call(
        app.clone(),
        get(&format!("/v1/auth/me?namespace={ns_id}"), &member),
    )
    .await;
    assert_eq!(body["usage"]["vcpu"].as_u64(), Some(2));
    assert_eq!(body["quotas"]["max_vms"].as_u64(), Some(10));
    let (status, body) = call(
        app.clone(),
        get(&format!("/v1/namespaces/{ns_name}/audit"), &member),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(!body["events"].as_array().unwrap().is_empty());

    let (status, body) = call(
        app.clone(),
        Request::builder()
            .method("PATCH")
            .uri(format!("/v1/namespaces/{ns_name}/quota"))
            .header("content-type", "application/json")
            .header("x-admin-token", "test-admin")
            .body(Body::from(
                r#"{"max_vms": 1, "max_vcpu": 2, "max_mem_mib": 1024}"#,
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ns_uuid: Uuid = ns_id.parse().unwrap();
    let err = quota::claim_start(&state.db, &ns_uuid, &Uuid::new_v4(), 1, 64)
        .await
        .unwrap_err();
    assert_eq!(err.status, StatusCode::PAYMENT_REQUIRED, "{err}");

    let (status, _) = call(
        app.clone(),
        json_req(
            "DELETE",
            &format!("/v1/namespaces/{ns_name}"),
            Some(&owner),
            serde_json::json!({}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}
