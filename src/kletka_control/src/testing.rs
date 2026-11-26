use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::k8s::K8sConfig;
use crate::state::AppState;

pub(crate) const TEST_PASSWORD: &str = "test-password-123";

pub(crate) struct TempDirGuard(std::path::PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn test_pool(prefix: &str) -> (sqlx::AnyPool, TempDirGuard) {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite:{}/t.db?mode=rwc", dir.display());
    let pool = crate::db::connect(&url).await.unwrap();
    (pool, TempDirGuard(dir))
}

pub(crate) async fn test_state() -> (AppState, TempDirGuard) {
    let (pool, guard) = test_pool("kletka-ctl").await;
    (AppState::test(pool), guard)
}

pub(crate) async fn test_state_with_config(config: K8sConfig) -> (AppState, TempDirGuard) {
    let (pool, guard) = test_pool("kletka-ctl").await;
    (AppState::test_with_config(pool, config), guard)
}

pub(crate) async fn test_state_with_limits(
    limits: crate::ratelimit::RateLimits,
) -> (AppState, TempDirGuard) {
    let (pool, guard) = test_pool("kletka-ctl").await;
    (
        AppState::test_with_config_and_limits(pool, K8sConfig::default(), limits),
        guard,
    )
}

pub(crate) fn json_req(
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: serde_json::Value,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        builder = builder.header("authorization", format!("Bearer {t}"));
    }
    builder
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap()
}

pub(crate) async fn call(app: Router, req: Request<Body>) -> (StatusCode, serde_json::Value) {
    let res = app.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

pub(crate) async fn signup(app: &Router, email: &str) -> (String, String) {
    let (status, body) = call(
        app.clone(),
        json_req(
            "POST",
            "/v1/auth/signup",
            None,
            serde_json::json!({"email": email, "password": TEST_PASSWORD}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (
        body["token"].as_str().unwrap().to_string(),
        body["user_id"].as_str().unwrap().to_string(),
    )
}
