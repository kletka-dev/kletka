use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use kletka_types::{AuthMethods, OAuthPoll, OAuthStart, urlencode};

use crate::audit::{self, Event, RequestMeta};
use crate::auth::{mint_token, set_token_cookie};
use crate::error::{ApiError, ApiResult};
use crate::oauth::{Profile, ProviderId};
use crate::state::AppState;

pub async fn methods(State(state): State<AppState>) -> Json<AuthMethods> {
    Json(AuthMethods {
        password: state.auth.password,
        oauth: state
            .auth
            .oauth
            .enabled()
            .iter()
            .map(|provider| provider.as_str().to_string())
            .collect(),
    })
}

#[derive(Debug, Deserialize)]
pub struct CliStartRequest {
    pub provider: String,
    #[serde(default)]
    pub redirect_uri: Option<String>,
}

pub async fn cli_start(
    State(state): State<AppState>,
    Json(req): Json<CliStartRequest>,
) -> ApiResult<Json<OAuthStart>> {
    let provider = provider_of(&state, &req.provider)?;
    let redirect = match req.redirect_uri.as_deref().map(str::trim) {
        None | Some("") => String::new(),
        Some(uri) => cli_redirect(uri)?.to_string(),
    };
    let flow = store::create_state(&state.db, provider.as_str(), &redirect)
        .await
        .map_err(db_error)?;
    Ok(Json(OAuthStart {
        authorize_url: state.auth.oauth.authorize_url(provider, &flow),
        state: flow,
    }))
}

pub async fn poll(
    State(state): State<AppState>,
    Path(flow): Path<String>,
) -> ApiResult<Json<OAuthPoll>> {
    match store::take_completed(&state.db, &flow).await.map_err(db_error)? {
        Some((token, email)) => Ok(Json(OAuthPoll {
            status: "complete".to_string(),
            token: Some(token),
            email: Some(email),
        })),
        None => match store::pending(&state.db, &flow).await.map_err(db_error)? {
            true => Ok(Json(OAuthPoll {
                status: "pending".to_string(),
                token: None,
                email: None,
            })),
            false => Ok(Json(OAuthPoll {
                status: "expired".to_string(),
                token: None,
                email: None,
            })),
        },
    }
}

pub async fn start(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    let provider = provider_of(&state, &provider)?;
    let redirect = match query.get("cli").map(String::as_str).map(str::trim) {
        None | Some("") => String::new(),
        Some(uri) => cli_redirect(uri)?.to_string(),
    };
    let flow = store::create_state(&state.db, provider.as_str(), &redirect)
        .await
        .map_err(db_error)?;
    Ok(Redirect::to(&state.auth.oauth.authorize_url(provider, &flow)).into_response())
}

pub(crate) async fn callback(
    State(state): State<AppState>,
    meta: RequestMeta,
    Path(provider): Path<String>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Response, CallbackError> {
    let provider = ProviderId::parse(&provider)
        .ok_or_else(|| CallbackError::bad(format!("unknown OAuth provider '{provider}'")))?;
    if !state.auth.oauth.is_enabled(provider) {
        return Err(CallbackError::bad(format!(
            "{} sign-in is not enabled on this deployment",
            provider.label()
        )));
    }
    let flow = query
        .get("state")
        .filter(|state| !state.is_empty())
        .ok_or_else(|| CallbackError::bad("missing OAuth state".to_string()))?;
    let row = store::take_state(&state.db, flow)
        .await
        .map_err(|err| CallbackError::internal(err.to_string()))?
        .filter(|row| row.provider == provider.as_str())
        .ok_or_else(|| {
            CallbackError::bad("this sign-in attempt expired; try again".to_string())
        })?;

    let profile = complete(&state, provider, &query).await?;
    let user_id = upsert_user(&state, &profile)
        .await
        .map_err(|err| CallbackError::internal(err.to_string()))?;
    let email: (String,) = crate::db::query_as("SELECT email FROM users WHERE id = ?")
        .bind(user_id.to_string())
        .fetch_one(&state.db)
        .await
        .map_err(|err| CallbackError::internal(err.to_string()))?;
    let token = mint_token(&state.db, &user_id)
        .await
        .map_err(|err| CallbackError::internal(err.to_string()))?;
    audit::record(
        &state.db,
        Event::user(user_id, "account.login", &meta).detail(serde_json::json!({
            "via": format!("oauth:{}", provider.as_str()),
        })),
    )
    .await;

    if row.redirect.is_empty() {
        return Ok((
            [(axum::http::header::SET_COOKIE, set_token_cookie(&token))],
            Redirect::to("/vms"),
        )
            .into_response());
    }
    if row.redirect == "poll" {
        store::complete(&state.db, flow, &token, &email.0)
            .await
            .map_err(|err| CallbackError::internal(err.to_string()))?;
        return Ok(Html(SIGNED_IN_PAGE).into_response());
    }
    let target = format!(
        "{}?token={}&email={}",
        row.redirect,
        urlencode(&token),
        urlencode(&email.0)
    );
    Ok(Redirect::to(&target).into_response())
}

pub(crate) struct CallbackError {
    pub status: StatusCode,
    pub message: String,
}

impl CallbackError {
    fn bad(message: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }

    fn internal(message: String) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message,
        }
    }
}

impl From<CallbackError> for ApiError {
    fn from(err: CallbackError) -> Self {
        ApiError::new(err.status, err.message)
    }
}

impl IntoResponse for CallbackError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

async fn complete(
    state: &AppState,
    provider: ProviderId,
    query: &HashMap<String, String>,
) -> Result<Profile, CallbackError> {
    let fail = |message: String| CallbackError::internal(message);
    match provider {
        ProviderId::Steam => {
            let openid: Vec<(String, String)> = query
                .iter()
                .filter(|(key, _)| key.starts_with("openid."))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            state
                .auth
                .oauth
                .verify_steam(&openid)
                .await
                .map_err(fail)
        }
        provider => {
            let code = query
                .get("code")
                .filter(|code| !code.is_empty())
                .ok_or_else(|| CallbackError::bad("the provider did not send an OAuth code".to_string()))?;
            state
                .auth
                .oauth
                .exchange_code(provider, code)
                .await
                .map_err(fail)
        }
    }
}

async fn upsert_user(state: &AppState, profile: &Profile) -> Result<Uuid, sqlx::Error> {
    let linked: Option<(String,)> = crate::db::query_as(
        "SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_uid = ?",
    )
    .bind(profile.provider.as_str())
    .bind(&profile.uid)
    .fetch_optional(&state.db)
    .await?;
    if let Some((id,)) = linked {
        return id.parse().map_err(|_| corrupt_user_id());
    }
    let existing: Option<(String,)> =
        crate::db::query_as("SELECT id FROM users WHERE email = ?")
            .bind(&profile.email)
            .fetch_optional(&state.db)
            .await?;
    if let Some((id,)) = existing {
        store::link_account(&state.db, profile.provider.as_str(), &profile.uid, &id).await?;
        return id.parse().map_err(|_| corrupt_user_id());
    }
    let user_id = Uuid::new_v4();
    let insert = crate::db::query("INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)")
        .bind(user_id.to_string())
        .bind(&profile.email)
        .bind(crate::db::now())
        .execute(&state.db)
        .await;
    if crate::db::is_unique_violation(&insert) {
        let (id,): (String,) = crate::db::query_as("SELECT id FROM users WHERE email = ?")
            .bind(&profile.email)
            .fetch_one(&state.db)
            .await?;
        store::link_account(&state.db, profile.provider.as_str(), &profile.uid, &id).await?;
        return id.parse().map_err(|_| corrupt_user_id());
    }
    let _ = insert;
    store::link_account(&state.db, profile.provider.as_str(), &profile.uid, &user_id.to_string())
        .await?;
    crate::namespaces::ensure_personal(&state.db, &user_id, &profile.email)
        .await
        .map_err(|err| sqlx::Error::Configuration(err.message.into()))?;
    audit::record(
        &state.db,
        audit::Event::user(user_id, "account.signup", &RequestMeta::default())
            .detail(serde_json::json!({
                "via": format!("oauth:{}", profile.provider.as_str()),
            })),
    )
    .await;
    Ok(user_id)
}

fn corrupt_user_id() -> sqlx::Error {
    sqlx::Error::Configuration("corrupt user id".into())
}

fn provider_of(state: &AppState, raw: &str) -> ApiResult<ProviderId> {
    let provider = ProviderId::parse(raw)
        .ok_or_else(|| ApiError::not_found(format!("unknown OAuth provider '{raw}'")))?;
    if !state.auth.oauth.is_enabled(provider) {
        return Err(ApiError::not_found(format!(
            "{} sign-in is not enabled on this deployment",
            provider.label()
        )));
    }
    Ok(provider)
}

fn cli_redirect(uri: &str) -> ApiResult<&str> {
    let trimmed = uri.trim_end_matches('/');
    let valid = (trimmed.starts_with("http://127.0.0.1:") || trimmed.starts_with("http://localhost:"))
        && trimmed
            .rsplit(':')
            .next()
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port > 0);
    if !valid {
        return Err(ApiError::bad_request(
            "redirect_uri must be a loopback URL like 'http://127.0.0.1:8123'",
        ));
    }
    Ok(uri)
}

fn db_error(err: sqlx::Error) -> ApiError {
    ApiError::internal(err.to_string())
}

const SIGNED_IN_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>kletka — signed in</title>
</head>
<body style="font-family: system-ui, sans-serif; text-align: center; padding: 4rem;">
<h1>Signed in</h1>
<p>Return to your terminal to continue.</p>
</body>
</html>"#;

mod store {
    use sqlx::AnyPool;

    const TTL_SECS: i64 = 600;

    pub async fn create_state(db: &AnyPool, provider: &str, redirect: &str) -> Result<String, sqlx::Error> {
        let state: [u8; 32] = rand::random();
        let state: String = state.iter().map(|byte| format!("{byte:02x}")).collect();
        crate::db::query("DELETE FROM oauth_states WHERE created_at < ?")
            .bind(crate::db::now() - 24 * 3600)
            .execute(db)
            .await?;
        crate::db::query(
            "INSERT INTO oauth_states (state, provider, redirect, token, email, created_at) \
             VALUES (?, ?, ?, '', '', ?)",
        )
        .bind(&state)
        .bind(provider)
        .bind(redirect)
        .bind(crate::db::now())
        .execute(db)
        .await?;
        Ok(state)
    }

    pub struct StateRow {
        pub provider: String,
        pub redirect: String,
    }

    pub async fn take_state(db: &AnyPool, state: &str) -> Result<Option<StateRow>, sqlx::Error> {
        let row: Option<(String, String, i64)> = crate::db::query_as(
            "SELECT provider, redirect, created_at FROM oauth_states WHERE state = ?",
        )
        .bind(state)
        .fetch_optional(db)
        .await?;
        let Some((provider, redirect, created_at)) = row else {
            return Ok(None);
        };
        crate::db::query("DELETE FROM oauth_states WHERE state = ?")
            .bind(state)
            .execute(db)
            .await?;
        if created_at < crate::db::now() - TTL_SECS {
            return Ok(None);
        }
        Ok(Some(StateRow { provider, redirect }))
    }

    pub async fn complete(
        db: &AnyPool,
        state: &str,
        token: &str,
        email: &str,
    ) -> Result<(), sqlx::Error> {
        crate::db::query("UPDATE oauth_states SET token = ?, email = ? WHERE state = ?")
            .bind(token)
            .bind(email)
            .bind(state)
            .execute(db)
            .await?;
        Ok(())
    }

    pub async fn take_completed(db: &AnyPool, state: &str) -> Result<Option<(String, String)>, sqlx::Error> {
        let row: Option<(String, String)> =
            crate::db::query_as("SELECT token, email FROM oauth_states WHERE state = ?")
                .bind(state)
                .fetch_optional(db)
                .await?;
        let Some((token, email)) = row else {
            return Ok(None);
        };
        if token.is_empty() {
            return Ok(None);
        }
        crate::db::query("DELETE FROM oauth_states WHERE state = ?")
            .bind(state)
            .execute(db)
            .await?;
        Ok(Some((token, email)))
    }

    pub async fn pending(db: &AnyPool, state: &str) -> Result<bool, sqlx::Error> {
        let row: Option<(i64,)> =
            crate::db::query_as("SELECT created_at FROM oauth_states WHERE state = ?")
                .bind(state)
                .fetch_optional(db)
                .await?;
        Ok(row
            .map(|(created_at,)| created_at >= crate::db::now() - TTL_SECS)
            .unwrap_or(false))
    }

    pub async fn link_account(
        db: &AnyPool,
        provider: &str,
        provider_uid: &str,
        user_id: &str,
    ) -> Result<(), sqlx::Error> {
        crate::db::query(
            "INSERT INTO oauth_accounts (provider, provider_uid, user_id, created_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(provider)
        .bind(provider_uid)
        .bind(user_id)
        .bind(crate::db::now())
        .execute(db)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{call, json_req, test_state};
    use tower::ServiceExt;

    #[tokio::test]
    async fn methods_reports_only_enabled_providers() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state);
        let (status, body) = call(app, json_req("GET", "/v1/auth/methods", None, serde_json::json!({}))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["password"], true);
        assert_eq!(body["oauth"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn cli_start_rejects_non_loopback_redirects() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state);
        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/auth/oauth/cli/start",
                None,
                serde_json::json!({"provider": "github", "redirect_uri": "https://evil.example/"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        let (status, _) = call(
            app,
            json_req(
                "POST",
                "/v1/auth/oauth/cli/start",
                None,
                serde_json::json!({"provider": "github"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn callback_requires_a_known_flow() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state);
        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/login/oauth/github/callback?code=x&state=missing")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    fn state_with_github(state: crate::state::AppState) -> crate::state::AppState {
        state_with_auth(state, true)
    }

    fn state_with_auth(
        state: crate::state::AppState,
        password: bool,
    ) -> crate::state::AppState {
        let mut oauth = crate::oauth::OAuthSettings::default();
        oauth.public_url = "https://control.example.com".to_string();
        oauth.github = Some(crate::oauth::OAuth2Client {
            client_id: "abc".to_string(),
            client_secret: "shh".to_string(),
        });
        crate::state::AppState {
            auth: std::sync::Arc::new(crate::state::AuthSettings { password, oauth }),
            ..state
        }
    }

    #[tokio::test]
    async fn disabled_password_blocks_email_signin_and_shows_only_oauth() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state_with_auth(state, false));

        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/auth/signup",
                None,
                serde_json::json!({"email": "a@example.com", "password": "test-password-123"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body["error"].as_str().unwrap().contains("disabled"));

        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/auth/login",
                None,
                serde_json::json!({"email": "a@example.com", "password": "test-password-123"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (status, body) = call(
            app.clone(),
            json_req("GET", "/v1/auth/methods", None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["password"], false);
        assert_eq!(body["oauth"].as_array().unwrap(), &["github"]);

        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/login")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = http_body_util::BodyExt::collect(res.into_body())
            .await
            .unwrap()
            .to_bytes();
        let page = String::from_utf8_lossy(&bytes).to_string();
        assert!(page.contains("/login/oauth/github"), "{page}");
        assert!(!page.contains("type=\"password\""), "{page}");
    }

    #[tokio::test]
    async fn cli_flow_starts_polls_and_completes() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state_with_github(state.clone()));

        let (status, body) = call(
            app.clone(),
            json_req(
                "POST",
                "/v1/auth/oauth/cli/start",
                None,
                serde_json::json!({"provider": "github", "redirect_uri": "http://127.0.0.1:8123"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["authorize_url"]
                .as_str()
                .unwrap()
                .starts_with("https://github.com/login/oauth/authorize?"),
            "{body}"
        );
        let flow = body["state"].as_str().unwrap().to_string();

        let (status, body) = call(
            app.clone(),
            json_req("GET", &format!("/v1/auth/oauth/poll/{flow}"), None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "pending");

        super::store::complete(&state.db, &flow, "tok-1", "a@example.com")
            .await
            .unwrap();

        let (status, body) = call(
            app.clone(),
            json_req("GET", &format!("/v1/auth/oauth/poll/{flow}"), None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "complete");
        assert_eq!(body["token"], "tok-1");
        assert_eq!(body["email"], "a@example.com");

        let (status, body) = call(
            app,
            json_req("GET", &format!("/v1/auth/oauth/poll/{flow}"), None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "expired", "the token is single use: {body}");
    }

    #[tokio::test]
    async fn web_start_redirects_to_the_provider() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state_with_github(state));
        let res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/login/oauth/github")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER);
        let location = res
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .to_string();
        assert!(location.starts_with("https://github.com/login/oauth/authorize?"), "{location}");
        assert!(location.contains("redirect_uri="), "{location}");

        let (status, _) = call(
            app,
            json_req("GET", "/v1/auth/methods", None, serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}
