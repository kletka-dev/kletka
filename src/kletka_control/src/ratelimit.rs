use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

pub const DEFAULT_AUTH_PER_MIN: u32 = 10;
pub const DEFAULT_API_PER_MIN: u32 = 600;

const CLEANUP_AT: usize = 4096;

#[derive(Debug, Clone)]
pub struct RateLimits {
    pub auth_per_min: u32,
    pub api_per_min: u32,
    buckets: Arc<Buckets>,
}

#[derive(Debug, Default)]
struct Buckets {
    windows: tokio::sync::Mutex<HashMap<IpAddr, Window>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    minute: u64,
    count: u32,
}

impl RateLimits {
    pub fn from_env() -> Self {
        Self::new(
            kletka_types::env_parse("KLETKA_RATE_LIMIT_AUTH_PER_MIN")
                .unwrap_or(DEFAULT_AUTH_PER_MIN),
            kletka_types::env_parse("KLETKA_RATE_LIMIT_API_PER_MIN").unwrap_or(DEFAULT_API_PER_MIN),
        )
    }

    pub fn new(auth_per_min: u32, api_per_min: u32) -> Self {
        Self {
            auth_per_min,
            api_per_min,
            buckets: Arc::new(Buckets::default()),
        }
    }

    pub fn disabled() -> Self {
        Self::new(0, 0)
    }

    fn tier_limit(&self, auth: bool) -> u32 {
        if auth {
            self.auth_per_min
        } else {
            self.api_per_min
        }
    }

    async fn strike(
        &self,
        auth: bool,
        ip: IpAddr,
        now: kletka_types::time::Timestamp,
    ) -> Result<(), u64> {
        let limit = self.tier_limit(auth);
        if limit == 0 {
            return Ok(());
        }
        let now = u64::try_from(now.as_second()).unwrap_or_default();
        let minute = now / 60;
        let mut windows = self.buckets.windows.lock().await;
        if windows.len() >= CLEANUP_AT {
            windows.retain(|_, window| window.minute == minute);
        }
        let window = windows.entry(ip).or_insert(Window { minute, count: 0 });
        if window.minute != minute {
            *window = Window { minute, count: 0 };
        }
        if window.count >= limit {
            return Err(60 - now % 60);
        }
        window.count += 1;
        Ok(())
    }
}

fn is_exempt(path: &str) -> bool {
    path == "/healthz" || path.starts_with("/assets/")
}

fn is_auth(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    path.starts_with("/v1/auth/") || path == "/login" || path == "/register"
}

pub fn client_ip(parts: &Parts) -> IpAddr {
    crate::audit::forwarded_client(parts)
        .and_then(|hop| hop.parse().ok())
        .or_else(|| crate::audit::peer_ip(parts))
        .unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

pub async fn rate_limit(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();
    if is_exempt(parts.uri.path()) {
        return next.run(axum::http::Request::from_parts(parts, body)).await;
    }
    let auth = is_auth(parts.uri.path());
    let ip = client_ip(&parts);
    let now = kletka_types::time::now();
    let request = axum::http::Request::from_parts(parts, body);
    match state.rate_limits.strike(auth, ip, now).await {
        Ok(()) => next.run(request).await,
        Err(retry_in) => too_many_requests(retry_in),
    }
}

fn too_many_requests(retry_in: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, retry_in.max(1).to_string())],
        format!("rate limit exceeded; retry in up to {retry_in} seconds"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_state_with_limits;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn request(path: &str, ip: &str) -> Request<Body> {
        let addr: SocketAddr = format!("{ip}:4444").parse().unwrap();
        Request::builder()
            .uri(path)
            .extension(ConnectInfo(addr))
            .body(Body::empty())
            .unwrap()
    }

    async fn status(app: &axum::Router, path: &str, ip: &str) -> (StatusCode, Option<u64>) {
        let response = app.clone().oneshot(request(path, ip)).await.unwrap();
        let retry = response
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok());
        (response.status(), retry)
    }

    #[test]
    fn tiers_classify_paths() {
        assert!(is_auth("/v1/auth/login"));
        assert!(is_auth("/login"));
        assert!(is_auth("/register"));
        assert!(!is_auth("/v1/vms"));
        assert!(!is_auth("/vms"));
        assert!(!is_auth("/v1/authx"));
        assert!(is_exempt("/healthz"));
        assert!(is_exempt("/assets/xterm.min.js"));
        assert!(!is_exempt("/vms"));
        assert!(!is_auth("/v1/audit?vm=x"));
    }

    #[tokio::test]
    async fn auth_budget_429s_independently_of_the_api_tier() {
        let (state, _guard) = test_state_with_limits(RateLimits::new(3, 100)).await;
        let app = crate::router(state);

        for _ in 0..3 {
            let (status, retry) = status(&app, "/v1/auth/login", "198.51.100.1").await;
            assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
            assert!(retry.is_none());
        }
        let (limited, retry) = status(&app, "/v1/auth/login", "198.51.100.1").await;
        assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
        assert!(retry.is_some());
        let (code, _) = status(&app, "/v1/auth/login", "203.0.113.9").await;
        assert_ne!(code, StatusCode::TOO_MANY_REQUESTS);
        for _ in 0..10 {
            let (code, _) = status(&app, "/vms", "198.51.100.1").await;
            assert_ne!(code, StatusCode::TOO_MANY_REQUESTS);
        }
    }

    #[tokio::test]
    async fn probes_and_assets_are_exempt_and_zero_disables() {
        let (state, _guard) = test_state_with_limits(RateLimits::new(1, 1)).await;
        let app = crate::router(state);
        for path in ["/healthz", "/assets/htmx.min.js"] {
            for _ in 0..5 {
                let (status, _) = status(&app, path, "198.51.100.1").await;
                assert_eq!(status, StatusCode::OK, "{path} must stay exempt");
            }
        }

        let (state, _guard) = test_state_with_limits(RateLimits::disabled()).await;
        let app = crate::router(state);
        for _ in 0..20 {
            let (code, _) = status(&app, "/v1/auth/login", "198.51.100.1").await;
            assert_ne!(code, StatusCode::TOO_MANY_REQUESTS);
        }
    }
}
