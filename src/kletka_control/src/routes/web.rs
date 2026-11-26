use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::auth::{
    Identity, NAMESPACE_COOKIE, UserContext, clear_token_cookie, cookie_value, lookup_token,
    set_token_cookie, token_from_headers,
};
use crate::credentials::{self, AuthError};
use crate::routes::vms::{find_vm, list_owned, vm_wire};
use crate::state::AppState;
use kletka_types::CreateVmRequest;

struct VmView {
    id: String,
    name: String,
    image: String,
    vcpu: usize,
    status: String,
    node: Option<String>,
    initial: String,
    avatar_bg: String,
    avatar_border: String,
    avatar_fg: String,
    memory_display: String,
    disk_display: String,
}

fn mib_display(mib: usize) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

fn avatar_palette(name: &str) -> (String, String, String) {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    const HUES: [u16; 8] = [150, 210, 260, 25, 330, 185, 90, 45];
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let hue = HUES[(hasher.finish() % HUES.len() as u64) as usize];
    (
        format!("hsl({hue} 45% 14%)"),
        format!("hsl({hue} 40% 28%)"),
        format!("hsl({hue} 75% 68%)"),
    )
}

impl From<&kletka_types::Vm> for VmView {
    fn from(vm: &kletka_types::Vm) -> Self {
        let (avatar_bg, avatar_border, avatar_fg) = avatar_palette(&vm.name);
        Self {
            id: vm.id.to_string(),
            name: vm.name.clone(),
            image: vm.image.clone(),
            vcpu: vm.vcpu,
            status: vm.status.as_str().to_string(),
            node: vm.assigned_node.clone(),
            initial: vm
                .name
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "?".into()),
            avatar_bg,
            avatar_border,
            avatar_fg,
            memory_display: mib_display(vm.memory_mib),
            disk_display: if vm.disk_mib == 0 {
                "—".into()
            } else {
                mib_display(vm.disk_mib)
            },
        }
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    error: Option<String>,
    password: bool,
    providers: Vec<ProviderButton>,
}

#[derive(Template)]
#[template(path = "register.html")]
struct RegisterPage {
    error: Option<String>,
    password: bool,
    providers: Vec<ProviderButton>,
}

pub(crate) struct ProviderButton {
    pub id: &'static str,
    pub label: &'static str,
}

pub(crate) fn provider_buttons(state: &AppState) -> Vec<ProviderButton> {
    state
        .auth
        .oauth
        .enabled()
        .iter()
        .map(|provider| ProviderButton {
            id: provider.as_str(),
            label: provider.label(),
        })
        .collect()
}

#[derive(Template)]
#[template(path = "vms.html")]
struct VmsPage {
    nav: Nav,
    vms: Vec<VmView>,
    error: Option<String>,
    usage: Option<String>,
    running_count: usize,
    pending_count: usize,
    failed_count: usize,
    stopped_count: usize,
}

fn status_counts(vms: &[VmView]) -> (usize, usize, usize, usize) {
    let mut counts = (0, 0, 0, 0);
    for vm in vms {
        match vm.status.as_str() {
            "running" => counts.0 += 1,
            "pending" => counts.1 += 1,
            "failed" => counts.2 += 1,
            _ => counts.3 += 1,
        }
    }
    counts
}

#[derive(Template)]
#[template(path = "vms_table.html")]
struct VmsTable {
    vms: Vec<VmView>,
}

#[derive(Template)]
#[template(path = "vm_detail.html")]
struct VmDetailPage {
    nav: Nav,
    namespace: String,
    vm: VmView,
    error: Option<String>,
    activity: Vec<ActivityRow>,
}

pub(crate) struct ActivityRow {
    pub time: String,
    pub action: String,
    pub outcome: String,
    pub from: String,
    pub details: String,
}

impl From<&kletka_types::AuditEvent> for ActivityRow {
    fn from(event: &kletka_types::AuditEvent) -> Self {
        Self {
            time: kletka_types::time::display(event.created_at),
            action: event.action.clone(),
            outcome: event.outcome.clone(),
            from: event.origin().to_string(),
            details: event.detail_summary(),
        }
    }
}

#[derive(Template)]
#[template(path = "terminal.html")]
struct TerminalPage {
    nav: Nav,
    vm: VmView,
}

pub(crate) struct NsOption {
    pub id: String,
    pub name: String,
    pub role: String,
    pub current: bool,
}

pub(crate) struct Nav {
    pub email: String,
    pub namespace: String,
    pub options: Vec<NsOption>,
    pub platform_admin: bool,
}

pub(crate) async fn nav_for(state: &AppState, user: &UserContext) -> Nav {
    let current = user.ns.id.to_string();
    let mut options: Vec<NsOption> = crate::namespaces::list_for_user(&state.db, &user.user_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(row, role)| NsOption {
            current: row.id == current,
            id: row.id,
            name: row.name,
            role: role.to_string(),
        })
        .collect();
    if !options.iter().any(|option| option.current) {
        options.push(NsOption {
            id: current,
            name: user.ns.name.clone(),
            role: "platform admin".to_string(),
            current: true,
        });
    }
    Nav {
        email: user.email.clone(),
        namespace: user.ns.name.clone(),
        options,
        platform_admin: user.platform_admin,
    }
}

pub(crate) async fn web_identity(state: &AppState, headers: &HeaderMap) -> Option<Identity> {
    let token = token_from_headers(headers)?;
    lookup_token(state, &token).await
}

pub(crate) async fn web_user(state: &AppState, headers: &HeaderMap) -> Option<UserContext> {
    let identity = web_identity(state, headers).await?;
    let selector = cookie_value(headers, NAMESPACE_COOKIE);
    if selector.is_some()
        && let Ok(user) = identity
            .clone()
            .in_namespace(&state.db, selector.as_deref())
            .await
    {
        return Some(user);
    }
    identity.in_namespace(&state.db, None).await.ok()
}

pub(crate) fn namespace_cookie(id: &str) -> String {
    format!("{NAMESPACE_COOKIE}={id}; Path=/; HttpOnly; SameSite=Lax; Max-Age=31536000")
}

pub(crate) fn is_hx(headers: &HeaderMap) -> bool {
    headers.contains_key("hx-request")
}

pub(crate) fn hx_redirect(to: &str) -> Response {
    ([("HX-Redirect", to)], StatusCode::OK).into_response()
}

pub(crate) fn redirect_or_hx(headers: &HeaderMap, to: &str) -> Response {
    if is_hx(headers) {
        hx_redirect(to)
    } else {
        Redirect::to(to).into_response()
    }
}

pub(crate) fn render<T: Template>(t: T) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("template error: {e}"),
        )
            .into_response(),
    }
}

async fn list_own(state: &AppState, user: &UserContext) -> Vec<VmView> {
    list_owned(&state.db, &user.ns.id)
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|r| vm_wire(r).ok())
        .map(|vm| VmView::from(&vm))
        .collect()
}

async fn vms_page_error(
    state: &AppState,
    user: &crate::auth::UserContext,
    message: String,
) -> Response {
    let vms = list_own(state, user).await;
    let (running_count, pending_count, failed_count, stopped_count) = status_counts(&vms);
    render(VmsPage {
        nav: nav_for(state, user).await,
        vms,
        error: Some(message),
        usage: usage_line(state, user).await,
        running_count,
        pending_count,
        failed_count,
        stopped_count,
    })
}

async fn usage_line(state: &AppState, user: &crate::auth::UserContext) -> Option<String> {
    let quotas = crate::quota::quotas(&state.db, &user.ns.id).await.ok()?;
    let usage = crate::quota::usage(&state.db, &user.ns.id).await.ok()?;
    Some(format!(
        "{}/{} VMs · {}/{} vCPU · {}/{} MiB",
        usage.vms, quotas.max_vms, usage.vcpu, quotas.max_vcpu, usage.mem_mib, quotas.max_mem_mib
    ))
}

async fn vm_view_or(
    state: &AppState,
    user: &crate::auth::UserContext,
    id: &str,
) -> Result<VmView, Box<Response>> {
    match find_vm(&state.db, user, id).await {
        Ok(row) => match vm_wire(&row) {
            Ok(vm) => Ok(VmView::from(&vm)),
            Err(e) => Err(Box::new(
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            )),
        },
        Err(_) => Err(Box::new(Redirect::to("/vms").into_response())),
    }
}

pub async fn index() -> Response {
    Redirect::to("/vms").into_response()
}

pub async fn login_page(State(state): State<AppState>) -> Response {
    render(LoginPage {
        error: None,
        password: state.auth.password,
        providers: provider_buttons(&state),
    })
}

pub async fn register_page(State(state): State<AppState>) -> Response {
    render(RegisterPage {
        error: None,
        password: state.auth.password,
        providers: provider_buttons(&state),
    })
}

#[derive(Debug, Deserialize)]
pub struct AuthForm {
    pub email: Option<String>,
    pub password: Option<String>,
}

async fn do_login(
    state: &AppState,
    email: &str,
    password: &str,
    meta: &crate::audit::RequestMeta,
) -> Result<String, (StatusCode, String)> {
    credentials::login(&state.db, email, Some(password), meta, Some("web"))
        .await
        .map(|session| session.token)
        .map_err(auth_page_error)
}

fn auth_page_error(err: AuthError) -> (StatusCode, String) {
    (err.status(), err.to_string())
}

fn login_success(headers: &HeaderMap, token: &str) -> Response {
    let cookie = set_token_cookie(token);
    if is_hx(headers) {
        (
            [
                ("Set-Cookie".to_string(), cookie),
                ("HX-Redirect".to_string(), "/vms".to_string()),
            ],
            StatusCode::OK,
        )
            .into_response()
    } else {
        (
            [(axum::http::header::SET_COOKIE, cookie)],
            Redirect::to("/vms"),
        )
            .into_response()
    }
}

pub async fn login_submit(
    State(state): State<AppState>,
    meta: crate::audit::RequestMeta,
    headers: HeaderMap,
    axum::Form(form): axum::Form<AuthForm>,
) -> Response {
    if !state.auth.password {
        return render(LoginPage {
            error: Some("email/password sign-in is disabled; use one of the buttons below".into()),
            password: false,
            providers: provider_buttons(&state),
        });
    }
    let email = form.email.unwrap_or_default();
    let password = form.password.unwrap_or_default();
    match do_login(&state, &email, &password, &meta).await {
        Ok(token) => login_success(&headers, &token),
        Err((_, msg)) => render(LoginPage {
            error: Some(msg),
            password: true,
            providers: provider_buttons(&state),
        }),
    }
}

pub async fn register_submit(
    State(state): State<AppState>,
    meta: crate::audit::RequestMeta,
    headers: HeaderMap,
    axum::Form(form): axum::Form<AuthForm>,
) -> Response {
    if !state.auth.password {
        return render(RegisterPage {
            error: Some("email/password sign-up is disabled; use one of the buttons below".into()),
            password: false,
            providers: provider_buttons(&state),
        });
    }
    let email = form.email.unwrap_or_default();
    let password = form.password.unwrap_or_default();
    let session =
        match credentials::signup(&state.db, &email, Some(&password), &meta, Some("web")).await {
            Ok(session) => session,
            Err(err) => {
                return render(RegisterPage {
                    error: Some(err.to_string()),
                    password: true,
                    providers: provider_buttons(&state),
                });
            }
        };
    login_success(&headers, &session.token)
}

pub async fn logout() -> Response {
    (
        axum::response::AppendHeaders([
            (axum::http::header::SET_COOKIE, clear_token_cookie()),
            (
                axum::http::header::SET_COOKIE,
                format!("{NAMESPACE_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
            ),
        ]),
        Redirect::to("/login"),
    )
        .into_response()
}

pub async fn vms_page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let usage = usage_line(&state, &user).await;
    let vms = list_own(&state, &user).await;
    let (running_count, pending_count, failed_count, stopped_count) = status_counts(&vms);
    render(VmsPage {
        nav: nav_for(&state, &user).await,
        vms,
        error: None,
        usage,
        running_count,
        pending_count,
        failed_count,
        stopped_count,
    })
}

pub async fn vms_table(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let vms = list_own(&state, &user).await;
    render(VmsTable { vms })
}

#[derive(Debug, Deserialize)]
pub struct CreateForm {
    pub name: Option<String>,
    pub image: Option<String>,
    pub vcpu: Option<String>,
    pub memory_mib: Option<String>,
    pub disk_mib: Option<String>,
    pub wireguard_config: Option<String>,
}

pub async fn vms_create(
    State(state): State<AppState>,
    meta: crate::audit::RequestMeta,
    headers: HeaderMap,
    axum::Form(form): axum::Form<CreateForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let number = |field: Option<String>| field.and_then(|raw| raw.trim().parse().ok());
    let req = CreateVmRequest {
        name: form.name,
        image: form.image,
        vcpu: number(form.vcpu),
        memory_mib: number(form.memory_mib),
        disk_mib: number(form.disk_mib),
        nat: Some(true),
        wireguard_config: form
            .wireguard_config
            .filter(|config| !config.trim().is_empty()),
        idle_timeout_secs: None,
        ssh_keys: vec![],
    };
    match crate::routes::vms::create_vm_and_job(&state, &user, &req, None, &meta).await {
        Ok(_) => redirect_or_hx(&headers, "/vms"),
        Err(e) => vms_page_error(&state, &user, e.message).await,
    }
}

pub async fn vm_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let vm = match vm_view_or(&state, &user, &id).await {
        Ok(vm) => vm,
        Err(resp) => return *resp,
    };
    let namespace = match crate::routes::vms::fetch_vm(&state.db, &vm.id).await {
        Ok(Some(row)) => crate::namespaces::find(&state.db, &row.namespace_id)
            .await
            .ok()
            .flatten(),
        _ => None,
    };
    let activity = match &namespace {
        Some(ns) => match ns.uuid() {
            Ok(ns_id) => crate::audit::list(
                &state.db,
                crate::audit::Scope::Namespace(ns_id),
                Some(&vm.id),
                None,
                20,
            )
            .await
            .map(|page| page.events.iter().map(ActivityRow::from).collect())
            .unwrap_or_default(),
            Err(_) => Vec::new(),
        },
        None => Vec::new(),
    };
    render(VmDetailPage {
        nav: nav_for(&state, &user).await,
        namespace: namespace.map(|ns| ns.name).unwrap_or_default(),
        vm,
        error: None,
        activity,
    })
}

#[derive(Debug, Clone, Copy)]
enum Lifecycle {
    Start,
    Stop,
    Destroy,
}

async fn web_lifecycle(
    state: &AppState,
    meta: &crate::audit::RequestMeta,
    headers: &HeaderMap,
    id: &str,
    op: Lifecycle,
) -> Response {
    let Some(user) = web_user(state, headers).await else {
        return Redirect::to("/login").into_response();
    };
    let res = match op {
        Lifecycle::Start => crate::routes::vms::start_vm(state, &user, id, meta)
            .await
            .map(drop),
        Lifecycle::Stop => crate::routes::vms::stop_vm(state, &user, id, meta)
            .await
            .map(drop),
        Lifecycle::Destroy => crate::routes::vms::destroy_internal(state, &user, id, meta)
            .await
            .map(drop),
    };
    match res {
        Ok(_) => redirect_or_hx(headers, "/vms"),
        Err(e) => vms_page_error(state, &user, e.message).await,
    }
}

pub async fn vm_start(
    State(state): State<AppState>,
    meta: crate::audit::RequestMeta,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    web_lifecycle(&state, &meta, &headers, &id, Lifecycle::Start).await
}

pub async fn vm_stop(
    State(state): State<AppState>,
    meta: crate::audit::RequestMeta,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    web_lifecycle(&state, &meta, &headers, &id, Lifecycle::Stop).await
}

pub async fn vm_delete(
    State(state): State<AppState>,
    meta: crate::audit::RequestMeta,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    web_lifecycle(&state, &meta, &headers, &id, Lifecycle::Destroy).await
}

pub async fn vm_clone(
    State(state): State<AppState>,
    meta: crate::audit::RequestMeta,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    match crate::routes::clone::clone_internal(
        &state,
        &user,
        &id,
        &kletka_types::CloneVmRequest::default(),
        &meta,
    )
    .await
    {
        Ok(_) => redirect_or_hx(&headers, "/vms"),
        Err(e) => vms_page_error(&state, &user, e.message).await,
    }
}

pub async fn vm_terminal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return Redirect::to("/login").into_response();
    };
    let vm = match vm_view_or(&state, &user, &id).await {
        Ok(vm) => vm,
        Err(resp) => return *resp,
    };
    render(TerminalPage {
        nav: nav_for(&state, &user).await,
        vm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use uuid::Uuid;

    async fn test_state() -> (AppState, crate::testing::TempDirGuard) {
        crate::testing::test_state().await
    }

    async fn test_state_with_guest_pin() -> (AppState, crate::testing::TempDirGuard) {
        let mut k8s = crate::k8s::K8sConfig::default();
        k8s.guest_images
            .insert("default".into(), "kletka-guest-default:dev".into());
        crate::testing::test_state_with_config(k8s).await
    }

    async fn body_text(res: Response) -> (StatusCode, HeaderMap, String) {
        let (mut parts, body) = res.into_parts();
        let status = parts.status;
        let headers = std::mem::take(&mut parts.headers);
        let bytes = body.collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8_lossy(&bytes).to_string())
    }

    fn cookie_of(headers: &HeaderMap) -> Option<String> {
        headers
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find(|v| v.starts_with("kletka_token="))
            .map(|v| v.split(';').next().unwrap_or("").to_string())
    }

    #[tokio::test]
    async fn vm_page_lists_its_activity_escaped() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state.clone());
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=a%40example.com&password=test-password-123",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (_, headers, _) = body_text(res.into_response()).await;
        let cookie = cookie_of(&headers).expect("set-cookie");
        let (owner,): (String,) = crate::db::query_as("SELECT id FROM users")
            .fetch_one(&state.db)
            .await
            .unwrap();
        let vm_id = Uuid::new_v4().to_string();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, status, created_at) \
             VALUES (?, ?, 'web', 'running', 1)",
        )
        .bind(&vm_id)
        .bind(&owner)
        .execute(&state.db)
        .await
        .unwrap();
        crate::audit::record(
            &state.db,
            crate::audit::Event::user(
                owner.parse().unwrap(),
                "session.exec",
                &crate::audit::RequestMeta {
                    ip: Some("198.51.100.4".into()),
                },
            )
            .vm(&vm_id, "web")
            .namespace(&owner)
            .detail(serde_json::json!({ "cmd": "echo <script>alert(1)</script>" })),
        )
        .await;

        let res = app
            .oneshot(
                Request::builder()
                    .uri(format!("/vms/{vm_id}"))
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, text) = body_text(res.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("Recent activity"));
        assert!(text.contains("session.exec"));
        assert!(text.contains("198.51.100.4"));
        assert!(
            !text.contains("<script>alert(1)"),
            "user input must be escaped"
        );
    }

    #[tokio::test]
    async fn register_login_and_vm_flow() {
        let (state, _guard) = test_state_with_guest_pin().await;
        let app = crate::router(state.clone());

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, text) = body_text(res.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("kletka"));

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=u%40example.com&password=test-password-123",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, headers, _) = body_text(res.into_response()).await;
        assert!(status.is_redirection() || status.is_success(), "{status}");
        let cookie = cookie_of(&headers).expect("set-cookie");
        assert!(cookie.starts_with("kletka_token="));

        let res = app
            .clone()
            .oneshot(Request::builder().uri("/vms").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, _, _) = body_text(res.into_response()).await;
        assert_eq!(status, StatusCode::SEE_OTHER);

        for uri in ["/vms", "/vms/table", "/v1/vms"] {
            let res = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .header("cookie", &cookie)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let (status, _, _) = body_text(res.into_response()).await;
            assert_eq!(status, StatusCode::OK, "{uri}");
        }

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vms")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("cookie", &cookie)
                    .body(Body::from("name=web1&image=default&vcpu=2&memory_mib=1024"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, text) = body_text(res.into_response()).await;
        assert!(status.is_redirection() || status.is_success(), "{status}");
        assert!(
            text.contains("error") || text.contains("failed"),
            "expected the panel to surface the create failure"
        );

        let failed: (String,) = crate::db::query_as("SELECT status FROM vms WHERE name = 'web1'")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(failed.0, "failed");
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/vms/web1")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, text) = body_text(res.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("web1"));

        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/vms/web1/delete")
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, _) = body_text(res.into_response()).await;
        assert!(status.is_redirection() || status.is_success(), "{status}");
        let gone: (i64,) = crate::db::query_as("SELECT COUNT(*) FROM vms WHERE name = 'web1'")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(gone.0, 0);
    }

    #[tokio::test]
    async fn vendored_assets_served_without_cdn() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state);
        for (path, contains) in [
            ("/assets/xterm.min.js", "Terminal"),
            ("/assets/xterm-addon-fit.min.js", "FitAddon"),
            ("/assets/htmx.min.js", "htmx"),
            ("/assets/tailwind.js", "tailwind"),
            ("/assets/xterm.min.css", "xterm"),
        ] {
            let res = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::OK, "{path}");
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            let text = String::from_utf8_lossy(&bytes);
            assert!(text.contains(contains), "{path} missing marker");
        }
        for path in ["/assets/..%2F..%2FCargo.toml", "/assets/nope.js"] {
            let res = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn login_wrong_password_shows_error() {
        let (state, _guard) = test_state().await;
        let app = crate::router(state);
        let _ = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/register")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=e%40example.com&password=test-password-123",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "email=e%40example.com&password=wrong-password-xyz",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, text) = body_text(res.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("wrong password"));
    }
}
