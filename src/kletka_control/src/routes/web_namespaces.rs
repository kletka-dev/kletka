use askama::Template;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::audit::RequestMeta;
use crate::auth::{Identity, UserContext};
use crate::error::ApiError;
use crate::namespaces::{self, NamespaceRow, NsAccess};
use crate::routes::admin::{self, AdminCaller};
use crate::routes::namespaces as ops;
use crate::routes::web::{
    ActivityRow, Nav, namespace_cookie, nav_for, redirect_or_hx, render, web_user,
};
use crate::state::{AppState, CreationPolicy};
use kletka_types::{NamespaceRole as Role, QuotaInfo, UpdateUserRequest, UsageInfo};

struct NamespaceView {
    id: String,
    name: String,
    personal: bool,
    role: String,
    members: usize,
    usage: String,
    created: String,
}

fn usage_text(usage: &UsageInfo, quotas: &QuotaInfo) -> String {
    format!(
        "{}/{} VMs · {}/{} vCPU · {}/{} MiB",
        usage.vms, quotas.max_vms, usage.vcpu, quotas.max_vcpu, usage.mem_mib, quotas.max_mem_mib
    )
}

async fn namespace_view(state: &AppState, row: &NamespaceRow, role: Option<Role>) -> NamespaceView {
    let info = namespaces::info(&state.db, row, role).await.ok();
    NamespaceView {
        id: row.id.clone(),
        name: row.name.clone(),
        personal: row.personal(),
        role: role.map_or_else(|| "platform admin".to_string(), |role| role.to_string()),
        members: info.as_ref().map_or(0, |info| info.members),
        usage: info
            .as_ref()
            .map(|info| usage_text(&info.usage, &info.quotas))
            .unwrap_or_default(),
        created: kletka_types::time::display(crate::db::timestamp(row.created_at)),
    }
}

#[derive(Template)]
#[template(path = "namespaces.html")]
struct NamespacesPage {
    nav: Nav,
    rows: Vec<NamespaceView>,
    error: Option<String>,
    allowance: String,
    can_create: bool,
    cannot_create_reason: String,
}

struct MemberView {
    user_id: String,
    email: String,
    role: String,
    added: String,
    is_self: bool,
    can_edit: bool,
    can_remove: bool,
}

#[derive(Template)]
#[template(path = "namespace_detail.html")]
struct NamespaceDetailPage {
    nav: Nav,
    ns: NamespaceView,
    quotas: QuotaInfo,
    usage: UsageInfo,
    members: Vec<MemberView>,
    grantable: Vec<String>,
    can_manage: bool,
    is_owner: bool,
    is_platform_admin: bool,
    activity: Vec<ActivityRow>,
    error: Option<String>,
    notice: Option<String>,
}

struct UserView {
    id: String,
    email: String,
    platform_admin: bool,
    via_config: bool,
    owned: usize,
    max_namespaces: String,
}

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminPage {
    nav: Nav,
    users: Vec<UserView>,
    namespaces: Vec<NamespaceView>,
    policy: String,
    default_allowance: usize,
    default_quota: String,
    error: Option<String>,
}

fn login() -> Response {
    Redirect::to("/login").into_response()
}

async fn namespaces_page(state: &AppState, user: &UserContext, error: Option<String>) -> Response {
    let mut rows = Vec::new();
    for (row, role) in namespaces::list_for_user(&state.db, &user.user_id)
        .await
        .unwrap_or_default()
    {
        rows.push(namespace_view(state, &row, Some(role)).await);
    }
    let allowance = namespaces::allowance(
        &state.db,
        &state.namespaces,
        &user.user_id,
        user.platform_admin,
    )
    .await
    .ok();
    let (allowance_text, can_create, reason) = match allowance {
        Some(a) => match a.limit {
            None => (
                format!("you own {} · no limit", a.used),
                true,
                String::new(),
            ),
            Some(0) => (
                String::new(),
                false,
                "Creating namespaces is not enabled for your account. Ask a platform admin if \
                 you need one."
                    .to_string(),
            ),
            Some(limit) => (
                format!("you own {} of {limit} allowed", a.used),
                a.can_create(),
                format!("You already own {limit} namespaces, the most your account allows."),
            ),
        },
        None => (
            String::new(),
            false,
            "Could not load your allowance.".into(),
        ),
    };
    render(NamespacesPage {
        nav: nav_for(state, user).await,
        rows,
        error,
        allowance: allowance_text,
        can_create,
        cannot_create_reason: reason,
    })
}

pub async fn namespaces_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    namespaces_page(&state, &user, None).await
}

#[derive(Debug, Deserialize)]
pub struct NameForm {
    pub name: Option<String>,
}

pub async fn namespaces_create(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    axum::Form(form): axum::Form<NameForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    let name = form.name.unwrap_or_default();
    match ops::create_ns(&state, &user.identity(), &meta, &name).await {
        Ok(row) => redirect_or_hx(&headers, &format!("/namespaces/{}", row.id)),
        Err(err) => namespaces_page(&state, &user, Some(err.message)).await,
    }
}

#[derive(Debug, Deserialize)]
pub struct SwitchForm {
    pub namespace: Option<String>,
}

pub async fn switch(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<SwitchForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    let key = form.namespace.unwrap_or_default();
    let target = match user.identity().in_namespace(&state.db, Some(&key)).await {
        Ok(target) => target,
        Err(err) => return namespaces_page(&state, &user, Some(err.message)).await,
    };
    (
        [(
            axum::http::header::SET_COOKIE,
            namespace_cookie(&target.ns.id.to_string()),
        )],
        Redirect::to("/vms"),
    )
        .into_response()
}

async fn open_web(
    state: &AppState,
    identity: &Identity,
    key: &str,
) -> Result<(NamespaceRow, NsAccess), ApiError> {
    ops::open(state, identity, key).await
}

async fn detail_page(
    state: &AppState,
    user: &UserContext,
    key: &str,
    error: Option<String>,
    notice: Option<String>,
) -> Response {
    let identity = user.identity();
    let (row, access) = match open_web(state, &identity, key).await {
        Ok(found) => found,
        Err(err) if err.status == StatusCode::NOT_FOUND => {
            return namespaces_page(state, user, Some(err.message)).await;
        }
        Err(err) => return (err.status, err.message).into_response(),
    };
    let role = access.member.then_some(access.role);
    let ns = namespace_view(state, &row, role).await;
    let quotas = crate::quota::quotas(&state.db, &access.id)
        .await
        .unwrap_or(crate::quota::DEFAULT_QUOTAS);
    let usage = crate::quota::usage(&state.db, &access.id)
        .await
        .unwrap_or(UsageInfo {
            vms: 0,
            vcpu: 0,
            mem_mib: 0,
        });
    let can_manage = access.role >= Role::Admin;
    let is_owner = access.role == Role::Owner;
    let members = namespaces::members(&state.db, &access.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|m| {
            let is_self = m.user_id == user.user_id;
            let touchable = can_manage && (m.role != Role::Owner || is_owner) && !row.personal();
            MemberView {
                user_id: m.user_id.to_string(),
                email: m.email,
                role: m.role.to_string(),
                added: kletka_types::time::display(m.added_at),
                is_self,
                can_edit: touchable,
                can_remove: (is_self && !row.personal()) || (touchable && !is_self),
            }
        })
        .collect();
    let grantable = Role::ALL
        .into_iter()
        .filter(|r| *r != Role::Owner || is_owner)
        .map(|r| r.to_string())
        .collect();
    let activity = if can_manage {
        crate::audit::list(
            &state.db,
            crate::audit::Scope::Namespace(access.id),
            None,
            None,
            25,
        )
        .await
        .map(|page| page.events.iter().map(ActivityRow::from).collect())
        .unwrap_or_default()
    } else {
        Vec::new()
    };
    render(NamespaceDetailPage {
        nav: nav_for(state, user).await,
        ns,
        quotas,
        usage,
        members,
        grantable,
        can_manage,
        is_owner,
        is_platform_admin: user.platform_admin,
        activity,
        error,
        notice,
    })
}

pub async fn namespace_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    detail_page(&state, &user, &key, None, None).await
}

async fn after(
    state: &AppState,
    headers: &HeaderMap,
    user: &UserContext,
    key: &str,
    result: Result<(), ApiError>,
) -> Response {
    match result {
        Ok(()) => redirect_or_hx(headers, &format!("/namespaces/{key}")),
        Err(err) => detail_page(state, user, key, Some(err.message), None).await,
    }
}

pub async fn namespace_rename(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Path(key): Path<String>,
    axum::Form(form): axum::Form<NameForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    let identity = user.identity();
    let result = async {
        let (_, access) = open_web(&state, &identity, &key).await?;
        ops::rename_ns(
            &state,
            &identity,
            &meta,
            &access,
            &form.name.unwrap_or_default(),
        )
        .await
    }
    .await;
    after(&state, &headers, &user, &key, result).await
}

pub async fn namespace_delete(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    let identity = user.identity();
    let result = async {
        let (_, access) = open_web(&state, &identity, &key).await?;
        ops::delete_ns(&state, &identity, &meta, &access).await
    }
    .await;
    match result {
        Ok(()) => redirect_or_hx(&headers, "/namespaces"),
        Err(err) => detail_page(&state, &user, &key, Some(err.message), None).await,
    }
}

#[derive(Debug, Deserialize)]
pub struct MemberForm {
    pub email: Option<String>,
    pub role: Option<String>,
}

fn parse_role(raw: Option<&str>) -> Result<Role, ApiError> {
    let raw = raw.unwrap_or("member");
    Role::parse(raw).ok_or_else(|| ApiError::bad_request(format!("unknown role '{raw}'")))
}

pub async fn member_add(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Path(key): Path<String>,
    axum::Form(form): axum::Form<MemberForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    let identity = user.identity();
    let result = async {
        let role = parse_role(form.role.as_deref())?;
        let (_, access) = open_web(&state, &identity, &key).await?;
        let email = form.email.unwrap_or_default();
        ops::add_member_op(&state, &identity, &meta, &access, &email, role).await
    }
    .await;
    after(&state, &headers, &user, &key, result).await
}

pub async fn member_role(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Path((key, member)): Path<(String, String)>,
    axum::Form(form): axum::Form<MemberForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    let identity = user.identity();
    let result = async {
        let role = parse_role(form.role.as_deref())?;
        let (_, access) = open_web(&state, &identity, &key).await?;
        ops::set_role_op(&state, &identity, &meta, &access, &member, role).await
    }
    .await;
    after(&state, &headers, &user, &key, result).await
}

pub async fn member_remove(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Path((key, member)): Path<(String, String)>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    let identity = user.identity();
    let leaving = member == user.user_id.to_string();
    let result = async {
        let (_, access) = open_web(&state, &identity, &key).await?;
        ops::remove_member_op(&state, &identity, &meta, &access, &member).await
    }
    .await;
    match result {
        Ok(()) if leaving => redirect_or_hx(&headers, "/namespaces"),
        other => after(&state, &headers, &user, &key, other).await,
    }
}

#[derive(Debug, Deserialize)]
pub struct QuotaForm {
    pub max_vms: Option<String>,
    pub max_vcpu: Option<String>,
    pub max_mem_mib: Option<String>,
    pub reset: Option<String>,
}

fn number(field: Option<&str>, what: &str) -> Result<usize, ApiError> {
    field
        .map(str::trim)
        .and_then(|raw| raw.parse().ok())
        .ok_or_else(|| ApiError::bad_request(format!("{what} must be a whole number")))
}

pub async fn namespace_quota(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Path(key): Path<String>,
    axum::Form(form): axum::Form<QuotaForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    if !user.platform_admin {
        return (StatusCode::FORBIDDEN, "this needs a platform admin").into_response();
    }
    let admin = AdminCaller::User(user.identity());
    let result = async {
        let row = namespaces::find(&state.db, &key)
            .await?
            .ok_or_else(|| ApiError::not_found(format!("namespace '{key}' not found")))?;
        let limits = if form.reset.is_some() {
            None
        } else {
            Some(QuotaInfo {
                max_vms: number(form.max_vms.as_deref(), "max VMs")?,
                max_vcpu: number(form.max_vcpu.as_deref(), "max vCPU")?,
                max_mem_mib: number(form.max_mem_mib.as_deref(), "max memory")?,
            })
        };
        ops::set_quota_op(&state, &admin, &meta, &row, limits)
            .await
            .map(drop)
    }
    .await;
    after(&state, &headers, &user, &key, result).await
}

async fn admin_page(state: &AppState, user: &UserContext, error: Option<String>) -> Response {
    let users = admin::user_summaries(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|u| UserView {
            id: u.user_id.to_string(),
            via_config: state.namespaces.is_configured_admin(&u.email),
            email: u.email,
            platform_admin: u.platform_admin,
            owned: u.namespaces_owned,
            max_namespaces: u.max_namespaces.map(|n| n.to_string()).unwrap_or_default(),
        })
        .collect();
    let mut all = Vec::new();
    for row in namespaces::list_all(&state.db).await.unwrap_or_default() {
        let role = namespaces::role_of(&state.db, &row.id, &user.user_id)
            .await
            .ok()
            .flatten();
        all.push(namespace_view(state, &row, role).await);
    }
    let settings = &state.namespaces;
    let defaults = settings.default_quotas;
    render(AdminPage {
        nav: nav_for(state, user).await,
        users,
        namespaces: all,
        policy: match settings.creation {
            CreationPolicy::Everyone => "everyone".to_string(),
            CreationPolicy::PlatformAdmins => "platform admins only".to_string(),
        },
        default_allowance: match settings.creation {
            CreationPolicy::Everyone => settings.max_per_user,
            CreationPolicy::PlatformAdmins => 0,
        },
        default_quota: format!(
            "{} VMs · {} vCPU · {} MiB",
            defaults.max_vms, defaults.max_vcpu, defaults.max_mem_mib
        ),
        error,
    })
}

pub async fn admin_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    if !user.platform_admin {
        return Redirect::to("/vms").into_response();
    }
    admin_page(&state, &user, None).await
}

#[derive(Debug, Deserialize)]
pub struct UserForm {
    pub platform_admin: Option<String>,
    pub max_namespaces: Option<String>,
}

pub async fn admin_user_update(
    State(state): State<AppState>,
    meta: RequestMeta,
    headers: HeaderMap,
    Path(target): Path<String>,
    axum::Form(form): axum::Form<UserForm>,
) -> Response {
    let Some(user) = web_user(&state, &headers).await else {
        return login();
    };
    if !user.platform_admin {
        return Redirect::to("/vms").into_response();
    }
    let admin = AdminCaller::User(user.identity());
    let result = async {
        let (target, _) = namespaces::user_by_key(&state.db, &target).await?;
        let platform_admin = match form.platform_admin.as_deref() {
            None => None,
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(other) => {
                return Err(ApiError::bad_request(format!(
                    "platform_admin must be true or false, not '{other}'"
                )));
            }
        };
        let max_namespaces = match form.max_namespaces.as_deref().map(str::trim) {
            None => None,
            Some("") => Some(None),
            Some(raw) => Some(Some(raw.parse::<usize>().map_err(|_| {
                ApiError::bad_request("the namespace allowance must be a whole number or blank")
            })?)),
        };
        let req = UpdateUserRequest {
            platform_admin,
            max_namespaces,
        };
        admin::apply_user_update(&state, &admin, &meta, target, &req).await
    }
    .await;
    match result {
        Ok(()) => redirect_or_hx(&headers, "/admin"),
        Err(err) => admin_page(&state, &user, Some(err.message)).await,
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::state::NamespaceSettings;

    struct Page {
        status: StatusCode,
        location: Option<String>,
        cookies: Vec<String>,
        text: String,
    }

    async fn send(app: &Router, method: &str, uri: &str, cookie: &str, form: &str) -> Page {
        let mut builder = Request::builder().method(method).uri(uri);
        if !cookie.is_empty() {
            builder = builder.header("cookie", cookie);
        }
        if method == "POST" {
            builder = builder.header("content-type", "application/x-www-form-urlencoded");
        }
        let res = app
            .clone()
            .oneshot(builder.body(Body::from(form.to_string())).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let header = |name| {
            res.headers()
                .get_all(name)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(|v| v.split(';').next().unwrap_or_default().to_string())
                .collect::<Vec<_>>()
        };
        let location = header(axum::http::header::LOCATION).into_iter().next();
        let cookies = header(axum::http::header::SET_COOKIE);
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        Page {
            status,
            location,
            cookies,
            text: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn register(app: &Router, email: &str) -> String {
        let page = send(
            app,
            "POST",
            "/register",
            "",
            &format!(
                "email={}&password=test-password-123",
                email.replace('@', "%40")
            ),
        )
        .await;
        page.cookies
            .into_iter()
            .find(|c| c.starts_with("kletka_token="))
            .expect("session cookie")
    }

    #[tokio::test]
    async fn panel_manages_namespaces_end_to_end() {
        let (mut state, _guard) = crate::testing::test_state().await;
        state.namespaces = std::sync::Arc::new(NamespaceSettings {
            platform_admins: vec!["boss@example.com".into()],
            ..NamespaceSettings::default()
        });
        let app = crate::router(state.clone());
        let owner = register(&app, "owner@example.com").await;
        let mate = register(&app, "mate@example.com").await;
        let boss = register(&app, "boss@example.com").await;

        let page = send(&app, "GET", "/namespaces", &owner, "").await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.text.contains("personal") && page.text.contains(">owner<"));
        assert!(
            !page.text.contains("Platform admin"),
            "non-admins get no admin link"
        );

        let page = send(&app, "POST", "/namespaces", &owner, "name=Bad Name").await;
        assert!(
            page.text.contains("invalid namespace name"),
            "errors render inline"
        );
        let page = send(&app, "POST", "/namespaces", &owner, "name=team").await;
        let detail = page.location.expect("redirect to the new namespace");
        let team_id = detail.trim_start_matches("/namespaces/").to_string();

        let page = send(
            &app,
            "POST",
            &format!("{detail}/members"),
            &owner,
            "email=nobody%40example.com&role=member",
        )
        .await;
        assert!(page.text.contains("nobody@example.com") && page.text.contains("not found"));
        let page = send(
            &app,
            "POST",
            &format!("{detail}/members"),
            &owner,
            "email=mate%40example.com&role=admin",
        )
        .await;
        assert!(page.status.is_redirection(), "{}", page.text);
        let page = send(&app, "GET", &detail, &owner, "").await;
        assert!(page.text.contains("mate@example.com"));
        assert!(
            page.text.contains("namespace.member.add"),
            "owners see activity"
        );

        let page = send(
            &app,
            "POST",
            "/ns/switch",
            &mate,
            &format!("namespace={team_id}"),
        )
        .await;
        let ns_cookie = page
            .cookies
            .iter()
            .find(|c| c.starts_with("kletka_ns="))
            .expect("namespace cookie")
            .clone();
        let both = format!("{mate}; {ns_cookie}");
        let page = send(&app, "GET", "/vms", &both, "").await;
        assert!(page.text.contains("Create VM in team"), "{}", page.text);

        let page = send(&app, "POST", &format!("{detail}/delete"), &mate, "").await;
        assert!(
            page.text.contains("needs the owner role"),
            "admins cannot delete"
        );

        let page = send(&app, "GET", "/admin", &owner, "").await;
        assert_eq!(page.location.as_deref(), Some("/vms"));
        let page = send(&app, "GET", "/admin", &boss, "").await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page.text.contains("owner@example.com") && page.text.contains("(config)"));

        let owner_id: (String,) =
            crate::db::query_as("SELECT id FROM users WHERE email = 'owner@example.com'")
                .fetch_one(&state.db)
                .await
                .unwrap();
        let page = send(
            &app,
            "POST",
            &format!("/admin/users/{}", owner_id.0),
            &boss,
            "max_namespaces=0",
        )
        .await;
        assert_eq!(page.location.as_deref(), Some("/admin"));
        let page = send(&app, "GET", "/namespaces", &owner, "").await;
        assert!(page.text.contains("not enabled for your account"));

        let page = send(
            &app,
            "POST",
            &format!("{detail}/quota"),
            &boss,
            "max_vms=3&max_vcpu=4&max_mem_mib=4096",
        )
        .await;
        assert!(page.status.is_redirection(), "{}", page.text);
        let page = send(&app, "GET", &detail, &boss, "").await;
        assert!(
            page.text.contains("0 / 3"),
            "quota visible on the namespace page"
        );
        let page = send(
            &app,
            "POST",
            &format!("{detail}/quota"),
            &owner,
            "max_vms=99&max_vcpu=1&max_mem_mib=1",
        )
        .await;
        assert_eq!(page.status, StatusCode::FORBIDDEN);

        let page = send(&app, "POST", &format!("{detail}/delete"), &owner, "").await;
        assert_eq!(page.location.as_deref(), Some("/namespaces"));
        let page = send(&app, "GET", "/vms", &both, "").await;
        assert!(
            page.text.contains("Create VM in mate"),
            "a dead namespace cookie falls back to personal"
        );
    }
}
