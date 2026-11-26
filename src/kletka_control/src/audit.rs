use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use kletka_types::time::Timestamp;
use uuid::Uuid;

const MAX_DETAIL_STRING: usize = 512;
pub const DEFAULT_PAGE: usize = 50;
pub const MAX_PAGE: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Actor {
    User,
    Admin,
    System,
}

impl Actor {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip: Option<String>,
}

pub(crate) fn trust_forwarded_for() -> bool {
    kletka_types::env_bool("KLETKA_TRUST_FORWARDED_FOR", false)
}

pub(crate) fn forwarded_client(parts: &Parts) -> Option<&str> {
    if !trust_forwarded_for() {
        return None;
    }
    parts
        .headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|hop| !hop.is_empty())
}

pub(crate) fn peer_ip(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

impl<S: Send + Sync> FromRequestParts<S> for RequestMeta {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip = forwarded_client(parts)
            .map(str::to_string)
            .or_else(|| peer_ip(parts).map(|ip| ip.to_string()));
        Ok(Self { ip })
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub user_id: Uuid,
    pub actor: Actor,
    pub action: &'static str,
    pub vm: Option<(String, String)>,
    pub namespace: Option<String>,
    pub denied: bool,
    pub detail: serde_json::Value,
    pub ip: Option<String>,
}

impl Event {
    fn new(user_id: Uuid, actor: Actor, action: &'static str, ip: Option<String>) -> Self {
        Self {
            user_id,
            actor,
            action,
            vm: None,
            namespace: None,
            denied: false,
            detail: serde_json::Value::Null,
            ip,
        }
    }

    pub fn user(user_id: Uuid, action: &'static str, meta: &RequestMeta) -> Self {
        Self::new(user_id, Actor::User, action, meta.ip.clone())
    }

    pub fn system(user_id: Uuid, action: &'static str) -> Self {
        Self::new(user_id, Actor::System, action, None)
    }

    pub fn vm(mut self, id: impl Into<String>, name: impl Into<String>) -> Self {
        self.vm = Some((id.into(), name.into()));
        self
    }

    pub fn for_vm(self, vm: &crate::routes::vms::VmRow) -> Self {
        self.vm(&vm.id, &vm.name).namespace(&vm.namespace_id)
    }

    pub fn namespace(mut self, id: impl ToString) -> Self {
        self.namespace = Some(id.to_string());
        self
    }

    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = detail;
        self
    }

    pub fn actor(mut self, actor: Actor) -> Self {
        self.actor = actor;
        self
    }

    pub fn denied(mut self) -> Self {
        self.denied = true;
        self
    }
}

fn clip(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(text) if text.len() > MAX_DETAIL_STRING => {
            let mut end = MAX_DETAIL_STRING;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            serde_json::Value::String(format!("{}…", &text[..end]))
        }
        serde_json::Value::Array(items) => items.into_iter().map(clip).collect(),
        serde_json::Value::Object(map) => map.into_iter().map(|(k, v)| (k, clip(v))).collect(),
        other => other,
    }
}

pub async fn record(db: &sqlx::AnyPool, event: Event) {
    let detail = match clip(event.detail) {
        serde_json::Value::Null => None,
        detail => Some(detail.to_string()),
    };
    let (vm_id, vm_name) = event.vm.unzip();
    let result = crate::db::query(
        "INSERT INTO audit_events (created_at, user_id, actor, action, vm_id, vm_name, outcome, \
         detail, source_ip, namespace_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(crate::db::now())
    .bind(event.user_id.to_string())
    .bind(event.actor.as_str())
    .bind(event.action)
    .bind(vm_id)
    .bind(vm_name)
    .bind(if event.denied { "denied" } else { "ok" })
    .bind(detail)
    .bind(event.ip)
    .bind(event.namespace)
    .execute(db)
    .await;
    if let Err(err) = result {
        tracing::warn!(action = event.action, %err, "audit event not recorded");
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditRow {
    pub id: i64,
    pub created_at: i64,
    pub actor: String,
    pub action: String,
    pub vm_id: Option<String>,
    pub vm_name: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
    pub source_ip: Option<String>,
}

impl AuditRow {
    pub fn to_wire(&self) -> kletka_types::AuditEvent {
        kletka_types::AuditEvent {
            id: self.id,
            created_at: crate::db::timestamp(self.created_at),
            actor: self.actor.clone(),
            action: self.action.clone(),
            vm_id: self.vm_id.clone(),
            vm_name: self.vm_name.clone(),
            outcome: self.outcome.clone(),
            detail: self
                .detail
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or(serde_json::Value::Null),
            source_ip: self.source_ip.clone(),
        }
    }
}

pub use kletka_types::AuditPage;

#[derive(Debug, Clone, Copy)]
pub enum Scope {
    User(Uuid),
    Namespace(Uuid),
}

pub async fn list(
    db: &sqlx::AnyPool,
    scope: Scope,
    vm: Option<&str>,
    before: Option<i64>,
    limit: usize,
) -> Result<AuditPage, sqlx::Error> {
    let limit = limit.clamp(1, MAX_PAGE);
    let (user, namespace) = match scope {
        Scope::User(id) => (Some(id.to_string()), None),
        Scope::Namespace(id) => (None, Some(id.to_string())),
    };
    let mut rows: Vec<AuditRow> = crate::db::query_as(
        "SELECT id, created_at, actor, action, vm_id, vm_name, outcome, detail, source_ip \
         FROM audit_events \
         WHERE (? IS NULL OR user_id = ?) \
           AND (? IS NULL OR namespace_id = ?) \
           AND (? IS NULL OR vm_id = ? OR vm_name = ?) \
           AND (? IS NULL OR id < ?) \
         ORDER BY id DESC LIMIT ?",
    )
    .bind(user.clone())
    .bind(user)
    .bind(namespace.clone())
    .bind(namespace)
    .bind(vm)
    .bind(vm)
    .bind(vm)
    .bind(before)
    .bind(before)
    .bind((limit + 1) as i64)
    .fetch_all(db)
    .await?;
    let next_before = (rows.len() > limit).then(|| {
        rows.truncate(limit);
        rows.last().map(|row| row.id)
    });
    Ok(AuditPage {
        events: rows.iter().map(AuditRow::to_wire).collect(),
        next_before: next_before.flatten(),
    })
}

pub fn spawn_retention(db: sqlx::AnyPool, gate: std::sync::Arc<crate::leader::LeaderGate>) {
    let days: u64 = kletka_types::env_parse("KLETKA_AUDIT_RETENTION_DAYS").unwrap_or(90);
    if days == 0 {
        tracing::info!("audit retention disabled; events are kept forever");
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
        loop {
            tick.tick().await;
            gate.wait().await;
            let cutoff = crate::db::timestamp(crate::db::now() - days as i64 * 24 * 60 * 60);
            match prune(&db, cutoff).await {
                Ok(0) => {}
                Ok(pruned) => tracing::info!(pruned, days, "pruned old audit events"),
                Err(err) => tracing::warn!(%err, "audit retention failed"),
            }
        }
    });
}

pub async fn prune(db: &sqlx::AnyPool, cutoff: Timestamp) -> Result<u64, sqlx::Error> {
    Ok(
        crate::db::query("DELETE FROM audit_events WHERE created_at < ?")
            .bind(crate::db::unix(cutoff))
            .execute(db)
            .await?
            .rows_affected(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> (sqlx::AnyPool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("kletka-audit-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::connect(&format!("sqlite:{}/t.db?mode=rwc", dir.display()))
            .await
            .unwrap();
        (pool, dir)
    }

    #[tokio::test]
    async fn events_page_newest_first_and_filter_by_vm() {
        let (db, dir) = db().await;
        let me = Uuid::new_v4();
        let other = Uuid::new_v4();
        let meta = RequestMeta {
            ip: Some("203.0.113.7".into()),
        };
        for i in 0..5 {
            record(
                &db,
                Event::user(me, "vm.start", &meta)
                    .vm(format!("id-{}", i % 2), format!("vm-{}", i % 2)),
            )
            .await;
        }
        record(&db, Event::user(other, "vm.start", &meta)).await;

        let page = list(&db, Scope::User(me), None, None, 3).await.unwrap();
        assert_eq!(page.events.len(), 3);
        assert!(page.events[0].id > page.events[1].id, "newest first");
        assert_eq!(page.events[0].source_ip.as_deref(), Some("203.0.113.7"));
        let rest = list(&db, Scope::User(me), None, page.next_before, 3)
            .await
            .unwrap();
        assert_eq!(rest.events.len(), 2);
        assert_eq!(rest.next_before, None);

        assert_eq!(
            list(&db, Scope::User(me), Some("vm-0"), None, 50)
                .await
                .unwrap()
                .events
                .len(),
            3
        );
        assert_eq!(
            list(&db, Scope::User(me), Some("id-1"), None, 50)
                .await
                .unwrap()
                .events
                .len(),
            2
        );
        assert_eq!(
            list(&db, Scope::User(other), None, None, 50)
                .await
                .unwrap()
                .events
                .len(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn details_are_clipped_and_old_events_pruned() {
        let (db, dir) = db().await;
        let me = Uuid::new_v4();
        let long = "x".repeat(5000);
        record(
            &db,
            Event::system(me, "session.exec").detail(serde_json::json!({ "cmd": [long] })),
        )
        .await;
        let page = list(&db, Scope::User(me), None, None, 10).await.unwrap();
        let cmd = page.events[0].detail.to_string();
        assert!(cmd.len() < 600, "{} bytes", cmd.len());
        assert_eq!(page.events[0].actor, "system");

        let cutoff = crate::db::timestamp(crate::db::now() + 1);
        assert_eq!(prune(&db, cutoff).await.unwrap(), 1);
        assert!(
            list(&db, Scope::User(me), None, None, 10)
                .await
                .unwrap()
                .events
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
