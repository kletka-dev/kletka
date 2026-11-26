use std::sync::OnceLock;
use std::time::Duration;

use kletka_types::time::Timestamp;
use uuid::Uuid;

use crate::routes::vms::{StopCause, stop_vm_with};
use crate::state::AppState;

pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 8 * 60 * 60;
pub const MIN_IDLE_TIMEOUT_SECS: u64 = 60;
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 30 * 24 * 60 * 60;

pub fn default_timeout_secs() -> u64 {
    static DEFAULT: OnceLock<u64> = OnceLock::new();
    *DEFAULT.get_or_init(|| {
        kletka_types::env_parse("KLETKA_IDLE_TIMEOUT_SECS").unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS)
    })
}

pub fn effective_timeout_secs(column: Option<i64>) -> u64 {
    match column {
        Some(secs) => secs.max(0) as u64,
        None => default_timeout_secs(),
    }
}

pub fn validate_timeout(secs: u64) -> Result<(), String> {
    if secs == 0 || (MIN_IDLE_TIMEOUT_SECS..=MAX_IDLE_TIMEOUT_SECS).contains(&secs) {
        return Ok(());
    }
    Err(format!(
        "idle timeout must be 0 (never) or between {MIN_IDLE_TIMEOUT_SECS}s and \
         {MAX_IDLE_TIMEOUT_SECS}s (30 days)"
    ))
}

pub fn spawn(state: AppState, gate: std::sync::Arc<crate::leader::LeaderGate>) {
    let every = kletka_types::env_parse("KLETKA_IDLE_CHECK_SECS")
        .unwrap_or(60u64)
        .max(5);
    tracing::info!(
        every_secs = every,
        default_timeout_secs = default_timeout_secs(),
        "idle auto-stop sweeper running"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(every));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            gate.wait().await;
            let stopped = sweep(&state, kletka_types::time::now()).await;
            if !stopped.is_empty() {
                tracing::info!(count = stopped.len(), "idle vms stopped");
            }
        }
    });
}

pub async fn due(
    db: &sqlx::AnyPool,
    now: Timestamp,
) -> Result<Vec<(Uuid, Uuid, String)>, sqlx::Error> {
    let now = crate::db::unix(now);
    crate::db::query(
        "UPDATE vms SET last_active_at = ? WHERE id IN \
         (SELECT vm_id FROM sessions WHERE expires_at > ?)",
    )
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    let rows: Vec<(String, String, String, Option<i64>, i64)> = crate::db::query_as(
        "SELECT id, COALESCE(created_by, namespace_id), name, idle_timeout_secs, \
         COALESCE(last_active_at, created_at) \
         FROM vms WHERE status = 'running'",
    )
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, owner, name, timeout, last_active)| {
            let timeout = effective_timeout_secs(timeout);
            let idle_for = now.saturating_sub(last_active).max(0) as u64;
            (timeout > 0 && idle_for >= timeout)
                .then(|| Some((id.parse().ok()?, owner.parse().ok()?, name)))
                .flatten()
        })
        .collect())
}

pub async fn sweep(state: &AppState, now: Timestamp) -> Vec<String> {
    let due = match due(&state.db, now).await {
        Ok(due) => due,
        Err(err) => {
            tracing::warn!(%err, "idle sweep query failed");
            return Vec::new();
        }
    };
    let stops = due.into_iter().map(|(vm_id, actor, name)| async move {
        tracing::info!(vm = %vm_id, name = %name, "vm idle; stopping");
        let vm = match crate::routes::vms::fetch_vm(&state.db, &vm_id.to_string()).await {
            Ok(Some(vm)) => vm,
            Ok(None) => return None,
            Err(err) => {
                tracing::warn!(vm = %vm_id, err = %err.message, "idle stop lookup failed");
                return None;
            }
        };
        match stop_vm_with(state, vm, &actor, StopCause::Idle).await {
            Ok(_) => Some(name),
            Err(err) => {
                tracing::warn!(vm = %vm_id, err = %err.message, "idle stop failed");
                None
            }
        }
    });
    futures_util::future::join_all(stops)
        .await
        .into_iter()
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_resolve_and_validate() {
        assert_eq!(effective_timeout_secs(Some(0)), 0);
        assert_eq!(effective_timeout_secs(Some(120)), 120);
        assert_eq!(effective_timeout_secs(None), default_timeout_secs());
        assert!(validate_timeout(0).is_ok());
        assert!(validate_timeout(60).is_ok());
        assert!(validate_timeout(MAX_IDLE_TIMEOUT_SECS).is_ok());
        assert!(validate_timeout(59).is_err());
        assert!(validate_timeout(MAX_IDLE_TIMEOUT_SECS + 1).is_err());
    }

    async fn db() -> (sqlx::AnyPool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("kletka-idle-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::connect(&format!("sqlite:{}/t.db?mode=rwc", dir.display()))
            .await
            .unwrap();
        (pool, dir)
    }

    async fn insert(
        db: &sqlx::AnyPool,
        owner: &str,
        name: &str,
        status: &str,
        timeout: Option<i64>,
        last_active: i64,
    ) -> String {
        let id = Uuid::new_v4().to_string();
        crate::db::query(
            "INSERT OR IGNORE INTO namespaces (id, name, created_at) VALUES (?, ?, 0)",
        )
        .bind(owner)
        .bind(format!("ns-{owner}"))
        .execute(db)
        .await
        .unwrap();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, status, idle_timeout_secs, last_active_at, \
             created_at) VALUES (?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(&id)
        .bind(owner)
        .bind(name)
        .bind(status)
        .bind(timeout)
        .bind(last_active)
        .execute(db)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn only_quiet_running_vms_with_a_timeout_are_due() {
        let (db, dir) = db().await;
        let owner = Uuid::new_v4().to_string();
        crate::db::query(
            "INSERT INTO users (id, email, created_at) VALUES (?, 'idle@example.com', 0)",
        )
        .bind(&owner)
        .execute(&db)
        .await
        .unwrap();
        let now = 1_000_000;
        insert(&db, &owner, "quiet", "running", Some(600), now - 601).await;
        insert(&db, &owner, "recent", "running", Some(600), now - 10).await;
        insert(&db, &owner, "never", "running", Some(0), 0).await;
        insert(&db, &owner, "stopped", "stopped", Some(600), 0).await;
        let busy = insert(&db, &owner, "busy", "running", Some(600), 0).await;
        crate::db::query(
            "INSERT INTO sessions (id, vm_id, node_id, kind_json, created_by, expires_at) \
             VALUES (?, ?, 'n', '{}', ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&busy)
        .bind(&owner)
        .bind(now + 30)
        .execute(&db)
        .await
        .unwrap();

        let due: Vec<String> = due(&db, crate::db::timestamp(now))
            .await
            .unwrap()
            .into_iter()
            .map(|(_, _, name)| name)
            .collect();
        assert_eq!(due, vec!["quiet".to_string()]);

        let (last,): (i64,) = crate::db::query_as("SELECT last_active_at FROM vms WHERE id = ?")
            .bind(&busy)
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(last, now, "a live session bumps the vm's activity");
        let _ = std::fs::remove_dir_all(dir);
    }
}
