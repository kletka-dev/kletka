use std::sync::Mutex;
use std::time::Duration;

use sqlx::AnyPool;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::db::{self, DbKind};

const LOCK_KEY: i64 = i64::from_be_bytes(*b"kletkaHA");
const RETRY: Duration = Duration::from_secs(5);
const HEARTBEAT: Duration = Duration::from_secs(10);

pub struct LeaderGate {
    held: watch::Receiver<bool>,
    _sender: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl LeaderGate {
    pub fn start(pool: AnyPool) -> std::sync::Arc<Self> {
        let sqlite = matches!(db::kind(), DbKind::Sqlite);
        let (tx, held) = watch::channel(sqlite);
        let task = match db::kind() {
            DbKind::Sqlite => None,
            DbKind::Postgres => Some(tokio::spawn(postgres_loop(pool, tx.clone()))),
        };
        std::sync::Arc::new(Self {
            held,
            _sender: tx,
            task: Mutex::new(task),
        })
    }

    pub fn is_leader(&self) -> bool {
        *self.held.borrow()
    }

    pub async fn wait(&self) {
        let mut rx = self.held.clone();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    pub async fn lost(&self) {
        let mut rx = self.held.clone();
        while *rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for LeaderGate {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

async fn postgres_loop(pool: AnyPool, tx: watch::Sender<bool>) {
    loop {
        let mut conn = match pool.acquire().await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(%err, "leader election: acquire failed; retrying");
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        let elected: bool = match db::query_scalar("SELECT pg_try_advisory_lock(?)")
            .bind(LOCK_KEY)
            .fetch_one(&mut *conn)
            .await
        {
            Ok(elected) => elected,
            Err(err) => {
                tracing::warn!(%err, "leader election: lock query failed; retrying");
                tokio::time::sleep(RETRY).await;
                continue;
            }
        };
        if !elected {
            tokio::time::sleep(RETRY).await;
            continue;
        }
        let _ = tx.send(true);
        tracing::info!("leadership acquired; this replica runs the background workers");
        while db::query_scalar::<i64>("SELECT 1")
            .fetch_one(&mut *conn)
            .await
            .is_ok()
        {
            tokio::time::sleep(HEARTBEAT).await;
        }
        let _ = tx.send(false);
        tracing::info!("leadership lost (database connection error); standing down");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_gate_leads_forever_and_never_loses() {
        let dir = std::env::temp_dir().join(format!("kletka-leader-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = db::connect(&format!("sqlite:{}/t.db", dir.display()))
            .await
            .unwrap();
        let gate = LeaderGate::start(pool);
        assert!(gate.is_leader());
        gate.wait().await;
        let lost = tokio::time::timeout(Duration::from_millis(100), gate.lost()).await;
        assert!(lost.is_err(), "sqlite never stands down");
        let _ = std::fs::remove_dir_all(dir);
    }
}
