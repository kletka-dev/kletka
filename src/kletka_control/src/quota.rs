use kletka_types::{AccountInfo, QuotaInfo as Quotas, UsageInfo as Usage};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};

pub const DEFAULT_QUOTAS: Quotas = Quotas {
    max_vms: 5,
    max_vcpu: 8,
    max_mem_mib: 8192,
};

pub async fn account(
    db: &sqlx::AnyPool,
    user: &crate::auth::UserContext,
) -> Result<AccountInfo, sqlx::Error> {
    Ok(AccountInfo {
        user_id: user.user_id,
        email: user.email.clone(),
        quotas: quotas(db, &user.ns.id).await?,
        usage: usage(db, &user.ns.id).await?,
        namespace: Some(user.ns.name.clone()),
        platform_admin: user.platform_admin,
    })
}

pub async fn usage<'e, E>(db: E, namespace: &Uuid) -> Result<Usage, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let row: (i64, Option<i64>, Option<i64>) = crate::db::query_as(
        "SELECT COUNT(*),
                CAST(COALESCE(SUM(CASE WHEN status IN ('pending','running','rebasing','cloning') THEN vcpu ELSE 0 END), 0) AS BIGINT),
                CAST(COALESCE(SUM(CASE WHEN status IN ('pending','running','rebasing','cloning') THEN memory_mib ELSE 0 END), 0) AS BIGINT)
         FROM vms WHERE namespace_id = ?",
    )
    .bind(namespace.to_string())
    .fetch_one(db)
    .await?;
    Ok(Usage {
        vms: row.0 as usize,
        vcpu: row.1.unwrap_or(0) as usize,
        mem_mib: row.2.unwrap_or(0) as usize,
    })
}

pub async fn quotas<'e, E>(db: E, namespace: &Uuid) -> Result<Quotas, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let row: Option<(Option<i64>, Option<i64>, Option<i64>)> = crate::db::query_as(
        "SELECT COALESCE(n.quota_max_vms, u.quota_max_vms),
                COALESCE(n.quota_max_vcpu, u.quota_max_vcpu),
                COALESCE(n.quota_max_mem_mib, u.quota_max_mem_mib)
         FROM namespaces n LEFT JOIN users u ON u.id = n.personal_user_id WHERE n.id = ?",
    )
    .bind(namespace.to_string())
    .fetch_optional(db)
    .await?;
    let (vms, vcpu, mem) = row.unwrap_or((None, None, None));
    Ok(Quotas {
        max_vms: vms.map_or(DEFAULT_QUOTAS.max_vms, |v| v.max(0) as usize),
        max_vcpu: vcpu.map_or(DEFAULT_QUOTAS.max_vcpu, |v| v.max(0) as usize),
        max_mem_mib: mem.map_or(DEFAULT_QUOTAS.max_mem_mib, |v| v.max(0) as usize),
    })
}

pub async fn check_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    namespace: &Uuid,
    vcpu: usize,
    mem_mib: usize,
    is_new_row: bool,
) -> ApiResult<()> {
    check_in(tx, namespace, vcpu, mem_mib, is_new_row).await
}

pub async fn claim_start(
    db: &sqlx::AnyPool,
    namespace: &Uuid,
    vm_id: &Uuid,
    vcpu: usize,
    mem_mib: usize,
) -> ApiResult<()> {
    let mut tx = db.begin().await?;
    check_in(&mut tx, namespace, vcpu, mem_mib, false).await?;
    let updated = crate::db::query(
        "UPDATE vms SET status = 'pending' WHERE id = ? AND status IN ('stopped', 'failed')",
    )
    .bind(vm_id.to_string())
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::conflict(
            "vm lifecycle changed while starting; try again",
        ));
    }
    tx.commit().await?;
    Ok(())
}

async fn check_in(
    conn: &mut sqlx::AnyConnection,
    namespace: &Uuid,
    vcpu: usize,
    mem_mib: usize,
    is_new_row: bool,
) -> ApiResult<()> {
    let limits = quotas(&mut *conn, namespace).await?;
    let used = usage(&mut *conn, namespace).await?;
    let (max_vms, max_vcpu, max_mem_mib) = (limits.max_vms, limits.max_vcpu, limits.max_mem_mib);
    let (used_vms, used_vcpu, used_mem) = (used.vms, used.vcpu, used.mem_mib);
    let vms = used_vms + usize::from(is_new_row);
    if vms > max_vms {
        return Err(ApiError::quota(format!(
            "too many VMs ({vms} > max {max_vms})"
        )));
    }
    if used_vcpu + vcpu > max_vcpu {
        return Err(ApiError::quota(format!(
            "not enough vCPU quota ({used_vcpu} + {vcpu} > max {max_vcpu})"
        )));
    }
    if used_mem + mem_mib > max_mem_mib {
        return Err(ApiError::quota(format!(
            "not enough memory quota ({used_mem} + {mem_mib} > max {max_mem_mib} MiB)"
        )));
    }
    Ok(())
}

pub async fn set_quotas(
    db: &sqlx::AnyPool,
    user_id: &Uuid,
    limits: &Quotas,
) -> Result<Quotas, sqlx::Error> {
    crate::db::query(
        "UPDATE users SET quota_max_vms = ?, quota_max_vcpu = ?, quota_max_mem_mib = ? WHERE id = ?",
    )
    .bind(limits.max_vms as i64)
    .bind(limits.max_vcpu as i64)
    .bind(limits.max_mem_mib as i64)
    .bind(user_id.to_string())
    .execute(db)
    .await?;
    let row: Option<(i64, i64, i64)> = crate::db::query_as(
        "SELECT quota_max_vms, quota_max_vcpu, quota_max_mem_mib FROM users WHERE id = ?",
    )
    .bind(user_id.to_string())
    .fetch_optional(db)
    .await?;
    Ok(row.map_or(DEFAULT_QUOTAS, |(vms, vcpu, mem)| Quotas {
        max_vms: vms.max(0) as usize,
        max_vcpu: vcpu.max(0) as usize,
        max_mem_mib: mem.max(0) as usize,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> (sqlx::AnyPool, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("kletka-quota-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = crate::db::connect(&format!("sqlite:{}/t.db?mode=rwc", dir.display()))
            .await
            .unwrap();
        (pool, dir)
    }

    async fn owner(db: &sqlx::AnyPool, max_vcpu: i64, max_mem: i64) -> Uuid {
        let id = Uuid::new_v4();
        crate::db::query(
            "INSERT INTO users (id, email, quota_max_vms, quota_max_vcpu, quota_max_mem_mib, \
             created_at) VALUES (?, ?, 20, ?, ?, 0)",
        )
        .bind(id.to_string())
        .bind(format!("quota-{}@example.com", id.simple()))
        .bind(max_vcpu)
        .bind(max_mem)
        .execute(db)
        .await
        .unwrap();
        crate::db::query(
            "INSERT INTO namespaces (id, name, personal_user_id, created_at) VALUES (?, ?, ?, 0)",
        )
        .bind(id.to_string())
        .bind(format!("q-{}", id.simple()))
        .bind(id.to_string())
        .execute(db)
        .await
        .unwrap();
        id
    }

    async fn vm(db: &sqlx::AnyPool, owner: &Uuid, name: &str, status: &str) -> Uuid {
        let id = Uuid::new_v4();
        crate::db::query(
            "INSERT INTO vms (id, namespace_id, name, image, vcpu, memory_mib, disk_mib, nat, \
             status, created_at, last_active_at) \
             VALUES (?, ?, ?, 'default', 2, 1024, 0, 1, ?, 0, 0)",
        )
        .bind(id.to_string())
        .bind(owner.to_string())
        .bind(name)
        .bind(status)
        .execute(db)
        .await
        .unwrap();
        id
    }

    async fn status(db: &sqlx::AnyPool, id: &Uuid) -> String {
        let (status,): (String,) = crate::db::query_as("SELECT status FROM vms WHERE id = ?")
            .bind(id.to_string())
            .fetch_one(db)
            .await
            .unwrap();
        status
    }

    #[tokio::test]
    async fn start_claim_reserves_quota_against_a_concurrent_start() {
        let (db, dir) = db().await;
        let owner = owner(&db, 3, 4096).await;
        let a = vm(&db, &owner, "a", "stopped").await;
        let b = vm(&db, &owner, "b", "stopped").await;

        claim_start(&db, &owner, &a, 2, 1024).await.unwrap();
        assert_eq!(status(&db, &a).await, "pending");

        let err = claim_start(&db, &owner, &b, 2, 1024).await.unwrap_err();
        assert_eq!(
            err.status,
            axum::http::StatusCode::PAYMENT_REQUIRED,
            "{err}"
        );
        assert_eq!(status(&db, &b).await, "stopped");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn second_start_of_the_same_vm_fails_without_changing_anything() {
        let (db, dir) = db().await;
        let owner = owner(&db, 8, 8192).await;
        let a = vm(&db, &owner, "a", "stopped").await;

        claim_start(&db, &owner, &a, 2, 1024).await.unwrap();
        let err = claim_start(&db, &owner, &a, 2, 1024).await.unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::CONFLICT, "{err}");
        assert_eq!(status(&db, &a).await, "pending");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn claim_repairs_a_failed_vm_and_refuses_running_ones() {
        let (db, dir) = db().await;
        let owner = owner(&db, 8, 8192).await;
        let failed = vm(&db, &owner, "failed", "failed").await;
        let running = vm(&db, &owner, "running", "running").await;

        claim_start(&db, &owner, &failed, 2, 1024).await.unwrap();
        assert_eq!(status(&db, &failed).await, "pending");

        let err = claim_start(&db, &owner, &running, 2, 1024)
            .await
            .unwrap_err();
        assert_eq!(err.status, axum::http::StatusCode::CONFLICT, "{err}");
        assert_eq!(status(&db, &running).await, "running");

        let _ = std::fs::remove_dir_all(dir);
    }
}
