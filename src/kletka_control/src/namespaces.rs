use kletka_types::{NamespaceInfo, NamespaceMember, NamespaceRole as Role, QuotaInfo};
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::state::{CreationPolicy, NamespaceSettings};

macro_rules! ns_select {
    ($tail:literal) => {
        concat!(
            "SELECT id, name, personal_user_id, quota_max_vms, quota_max_vcpu, quota_max_mem_mib, \
             created_by, created_at FROM namespaces ",
            $tail
        )
    };
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NamespaceRow {
    pub id: String,
    pub name: String,
    pub personal_user_id: Option<String>,
    pub quota_max_vms: Option<i64>,
    pub quota_max_vcpu: Option<i64>,
    pub quota_max_mem_mib: Option<i64>,
    pub created_by: Option<String>,
    pub created_at: i64,
}

impl NamespaceRow {
    pub fn uuid(&self) -> ApiResult<Uuid> {
        self.id
            .parse()
            .map_err(|_| ApiError::internal("corrupt namespace id"))
    }

    pub fn personal(&self) -> bool {
        self.personal_user_id.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct NsAccess {
    pub id: Uuid,
    pub name: String,
    pub personal: bool,
    pub role: Role,
    pub member: bool,
}

impl NsAccess {
    fn new(row: &NamespaceRow, role: Role, member: bool) -> ApiResult<Self> {
        Ok(Self {
            id: row.uuid()?,
            name: row.name.clone(),
            personal: row.personal(),
            role,
            member,
        })
    }

    pub fn require(&self, min: Role, what: &str) -> ApiResult<()> {
        if self.role >= min {
            return Ok(());
        }
        Err(ApiError::forbidden(format!(
            "{what} needs the {min} role in namespace '{}' (you are {})",
            self.name, self.role
        )))
    }
}

pub async fn find(db: &sqlx::AnyPool, key: &str) -> ApiResult<Option<NamespaceRow>> {
    Ok(crate::db::query_as(ns_select!("WHERE id = ? OR name = ?"))
        .bind(key)
        .bind(key)
        .fetch_optional(db)
        .await?)
}

pub async fn role_of(db: &sqlx::AnyPool, ns_id: &str, user_id: &Uuid) -> ApiResult<Option<Role>> {
    let row: Option<(String,)> = crate::db::query_as(
        "SELECT role FROM namespace_members WHERE namespace_id = ? AND user_id = ?",
    )
    .bind(ns_id)
    .bind(user_id.to_string())
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|(role,)| Role::parse(&role)))
}

pub async fn access(
    db: &sqlx::AnyPool,
    user_id: &Uuid,
    platform_admin: bool,
    row: &NamespaceRow,
) -> ApiResult<Option<NsAccess>> {
    match role_of(db, &row.id, user_id).await? {
        Some(role) => NsAccess::new(row, role, true).map(Some),
        None if platform_admin => NsAccess::new(row, Role::Owner, false).map(Some),
        None => Ok(None),
    }
}

pub async fn resolve(
    db: &sqlx::AnyPool,
    user_id: &Uuid,
    email: &str,
    platform_admin: bool,
    selector: Option<&str>,
) -> ApiResult<NsAccess> {
    let row = match selector.map(str::trim).filter(|key| !key.is_empty()) {
        None => ensure_personal(db, user_id, email).await?,
        Some(key) => find(db, key)
            .await?
            .ok_or_else(|| ApiError::not_found(format!("namespace '{key}' not found")))?,
    };
    access(db, user_id, platform_admin, &row)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("namespace '{}' not found", row.name)))
}

pub async fn personal(db: &sqlx::AnyPool, user_id: &Uuid) -> ApiResult<Option<NamespaceRow>> {
    Ok(
        crate::db::query_as(ns_select!("WHERE personal_user_id = ?"))
            .bind(user_id.to_string())
            .fetch_optional(db)
            .await?,
    )
}

pub async fn ensure_personal(
    db: &sqlx::AnyPool,
    user_id: &Uuid,
    email: &str,
) -> ApiResult<NamespaceRow> {
    if let Some(row) = personal(db, user_id).await? {
        return Ok(row);
    }
    let base = personal_base_name(email);
    for attempt in 0..50u32 {
        let name = match attempt {
            0 => base.clone(),
            n => suffixed(&base, &(n + 1).to_string()),
        };
        let mut tx = db.begin().await?;
        let insert = crate::db::query(
            "INSERT INTO namespaces (id, name, personal_user_id, created_by, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(user_id.to_string())
        .bind(&name)
        .bind(user_id.to_string())
        .bind(user_id.to_string())
        .bind(crate::db::now())
        .execute(&mut *tx)
        .await;
        if crate::db::is_unique_violation(&insert) {
            drop(tx);
            if let Some(row) = personal(db, user_id).await? {
                return Ok(row);
            }
            continue;
        }
        insert?;
        add_member_row(&mut tx, &user_id.to_string(), user_id, Role::Owner).await?;
        tx.commit().await?;
        return personal(db, user_id)
            .await?
            .ok_or_else(|| ApiError::internal("personal namespace vanished after insert"));
    }
    Err(ApiError::internal(
        "could not find a free name for the personal namespace",
    ))
}

fn personal_base_name(email: &str) -> String {
    let local = email.split('@').next().unwrap_or_default();
    let mut name = String::new();
    for c in local.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            name.push(c);
        } else if !name.ends_with('-') {
            name.push('-');
        }
    }
    let name: String = name
        .trim_matches('-')
        .chars()
        .take(kletka_types::MAX_NAMESPACE_NAME_LEN - 4)
        .collect();
    let name = name.trim_end_matches('-').to_string();
    if name.is_empty() {
        "user".to_string()
    } else {
        name
    }
}

fn suffixed(base: &str, suffix: &str) -> String {
    let room = kletka_types::MAX_NAMESPACE_NAME_LEN - suffix.len() - 1;
    let head: String = base.chars().take(room).collect();
    format!("{}-{suffix}", head.trim_end_matches('-'))
}

async fn add_member_row(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    ns_id: &str,
    user_id: &Uuid,
    role: Role,
) -> Result<(), sqlx::Error> {
    crate::db::query(
        "INSERT INTO namespace_members (namespace_id, user_id, role, created_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(ns_id)
    .bind(user_id.to_string())
    .bind(role.as_str())
    .bind(crate::db::now())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowance {
    pub limit: Option<usize>,
    pub used: usize,
}

impl Allowance {
    pub fn can_create(&self) -> bool {
        self.limit.is_none_or(|limit| self.used < limit)
    }
}

pub async fn allowance(
    db: &sqlx::AnyPool,
    settings: &NamespaceSettings,
    user_id: &Uuid,
    platform_admin: bool,
) -> ApiResult<Allowance> {
    let (override_limit, used): (Option<i64>, i64) = crate::db::query_as(
        "SELECT (SELECT max_namespaces FROM users WHERE id = ?), \
                (SELECT COUNT(*) FROM namespace_members m \
                   JOIN namespaces n ON n.id = m.namespace_id \
                  WHERE m.user_id = ? AND m.role = 'owner' AND n.personal_user_id IS NULL)",
    )
    .bind(user_id.to_string())
    .bind(user_id.to_string())
    .fetch_one(db)
    .await?;
    let limit = if platform_admin {
        None
    } else if let Some(limit) = override_limit {
        Some(limit.max(0) as usize)
    } else {
        match settings.creation {
            CreationPolicy::Everyone => Some(settings.max_per_user),
            CreationPolicy::PlatformAdmins => Some(0),
        }
    };
    Ok(Allowance {
        limit,
        used: used.max(0) as usize,
    })
}

pub async fn create(
    db: &sqlx::AnyPool,
    settings: &NamespaceSettings,
    user_id: &Uuid,
    platform_admin: bool,
    name: &str,
) -> ApiResult<NamespaceRow> {
    let name = name.trim();
    kletka_types::validate_namespace_name(name).map_err(ApiError::bad_request)?;
    let allowance = allowance(db, settings, user_id, platform_admin).await?;
    if !allowance.can_create() {
        return Err(match allowance.limit {
            Some(0) => ApiError::forbidden(
                "creating namespaces is not enabled for your account; ask a platform admin",
            ),
            Some(limit) => ApiError::quota(format!(
                "you already own {} namespaces (max {limit})",
                allowance.used
            )),
            None => unreachable!("unlimited allowances can always create"),
        });
    }
    let id = Uuid::new_v4();
    let quotas = settings.default_quotas;
    let mut tx = db.begin().await?;
    let insert = crate::db::query(
        "INSERT INTO namespaces (id, name, personal_user_id, quota_max_vms, quota_max_vcpu, \
         quota_max_mem_mib, created_by, created_at) VALUES (?, ?, NULL, ?, ?, ?, ?, ?)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(quotas.max_vms as i64)
    .bind(quotas.max_vcpu as i64)
    .bind(quotas.max_mem_mib as i64)
    .bind(user_id.to_string())
    .bind(crate::db::now())
    .execute(&mut *tx)
    .await;
    if crate::db::is_unique_violation(&insert) {
        return Err(ApiError::conflict(format!(
            "the namespace name '{name}' is taken"
        )));
    }
    insert?;
    add_member_row(&mut tx, &id.to_string(), user_id, Role::Owner).await?;
    tx.commit().await?;
    find(db, &id.to_string())
        .await?
        .ok_or_else(|| ApiError::internal("namespace vanished after insert"))
}

pub async fn rename(db: &sqlx::AnyPool, ns: &NsAccess, new_name: &str) -> ApiResult<()> {
    ns.require(Role::Owner, "renaming the namespace")?;
    let new_name = new_name.trim();
    kletka_types::validate_namespace_name(new_name).map_err(ApiError::bad_request)?;
    let update = crate::db::query("UPDATE namespaces SET name = ? WHERE id = ?")
        .bind(new_name)
        .bind(ns.id.to_string())
        .execute(db)
        .await;
    if crate::db::is_unique_violation(&update) {
        return Err(ApiError::conflict(format!(
            "the namespace name '{new_name}' is taken"
        )));
    }
    update?;
    Ok(())
}

pub async fn delete(db: &sqlx::AnyPool, ns: &NsAccess) -> ApiResult<()> {
    ns.require(Role::Owner, "deleting the namespace")?;
    if ns.personal {
        return Err(ApiError::bad_request(
            "personal namespaces cannot be deleted",
        ));
    }
    let mut tx = db.begin().await?;
    let (vms,): (i64,) = crate::db::query_as("SELECT COUNT(*) FROM vms WHERE namespace_id = ?")
        .bind(ns.id.to_string())
        .fetch_one(&mut *tx)
        .await?;
    if vms > 0 {
        return Err(ApiError::conflict(format!(
            "namespace '{}' still has {vms} VM(s); destroy them first",
            ns.name
        )));
    }
    crate::db::query("DELETE FROM namespace_members WHERE namespace_id = ?")
        .bind(ns.id.to_string())
        .execute(&mut *tx)
        .await?;
    crate::db::query("DELETE FROM namespaces WHERE id = ?")
        .bind(ns.id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn members(db: &sqlx::AnyPool, ns_id: &Uuid) -> ApiResult<Vec<NamespaceMember>> {
    let rows: Vec<(String, String, String, i64)> = crate::db::query_as(
        "SELECT u.id, u.email, m.role, m.created_at FROM namespace_members m \
         JOIN users u ON u.id = m.user_id WHERE m.namespace_id = ? \
         ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.email",
    )
    .bind(ns_id.to_string())
    .fetch_all(db)
    .await?;
    rows.into_iter()
        .map(|(id, email, role, added)| {
            Ok(NamespaceMember {
                user_id: id
                    .parse()
                    .map_err(|_| ApiError::internal("corrupt user id"))?,
                email,
                role: Role::parse(&role)
                    .ok_or_else(|| ApiError::internal(format!("unknown role {role}")))?,
                added_at: crate::db::timestamp(added),
            })
        })
        .collect()
}

async fn owner_count<'e, E>(db: E, ns_id: &Uuid) -> Result<i64, sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Any>,
{
    let (owners,): (i64,) = crate::db::query_as(
        "SELECT COUNT(*) FROM namespace_members WHERE namespace_id = ? AND role = 'owner'",
    )
    .bind(ns_id.to_string())
    .fetch_one(db)
    .await?;
    Ok(owners)
}

pub async fn user_by_key(db: &sqlx::AnyPool, key: &str) -> ApiResult<(Uuid, String)> {
    let key = key.trim();
    let row: Option<(String, String)> =
        crate::db::query_as("SELECT id, email FROM users WHERE id = ? OR lower(email) = lower(?)")
            .bind(key)
            .bind(key)
            .fetch_optional(db)
            .await?;
    match row {
        Some((id, email)) => Ok((
            id.parse()
                .map_err(|_| ApiError::internal("corrupt user id"))?,
            email,
        )),
        None => Err(ApiError::not_found(format!("user '{key}' not found"))),
    }
}

pub async fn add_member(
    db: &sqlx::AnyPool,
    ns: &NsAccess,
    email: &str,
    role: Role,
) -> ApiResult<(Uuid, String)> {
    ns.require(Role::Admin, "adding members")?;
    if role == Role::Owner {
        ns.require(Role::Owner, "adding an owner")?;
    }
    if ns.personal {
        return Err(ApiError::bad_request(
            "personal namespaces cannot be shared; create a namespace for the team instead",
        ));
    }
    let (user_id, email) = user_by_key(db, email).await?;
    let mut tx = db.begin().await?;
    let insert = add_member_row(&mut tx, &ns.id.to_string(), &user_id, role).await;
    if crate::db::is_unique_violation(&insert) {
        return Err(ApiError::conflict(format!(
            "{email} is already a member of '{}'",
            ns.name
        )));
    }
    insert?;
    tx.commit().await?;
    Ok((user_id, email))
}

pub async fn set_role(
    db: &sqlx::AnyPool,
    ns: &NsAccess,
    target: &Uuid,
    role: Role,
) -> ApiResult<Role> {
    ns.require(Role::Admin, "changing member roles")?;
    let current = role_of(db, &ns.id.to_string(), target)
        .await?
        .ok_or_else(|| ApiError::not_found("that user is not a member of this namespace"))?;
    if current == Role::Owner || role == Role::Owner {
        ns.require(Role::Owner, "granting or revoking the owner role")?;
    }
    if current == role {
        return Ok(current);
    }
    let mut tx = db.begin().await?;
    if current == Role::Owner && owner_count(&mut *tx, &ns.id).await? <= 1 {
        return Err(ApiError::conflict(
            "a namespace needs at least one owner; promote someone else first",
        ));
    }
    crate::db::query(
        "UPDATE namespace_members SET role = ? WHERE namespace_id = ? AND user_id = ?",
    )
    .bind(role.as_str())
    .bind(ns.id.to_string())
    .bind(target.to_string())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(current)
}

pub async fn remove_member(
    db: &sqlx::AnyPool,
    ns: &NsAccess,
    actor: &Uuid,
    target: &Uuid,
) -> ApiResult<Role> {
    let current = role_of(db, &ns.id.to_string(), target)
        .await?
        .ok_or_else(|| ApiError::not_found("that user is not a member of this namespace"))?;
    if actor != target {
        ns.require(Role::Admin, "removing members")?;
        if current == Role::Owner {
            ns.require(Role::Owner, "removing an owner")?;
        }
    }
    let mut tx = db.begin().await?;
    if current == Role::Owner && owner_count(&mut *tx, &ns.id).await? <= 1 {
        return Err(ApiError::conflict(
            "a namespace needs at least one owner; promote someone else first",
        ));
    }
    crate::db::query("DELETE FROM namespace_members WHERE namespace_id = ? AND user_id = ?")
        .bind(ns.id.to_string())
        .bind(target.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(current)
}

pub async fn info(
    db: &sqlx::AnyPool,
    row: &NamespaceRow,
    role: Option<Role>,
) -> ApiResult<NamespaceInfo> {
    let id = row.uuid()?;
    let (members,): (i64,) =
        crate::db::query_as("SELECT COUNT(*) FROM namespace_members WHERE namespace_id = ?")
            .bind(&row.id)
            .fetch_one(db)
            .await?;
    Ok(NamespaceInfo {
        id,
        name: row.name.clone(),
        personal: row.personal(),
        role,
        members: members.max(0) as usize,
        quotas: crate::quota::quotas(db, &id).await?,
        usage: crate::quota::usage(db, &id).await?,
        created_at: crate::db::timestamp(row.created_at),
    })
}

pub async fn list_for_user(
    db: &sqlx::AnyPool,
    user_id: &Uuid,
) -> ApiResult<Vec<(NamespaceRow, Role)>> {
    let rows: Vec<NamespaceRow> = crate::db::query_as(ns_select!(
        "WHERE id IN (SELECT namespace_id FROM namespace_members WHERE user_id = ?) \
         ORDER BY CASE WHEN personal_user_id IS NULL THEN 1 ELSE 0 END, name"
    ))
    .bind(user_id.to_string())
    .fetch_all(db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(role) = role_of(db, &row.id, user_id).await? {
            out.push((row, role));
        }
    }
    Ok(out)
}

pub async fn list_all(db: &sqlx::AnyPool) -> ApiResult<Vec<NamespaceRow>> {
    Ok(crate::db::query_as(ns_select!(
        "ORDER BY CASE WHEN personal_user_id IS NULL THEN 0 ELSE 1 END, name"
    ))
    .fetch_all(db)
    .await?)
}

pub async fn set_quota(
    db: &sqlx::AnyPool,
    settings: &NamespaceSettings,
    row: &NamespaceRow,
    limits: Option<QuotaInfo>,
) -> ApiResult<QuotaInfo> {
    let id = row.uuid()?;
    if let Some(user_id) = &row.personal_user_id {
        let user_id: Uuid = user_id
            .parse()
            .map_err(|_| ApiError::internal("corrupt user id"))?;
        let limits = limits.unwrap_or(crate::quota::DEFAULT_QUOTAS);
        return Ok(crate::quota::set_quotas(db, &user_id, &limits).await?);
    }
    let limits = limits.unwrap_or(settings.default_quotas);
    crate::db::query(
        "UPDATE namespaces SET quota_max_vms = ?, quota_max_vcpu = ?, quota_max_mem_mib = ? \
         WHERE id = ?",
    )
    .bind(limits.max_vms as i64)
    .bind(limits.max_vcpu as i64)
    .bind(limits.max_mem_mib as i64)
    .bind(&row.id)
    .execute(db)
    .await?;
    Ok(crate::quota::quotas(db, &id).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_names_derive_from_the_email() {
        assert_eq!(
            personal_base_name("Kai.Averkvist+x@example.com"),
            "kai-averkvist-x"
        );
        assert_eq!(personal_base_name("___@example.com"), "user");
        assert_eq!(personal_base_name("9lives@example.com"), "9lives");
        let long = personal_base_name(&format!("{}@example.com", "a".repeat(80)));
        assert!(long.len() <= kletka_types::MAX_NAMESPACE_NAME_LEN - 4);
        let tagged = suffixed(&"b".repeat(32), "12");
        assert!(
            kletka_types::validate_namespace_name(&tagged).is_ok(),
            "{tagged}"
        );
        assert!(tagged.ends_with("-12"));
    }

    #[test]
    fn allowances_follow_the_limit() {
        let open = Allowance {
            limit: None,
            used: 99,
        };
        let full = Allowance {
            limit: Some(2),
            used: 2,
        };
        let room = Allowance {
            limit: Some(2),
            used: 1,
        };
        assert!(open.can_create() && !full.can_create() && room.can_create());
    }
}
