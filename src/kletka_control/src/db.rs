use std::borrow::Cow;
use std::sync::atomic::{AtomicU8, Ordering};

use kletka_types::time::Timestamp;
use sqlx::any::{AnyArguments, AnyPoolOptions, AnyRow};
use sqlx::{Any, AnyPool, AssertSqlSafe};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
    Sqlite,
    Postgres,
}

impl DbKind {
    fn from_url(url: &str) -> Self {
        let lower = url.trim().to_ascii_lowercase();
        if lower.starts_with("postgres://") || lower.starts_with("postgresql://") {
            Self::Postgres
        } else {
            Self::Sqlite
        }
    }
}

static KIND: AtomicU8 = AtomicU8::new(0);

pub fn kind() -> DbKind {
    match KIND.load(Ordering::Relaxed) {
        1 => DbKind::Postgres,
        _ => DbKind::Sqlite,
    }
}

fn set_kind(kind: DbKind) {
    KIND.store(
        match kind {
            DbKind::Sqlite => 0,
            DbKind::Postgres => 1,
        },
        Ordering::Relaxed,
    );
}

pub fn unix(ts: Timestamp) -> i64 {
    ts.as_second()
}

pub fn now() -> i64 {
    unix(kletka_types::time::now())
}

pub fn timestamp(secs: i64) -> Timestamp {
    kletka_types::time::from_unix(secs)
}

pub fn is_unique_violation<E>(result: &Result<E, sqlx::Error>) -> bool {
    result.as_ref().err().is_some_and(
        |err| matches!(err, sqlx::Error::Database(db_err) if db_err.is_unique_violation()),
    )
}

pub type Query = sqlx::query::Query<'static, Any, AnyArguments>;
pub type QueryAs<T> = sqlx::query::QueryAs<'static, Any, T, AnyArguments>;
pub type QueryScalar<T> = sqlx::query::QueryScalar<'static, Any, T, AnyArguments>;

pub fn query(sql: &'static str) -> Query {
    sqlx::query(AssertSqlSafe(translate(sql)))
}

pub fn query_as<T>(sql: &'static str) -> QueryAs<T>
where
    T: for<'r> sqlx::FromRow<'r, AnyRow>,
{
    sqlx::query_as(AssertSqlSafe(translate(sql)))
}

pub fn query_scalar<T>(sql: &'static str) -> QueryScalar<T>
where
    (T,): for<'r> sqlx::FromRow<'r, AnyRow>,
{
    sqlx::query_scalar(AssertSqlSafe(translate(sql)))
}

pub fn translate(sql: &'static str) -> Cow<'static, str> {
    translate_with(kind(), sql)
}

pub fn translate_with(kind: DbKind, sql: &'static str) -> Cow<'static, str> {
    if kind != DbKind::Postgres {
        return Cow::Borrowed(sql);
    }
    let mut out = String::with_capacity(sql.len() + 8);
    let mut parameter = 1usize;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '?' => {
                out.push('$');
                let digits = parameter.to_string();
                out.push_str(&digits);
                parameter += 1;
            }
            '\'' => {
                out.push(c);
                while let Some(inner) = chars.next() {
                    out.push(inner);
                    if inner == '\'' {
                        if chars.peek() == Some(&'\'') {
                            out.push('\'');
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
            }
            _ => out.push(c),
        }
    }
    Cow::Owned(out)
}

pub async fn connect(database_url: &str) -> Result<AnyPool, sqlx::Error> {
    sqlx::any::install_default_drivers();
    let kind = DbKind::from_url(database_url);
    set_kind(kind);
    let mut url = Cow::Borrowed(database_url);
    if kind == DbKind::Sqlite && !url.contains("mode=") {
        url = match url.contains('?') {
            true => format!("{url}&mode=rwc"),
            false => format!("{url}?mode=rwc"),
        }
        .into();
    }
    let mut options = AnyPoolOptions::new().max_connections(8);
    if kind == DbKind::Sqlite {
        options = options.after_connect(|connection, _| {
            Box::pin(async move {
                for pragma in [
                    "PRAGMA journal_mode = WAL",
                    "PRAGMA synchronous = NORMAL",
                    "PRAGMA busy_timeout = 5000",
                ] {
                    sqlx::raw_sql(pragma).execute(&mut *connection).await?;
                }
                Ok(())
            })
        });
    }
    let pool = options.connect(url.as_ref()).await?;
    let migrator = match kind {
        DbKind::Sqlite => sqlx::migrate!("migrations/sqlite"),
        DbKind::Postgres => sqlx::migrate!("migrations/postgres"),
    };
    migrator.run(&pool).await?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn placeholders_translate_to_postgres_dollar_syntax() {
        assert_eq!(
            translate_with(
                DbKind::Postgres,
                "SELECT id FROM vms WHERE owner_id = ? AND status = ?"
            ),
            "SELECT id FROM vms WHERE owner_id = $1 AND status = $2",
        );
        assert_eq!(
            translate_with(
                DbKind::Postgres,
                "UPDATE vms SET status = 'failed' WHERE id = ?"
            ),
            "UPDATE vms SET status = 'failed' WHERE id = $1",
        );
        assert_eq!(
            translate_with(DbKind::Sqlite, "SELECT id FROM vms WHERE owner_id = ?"),
            "SELECT id FROM vms WHERE owner_id = ?",
        );
    }

    #[test]
    fn question_marks_inside_string_literals_stay_literal() {
        let sql: &'static str = "SELECT COUNT(*) FROM t WHERE name = 'a?b' AND id > ?";
        let translated = translate_with(DbKind::Postgres, sql).into_owned();
        assert!(translated.ends_with("id > $1"), "{translated}");
        assert!(translated.contains("'a?b'"), "{translated}");
        let doubled: &'static str = "SELECT 'it''s ? here' || ?";
        let translated = translate_with(DbKind::Postgres, doubled).into_owned();
        assert_eq!(translated, "SELECT 'it''s ? here' || $1");
    }

    #[test]
    fn urls_classify_and_audit() {
        let start = Instant::now();
        assert_eq!(DbKind::from_url("postgres://a@b/c"), DbKind::Postgres);
        assert_eq!(DbKind::from_url("postgresql://a@b/c"), DbKind::Postgres);
        assert_eq!(DbKind::from_url("sqlite:/x/y.db"), DbKind::Sqlite);
        assert!(start.elapsed().as_millis() < 1_000);
    }
}
