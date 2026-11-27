// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use crate::{
    catalog::CATALOG_LOCK,
    config::{Settings, flag},
    database::Database,
};

const IDENTITY: &str = include_str!("../migrations/001_identity.sql");
const CATALOG: &str = include_str!("../migrations/002_catalog.sql");
const LEGACY_SSE: &str = include_str!("../migrations/003_legacy_sse.sql");
const MIGRATIONS: [&str; 3] = ["identity", "catalog", "legacy_sse"];

const CREATE_HISTORY: &str = "
    CREATE TABLE IF NOT EXISTS context_forge_schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
    )";
const HISTORY: &str = "SELECT version, name FROM context_forge_schema_migrations ORDER BY version";
const RECORD: &str = "INSERT INTO context_forge_schema_migrations (version, name) VALUES ($1, $2)";
const SQLITE_HAS_HISTORY: &str = "SELECT EXISTS(
    SELECT 1 FROM sqlite_schema
    WHERE type = 'table' AND name = 'context_forge_schema_migrations'
)";
const POSTGRES_HAS_HISTORY: &str =
    "SELECT to_regclass('context_forge_schema_migrations') IS NOT NULL";

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("database schema is not current. Run context-forge-rs migrate before startup.")]
    NotCurrent,
    #[error("database contains an unknown or inconsistent native migration at revision {0}")]
    InconsistentHistory(i32),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub fn skip_migrations() -> Result<bool, Box<dyn Error + Send + Sync>> {
    Ok(flag("MCPGATEWAY_SKIP_MIGRATIONS")?.unwrap_or(false))
}

pub async fn cli(
    mut args: impl Iterator<Item = String>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    match args.next().as_deref() {
        None => {
            let database = Database::from_settings(&Settings::from_env()?)?;
            database.migrate_schema().await?;
            println!(
                "Database ready (native schema revision {})",
                MIGRATIONS.len()
            );
            Ok(())
        }
        Some("-h" | "--help") if args.next().is_none() => {
            println!(
                "Usage: context-forge-rs migrate\n\nUpgrade the database configured by DATABASE_URL."
            );
            Ok(())
        }
        Some(_) => Err("unknown migrate option. See migrate --help.".into()),
    }
}

macro_rules! catalog_audit_columns {
    ($prefix:literal) => {
        [
            ("created_by", concat!($prefix, "created_by VARCHAR(255)")),
            (
                "created_from_ip",
                concat!($prefix, "created_from_ip VARCHAR(45)"),
            ),
            ("created_via", concat!($prefix, "created_via VARCHAR(100)")),
            (
                "created_user_agent",
                concat!($prefix, "created_user_agent TEXT"),
            ),
            ("modified_by", concat!($prefix, "modified_by VARCHAR(255)")),
            (
                "modified_from_ip",
                concat!($prefix, "modified_from_ip VARCHAR(45)"),
            ),
            (
                "modified_via",
                concat!($prefix, "modified_via VARCHAR(100)"),
            ),
            (
                "modified_user_agent",
                concat!($prefix, "modified_user_agent TEXT"),
            ),
            (
                "import_batch_id",
                concat!($prefix, "import_batch_id VARCHAR(36)"),
            ),
            (
                "federation_source",
                concat!($prefix, "federation_source VARCHAR(255)"),
            ),
            (
                "version",
                concat!($prefix, "version INTEGER NOT NULL DEFAULT 1"),
            ),
        ]
    };
}

macro_rules! add_catalog_columns {
    ($transaction:ident, $columns:expr) => {{
        let resources = catalog_audit_columns!("ALTER TABLE resources ADD COLUMN ");
        let prompts = catalog_audit_columns!("ALTER TABLE prompts ADD COLUMN ")
            .into_iter()
            .chain([(
                "display_name",
                "ALTER TABLE prompts ADD COLUMN display_name VARCHAR(255)",
            )]);

        macro_rules! add_columns {
            ($table:expr, $definitions:expr) => {{
                let existing = sqlx::query_scalar::<_, String>($columns)
                    .bind($table)
                    .fetch_all(&mut *$transaction)
                    .await?;
                for (name, statement) in $definitions {
                    if !existing.iter().any(|column| column == name) {
                        sqlx::query(statement).execute(&mut *$transaction).await?;
                    }
                }
            }};
        }
        add_columns!("resources", resources);
        add_columns!("prompts", prompts);
    }};
}

impl Database {
    pub async fn require_current_schema(&self) -> Result<(), MigrationError> {
        if self.applied_schema_versions().await? != MIGRATIONS.len() {
            return Err(MigrationError::NotCurrent);
        }
        Ok(())
    }

    async fn applied_schema_versions(&self) -> Result<usize, MigrationError> {
        macro_rules! history {
            ($pool:ident, $exists:expr) => {
                if sqlx::query_scalar::<_, bool>($exists)
                    .fetch_one($pool)
                    .await?
                {
                    sqlx::query_as::<_, (i32, String)>(HISTORY)
                        .fetch_all($pool)
                        .await?
                } else {
                    Vec::new()
                }
            };
        }
        let rows = match self {
            Self::Sqlite(pool) => history!(pool, SQLITE_HAS_HISTORY),
            Self::Postgres(pool) => history!(pool, POSTGRES_HAS_HISTORY),
        };
        validate_history(&rows)
    }

    pub async fn migrate_schema(&self) -> Result<(), MigrationError> {
        if self.applied_schema_versions().await? == MIGRATIONS.len() {
            return Ok(());
        }
        macro_rules! upgrade {
            ($transaction:ident, $usage:expr, $accounts:expr, $columns:expr) => {{
                sqlx::query(CREATE_HISTORY)
                    .execute(&mut *$transaction)
                    .await?;
                let rows = sqlx::query_as::<_, (i32, String)>(HISTORY)
                    .fetch_all(&mut *$transaction)
                    .await?;
                let applied = validate_history(&rows)?;
                for (index, name) in MIGRATIONS.iter().enumerate().skip(applied) {
                    match index {
                        0 => {
                            for statement in [IDENTITY, $usage, $accounts] {
                                sqlx::raw_sql(statement).execute(&mut *$transaction).await?;
                            }
                        }
                        1 => {
                            sqlx::raw_sql(CATALOG).execute(&mut *$transaction).await?;
                            add_catalog_columns!($transaction, $columns);
                        }
                        2 => {
                            sqlx::raw_sql(LEGACY_SSE)
                                .execute(&mut *$transaction)
                                .await?;
                        }
                        _ => unreachable!("unknown migration implementation"),
                    }
                    sqlx::query(RECORD)
                        .bind((index + 1) as i32)
                        .bind(*name)
                        .execute(&mut *$transaction)
                        .await?;
                }
                $transaction.commit().await?;
            }};
        }

        match self {
            Self::Sqlite(pool) => {
                let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
                upgrade!(
                    transaction,
                    crate::tokens::SQLITE_USAGE_MIGRATION,
                    crate::local_auth::SQLITE_MIGRATION,
                    "SELECT name FROM pragma_table_info($1)"
                );
            }
            Self::Postgres(pool) => {
                let mut transaction = pool.begin().await?;
                for lock in [
                    "SELECT pg_advisory_xact_lock(1128682066)",
                    CATALOG_LOCK,
                    "SELECT pg_advisory_xact_lock(1128682068)",
                ] {
                    sqlx::query(lock).execute(&mut *transaction).await?;
                }
                upgrade!(
                    transaction,
                    crate::tokens::POSTGRES_USAGE_MIGRATION,
                    crate::local_auth::POSTGRES_MIGRATION,
                    "SELECT CAST(column_name AS TEXT) FROM information_schema.columns
                     WHERE table_schema = current_schema() AND table_name = $1"
                );
            }
        }
        Ok(())
    }
}

fn validate_history(rows: &[(i32, String)]) -> Result<usize, MigrationError> {
    for (index, (version, name)) in rows.iter().enumerate() {
        if *version != (index + 1) as i32 || MIGRATIONS.get(index).copied() != Some(name.as_str()) {
            return Err(MigrationError::InconsistentHistory(*version));
        }
    }
    Ok(rows.len())
}

#[cfg(test)]
mod tests {
    use sqlx::{SqlitePool, sqlite::SqlitePoolOptions};

    use super::*;

    async fn database() -> (Database, SqlitePool) {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        (Database::Sqlite(pool.clone()), pool)
    }

    #[tokio::test]
    async fn adopts_existing_tables_and_preserves_upstream_history() {
        let (database, pool) = database().await;
        sqlx::raw_sql(IDENTITY).execute(&pool).await.unwrap();
        sqlx::raw_sql(
            "CREATE TABLE alembic_version (version_num TEXT PRIMARY KEY);
                      INSERT INTO alembic_version VALUES ('f2c3d4e5a6b7');
                      INSERT INTO email_users (id, email) VALUES ('owner', 'owner@example.test');",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            database.require_current_schema().await,
            Err(MigrationError::NotCurrent)
        ));

        database.migrate_schema().await.unwrap();
        let history: Vec<(i32, String, String)> = sqlx::query_as(
            "SELECT version, name, CAST(applied_at AS TEXT)
             FROM context_forge_schema_migrations ORDER BY version",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(history.len(), MIGRATIONS.len());
        database.require_current_schema().await.unwrap();
        database.migrate_schema().await.unwrap();
        assert_eq!(
            sqlx::query_as::<_, (i32, String, String)>(
                "SELECT version, name, CAST(applied_at AS TEXT)
             FROM context_forge_schema_migrations ORDER BY version",
            )
            .fetch_all(&pool)
            .await
            .unwrap(),
            history
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT version_num FROM alembic_version")
                .fetch_one(&pool)
                .await
                .unwrap(),
            "f2c3d4e5a6b7"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT email FROM email_users")
                .fetch_one(&pool)
                .await
                .unwrap(),
            "owner@example.test"
        );
    }

    #[tokio::test]
    async fn rolls_back_the_schema_and_ledger_if_an_upgrade_fails() {
        let (database, pool) = database().await;
        sqlx::query("CREATE TABLE gateways (id TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            database.migrate_schema().await,
            Err(MigrationError::Database(_))
        ));
        assert!(matches!(
            database.require_current_schema().await,
            Err(MigrationError::NotCurrent)
        ));
        let tables =
            sqlx::query_scalar::<_, String>("SELECT name FROM sqlite_schema WHERE type = 'table'")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(tables, ["gateways"]);
    }

    #[tokio::test]
    async fn rejects_history_from_a_newer_binary() {
        let (database, pool) = database().await;
        database.migrate_schema().await.unwrap();
        sqlx::query(RECORD)
            .bind(4_i32)
            .bind("future")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            database.require_current_schema().await,
            Err(MigrationError::InconsistentHistory(4))
        ));
        assert!(matches!(
            database.migrate_schema().await,
            Err(MigrationError::InconsistentHistory(4))
        ));
    }
}
