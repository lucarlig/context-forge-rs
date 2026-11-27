// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

mod response_filters;

use crate::{
    catalog::{CATALOG_LOCK, slugify_with_separator},
    config::{Settings, flag},
    database::Database,
};

const IDENTITY: &str = include_str!("../migrations/001_identity.sql");
const CATALOG: &str = include_str!("../migrations/002_catalog.sql");
const LEGACY_SSE: &str = include_str!("../migrations/003_legacy_sse.sql");
const GRPC: &str = include_str!("../migrations/004_grpc.sql");
const A2A: &str = include_str!("../migrations/005_a2a.sql");
const A2A_TASKS: &str = include_str!("../migrations/006_a2a_tasks.sql");
const A2A_PUSH_CONFIGS: &str = include_str!("../migrations/007_a2a_push_configs.sql");
const A2A_CARDS: &str = include_str!("../migrations/008_a2a_cards.sql");
const MIGRATIONS: [&str; 10] = [
    "identity",
    "catalog",
    "legacy_sse",
    "historical_catalog",
    "cel_response_filters",
    "grpc_services",
    "a2a_agents",
    "a2a_tasks",
    "a2a_push_configs",
    "a2a_cards",
];

type ColumnDefinition = (&'static str, &'static str);

const CATALOG_AUDIT_COLUMNS: [ColumnDefinition; 11] = [
    ("created_by", "VARCHAR(255)"),
    ("created_from_ip", "VARCHAR(45)"),
    ("created_via", "VARCHAR(100)"),
    ("created_user_agent", "TEXT"),
    ("modified_by", "VARCHAR(255)"),
    ("modified_from_ip", "VARCHAR(45)"),
    ("modified_via", "VARCHAR(100)"),
    ("modified_user_agent", "TEXT"),
    ("import_batch_id", "VARCHAR(36)"),
    ("federation_source", "VARCHAR(255)"),
    ("version", "INTEGER NOT NULL DEFAULT 1"),
];

const HISTORICAL_COLUMNS: &[(&str, &[ColumnDefinition])] = &[
    ("sso_providers", &[("ca_certificate", "TEXT")]),
    ("oauth_states", &[("browser_binding_hash", "VARCHAR(64)")]),
    (
        "gateways",
        &[
            ("upstream_instructions", "TEXT"),
            ("tool_validation_policy", "TEXT"),
            ("sigv4_config", "JSON"),
        ],
    ),
    (
        "tools",
        &[
            ("tool_validation_policy", "TEXT"),
            ("validation_refusal", "TEXT"),
            ("sigv4_config", "JSON"),
        ],
    ),
    (
        "servers",
        &[
            ("instructions", "TEXT"),
            ("oauth_config_approved", "BOOLEAN NOT NULL DEFAULT FALSE"),
            ("oauth_config_generation", "VARCHAR(32)"),
        ],
    ),
];

const RESOURCE_NAME_COLUMNS: [ColumnDefinition; 2] =
    [("original_name", "TEXT"), ("custom_name_slug", "TEXT")];

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

macro_rules! add_columns {
    ($transaction:ident, $columns:expr, $table:expr, $definitions:expr) => {{
        let table = $table;
        let existing = sqlx::query_scalar::<_, String>($columns)
            .bind(table)
            .fetch_all(&mut *$transaction)
            .await?;
        let mut added = false;
        for (name, data_type) in $definitions {
            if !existing.iter().any(|column| column == name) {
                // The revision supplies every identifier and type as static SQL.
                let statement = sqlx::AssertSqlSafe(format!(
                    "ALTER TABLE {table} ADD COLUMN {name} {data_type}"
                ));
                sqlx::query(statement).execute(&mut *$transaction).await?;
                added = true;
            }
        }
        added
    }};
}

macro_rules! backfill_resource_names {
    ($transaction:ident, $separator:expr) => {{
        loop {
            let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
                "SELECT r.id, r.name, g.name FROM resources r
                 LEFT JOIN gateways g ON r.gateway_id = g.id
                 WHERE r.original_name IS NULL ORDER BY r.id LIMIT 500",
            )
            .fetch_all(&mut *$transaction)
            .await?;
            if rows.is_empty() {
                break;
            }
            for (id, original, gateway) in rows {
                let slug = slugify_with_separator(&original, $separator);
                let name = resource_name(&original, &slug, gateway.as_deref(), $separator);
                sqlx::query(
                    "UPDATE resources SET original_name = $1, custom_name_slug = $2, name = $3
                     WHERE id = $4 AND original_name IS NULL",
                )
                .bind(original)
                .bind(slug)
                .bind(name)
                .bind(id)
                .execute(&mut *$transaction)
                .await?;
            }
        }
    }};
}

fn resource_name(original: &str, slug: &str, gateway: Option<&str>, separator: &str) -> String {
    let gateway = gateway.map_or_else(String::new, |name| slugify_with_separator(name, separator));
    if gateway.is_empty() {
        return original.to_owned();
    }
    let mut name = gateway;
    if !slug.is_empty() {
        name.push_str(separator);
        name.push_str(slug);
    }
    name.truncate(255);
    name
}

fn resource_name_separator() -> &'static str {
    match std::env::var("GATEWAY_TOOL_NAME_SEPARATOR").as_deref() {
        Ok("--") => "--",
        Ok("_") => "_",
        Ok(".") => ".",
        _ => "-",
    }
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
                            add_columns!(
                                $transaction,
                                $columns,
                                "resources",
                                CATALOG_AUDIT_COLUMNS
                            );
                            add_columns!(
                                $transaction,
                                $columns,
                                "prompts",
                                CATALOG_AUDIT_COLUMNS
                                    .into_iter()
                                    .chain([("display_name", "VARCHAR(255)")])
                            );
                        }
                        2 => {
                            sqlx::raw_sql(LEGACY_SSE)
                                .execute(&mut *$transaction)
                                .await?;
                        }
                        3 => {
                            for &(table, definitions) in HISTORICAL_COLUMNS {
                                add_columns!(
                                    $transaction,
                                    $columns,
                                    table,
                                    definitions.iter().copied()
                                );
                            }
                            if add_columns!(
                                $transaction,
                                $columns,
                                "resources",
                                RESOURCE_NAME_COLUMNS
                            ) {
                                let separator = resource_name_separator();
                                backfill_resource_names!($transaction, separator);
                            }
                        }
                        4 => response_filters::translate_filters!($transaction),
                        5 => {
                            sqlx::raw_sql(GRPC).execute(&mut *$transaction).await?;
                        }
                        6 => {
                            sqlx::raw_sql(A2A).execute(&mut *$transaction).await?;
                        }
                        7 => {
                            sqlx::raw_sql(A2A_TASKS).execute(&mut *$transaction).await?;
                        }
                        8 => {
                            sqlx::raw_sql(A2A_PUSH_CONFIGS)
                                .execute(&mut *$transaction)
                                .await?;
                        }
                        9 => {
                            sqlx::raw_sql(A2A_CARDS).execute(&mut *$transaction).await?;
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
    async fn upgrades_historical_resources_and_oauth_configuration() {
        let (database, pool) = database().await;
        database.migrate_schema().await.unwrap();
        sqlx::raw_sql(
            "DELETE FROM context_forge_schema_migrations WHERE version > 3;
             ALTER TABLE resources DROP COLUMN original_name;
             ALTER TABLE resources DROP COLUMN custom_name_slug;
             ALTER TABLE servers DROP COLUMN oauth_config_approved;
             ALTER TABLE servers DROP COLUMN oauth_config_generation;
             ALTER TABLE oauth_states DROP COLUMN browser_binding_hash;
             INSERT INTO gateways (id, name, slug, url, transport)
             VALUES ('peer', 'Research', 'old-slug', 'https://peer.example.test/mcp', 'STREAMABLEHTTP');
             INSERT INTO resources (id, uri, name, gateway_id) VALUES
                 ('local', 'fixture://local', 'Local Document', NULL),
                 ('remote', 'fixture://remote', 'Café a''b''c', 'peer');
             INSERT INTO servers (id, name, oauth_enabled, oauth_config)
             VALUES ('server', 'Existing server', TRUE, '{\"provider\":\"idp\"}');
             INSERT INTO oauth_states (id, gateway_id, state, expires_at)
             VALUES ('state', 'peer', 'fixture-state', '2027-01-01 00:00:00');",
        )
        .execute(&pool)
        .await
        .unwrap();

        database.migrate_schema().await.unwrap();
        database.require_current_schema().await.unwrap();

        let names: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT name, original_name, custom_name_slug FROM resources ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let separator = resource_name_separator();
        assert_eq!(
            names[0],
            (
                "Local Document".into(),
                "Local Document".into(),
                format!("local{separator}document")
            )
        );
        assert_eq!(
            names[1],
            (
                format!("research{separator}cafe{separator}ab{separator}c"),
                "Café a'b'c".into(),
                format!("cafe{separator}ab{separator}c")
            )
        );
        let server: (bool, bool, Option<String>, String) = sqlx::query_as(
            "SELECT oauth_enabled, oauth_config_approved, oauth_config_generation, oauth_config
             FROM servers WHERE id = 'server'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(server, (true, false, None, "{\"provider\":\"idp\"}".into()));
        let binding: Option<String> =
            sqlx::query_scalar("SELECT browser_binding_hash FROM oauth_states WHERE id = 'state'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(binding, None);
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
        let future = MIGRATIONS.len() as i32 + 1;
        sqlx::query(RECORD)
            .bind(future)
            .bind("future")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            database.require_current_schema().await,
            Err(MigrationError::InconsistentHistory(version)) if version == future
        ));
        assert!(matches!(
            database.migrate_schema().await,
            Err(MigrationError::InconsistentHistory(version)) if version == future
        ));
    }
}
