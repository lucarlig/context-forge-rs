// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, str::FromStr};

use sqlx::{
    PgPool, SqlitePool,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::config::Settings;

#[derive(Clone)]
pub enum Database {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

impl Database {
    pub fn from_settings(settings: &Settings) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::connect(settings, None)
    }

    pub(crate) fn for_credential_rotation(
        settings: &Settings,
        dry_run: bool,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        Self::connect(settings, Some(dry_run))
    }

    fn connect(
        settings: &Settings,
        maintenance: Option<bool>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let url = settings.database_url.as_str();
        if url.starts_with("sqlite:") {
            let memory = matches!(url, "sqlite://" | "sqlite:///:memory:" | "sqlite::memory:");
            let options = if memory {
                SqliteConnectOptions::from_str("sqlite::memory:")?
            } else {
                let path = url
                    .strip_prefix("sqlite:///")
                    .filter(|path| !path.is_empty())
                    .ok_or("invalid SQLite DATABASE_URL")?;
                let connect = SqliteConnectOptions::new().filename(path);
                match maintenance {
                    Some(read_only) => connect.read_only(read_only),
                    None => connect
                        .create_if_missing(true)
                        .journal_mode(SqliteJournalMode::Wal),
                }
            };
            let options = options
                .busy_timeout(settings.sqlite_busy_timeout)
                .foreign_keys(true)
                .synchronous(SqliteSynchronous::Normal);
            let max_connections = if memory {
                1
            } else {
                settings.db_pool_size.min(50)
            };
            let pool = SqlitePoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(settings.db_pool_timeout)
                .connect_lazy_with(options);
            return Ok(Self::Sqlite(pool));
        }

        let normalized;
        let url = if let Some(rest) = url.strip_prefix("postgresql+psycopg://") {
            normalized = format!("postgresql://{rest}");
            &normalized
        } else {
            url
        };
        if !url.starts_with("postgresql://") && !url.starts_with("postgres://") {
            return Err("unsupported DATABASE_URL scheme".into());
        }
        let options =
            PgConnectOptions::from_str(url).map_err(|_| "invalid PostgreSQL DATABASE_URL")?;
        let pool = PgPoolOptions::new()
            .max_connections(settings.db_pool_size)
            .acquire_timeout(settings.db_pool_timeout)
            .connect_lazy_with(options);
        Ok(Self::Postgres(pool))
    }

    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
        };
        Ok(())
    }
}
