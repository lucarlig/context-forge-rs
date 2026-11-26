// SPDX-License-Identifier: Apache-2.0

use std::{env, error::Error, str::FromStr, time::Duration};

pub struct Settings {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub db_pool_size: u32,
    pub db_pool_timeout: Duration,
    pub sqlite_busy_timeout: Duration,
    pub redis: Option<RedisSettings>,
}

pub struct RedisSettings {
    pub url: String,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
}

impl Settings {
    pub fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        let redis = match value("CACHE_TYPE", "database")?.as_str() {
            "redis" => {
                let url = value("REDIS_URL", "")?;
                if url.is_empty() {
                    None
                } else {
                    Some(RedisSettings {
                        url,
                        connect_timeout: positive_seconds("REDIS_SOCKET_CONNECT_TIMEOUT", 2.0)?,
                        response_timeout: positive_seconds("REDIS_SOCKET_TIMEOUT", 2.0)?,
                    })
                }
            }
            "database" | "memory" | "none" => None,
            _ => return Err("invalid CACHE_TYPE".into()),
        };
        let pool_size = parse::<u32>("DB_POOL_SIZE", 200)?;
        let overflow = parse::<u32>("DB_MAX_OVERFLOW", 10)?;
        let db_pool_size = pool_size
            .checked_add(overflow)
            .ok_or("DB pool size overflow")?;
        if db_pool_size == 0 {
            return Err("DB pool size must be positive".into());
        }
        let sqlite_busy_timeout = parse("DB_SQLITE_BUSY_TIMEOUT", 5000)?;
        if !(1000..=60_000).contains(&sqlite_busy_timeout) {
            return Err(
                "DB_SQLITE_BUSY_TIMEOUT must be between 1000 and 60000 milliseconds".into(),
            );
        }

        Ok(Self {
            host: value("HOST", "127.0.0.1")?,
            port: parse("PORT", 4444)?,
            database_url: value("DATABASE_URL", "sqlite:///./mcp.db")?,
            db_pool_size,
            db_pool_timeout: positive_seconds("DB_POOL_TIMEOUT", 30.0)?,
            sqlite_busy_timeout: Duration::from_millis(sqlite_busy_timeout),
            redis,
        })
    }
}

fn value(name: &str, default: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(format!("invalid Unicode in {name}").into()),
    }
}

fn parse<T: FromStr>(name: &str, default: T) -> Result<T, Box<dyn Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => value.parse().map_err(|_| format!("invalid {name}").into()),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(_)) => Err(format!("invalid Unicode in {name}").into()),
    }
}

fn positive_seconds(name: &str, default: f64) -> Result<Duration, Box<dyn Error + Send + Sync>> {
    let duration = Duration::try_from_secs_f64(parse(name, default)?)
        .map_err(|_| format!("invalid {name}"))?;
    if duration.is_zero() {
        return Err(format!("{name} must be positive").into());
    }
    Ok(duration)
}
