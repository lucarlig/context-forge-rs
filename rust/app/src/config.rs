// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, env, error::Error, str::FromStr, time::Duration};

use crate::{
    gateway::{CatalogRefresh, Pagination},
    jwt::{JwtConfig, JwtVerifier},
    mcp::{HttpOptions, IngressPolicy, ProtocolMode, RedisSessionDirectory, SessionSettings},
    redis_sessions::{DEFAULT_AFFINITY_TTL, DEFAULT_LISTENER_TTL},
    upstream::{ConnectMode, EgressPolicy, UpstreamClient},
};

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

    pub fn jwt_verifier() -> Result<Option<JwtVerifier>, Box<dyn Error + Send + Sync>> {
        let algorithm = value("JWT_ALGORITHM", "HS256")?;
        let key = match algorithm.as_str() {
            "HS256" | "HS384" | "HS512" => {
                let secret = value("JWT_SECRET_KEY", "")?;
                if secret.is_empty() {
                    return Ok(None);
                }
                secret.into_bytes()
            }
            _ => {
                let path = value("JWT_PUBLIC_KEY_PATH", "")?;
                if path.is_empty() {
                    return Err(
                        "JWT_PUBLIC_KEY_PATH is required for asymmetric JWT verification".into(),
                    );
                }
                std::fs::read(path).map_err(|_| "could not read JWT_PUBLIC_KEY_PATH")?
            }
        };

        let issuer = value("JWT_ISSUER", "mcpgateway")?;
        let audience = value("JWT_AUDIENCE", "mcpgateway-api")?;
        let environment = value("ENVIRONMENT", "development")?;
        Ok(Some(JwtVerifier::new(JwtConfig {
            algorithm: &algorithm,
            key: &key,
            issuer: flag("JWT_ISSUER_VERIFICATION")?
                .unwrap_or(true)
                .then_some(&issuer),
            audience: flag("JWT_AUDIENCE_VERIFICATION")?
                .unwrap_or(true)
                .then_some(&audience),
            require_expiration: flag("REQUIRE_TOKEN_EXPIRATION")?.unwrap_or(true),
            require_jti: flag("REQUIRE_JTI")?.unwrap_or(true),
            environment: &environment,
            validate_environment: flag("VALIDATE_TOKEN_ENVIRONMENT")?.unwrap_or(true),
            derive_key_per_environment: flag("DERIVE_KEY_PER_ENVIRONMENT")?.unwrap_or(false),
        })?))
    }

    pub fn mcp_requires_auth() -> Result<bool, Box<dyn Error + Send + Sync>> {
        match flag("MCP_REQUIRE_AUTH")? {
            Some(required) => Ok(required),
            None => Ok(flag("AUTH_REQUIRED")?.unwrap_or(true)),
        }
    }

    pub fn mcp_ingress_policy() -> Result<IngressPolicy, Box<dyn Error + Send + Sync>> {
        Ok(IngressPolicy {
            origins: allowlist("MCP_ALLOWED_ORIGINS")?,
            hosts: allowlist("MCP_ALLOWED_HOSTS")?,
        })
    }

    pub fn mcp_inbound_protocol_mode() -> Result<ProtocolMode, Box<dyn Error + Send + Sync>> {
        match value("MCP_INBOUND_PROTOCOL_MODE", "auto")?.as_str() {
            "auto" => Ok(ProtocolMode::Auto),
            "legacy" => Ok(ProtocolMode::Legacy),
            _ => Err("invalid MCP_INBOUND_PROTOCOL_MODE".into()),
        }
    }

    pub fn mcp_http_options(&self) -> Result<HttpOptions, Box<dyn Error + Send + Sync>> {
        Ok(HttpOptions {
            json_response: flag("JSON_RESPONSE_ENABLED")?.unwrap_or(true),
            sessions: self.mcp_sessions()?,
        })
    }

    fn mcp_sessions(&self) -> Result<Option<SessionSettings>, Box<dyn Error + Send + Sync>> {
        if !flag("USE_STATEFUL_SESSIONS")?.unwrap_or(false) {
            return Ok(None);
        }
        let defaults = SessionSettings::default();
        let ttl = parse("SESSION_TTL", defaults.ttl.as_secs())?;
        let event_capacity = parse(
            "STREAMABLE_HTTP_MAX_EVENTS_PER_STREAM",
            defaults.event_capacity,
        )?;
        let event_ttl = parse("STREAMABLE_HTTP_EVENT_TTL", defaults.event_ttl.as_secs())?;
        if ttl == 0 {
            return Err("SESSION_TTL must be positive".into());
        }
        if event_capacity == 0 || event_ttl == 0 {
            return Err("MCP event history settings must be positive".into());
        }
        let redis = if let Some(redis) = &self.redis {
            let affinity = if flag("MCPGATEWAY_SESSION_AFFINITY_ENABLED")?.unwrap_or(false) {
                let seconds = parse(
                    "MCPGATEWAY_SESSION_AFFINITY_TTL",
                    DEFAULT_AFFINITY_TTL.as_secs(),
                )?;
                if seconds == 0 {
                    return Err("MCPGATEWAY_SESSION_AFFINITY_TTL must be positive".into());
                }
                Some(Duration::from_secs(seconds))
            } else {
                None
            };
            let listener = parse(
                "MCP_GET_STREAM_LISTENER_TTL_SECONDS",
                DEFAULT_LISTENER_TTL.as_secs(),
            )?;
            if listener == 0 {
                return Err("MCP_GET_STREAM_LISTENER_TTL_SECONDS must be positive".into());
            }
            let directory = RedisSessionDirectory::new(redis)
                .map_err(|_| "invalid REDIS_URL")?
                .with_leases(affinity, Duration::from_secs(listener));
            Some(std::sync::Arc::new(directory))
        } else {
            None
        };
        let affinity_forward_timeout = if redis.is_some() {
            positive_seconds(
                "MCPGATEWAY_POOL_RPC_FORWARD_TIMEOUT",
                defaults.affinity_forward_timeout.as_secs_f64(),
            )?
        } else {
            defaults.affinity_forward_timeout
        };
        let affinity_forward_concurrency = if redis.is_some() {
            parse(
                "MCPGATEWAY_AFFINITY_FORWARD_CONCURRENCY",
                defaults.affinity_forward_concurrency,
            )?
        } else {
            defaults.affinity_forward_concurrency
        };
        if !(1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&affinity_forward_concurrency) {
            return Err("invalid MCPGATEWAY_AFFINITY_FORWARD_CONCURRENCY".into());
        }
        Ok(Some(SessionSettings {
            ttl: Duration::from_secs(ttl),
            get_stream_enabled: flag("MCP_GET_STREAM_ENABLED")?
                .unwrap_or(defaults.get_stream_enabled),
            event_capacity,
            event_ttl: Duration::from_secs(event_ttl),
            redis,
            affinity_forward_timeout,
            affinity_forward_concurrency,
            ..defaults
        }))
    }

    pub fn upstream_client() -> Result<UpstreamClient, Box<dyn Error + Send + Sync>> {
        let policy = EgressPolicy {
            allow_localhost: flag("SSRF_ALLOW_LOCALHOST")?.unwrap_or(false),
            allow_private_networks: flag("SSRF_ALLOW_PRIVATE_NETWORKS")?.unwrap_or(false),
            allowed_networks: parse_networks("SSRF_ALLOWED_NETWORKS")?,
            blocked_networks: parse_networks("SSRF_BLOCKED_NETWORKS")?,
            blocked_hosts: allowlist("SSRF_BLOCKED_HOSTS")?.into_iter().collect(),
        };
        let connect_mode = match value("MCP_CLIENT_CONNECT_MODE", "auto")?.as_str() {
            "auto" => ConnectMode::Auto,
            "legacy" => ConnectMode::Legacy,
            _ => return Err("invalid MCP_CLIENT_CONNECT_MODE".into()),
        };
        Ok(UpstreamClient::new(
            policy,
            positive_seconds("GATEWAY_HEALTH_CHECK_TIMEOUT", 30.0)?,
        )
        .with_connect_mode(connect_mode))
    }

    pub fn mcp_pagination() -> Result<Pagination, Box<dyn Error + Send + Sync>> {
        let size = parse("MCP_LIST_PAGE_SIZE", 100)?;
        let lifetime = parse("MCP_LIST_CURSOR_TTL_SECONDS", 900)?;
        if !(1..=1000).contains(&size) || lifetime <= 0 {
            return Err("invalid MCP catalog page size or cursor lifetime".into());
        }
        let secret = value("AUTH_ENCRYPTION_SECRET", "")?;
        let secret = if secret.is_empty() {
            value("JWT_SECRET_KEY", "")?
        } else {
            secret
        };
        Ok(Pagination::new(
            size,
            lifetime,
            (!secret.is_empty()).then_some(&secret),
        ))
    }

    pub fn catalog_refresh() -> Result<CatalogRefresh, Box<dyn Error + Send + Sync>> {
        let defaults = CatalogRefresh::default();
        let default_seconds = parse("GATEWAY_AUTO_REFRESH_INTERVAL", defaults.default_seconds)?;
        let minimum_seconds = parse("HEALTH_CHECK_INTERVAL", defaults.minimum_seconds)?;
        if default_seconds < 60 || minimum_seconds <= 0 {
            return Err("invalid catalog refresh or health check interval".into());
        }
        Ok(CatalogRefresh {
            default_seconds,
            minimum_seconds,
        })
    }

    pub fn invalidate_sessions_on_password_change() -> Result<bool, Box<dyn Error + Send + Sync>> {
        Ok(flag("PASSWORD_RESET_INVALIDATE_SESSIONS")?.unwrap_or(true))
    }
}

fn parse_networks(name: &str) -> Result<Vec<ipnet::IpNet>, Box<dyn Error + Send + Sync>> {
    allowlist(name)?
        .into_iter()
        .map(|cidr| {
            cidr.parse()
                .map_err(|_| format!("invalid network in {name}").into())
        })
        .collect()
}
fn allowlist(name: &str) -> Result<HashSet<String>, Box<dyn Error + Send + Sync>> {
    let raw = value(name, "")?;
    let raw = raw.trim();
    let items = match raw.as_bytes().first() {
        Some(b'[') => {
            serde_json::from_str::<Vec<String>>(raw).map_err(|_| format!("invalid {name}"))?
        }
        Some(b'"') => {
            vec![serde_json::from_str::<String>(raw).map_err(|_| format!("invalid {name}"))?]
        }
        _ => raw.split(',').map(str::to_owned).collect(),
    };
    Ok(items
        .into_iter()
        .filter_map(|entry| {
            let entry = entry.trim();
            (!entry.is_empty()).then(|| entry.to_owned())
        })
        .collect())
}
fn flag(name: &str) -> Result<Option<bool>, Box<dyn Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "t" | "y" | "yes" => Ok(Some(true)),
            "0" | "false" | "off" | "f" | "n" | "no" => Ok(Some(false)),
            _ => Err(format!("invalid {name}").into()),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("invalid Unicode in {name}").into()),
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
