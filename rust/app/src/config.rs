// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, env, error::Error, str::FromStr, time::Duration};

use jsonwebtoken::EncodingKey;
use tokio_util::sync::CancellationToken;

use crate::{
    gateway::{
        CIMD_DOCUMENT_PATH, CatalogRefresh, CimdSettings, DcrSettings, GatewayHealth,
        GatewayLifecycle, GatewayListeners, GatewayOAuthSettings, ListenerElection, Pagination,
        ResourceLimits, RootSettings,
    },
    jwt::{JwtConfig, JwtIssuer, JwtVerifier},
    local_auth::{
        AccountSettings, ExternalIdentitySettings, ResetSettings, SsoIdentityPolicy, SsoSettings,
        TeamSettings, UserProvisioning,
        mail::{MailSettings, MailTls, Mailer},
    },
    mcp::{
        HttpOptions, IngressPolicy, ListenSettings, ProtocolMode, RedisSessionDirectory,
        SessionSettings, SseBackend, SseSettings, WebSocketSettings,
    },
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

#[derive(Clone)]
pub struct RedisSettings {
    pub url: String,
    pub connect_timeout: Duration,
    pub response_timeout: Duration,
}

pub struct HeaderForwarding {
    pub(crate) enabled: bool,
    pub(crate) sensitive: bool,
    pub(crate) overwrite: bool,
    pub(crate) max_value_length: usize,
    pub(crate) source: HeaderSource,
    pub(crate) defaults: HashSet<String>,
}

pub struct IdentityForwarding {
    pub(crate) enabled: bool,
    pub(crate) mode: IdentityMode,
    pub(crate) headers_prefix: String,
    pub(crate) sign_claims: bool,
    pub(crate) signing_key: Option<EncodingKey>,
}

pub struct ProxyCatalogSettings {
    pub(crate) redis: Option<std::sync::Arc<RedisSessionDirectory>>,
    pub(crate) max_snapshot_bytes: usize,
    pub(crate) max_total_bytes: usize,
    pub(crate) max_collectors: usize,
    pub(crate) max_snapshots: usize,
}

#[derive(Clone, Copy)]
pub struct SecretKdf {
    pub(crate) time_cost: u32,
    pub(crate) memory_cost: u32,
    pub(crate) parallelism: u32,
}

impl Default for SecretKdf {
    fn default() -> Self {
        Self {
            time_cost: 3,
            memory_cost: 65_536,
            parallelism: 1,
        }
    }
}

impl Default for ProxyCatalogSettings {
    fn default() -> Self {
        Self {
            redis: None,
            max_snapshot_bytes: 64 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_collectors: 32,
            max_snapshots: 128,
        }
    }
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum IdentityMode {
    Headers,
    Meta,
    Both,
}

impl Default for IdentityForwarding {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: IdentityMode::Both,
            headers_prefix: "X-Forwarded-User".to_owned(),
            sign_claims: false,
            signing_key: None,
        }
    }
}

pub(crate) enum HeaderSource {
    Environment,
    Database,
    Merge,
}

impl Default for HeaderForwarding {
    fn default() -> Self {
        Self {
            enabled: false,
            sensitive: false,
            overwrite: false,
            max_value_length: 4096,
            source: HeaderSource::Database,
            defaults: ["X-Tenant-Id".to_owned(), "X-Trace-Id".to_owned()].into(),
        }
    }
}

impl Settings {
    pub fn management_page_sizes() -> Result<(u32, u32), Box<dyn Error + Send + Sync>> {
        let default = parse("PAGINATION_DEFAULT_PAGE_SIZE", 50)?;
        let maximum = parse("PAGINATION_MAX_PAGE_SIZE", 500)?;
        if !(1..=1000).contains(&default) || !(1..=10000).contains(&maximum) {
            return Err("invalid management pagination settings".into());
        }
        Ok((default, maximum))
    }

    pub fn secret_kdf() -> Result<SecretKdf, Box<dyn Error + Send + Sync>> {
        let defaults = SecretKdf::default();
        let settings = SecretKdf {
            time_cost: parse("ARGON2ID_TIME_COST", defaults.time_cost)?,
            memory_cost: parse("ARGON2ID_MEMORY_COST", defaults.memory_cost)?,
            parallelism: parse("ARGON2ID_PARALLELISM", defaults.parallelism)?,
        };
        settings.params().map_err(|_| "invalid Argon2id settings")?;
        Ok(settings)
    }
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

    pub fn auth_encryption_secret() -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
        let secret = value("AUTH_ENCRYPTION_SECRET", "")?;
        Ok((!secret.is_empty()).then_some(secret))
    }

    pub fn jwt_issuer() -> Result<Option<JwtIssuer>, Box<dyn Error + Send + Sync>> {
        let algorithm = value("JWT_ALGORITHM", "HS256")?;
        let key = if matches!(algorithm.as_str(), "HS256" | "HS384" | "HS512") {
            value("JWT_SECRET_KEY", "")?.into_bytes()
        } else {
            let path = value("JWT_PRIVATE_KEY_PATH", "")?;
            if path.is_empty() {
                return Ok(None);
            }
            std::fs::read(path).map_err(|_| "could not read JWT_PRIVATE_KEY_PATH")?
        };
        if key.is_empty() {
            return Ok(None);
        }
        let key = zeroize::Zeroizing::new(key);
        Ok(Some(JwtIssuer::new(
            &algorithm,
            &key,
            value("JWT_ISSUER", "mcpgateway")?,
            value("JWT_AUDIENCE", "mcpgateway-api")?,
            value("ENVIRONMENT", "development")?,
            flag("DERIVE_KEY_PER_ENVIRONMENT")?.unwrap_or(false),
        )?))
    }

    pub fn jwt_issuer_name() -> Result<String, Box<dyn Error + Send + Sync>> {
        value("JWT_ISSUER", "mcpgateway")
    }

    pub fn email_auth_enabled() -> Result<bool, Box<dyn Error + Send + Sync>> {
        Ok(flag("EMAIL_AUTH_ENABLED")?.unwrap_or(true))
    }

    pub fn token_usage_logging() -> Result<bool, Box<dyn Error + Send + Sync>> {
        Ok(flag("TOKEN_USAGE_LOGGING_ENABLED")?.unwrap_or(true))
    }

    pub fn gateway_oauth() -> Result<GatewayOAuthSettings, Box<dyn Error + Send + Sync>> {
        let base = url::Url::parse(&value("APP_DOMAIN", "http://localhost:4444")?)?;
        if !matches!(base.scheme(), "http" | "https")
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err("invalid OAuth callback domain".into());
        }
        let root = value("APP_ROOT_PATH", "")?;
        let root = root.trim_matches('/');
        let app_path = base.path().trim_matches('/');
        let path = [app_path, root, "oauth/callback"]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        let callback_path = format!("/{path}");
        let origin = base.origin().ascii_serialization();
        let refresh_threshold = parse("OAUTH_TOKEN_REFRESH_THRESHOLD_SECONDS", 600)?;
        if !(0..=3600).contains(&refresh_threshold) {
            return Err("invalid OAUTH_TOKEN_REFRESH_THRESHOLD_SECONDS".into());
        }
        let auth_method = value("DCR_TOKEN_ENDPOINT_AUTH_METHOD", "client_secret_basic")?;
        if !matches!(
            auth_method.as_str(),
            "client_secret_basic" | "client_secret_post" | "none"
        ) {
            return Err("invalid DCR_TOKEN_ENDPOINT_AUTH_METHOD".into());
        }
        let application_type = value("DCR_APPLICATION_TYPE", "auto")?;
        if !matches!(application_type.as_str(), "auto" | "web" | "native") {
            return Err("invalid DCR_APPLICATION_TYPE".into());
        }
        let default_scopes =
            serde_json::from_str(&value("DCR_DEFAULT_SCOPES", r#"["mcp:read"]"#)?)?;
        let dcr = DcrSettings {
            enabled: flag("DCR_ENABLED")?.unwrap_or(true),
            auto_register: flag("DCR_AUTO_REGISTER_ON_MISSING_CREDENTIALS")?.unwrap_or(true),
            allowed_issuers: allowlist("DCR_ALLOWED_ISSUERS")?,
            default_scopes,
            auth_method,
            application_type,
            metadata_ttl: Duration::from_secs(parse("DCR_METADATA_CACHE_TTL", 3600)?),
            client_name_template: value(
                "DCR_CLIENT_NAME_TEMPLATE",
                "ContextForge ({gateway_name})",
            )?,
            request_refresh_without_advertisement: flag(
                "DCR_REQUEST_REFRESH_TOKEN_WHEN_UNSUPPORTED",
            )?
            .unwrap_or(false),
        };
        let cimd_base = callback_path
            .strip_suffix("/oauth/callback")
            .unwrap_or_default();
        let client_id = value("CIMD_CLIENT_METADATA_URL", "")?;
        let client_id = if client_id.is_empty() {
            format!("{origin}{cimd_base}{CIMD_DOCUMENT_PATH}")
        } else {
            client_id
        };
        let cimd_url = url::Url::parse(&client_id)?;
        if !matches!(cimd_url.scheme(), "http" | "https")
            || !cimd_url.username().is_empty()
            || cimd_url.password().is_some()
            || cimd_url.query().is_some()
            || cimd_url.fragment().is_some()
            || !cimd_url.path().ends_with(CIMD_DOCUMENT_PATH)
        {
            return Err("invalid CIMD_CLIENT_METADATA_URL".into());
        }
        let signed = match value("CIMD_TOKEN_ENDPOINT_AUTH_METHOD", "none")?.as_str() {
            "none" => false,
            "private_key_jwt" => true,
            _ => return Err("invalid CIMD_TOKEN_ENDPOINT_AUTH_METHOD".into()),
        };
        let cimd = CimdSettings {
            enabled: flag("CIMD_ENABLED")?.unwrap_or(true),
            client_id,
            client_name: value("CIMD_CLIENT_NAME", "ContextForge")?,
            signed,
            private_key_path: value("CIMD_PRIVATE_KEY_PATH", "")?,
            previous_public_key_path: value("CIMD_PREVIOUS_PUBLIC_KEY_PATH", "")?,
            jwt_private_key_path: value("JWT_PRIVATE_KEY_PATH", "")?,
            key_id: value("CIMD_KEY_ID", "cimd-1")?,
            previous_key_id: value("CIMD_PREVIOUS_KEY_ID", "")?,
            algorithm: serde_json::from_value(serde_json::Value::String(value(
                "CIMD_SIGNING_ALG",
                "RS256",
            )?))?,
            cache_seconds: parse("CIMD_DOCUMENT_CACHE_SECONDS", 3600)?,
        };
        if cimd.enabled && cimd.signed && cimd.private_key_path.is_empty() {
            return Err(
                "CIMD_TOKEN_ENDPOINT_AUTH_METHOD=private_key_jwt requires CIMD_PRIVATE_KEY_PATH"
                    .into(),
            );
        }
        Ok(GatewayOAuthSettings {
            redirect_uri: format!("{origin}{callback_path}"),
            callback_path,
            browser_origin: origin,
            secure_cookies: flag("SECURE_COOKIES")?.unwrap_or(true)
                || value("ENVIRONMENT", "development")? == "production",
            token_retrieval: flag("OAUTH_TOKEN_RETRIEVAL_ENABLED")?.unwrap_or(false),
            refresh_threshold,
            dcr,
            cimd,
            request_timeout: positive_seconds("OAUTH_REQUEST_TIMEOUT", 30.0)?,
            issuer_metadata: Default::default(),
        })
    }

    pub fn local_accounts() -> Result<AccountSettings, Box<dyn Error + Send + Sync>> {
        use zeroize::Zeroizing;
        let enabled =
            |name, default| Ok::<_, Box<dyn Error + Send + Sync>>(flag(name)?.unwrap_or(default));
        let expiry: i64 = parse("TOKEN_EXPIRY", 20)?;
        let attempts = parse("MAX_FAILED_LOGIN_ATTEMPTS", 5)?;
        let lockout: i64 = parse("ACCOUNT_LOCKOUT_DURATION_MINUTES", 60)?;
        if !(5..=1440).contains(&expiry) || attempts < 1 || !(1..=525_600).contains(&lockout) {
            return Err("invalid local authentication settings".into());
        }
        let csrf_seconds = parse("CSRF_TOKEN_EXPIRY", 3600)?;
        let (page_size, max_page_size) = Self::management_page_sizes()?;
        let csrf_secret = Zeroizing::new(
            env::var("CSRF_SECRET_KEY")
                .ok()
                .filter(|secret| !secret.is_empty())
                .unwrap_or(value("JWT_SECRET_KEY", "")?),
        );
        if csrf_seconds < 1 {
            return Err("invalid CSRF token expiry".into());
        }
        Ok(AccountSettings {
            bootstrap_email: value("PLATFORM_ADMIN_EMAIL", "admin@example.com")?,
            bootstrap_name: value("PLATFORM_ADMIN_FULL_NAME", "Platform Administrator")?,
            bootstrap_password: env::var("PLATFORM_ADMIN_PASSWORD")
                .ok()
                .filter(|password| !password.is_empty())
                .map(Zeroizing::new),
            bootstrap_require_change: enabled("ADMIN_REQUIRE_PASSWORD_CHANGE_ON_BOOTSTRAP", true)?,
            default_password: Zeroizing::new(value("DEFAULT_USER_PASSWORD", "changeme")?),
            public_registration: enabled("PUBLIC_REGISTRATION_ENABLED", false)?,
            provisioning: Self::user_provisioning()?,
            teams: Self::account_teams()?,
            enforce_password_change: enabled("PASSWORD_CHANGE_ENFORCEMENT_ENABLED", true)?,
            detect_default_password: enabled("DETECT_DEFAULT_PASSWORD_ON_LOGIN", true)?,
            require_change_for_default: enabled(
                "REQUIRE_PASSWORD_CHANGE_FOR_DEFAULT_PASSWORD",
                true,
            )?,
            password_max_age_days: parse("PASSWORD_MAX_AGE_DAYS", 90)?,
            password_min_user: parse("PASSWORD_MIN_LENGTH_USER", 12)?,
            password_min_admin: parse("PASSWORD_MIN_LENGTH_PRIVILEGED", 22)?,
            password_policy: enabled("PASSWORD_POLICY_ENABLED", true)?,
            password_history: parse("PASSWORD_HISTORY_COUNT", 5)?,
            invalidate_sessions: Self::invalidate_sessions_on_password_change()?,
            reset: Self::password_reset()?,
            mailer: Self::account_mailer()?,
            protect_admins: enabled("PROTECT_ALL_ADMINS", true)?,
            lockout_attempts: attempts,
            lockout_seconds: lockout * 60,
            failure_floor: Duration::from_millis(parse("FAILED_LOGIN_MIN_RESPONSE_MS", 250)?),
            token_seconds: expiry * 60,
            csrf_secret,
            csrf_name: value("CSRF_COOKIE_NAME", "mcpgateway_csrf_token")?,
            csrf_samesite: value("CSRF_COOKIE_SAMESITE", "Strict")?,
            csrf_secure: enabled("CSRF_COOKIE_SECURE", true)?,
            csrf_httponly: enabled("CSRF_COOKIE_HTTPONLY", false)?,
            csrf_seconds,
            a2a_enabled: enabled("MCPGATEWAY_A2A_ENABLED", true)?,
            page_size,
            max_page_size,
            kdf: Self::secret_kdf()?,
            sso: Self::sso()?,
        })
    }

    fn user_provisioning() -> Result<UserProvisioning, Box<dyn Error + Send + Sync>> {
        Ok(UserProvisioning {
            personal_teams: flag("AUTO_CREATE_PERSONAL_TEAMS")?.unwrap_or(true),
            personal_team_prefix: value("PERSONAL_TEAM_PREFIX", "")?,
            admin_role: value("DEFAULT_ADMIN_ROLE", "platform_admin")?,
            user_role: value("DEFAULT_USER_ROLE", "platform_viewer")?,
            owner_role: value("DEFAULT_TEAM_OWNER_ROLE", "team_admin")?,
        })
    }

    pub fn sso_external_identity()
    -> Result<Option<ExternalIdentitySettings>, Box<dyn Error + Send + Sync>> {
        if !flag("SSO_API_TOKEN_AUTH_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        Ok(Some(ExternalIdentitySettings {
            upstream: Self::upstream_client()?,
            provisioning: Self::user_provisioning()?,
            internal_issuer: value("JWT_ISSUER", "mcpgateway")?,
            identity_policy: Self::sso_identity_policy()?,
        }))
    }

    fn sso() -> Result<Option<SsoSettings>, Box<dyn Error + Send + Sync>> {
        if !flag("SSO_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        let kdf = Self::secret_kdf()?;
        let secret = Self::auth_encryption_secret()?.map(zeroize::Zeroizing::new);
        let binding_key = secret
            .as_ref()
            .map(|secret| ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes()));
        let vault = secret.as_ref().map(|secret| {
            let mut vault = crate::secret_envelope::SecretEnvelope::new(secret);
            vault.kdf = kdf;
            vault
        });
        Ok(Some(SsoSettings {
            upstream: Self::upstream_client()?,
            vault,
            allowed_issuers: allowlist("SSO_ISSUERS")?,
            binding_key,
            app_domain: url::Url::parse(&value("APP_DOMAIN", "http://localhost:4444")?)?,
            allowed_origins: allowlist("ALLOWED_ORIGINS")?,
            root_path: value("APP_ROOT_PATH", "")?.trim_end_matches('/').to_owned(),
            secure_cookies: flag("SECURE_COOKIES")?.unwrap_or(true)
                || value("ENVIRONMENT", "development")? == "production",
            same_site: value("COOKIE_SAMESITE", "lax")?,
            identity_policy: Self::sso_identity_policy()?,
            admin_api_enabled: flag("MCPGATEWAY_ADMIN_API_ENABLED")?.unwrap_or(false),
        }))
    }

    fn sso_identity_policy() -> Result<SsoIdentityPolicy, Box<dyn Error + Send + Sync>> {
        Ok(SsoIdentityPolicy {
            approval_required: flag("SSO_REQUIRE_ADMIN_APPROVAL")?.unwrap_or(false),
            allow_provider_linking: flag("SSO_ALLOW_PROVIDER_LINKING")?.unwrap_or(false),
            teams: Self::account_teams()?,
            admin_domains: allowlist("SSO_AUTO_ADMIN_DOMAINS")?,
            github_admin_orgs: allowlist("SSO_GITHUB_ADMIN_ORGS")?,
            google_admin_domains: allowlist("SSO_GOOGLE_ADMIN_DOMAINS")?,
            entra_admin_groups: allowlist("SSO_ENTRA_ADMIN_GROUPS")?,
            generic_provider: value("SSO_GENERIC_PROVIDER_ID", "")?,
            generic_admin_groups: allowlist("SSO_GENERIC_ADMIN_GROUPS")?,
        })
    }

    fn account_teams() -> Result<TeamSettings, Box<dyn Error + Send + Sync>> {
        let max_members = parse("MAX_MEMBERS_PER_TEAM", 100)?;
        let max_teams = parse("MAX_TEAMS_PER_USER", 50)?;
        let max_seeds = parse("MAX_TEAM_MEMBER_SEEDS", 500)?;
        let expires: i64 = parse("INVITATION_EXPIRY_DAYS", 7)?;
        if max_members < 1 || max_teams < 1 || !(1..=365).contains(&expires) {
            return Err("invalid team management settings".into());
        }
        Ok(TeamSettings {
            allow_creation: flag("ALLOW_TEAM_CREATION")?.unwrap_or(true),
            allow_join_requests: flag("ALLOW_TEAM_JOIN_REQUESTS")?.unwrap_or(true),
            allow_invitations: flag("ALLOW_TEAM_INVITATIONS")?.unwrap_or(true),
            verify_invite_email: flag("REQUIRE_EMAIL_VERIFICATION_FOR_INVITES")?.unwrap_or(true),
            max_members,
            max_teams,
            max_seeds,
            expires_in_seconds: expires * 86_400,
            member_role: value("DEFAULT_TEAM_MEMBER_ROLE", "viewer")?,
        })
    }

    fn password_reset() -> Result<ResetSettings, Box<dyn Error + Send + Sync>> {
        let expires: i64 = parse("PASSWORD_RESET_TOKEN_EXPIRY_MINUTES", 60)?;
        let window: i64 = parse("PASSWORD_RESET_RATE_WINDOW_MINUTES", 15)?;
        let limit: i64 = parse("PASSWORD_RESET_RATE_LIMIT", 5)?;
        if !(1..=525_600).contains(&expires) || !(1..=525_600).contains(&window) || limit < 1 {
            return Err("invalid password reset settings".into());
        }
        let ui = env::var("UI_BASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty());
        let mut frontend = if let Some(url) = ui.as_deref() {
            url.to_owned()
        } else {
            let domain = value("APP_DOMAIN", "http://localhost:4444")?;
            let root = value("APP_ROOT_PATH", "")?;
            let root = root.trim_matches('/');
            if root.is_empty() {
                domain
            } else {
                format!("{}/{root}", domain.trim_end_matches('/'))
            }
        };
        let admin = ui.is_none() && flag("MCPGATEWAY_ADMIN_API_ENABLED")?.unwrap_or(false);
        let mount = if admin { "/admin" } else { "/app" };
        frontend.truncate(frontend.trim_end_matches('/').len());
        let parsed = url::Url::parse(&frontend)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err("invalid browser-facing URL for password reset".into());
        }
        if !parsed.path().ends_with(mount) {
            frontend.push_str(mount);
        }
        Ok(ResetSettings {
            enabled: flag("PASSWORD_RESET_ENABLED")?.unwrap_or(true),
            lifetime: expires * 60,
            window: window * 60,
            limit,
            response_floor: Duration::from_millis(parse("PASSWORD_RESET_MIN_RESPONSE_MS", 250)?),
            lockout_email: flag("ACCOUNT_LOCKOUT_NOTIFICATION_ENABLED")?.unwrap_or(true),
            frontend,
        })
    }

    fn account_mailer() -> Result<Option<Mailer>, Box<dyn Error + Send + Sync>> {
        if !flag("SMTP_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        let host = value("SMTP_HOST", "")?;
        let from_email = value("SMTP_FROM_EMAIL", "")?;
        if host.is_empty() || from_email.is_empty() {
            return Ok(None);
        }
        let tls = if flag("SMTP_USE_SSL")?.unwrap_or(false) {
            MailTls::Implicit
        } else if flag("SMTP_USE_TLS")?.unwrap_or(true) {
            MailTls::StartTls
        } else {
            MailTls::Disabled
        };
        let auth = env::var("SMTP_USER")
            .ok()
            .filter(|username| !username.is_empty())
            .zip(
                env::var("SMTP_PASSWORD")
                    .ok()
                    .filter(|password| !password.is_empty())
                    .map(zeroize::Zeroizing::new),
            );
        Ok(Some(Mailer::new(MailSettings {
            host,
            port: parse("SMTP_PORT", 587)?,
            timeout: positive_seconds("SMTP_TIMEOUT_SECONDS", 15.0)?,
            from_email,
            from_name: value("SMTP_FROM_NAME", "ContextForge")?,
            tls,
            auth,
        })?))
    }

    pub fn query_auth_hosts() -> Result<Option<HashSet<String>>, Box<dyn Error + Send + Sync>> {
        flag("INSECURE_ALLOW_QUERYPARAM_AUTH")?
            .unwrap_or(false)
            .then(|| allowlist("INSECURE_QUERYPARAM_AUTH_ALLOWED_HOSTS"))
            .transpose()
    }

    pub fn header_forwarding() -> Result<HeaderForwarding, Box<dyn Error + Send + Sync>> {
        let defaults = HeaderForwarding::default();
        let source = match value("PASSTHROUGH_HEADERS_SOURCE", "db")?.as_str() {
            "env" => HeaderSource::Environment,
            "db" => HeaderSource::Database,
            "merge" => HeaderSource::Merge,
            _ => return Err("invalid PASSTHROUGH_HEADERS_SOURCE".into()),
        };
        let configured = if env::var_os("DEFAULT_PASSTHROUGH_HEADERS").is_some() {
            allowlist("DEFAULT_PASSTHROUGH_HEADERS")?
        } else {
            defaults.defaults
        };
        let max_value_length = parse("MAX_HEADER_VALUE_LENGTH", defaults.max_value_length)?;
        if max_value_length == 0 {
            return Err("MAX_HEADER_VALUE_LENGTH must be positive".into());
        }
        let enabled = flag("ENABLE_HEADER_PASSTHROUGH")?.unwrap_or(false);
        let sensitive = flag("ENABLE_SENSITIVE_HEADER_PASSTHROUGH")?.unwrap_or(false);
        if sensitive && !enabled {
            return Err(
                "ENABLE_SENSITIVE_HEADER_PASSTHROUGH requires ENABLE_HEADER_PASSTHROUGH".into(),
            );
        }
        Ok(HeaderForwarding {
            enabled,
            sensitive,
            overwrite: flag("ENABLE_OVERWRITE_BASE_HEADERS")?.unwrap_or(false),
            max_value_length,
            source,
            defaults: configured,
        })
    }

    pub fn identity_forwarding() -> Result<IdentityForwarding, Box<dyn Error + Send + Sync>> {
        let enabled = flag("IDENTITY_PROPAGATION_ENABLED")?.unwrap_or(false);
        let mode = match value("IDENTITY_PROPAGATION_MODE", "both")?.as_str() {
            "headers" => IdentityMode::Headers,
            "meta" => IdentityMode::Meta,
            "both" => IdentityMode::Both,
            _ => return Err("invalid IDENTITY_PROPAGATION_MODE".into()),
        };
        let headers_prefix = value("IDENTITY_PROPAGATION_HEADERS_PREFIX", "X-Forwarded-User")?;
        crate::forward_identity::validate_prefix(&headers_prefix)?;
        let sign_claims = flag("IDENTITY_SIGN_CLAIMS")?.unwrap_or(false);
        let secret = value("IDENTITY_CLAIMS_SECRET", "")?;
        let jwt = value("JWT_SECRET_KEY", "")?;
        let signing_key = (!secret.is_empty() && secret != jwt)
            .then(|| EncodingKey::from_secret(secret.as_bytes()))
            .transpose()?;
        if sign_claims && signing_key.is_none() {
            return Err("IDENTITY_SIGN_CLAIMS requires a dedicated IDENTITY_CLAIMS_SECRET".into());
        }
        Ok(IdentityForwarding {
            enabled,
            mode,
            headers_prefix,
            sign_claims,
            signing_key,
        })
    }

    pub fn direct_proxy_timeout() -> Result<Option<Duration>, Box<dyn Error + Send + Sync>> {
        flag("MCPGATEWAY_DIRECT_PROXY_ENABLED")?
            .unwrap_or(false)
            .then(|| positive_seconds("MCPGATEWAY_DIRECT_PROXY_TIMEOUT", 30.0))
            .transpose()
    }

    pub fn proxy_catalog(&self) -> Result<ProxyCatalogSettings, Box<dyn Error + Send + Sync>> {
        let defaults = ProxyCatalogSettings::default();
        let settings = ProxyCatalogSettings {
            redis: self
                .redis
                .as_ref()
                .map(RedisSessionDirectory::new)
                .transpose()?
                .map(std::sync::Arc::new),
            max_snapshot_bytes: parse(
                "MCP_PROXY_LIST_MAX_SNAPSHOT_BYTES",
                defaults.max_snapshot_bytes,
            )?,
            max_total_bytes: parse("MCP_PROXY_LIST_MAX_TOTAL_BYTES", defaults.max_total_bytes)?,
            max_collectors: parse("MCP_PROXY_LIST_MAX_COLLECTORS", defaults.max_collectors)?,
            max_snapshots: parse("MCP_PROXY_LIST_MAX_SNAPSHOTS", defaults.max_snapshots)?,
        };
        if settings.max_snapshot_bytes == 0
            || settings.max_total_bytes == 0
            || !(1..=128).contains(&settings.max_collectors)
            || !(1..=1024).contains(&settings.max_snapshots)
        {
            return Err("invalid direct-proxy catalog limits".into());
        }
        Ok(settings)
    }

    pub fn mcp_requires_auth() -> Result<bool, Box<dyn Error + Send + Sync>> {
        match flag("MCP_REQUIRE_AUTH")? {
            Some(required) => Ok(required),
            None => Self::api_requires_auth(),
        }
    }

    pub fn api_requires_auth() -> Result<bool, Box<dyn Error + Send + Sync>> {
        Ok(flag("AUTH_REQUIRED")?.unwrap_or(true))
    }

    pub fn websocket_settings(
        shutdown: CancellationToken,
    ) -> Result<WebSocketSettings, Box<dyn Error + Send + Sync>> {
        Ok(WebSocketSettings {
            enabled: flag("MCPGATEWAY_WS_RELAY_ENABLED")?.unwrap_or(false),
            require_auth: flag("MCP_CLIENT_AUTH_ENABLED")?.unwrap_or(true)
                || Self::api_requires_auth()?,
            shutdown,
        })
    }

    pub fn sse_settings(
        shutdown: CancellationToken,
    ) -> Result<SseSettings, Box<dyn Error + Send + Sync>> {
        let keepalive = if flag("SSE_KEEPALIVE_ENABLED")?.unwrap_or(true) {
            Some(positive_seconds("SSE_KEEPALIVE_INTERVAL", 30.0)?)
        } else {
            None
        };
        Ok(SseSettings {
            retry_ms: parse("SSE_RETRY_TIMEOUT", 5000)?,
            keepalive,
            shutdown,
            ..SseSettings::default()
        })
    }

    pub fn gateway_sse_settings(
        &self,
        shutdown: CancellationToken,
    ) -> Result<SseSettings, Box<dyn Error + Send + Sync>> {
        let mut settings = Self::sse_settings(shutdown)?;
        settings.backend = match (value("CACHE_TYPE", "database")?.as_str(), &self.redis) {
            ("redis", Some(redis)) => {
                let directory =
                    RedisSessionDirectory::new(redis).map_err(|_| "invalid REDIS_URL")?;
                SseBackend::Redis(std::sync::Arc::new(directory))
            }
            ("database", _) => SseBackend::Database,
            ("none", _) => SseBackend::Disabled,
            _ => SseBackend::Memory,
        };
        if matches!(
            settings.backend,
            SseBackend::Redis(_) | SseBackend::Database
        ) {
            settings.session_ttl = positive_seconds("SESSION_TTL", 3600.0)?;
            settings.message_ttl = positive_seconds("MESSAGE_TTL", 600.0)?;
        }
        Ok(settings)
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

    pub fn mcp_listen_settings(
        shutdown: CancellationToken,
    ) -> Result<ListenSettings, Box<dyn Error + Send + Sync>> {
        let defaults = ListenSettings::default();
        let lifetime = parse(
            "MCP_LISTEN_MAX_LIFETIME_SECONDS",
            defaults.max_lifetime.as_secs(),
        )?;
        let max_per_principal = parse(
            "MCP_LISTEN_MAX_STREAMS_PER_PRINCIPAL",
            defaults.max_per_principal,
        )?;
        let max_anonymous = parse("MCP_LISTEN_MAX_ANONYMOUS_STREAMS", defaults.max_anonymous)?;
        if !(60..=86400).contains(&lifetime) {
            return Err("invalid MCP_LISTEN_MAX_LIFETIME_SECONDS".into());
        }
        if !(1..=1024).contains(&max_per_principal) {
            return Err("invalid MCP_LISTEN_MAX_STREAMS_PER_PRINCIPAL".into());
        }
        if max_anonymous > 1024 {
            return Err("invalid MCP_LISTEN_MAX_ANONYMOUS_STREAMS".into());
        }
        Ok(ListenSettings {
            max_lifetime: Duration::from_secs(lifetime),
            max_per_principal,
            max_anonymous,
            shutdown,
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
        let affinity_session_lock_timeout =
            if redis.as_ref().is_some_and(|redis| redis.affinity_enabled()) {
                positive_seconds(
                    "MCPGATEWAY_AFFINITY_SESSION_LOCK_TIMEOUT",
                    defaults.affinity_session_lock_timeout.as_secs_f64(),
                )?
            } else {
                defaults.affinity_session_lock_timeout
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
            affinity_session_lock_timeout,
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

    pub fn gateway_health(
        refresh: &CatalogRefresh,
    ) -> Result<GatewayHealth, Box<dyn Error + Send + Sync>> {
        let threshold = parse("UNHEALTHY_THRESHOLD", 3i32)?;
        let concurrency = parse("MAX_CONCURRENT_HEALTH_CHECKS", 10usize)?;
        if threshold < -1 || concurrency == 0 {
            return Err("invalid gateway health threshold or concurrency".into());
        }
        Ok(GatewayHealth {
            interval: Duration::from_secs(u64::try_from(refresh.minimum_seconds)?),
            timeout: positive_seconds("GATEWAY_HEALTH_CHECK_TIMEOUT", 30.0)?,
            failure_threshold: u32::try_from(threshold).ok(),
            concurrency,
            auto_refresh: flag("AUTO_REFRESH_SERVERS")?.unwrap_or(false),
        })
    }

    pub fn gateway_lifecycle() -> Result<Option<GatewayLifecycle>, Box<dyn Error + Send + Sync>> {
        if !flag("GATEWAY_ASYNC_LIFECYCLE_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        Ok(Some(GatewayLifecycle {
            poll_interval: positive_seconds("GATEWAY_ASYNC_LIFECYCLE_POLL_INTERVAL", 5.0)?,
            attempt_timeout: positive_seconds("GATEWAY_ASYNC_LIFECYCLE_ATTEMPT_TIMEOUT", 30.0)?,
            lease: positive_seconds("GATEWAY_ASYNC_LIFECYCLE_LEASE_SECONDS", 90.0)?,
            concurrency: parse("MAX_CONCURRENT_HEALTH_CHECKS", 10usize)?.max(1),
        }))
    }

    pub fn root_settings() -> Result<RootSettings, Box<dyn Error + Send + Sync>> {
        let defaults = value("DEFAULT_ROOTS", "[]")?;
        Ok(RootSettings {
            network_schemes: allowlist("ROOT_ALLOWED_SCHEMES")?,
            file_enabled: flag("ROOT_ALLOW_FILE_SCHEME")?.unwrap_or(false),
            file_prefixes: allowlist("ROOT_ALLOWED_FILE_PREFIXES")?,
            defaults: serde_json::from_str(&defaults).map_err(|_| "invalid DEFAULT_ROOTS")?,
        })
    }

    pub fn max_prompt_bytes() -> Result<usize, Box<dyn Error + Send + Sync>> {
        let bytes = parse("CONTENT_MAX_PROMPT_SIZE", 10240)?;
        if !(512..=1048576).contains(&bytes) {
            return Err("invalid CONTENT_MAX_PROMPT_SIZE".into());
        }
        Ok(bytes)
    }

    pub fn tool_preview_enabled() -> Result<bool, Box<dyn Error + Send + Sync>> {
        Ok(flag("MCPGATEWAY_TOOL_PREVIEW_ENABLED")?.unwrap_or(true))
    }

    pub fn virtual_server_base() -> Result<String, Box<dyn Error + Send + Sync>> {
        let domain = value("APP_DOMAIN", "http://localhost:4444")?;
        let url = reqwest::Url::parse(&domain).map_err(|_| "invalid APP_DOMAIN")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err("invalid APP_DOMAIN".into());
        }
        let root = value("APP_ROOT_PATH", "")?;
        let root = root.trim_matches('/');
        let base = url.as_str().trim_end_matches('/');
        Ok(if root.is_empty() || base.ends_with(&format!("/{root}")) {
            base.to_owned()
        } else {
            format!("{base}/{root}")
        })
    }

    pub fn server_oauth_metadata() -> Result<(bool, u32, bool), Box<dyn Error + Send + Sync>> {
        Ok((
            flag("WELL_KNOWN_ENABLED")?.unwrap_or(true),
            parse("WELL_KNOWN_CACHE_MAX_AGE", 3600)?,
            flag("SSRF_ALLOW_LOCALHOST")?.unwrap_or(false),
        ))
    }

    pub fn gateway_listeners(
        &self,
    ) -> Result<Option<GatewayListeners>, Box<dyn Error + Send + Sync>> {
        if !flag("GATEWAY_MODERN_LISTENERS_ENABLED")?.unwrap_or(false) {
            return Ok(None);
        }
        let path = env::var_os("PRIMARY_WORKER_LOCK_PATH")
            .filter(|path| !path.is_empty())
            .map_or_else(
                || env::temp_dir().join(format!("mcpgw_plugin_primary_{}.lock", self.port)),
                Into::into,
            );
        let election = match value("PRIMARY_WORKER_ELECTION_BACKEND", "filelock")?.as_str() {
            "filelock" => ListenerElection::File(path),
            "redis" => {
                let lease = positive_seconds("PRIMARY_WORKER_LEASE_TTL", 15.0)?;
                let heartbeat = positive_seconds("PRIMARY_WORKER_HEARTBEAT_INTERVAL", 5.0)?;
                if heartbeat >= lease / 2 {
                    return Err(
                        "PRIMARY_WORKER_HEARTBEAT_INTERVAL must be less than half the lease TTL"
                            .into(),
                    );
                }
                let file_fallback =
                    match value("PRIMARY_WORKER_REDIS_UNAVAILABLE_POLICY", "fail_closed")?.as_str()
                    {
                        "fail_closed" => None,
                        "filelock_fallback" => Some(path),
                        _ => return Err("invalid PRIMARY_WORKER_REDIS_UNAVAILABLE_POLICY".into()),
                    };
                ListenerElection::Redis {
                    connection: self.redis.clone(),
                    key: value("PRIMARY_WORKER_REDIS_KEY", "mcpgw:primary_worker")?,
                    lease,
                    heartbeat,
                    file_fallback,
                }
            }
            _ => return Err("invalid PRIMARY_WORKER_ELECTION_BACKEND".into()),
        };
        Ok(Some(GatewayListeners { election }))
    }

    pub fn resource_limits() -> Result<ResourceLimits, Box<dyn Error + Send + Sync>> {
        let mut limits = ResourceLimits::default();
        limits.max_bytes = parse("CONTENT_MAX_RESOURCE_SIZE", limits.max_bytes)?;
        if !(1024..=10485760).contains(&limits.max_bytes) {
            return Err("invalid CONTENT_MAX_RESOURCE_SIZE".into());
        }
        limits.strict_mime = flag("CONTENT_STRICT_MIME_VALIDATION")?.unwrap_or(false);
        if env::var_os("CONTENT_ALLOWED_RESOURCE_MIMETYPES").is_some() {
            let configured = value("CONTENT_ALLOWED_RESOURCE_MIMETYPES", "[]")?;
            limits.allowed_mime = serde_json::from_str(&configured)
                .map_err(|_| "invalid CONTENT_ALLOWED_RESOURCE_MIMETYPES")?;
        }
        Ok(limits)
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
pub(crate) fn allowlist(name: &str) -> Result<HashSet<String>, Box<dyn Error + Send + Sync>> {
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
pub(crate) fn flag(name: &str) -> Result<Option<bool>, Box<dyn Error + Send + Sync>> {
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
pub(crate) fn value(name: &str, default: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    match env::var(name) {
        Ok(value) => Ok(value),
        Err(env::VarError::NotPresent) => Ok(default.to_owned()),
        Err(env::VarError::NotUnicode(_)) => Err(format!("invalid Unicode in {name}").into()),
    }
}

pub(crate) fn parse<T: FromStr>(name: &str, default: T) -> Result<T, Box<dyn Error + Send + Sync>> {
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
