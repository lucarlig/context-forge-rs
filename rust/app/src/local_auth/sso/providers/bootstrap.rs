// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use url::{Position, Url};

use super::*;
use crate::config::{allowlist, flag, parse, value};
use crate::database::observed;

const DEFAULT_SCOPE: &str = "openid profile email";
type ConfigError = Box<dyn Error + Send + Sync>;

pub(in crate::local_auth) async fn bootstrap(database: &Database, settings: &SsoSettings) {
    if let Err(error) = load(database, settings).await {
        tracing::warn!(%error, "could not load SSO providers from configuration");
    }
}

async fn load(database: &Database, settings: &SsoSettings) -> Result<(), ConfigError> {
    let mut domains: Vec<_> = allowlist("SSO_TRUSTED_DOMAINS")?.into_iter().collect();
    domains.sort_unstable();
    let auto_create = flag("SSO_AUTO_CREATE_USERS")?.unwrap_or(true);
    let auto_disable = flag("SSO_AUTO_DISABLE_UNCONFIGURED_PROVIDERS")?.unwrap_or(false);
    let mut configured = HashSet::new();
    for (kind, prefix, display) in [
        ("github", "SSO_GITHUB", "GitHub"),
        ("google", "SSO_GOOGLE", "Google"),
        ("ibm_verify", "SSO_IBM_VERIFY", "IBM Security Verify"),
        ("okta", "SSO_OKTA", "Okta"),
        ("entra", "SSO_ENTRA", "Microsoft Entra ID"),
        ("keycloak", "SSO_KEYCLOAK", "Keycloak"),
        ("adfs", "SSO_ADFS", "ADFS Login"),
        ("generic", "SSO_GENERIC", ""),
    ] {
        let env = ProviderEnv(prefix);
        if !env.enabled("ENABLED", false)? {
            continue;
        }
        let Some(client_id) = env.optional("CLIENT_ID")? else {
            continue;
        };
        let id = if kind == "generic" {
            let Some(id) = env.optional("PROVIDER_ID")? else {
                continue;
            };
            id
        } else {
            kind.to_owned()
        };
        if !valid_id(&id) {
            tracing::warn!(
                provider = kind,
                "invalid configured SSO provider identifier"
            );
            continue;
        }
        configured.insert(id.clone());
        let display = if kind == "generic" {
            id.split_inclusive(['-', '_'])
                .map(|word| {
                    word.chars().next().map_or_else(String::new, |first| {
                        format!(
                            "{}{}",
                            first.to_uppercase(),
                            word[first.len_utf8()..].to_lowercase()
                        )
                    })
                })
                .collect::<String>()
        } else {
            display.to_owned()
        };
        let mut config = ProviderConfig {
            name: id.clone(),
            display_name: display,
            provider_type: "oidc".to_owned(),
            is_enabled: true,
            client_id,
            authorization_url: String::new(),
            token_url: String::new(),
            userinfo_url: String::new(),
            issuer: None,
            jwks_uri: None,
            ca_certificate: None,
            trusted_for_api_auth: false,
            api_audience: None,
            trusted_domains: DbJson(domains.clone()),
            scope: DEFAULT_SCOPE.to_owned(),
            auto_create_users: auto_create,
            team_mapping: DbJson(Map::new()),
            provider_metadata: DbJson(Map::new()),
        };
        if let Err(error) = configure(kind, &env, &mut config, settings).await {
            tracing::warn!(provider = kind, %error, "could not configure SSO provider");
            continue;
        }
        if settings.validate(&mut config).is_err() {
            tracing::warn!(provider = kind, "invalid configured SSO endpoints");
            continue;
        }
        let secret = Zeroizing::new(env.get("CLIENT_SECRET", "")?);
        database
            .seed_sso_provider(&id, config, secret, settings)
            .await?;
    }
    database
        .reconcile_sso_providers(&configured, auto_disable, settings)
        .await?;
    Ok(())
}

struct ProviderEnv(&'static str);

impl ProviderEnv {
    fn get(&self, name: &str, default: &str) -> Result<String, ConfigError> {
        value(&format!("{}_{name}", self.0), default)
    }

    fn optional(&self, name: &str) -> Result<Option<String>, ConfigError> {
        let value = self.get(name, "")?;
        Ok((!value.trim().is_empty()).then_some(value))
    }

    fn enabled(&self, name: &str, default: bool) -> Result<bool, ConfigError> {
        Ok(flag(&format!("{}_{name}", self.0))?.unwrap_or(default))
    }

    fn role_mappings(&self) -> Result<Map<String, Value>, ConfigError> {
        mappings(&format!("{}_ROLE_MAPPINGS", self.0))
    }
}

fn mappings(name: &str) -> Result<Map<String, Value>, ConfigError> {
    serde_json::from_str(&value(name, "{}")?).map_err(|_| format!("invalid {name}").into())
}

fn endpoints(
    config: &mut ProviderConfig,
    issuer: Option<&str>,
    authorize: &str,
    token: &str,
    userinfo: &str,
) {
    config.issuer = issuer.map(str::to_owned);
    authorize.clone_into(&mut config.authorization_url);
    token.clone_into(&mut config.token_url);
    userinfo.clone_into(&mut config.userinfo_url);
}

async fn configure(
    kind: &str,
    env: &ProviderEnv,
    config: &mut ProviderConfig,
    settings: &SsoSettings,
) -> Result<(), ConfigError> {
    match kind {
        "github" => {
            config.provider_type = "oauth2".to_owned();
            config.scope = "user:email".to_owned();
            endpoints(
                config,
                None,
                "https://github.com/login/oauth/authorize",
                "https://github.com/login/oauth/access_token",
                "https://api.github.com/user",
            );
        }
        "google" => endpoints(
            config,
            Some("https://accounts.google.com"),
            "https://accounts.google.com/o/oauth2/auth",
            "https://oauth2.googleapis.com/token",
            "https://openidconnect.googleapis.com/v1/userinfo",
        ),
        "ibm_verify" => {
            let base = env.get("ISSUER", "https://tenant.verify.ibm.com")?;
            let issuer = format!("{}/oidc/endpoint/default", base.trim_end_matches('/'));
            endpoints(
                config,
                Some(&issuer),
                &format!("{issuer}/authorize"),
                &format!("{issuer}/token"),
                &format!("{issuer}/userinfo"),
            );
            config.team_mapping = DbJson(mappings("IBM_VERIFY_GROUP_MAPPING")?);
        }
        "okta" => {
            let base = env.get("ISSUER", "https://company.okta.com")?;
            let issuer = format!("{}/oauth2/default", base.trim_end_matches('/'));
            endpoints(
                config,
                Some(&issuer),
                &format!("{issuer}/v1/authorize"),
                &format!("{issuer}/v1/token"),
                &format!("{issuer}/v1/userinfo"),
            );
            config.scope = env.get("SCOPE", DEFAULT_SCOPE)?;
            config.team_mapping = DbJson(mappings("OKTA_GROUP_MAPPING")?);
        }
        "entra" => {
            let tenant = env.optional("TENANT_ID")?.ok_or("missing Entra tenant")?;
            if !tenant
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
            {
                return Err("invalid Entra tenant".into());
            }
            let base = format!("https://login.microsoftonline.com/{tenant}");
            endpoints(
                config,
                Some(&format!("{base}/v2.0")),
                &format!("{base}/oauth2/v2.0/authorize"),
                &format!("{base}/oauth2/v2.0/token"),
                "https://graph.microsoft.com/oidc/userinfo",
            );
            config.scope = "openid profile email User.Read".to_owned();
            config.provider_metadata.0 = metadata(json!({
                "groups_claim":env.get("GROUPS_CLAIM","groups")?,
                "role_mappings":env.role_mappings()?,
                "graph_api_enabled":env.enabled("GRAPH_API_ENABLED",true)?,
                "graph_api_timeout":parse::<u64>("SSO_ENTRA_GRAPH_API_TIMEOUT",10)?,
                "graph_api_max_groups":parse::<usize>("SSO_ENTRA_GRAPH_API_MAX_GROUPS",0)?,
            }));
        }
        "keycloak" => configure_keycloak(env, config, settings).await?,
        "adfs" => {
            let token = env.get("TOKEN_URL", "")?;
            endpoints(
                config,
                env.optional("ISSUER")?.as_deref(),
                &env.get("AUTHORIZATION_URL", "")?,
                &token,
                &token,
            );
            config.scope = env.get("SCOPE", DEFAULT_SCOPE)?;
            config.display_name = env.get("DISPLAY_NAME", "ADFS Login")?;
        }
        "generic" => {
            endpoints(
                config,
                env.optional("ISSUER")?.as_deref(),
                &env.get("AUTHORIZATION_URL", "")?,
                &env.get("TOKEN_URL", "")?,
                &env.get("USERINFO_URL", "")?,
            );
            config.jwks_uri = env.optional("JWKS_URI")?;
            config.scope = env.get("SCOPE", DEFAULT_SCOPE)?;
            config.display_name = env.get("DISPLAY_NAME", &config.display_name)?;
            let mut admins: Vec<_> = allowlist("SSO_GENERIC_ADMIN_GROUPS")?.into_iter().collect();
            admins.sort_unstable();
            config.provider_metadata.0 = metadata(json!({
                "groups_claim":env.get("GROUPS_CLAIM","groups")?,
                "admin_groups":admins,
                "role_mappings":env.role_mappings()?,
                "default_role":env.optional("DEFAULT_ROLE")?,
                "sync_roles":env.enabled("SYNC_ROLES_ON_LOGIN",true)?,
            }));
        }
        _ => unreachable!(),
    }
    if config.authorization_url.is_empty()
        || config.token_url.is_empty()
        || config.userinfo_url.is_empty()
    {
        return Err("missing required provider endpoint".into());
    }
    Ok(())
}

fn metadata(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(value) => value,
        _ => unreachable!(),
    }
}

#[derive(Deserialize)]
struct DiscoveredProvider {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
}

async fn configure_keycloak(
    env: &ProviderEnv,
    config: &mut ProviderConfig,
    settings: &SsoSettings,
) -> Result<(), ConfigError> {
    let base = env
        .optional("BASE_URL")?
        .ok_or("missing Keycloak base URL")?;
    let public = env.optional("PUBLIC_BASE_URL")?;
    let realm = env.get("REALM", "master")?;
    let mut origin = Url::parse(&base)?;
    if origin.query().is_some() || origin.fragment().is_some() || realm.trim().is_empty() {
        return Err("invalid Keycloak discovery URL".into());
    }
    let public_origin = public.as_deref().map(Url::parse).transpose()?;
    origin
        .path_segments_mut()
        .map_err(|_| "invalid Keycloak base URL")?
        .pop_if_empty()
        .extend(["realms", &realm, ".well-known", "openid-configuration"]);
    let discovered: DiscoveredProvider = settings
        .upstream
        .oauth_document(origin.as_str(), None, None, None)
        .await?;
    let browser = |endpoint: &Url| match &public_origin {
        Some(public) => rewrite_origin(endpoint, public),
        None => endpoint.to_string(),
    };
    let jwks = rewrite_origin(&Url::parse(&discovered.jwks_uri)?, &origin);
    endpoints(
        config,
        Some(&browser(&Url::parse(&discovered.issuer)?)),
        &browser(&Url::parse(&discovered.authorization_endpoint)?),
        &rewrite_origin(&Url::parse(&discovered.token_endpoint)?, &origin),
        &rewrite_origin(&Url::parse(&discovered.userinfo_endpoint)?, &origin),
    );
    config.jwks_uri = Some(jwks.clone());
    config.display_name = format!("Keycloak ({realm})");
    config.provider_metadata.0 = metadata(json!({
        "realm":realm,"base_url":base,"public_base_url":public,
        "map_realm_roles":env.enabled("MAP_REALM_ROLES",true)?,
        "map_client_roles":env.enabled("MAP_CLIENT_ROLES",false)?,
        "username_claim":env.get("USERNAME_CLAIM","preferred_username")?,
        "email_claim":env.get("EMAIL_CLAIM","email")?,
        "groups_claim":env.get("GROUPS_CLAIM","groups")?,
        "jwks_uri":jwks,"role_mappings":env.role_mappings()?,
        "default_role":env.optional("DEFAULT_ROLE")?,
        "resolve_team_scope_to_personal_team":env.enabled("RESOLVE_TEAM_SCOPE_TO_PERSONAL_TEAM",false)?,
    }));
    Ok(())
}

fn rewrite_origin(endpoint: &Url, origin: &Url) -> String {
    format!(
        "{}{}",
        origin.origin().ascii_serialization(),
        &endpoint[Position::BeforePath..],
    )
}

impl Database {
    async fn seed_sso_provider(
        &self,
        id: &str,
        mut config: ProviderConfig,
        secret: Zeroizing<String>,
        settings: &SsoSettings,
    ) -> Result<(), ConfigError> {
        const MATCH: &str = concat!(
            "SELECT ",
            provider_columns!(),
            " FROM sso_providers WHERE id=$1 OR name=$2
              ORDER BY CASE WHEN id=$1 THEN 0 ELSE 1 END LIMIT 1"
        );
        let vault = settings
            .vault
            .as_ref()
            .ok_or("SSO encryption key is unavailable")?;
        macro_rules! seed {
            ($tx:ident,$sql:ident) => {{
                let existing = sqlx::query_as::<_, Provider>(MATCH)
                    .bind(id)
                    .bind(&config.name)
                    .fetch_optional(observed(&mut *$tx))
                    .await?;
                let mut target = id;
                let mut same_secret = None;
                if let Some(old) = &existing {
                    target = &old.id;
                    merge_provider_defaults(&mut config, &old.config);
                    if vault
                        .open(old.client_secret_encrypted.clone())
                        .await
                        .is_ok_and(|clear| clear.as_str() == secret.as_str())
                    {
                        if config == old.config {
                            return Ok(());
                        }
                        same_secret = Some(old.client_secret_encrypted.clone());
                    }
                }
                let encrypted = match same_secret {
                    Some(encrypted) => encrypted,
                    None => vault
                        .seal(secret)
                        .await
                        .map_err(|_| "could not encrypt SSO client credentials")?,
                };
                bind_provider!($sql, target, &config, &encrypted, true)
                    .fetch_one(observed(&mut *$tx))
                    .await?;
                if existing.is_some() {
                    sqlx::query("DELETE FROM sso_auth_sessions WHERE provider_id=$1")
                        .bind(target)
                        .execute(observed(&mut *$tx))
                        .await?;
                }
                $tx.commit().await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                seed!(tx, SQLITE_WRITE);
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("LOCK TABLE sso_providers IN SHARE ROW EXCLUSIVE MODE")
                    .execute(observed(&mut *tx))
                    .await?;
                seed!(tx, POSTGRES_WRITE);
            }
        }
        Ok(())
    }

    async fn reconcile_sso_providers(
        &self,
        configured: &HashSet<String>,
        auto_disable: bool,
        settings: &SsoSettings,
    ) -> Result<(), ConfigError> {
        for provider in self.sso_providers().await? {
            let mut change = Map::new();
            if auto_disable
                && provider.config.is_enabled
                && !configured.contains(&provider.id)
                && !configured.contains(&provider.config.name)
            {
                change.insert("is_enabled".to_owned(), false.into());
            }
            if provider.config.trusted_for_api_auth
                && provider
                    .config
                    .api_audience
                    .as_deref()
                    .is_none_or(|aud| aud.trim().is_empty())
            {
                change.insert("trusted_for_api_auth".to_owned(), false.into());
            }
            if !change.is_empty() {
                self.update_sso_provider(&provider.id, &change, None, settings)
                    .await
                    .map_err(|_| "could not reconcile SSO provider configuration")?;
            }
        }
        Ok(())
    }
}

fn merge_provider_defaults(config: &mut ProviderConfig, current: &ProviderConfig) {
    config
        .provider_metadata
        .0
        .extend(current.provider_metadata.0.clone());
    if config.scope == DEFAULT_SCOPE && !current.scope.is_empty() {
        config.scope.clone_from(&current.scope);
    }
    if config.team_mapping.is_empty() {
        config.team_mapping.0.clone_from(&current.team_mapping.0);
    }
    if config.jwks_uri.is_none() {
        config.jwks_uri.clone_from(&current.jwks_uri);
    }
    config.ca_certificate.clone_from(&current.ca_certificate);
    config.api_audience.clone_from(&current.api_audience);
    config.trusted_for_api_auth = current.trusted_for_api_auth
        && config
            .api_audience
            .as_deref()
            .is_some_and(|aud| !aud.trim().is_empty());
}
