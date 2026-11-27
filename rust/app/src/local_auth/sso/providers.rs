// SPDX-License-Identifier: Apache-2.0

use serde_json::Map;
use sqlx::types::Json as DbJson;

use super::*;
use crate::upstream_tls::TlsMaterial;

const READ: &str = "admin.sso_providers:read";
const CREATE: &str = "admin.sso_providers:create";
const UPDATE: &str = "admin.sso_providers:update";
const DELETE: &str = "admin.sso_providers:delete";

pub(super) async fn public_list(
    State(accounts): State<Arc<Accounts>>,
) -> Result<Json<Vec<Value>>, AccountError> {
    let values = accounts
        .database
        .enabled_sso_provider_names()
        .await?
        .into_iter()
        .map(|(id, name, display_name)| {
            json!({
                "id":id,"name":name,"display_name":display_name,"authorization_url":null,
            })
        })
        .collect();
    Ok(Json(values))
}

pub(super) async fn list(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<Value>>, AccountError> {
    require(&accounts, &principal, READ).await?;
    let values = accounts
        .database
        .sso_providers()
        .await?
        .into_iter()
        .map(|provider| provider.summary())
        .collect();
    Ok(Json(values))
}

pub(super) async fn read(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    require(&accounts, &principal, READ).await?;
    let provider = accounts
        .database
        .sso_provider(&id)
        .await?
        .ok_or_else(|| missing(&id))?;
    Ok(Json(provider.details()))
}

pub(super) async fn create(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Json(mut input): Json<CreateProvider>,
) -> Result<Json<Value>, AccountError> {
    require(&accounts, &principal, CREATE).await?;
    let settings = accounts.sso()?;
    if !valid_id(&input.id) {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid SSO provider identifier",
        ));
    }
    input.config.is_enabled = true;
    check_requested_audience(
        input.config.trusted_for_api_auth,
        input.config.api_audience.as_deref(),
    )?;
    settings.validate(&mut input.config)?;
    let secret = settings.encrypt(input.client_secret).await?;
    let duplicate = || {
        AccountError::detail(
            StatusCode::CONFLICT,
            format!("SSO provider '{}' already exists", input.id),
        )
    };
    match accounts
        .database
        .insert_sso_provider(&input.id, &input.config, &secret)
        .await
    {
        Ok(Some(provider)) => Ok(Json(provider.change(true))),
        Ok(None) => Err(duplicate()),
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => Err(duplicate()),
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn update(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    Json(mut patch): Json<Map<String, Value>>,
) -> Result<Json<Value>, AccountError> {
    require(&accounts, &principal, UPDATE).await?;
    let settings = accounts.sso()?;
    patch.retain(|_, value| !value.is_null());
    let client_secret = patch
        .remove("client_secret")
        .map(|value| serde_json::from_value::<String>(value).map_err(|_| invalid()))
        .transpose()?;
    if patch.is_empty() && client_secret.is_none() {
        return Err(AccountError::bad_request("No update data provided"));
    }
    check_requested_audience(
        patch.get("trusted_for_api_auth") == Some(&Value::Bool(true)),
        patch.get("api_audience").and_then(Value::as_str),
    )?;
    let secret = match client_secret {
        Some(secret) => Some(settings.encrypt(secret).await?),
        None => None,
    };
    let result = accounts
        .database
        .update_sso_provider(&id, &patch, secret, settings)
        .await?;
    Ok(Json(result.ok_or_else(|| missing(&id))?.change(false)))
}

pub(super) async fn delete(
    State(accounts): State<Arc<Accounts>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AccountError> {
    require(&accounts, &principal, DELETE).await?;
    if !accounts.database.delete_sso_provider(&id).await? {
        return Err(missing(&id));
    }
    Ok(Json(
        json!({"message":format!("SSO provider '{id}' deleted successfully")}),
    ))
}

async fn require(
    accounts: &Accounts,
    principal: &Principal,
    permission: &str,
) -> Result<(), AccountError> {
    if !accounts
        .access
        .allows(principal, permission, RoleContext::Global, true)
        .await?
    {
        return Err(AccountError::detail(StatusCode::FORBIDDEN, "Access denied"));
    }
    Ok(())
}

fn missing(id: &str) -> AccountError {
    AccountError::detail(
        StatusCode::NOT_FOUND,
        format!("SSO provider '{id}' not found"),
    )
}

fn invalid() -> AccountError {
    AccountError::bad_request("Invalid SSO provider configuration")
}

fn check_requested_audience(trusted: bool, audience: Option<&str>) -> Result<(), AccountError> {
    if trusted && audience.is_none_or(|audience| audience.trim().is_empty()) {
        return Err(AccountError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            "api_audience is required when trusted_for_api_auth is enabled (prevents confused-deputy token acceptance)",
        ));
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 50
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Deserialize)]
pub(super) struct CreateProvider {
    id: String,
    client_secret: String,
    #[serde(flatten)]
    config: ProviderConfig,
}

#[derive(Deserialize, Serialize, PartialEq, sqlx::FromRow)]
pub(super) struct ProviderConfig {
    name: String,
    display_name: String,
    pub(super) provider_type: String,
    #[serde(default = "yes")]
    pub(super) is_enabled: bool,
    pub(super) client_id: String,
    pub(super) authorization_url: String,
    pub(super) token_url: String,
    pub(super) userinfo_url: String,
    pub(super) issuer: Option<String>,
    pub(super) jwks_uri: Option<String>,
    pub(super) ca_certificate: Option<String>,
    #[serde(default)]
    pub(super) trusted_for_api_auth: bool,
    pub(super) api_audience: Option<String>,
    #[serde(default)]
    pub(super) trusted_domains: DbJson<Vec<String>>,
    #[serde(default = "default_scope")]
    pub(super) scope: String,
    #[serde(default = "yes")]
    pub(super) auto_create_users: bool,
    #[serde(default)]
    pub(super) team_mapping: DbJson<Map<String, Value>>,
    #[serde(default)]
    pub(super) provider_metadata: DbJson<Map<String, Value>>,
}

fn yes() -> bool {
    true
}
fn default_scope() -> String {
    "openid profile email".to_owned()
}

impl SsoSettings {
    fn validate(&self, config: &mut ProviderConfig) -> Result<(), AccountError> {
        if [
            (&config.name, 100),
            (&config.display_name, 100),
            (&config.client_id, 255),
        ]
        .into_iter()
        .any(|(value, limit)| {
            value.trim().is_empty() || value.len() > limit || value.chars().any(char::is_control)
        }) || !matches!(config.provider_type.as_str(), "oidc" | "oauth2")
            || config.scope.len() > 200
            || config
                .api_audience
                .as_ref()
                .is_some_and(|audience| audience.len() > 500)
            || config.trusted_for_api_auth
                && config
                    .api_audience
                    .as_deref()
                    .is_none_or(|audience| audience.trim().is_empty())
        {
            return Err(invalid());
        }
        for endpoint in [
            Some(config.authorization_url.as_str()),
            Some(config.token_url.as_str()),
            Some(config.userinfo_url.as_str()),
            config.issuer.as_deref(),
            config.jwks_uri.as_deref(),
        ]
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        {
            if endpoint.len() > 500 || self.upstream.check_endpoint(endpoint).is_err() {
                return Err(invalid());
            }
        }
        if let Some(issuer) = config
            .issuer
            .as_deref()
            .filter(|issuer| !issuer.trim().is_empty())
            && !self.allowed_issuers.is_empty()
            && !self.allowed_issuers.iter().any(|allowed| {
                allowed
                    .trim_end_matches('/')
                    .eq_ignore_ascii_case(issuer.trim().trim_end_matches('/'))
            })
        {
            return Err(invalid());
        }
        config.ca_certificate = config
            .ca_certificate
            .take()
            .and_then(|value| (!value.trim().is_empty()).then_some(value));
        if let Some(pem) = config.ca_certificate.as_deref()
            && (pem.len() > 65536 || TlsMaterial::from_pem(Some(pem), None, None).is_err())
        {
            return Err(AccountError::bad_request("Invalid CA certificate"));
        }
        Ok(())
    }
}

#[derive(sqlx::FromRow)]
pub(super) struct Provider {
    pub(super) id: String,
    #[sqlx(flatten)]
    pub(super) config: ProviderConfig,
    pub(super) client_secret_encrypted: String,
    created_at: String,
    pub(super) updated_at: String,
}

impl Provider {
    fn change(&self, created: bool) -> Value {
        let mut result = json!({
            "id":self.id,"name":self.config.name,"display_name":self.config.display_name,
            "provider_type":self.config.provider_type,"is_enabled":self.config.is_enabled,
        });
        let (key, time) = if created {
            ("created_at", &self.created_at)
        } else {
            ("updated_at", &self.updated_at)
        };
        result[key] = time.replacen(' ', "T", 1).into();
        result
    }

    fn summary(&self) -> Value {
        let mut value = self.change(false);
        value["created_at"] = self.created_at.replacen(' ', "T", 1).into();
        value["trusted_domains"] = json!(self.config.trusted_domains);
        value["auto_create_users"] = self.config.auto_create_users.into();
        value["trusted_for_api_auth"] = self.config.trusted_for_api_auth.into();
        value["api_audience"] = json!(self.config.api_audience);
        value
    }

    fn details(&self) -> Value {
        let mut value = json!(self.config);
        value["id"] = self.id.as_str().into();
        value["created_at"] = self.created_at.replacen(' ', "T", 1).into();
        value["updated_at"] = self.updated_at.replacen(' ', "T", 1).into();
        value
    }

    fn apply_patch(
        &mut self,
        update: &Map<String, Value>,
        secret: Option<String>,
        settings: &SsoSettings,
    ) -> Result<(), AccountError> {
        let Value::Object(mut fields) = json!(self.config) else {
            unreachable!()
        };
        let mut changed = false;
        for (key, value) in update {
            if let Some(field) = fields.get_mut(key) {
                field.clone_from(value);
                changed = true;
            }
        }
        if !changed && secret.is_none() {
            return Err(AccountError::bad_request("No update data provided"));
        }
        let mut config = serde_json::from_value(Value::Object(fields)).map_err(|_| invalid())?;
        settings.validate(&mut config)?;
        self.config = config;
        if let Some(secret) = secret {
            self.client_secret_encrypted = secret;
        }
        Ok(())
    }
}

macro_rules! provider_columns {
    () => {
        "id,name,display_name,provider_type,is_enabled,client_id,client_secret_encrypted,
         authorization_url,token_url,userinfo_url,issuer,jwks_uri,ca_certificate,
         COALESCE(trusted_for_api_auth,FALSE) AS trusted_for_api_auth,api_audience,trusted_domains,
         scope,auto_create_users,team_mapping,provider_metadata,
         CAST(created_at AS TEXT) AS created_at,CAST(updated_at AS TEXT) AS updated_at"
    };
}

const GET: &str = concat!(
    "SELECT ",
    provider_columns!(),
    " FROM sso_providers WHERE id=$1"
);
const GET_FOR_UPDATE: &str = concat!(
    "SELECT ",
    provider_columns!(),
    " FROM sso_providers WHERE id=$1 FOR UPDATE"
);
const LIST: &str = concat!(
    "SELECT ",
    provider_columns!(),
    " FROM sso_providers ORDER BY created_at,id"
);
macro_rules! write_sql {
    ($stamp:literal) => { concat!(
    "INSERT INTO sso_providers(id,name,display_name,provider_type,is_enabled,client_id,client_secret_encrypted,
       authorization_url,token_url,userinfo_url,issuer,jwks_uri,ca_certificate,trusted_for_api_auth,
       api_audience,trusted_domains,scope,auto_create_users,team_mapping,provider_metadata,created_at,updated_at)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,",
     $stamp, ",", $stamp, ")
     ON CONFLICT(id) DO UPDATE SET name=excluded.name,display_name=excluded.display_name,
       provider_type=excluded.provider_type,is_enabled=excluded.is_enabled,client_id=excluded.client_id,
       client_secret_encrypted=excluded.client_secret_encrypted,authorization_url=excluded.authorization_url,
       token_url=excluded.token_url,userinfo_url=excluded.userinfo_url,issuer=excluded.issuer,jwks_uri=excluded.jwks_uri,
       ca_certificate=excluded.ca_certificate,trusted_for_api_auth=excluded.trusted_for_api_auth,
       api_audience=excluded.api_audience,trusted_domains=excluded.trusted_domains,scope=excluded.scope,
       auto_create_users=excluded.auto_create_users,team_mapping=excluded.team_mapping,
       provider_metadata=excluded.provider_metadata,updated_at=excluded.updated_at
     WHERE $21 RETURNING ", provider_columns!()
    ) };
}

const SQLITE_WRITE: &str = write_sql!("$22");
const POSTGRES_WRITE: &str = write_sql!("CAST(CAST($22 AS TEXT) AS TIMESTAMPTZ)");

macro_rules! bind_provider {
    ($sql:ident,$id:expr,$config:expr,$secret:expr,$update:expr) => {{
        let config = $config;
        sqlx::query_as::<_, Provider>($sql)
            .bind($id)
            .bind(&config.name)
            .bind(&config.display_name)
            .bind(&config.provider_type)
            .bind(config.is_enabled)
            .bind(&config.client_id)
            .bind($secret)
            .bind(&config.authorization_url)
            .bind(&config.token_url)
            .bind(&config.userinfo_url)
            .bind(config.issuer.as_deref())
            .bind(config.jwks_uri.as_deref())
            .bind(config.ca_certificate.as_deref())
            .bind(config.trusted_for_api_auth)
            .bind(config.api_audience.as_deref())
            .bind(&config.trusted_domains)
            .bind(&config.scope)
            .bind(config.auto_create_users)
            .bind(&config.team_mapping)
            .bind(&config.provider_metadata)
            .bind($update)
            .bind(Timestamp::now().to_string())
    }};
}

impl Database {
    async fn enabled_sso_provider_names(
        &self,
    ) -> Result<Vec<(String, String, String)>, sqlx::Error> {
        const SQL: &str = "SELECT id,name,display_name FROM sso_providers WHERE is_enabled ORDER BY created_at,id";
        match self {
            Self::Sqlite(pool) => sqlx::query_as(SQL).fetch_all(pool).await,
            Self::Postgres(pool) => sqlx::query_as(SQL).fetch_all(pool).await,
        }
    }

    async fn sso_providers(&self) -> Result<Vec<Provider>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => sqlx::query_as(LIST).fetch_all(pool).await,
            Self::Postgres(pool) => sqlx::query_as(LIST).fetch_all(pool).await,
        }
    }

    pub(super) async fn sso_provider(&self, id: &str) -> Result<Option<Provider>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => sqlx::query_as(GET).bind(id).fetch_optional(pool).await,
            Self::Postgres(pool) => sqlx::query_as(GET).bind(id).fetch_optional(pool).await,
        }
    }

    pub(super) async fn trusted_sso_provider(
        &self,
        issuer: &str,
    ) -> Result<Option<Provider>, sqlx::Error> {
        const SQL: &str = concat!(
            "SELECT ",
            provider_columns!(),
            " FROM sso_providers WHERE is_enabled AND trusted_for_api_auth
               AND rtrim(issuer,'/')=$1 ORDER BY id LIMIT 2"
        );
        let issuer = issuer.trim_end_matches('/');
        let mut rows = match self {
            Self::Sqlite(pool) => sqlx::query_as(SQL).bind(issuer).fetch_all(pool).await?,
            Self::Postgres(pool) => sqlx::query_as(SQL).bind(issuer).fetch_all(pool).await?,
        };
        Ok(if rows.len() == 1 { rows.pop() } else { None })
    }

    async fn insert_sso_provider(
        &self,
        id: &str,
        config: &ProviderConfig,
        secret: &str,
    ) -> Result<Option<Provider>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                bind_provider!(SQLITE_WRITE, id, config, secret, false)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                bind_provider!(POSTGRES_WRITE, id, config, secret, false)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    async fn update_sso_provider(
        &self,
        id: &str,
        patch: &Map<String, Value>,
        secret: Option<String>,
        settings: &SsoSettings,
    ) -> Result<Option<Provider>, AccountError> {
        macro_rules! update {
            ($tx:ident,$query:expr,$sql:ident) => {{
                let Some(mut provider) = sqlx::query_as::<_, Provider>($query)
                    .bind(id)
                    .fetch_optional(&mut *$tx)
                    .await?
                else {
                    return Ok(None);
                };
                provider.apply_patch(patch, secret, settings)?;
                let updated = bind_provider!(
                    $sql,
                    id,
                    &provider.config,
                    &provider.client_secret_encrypted,
                    true
                )
                .fetch_one(&mut *$tx)
                .await?;
                sqlx::query("DELETE FROM sso_auth_sessions WHERE provider_id=$1")
                    .bind(id)
                    .execute(&mut *$tx)
                    .await?;
                $tx.commit().await?;
                Ok(Some(updated))
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                update!(tx, GET, SQLITE_WRITE)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                update!(tx, GET_FOR_UPDATE, POSTGRES_WRITE)
            }
        }
    }

    async fn delete_sso_provider(&self, id: &str) -> Result<bool, sqlx::Error> {
        macro_rules! delete {
            ($tx:ident) => {{
                sqlx::query("DELETE FROM sso_auth_sessions WHERE provider_id=$1")
                    .bind(id)
                    .execute(&mut *$tx)
                    .await?;
                let rows = sqlx::query("DELETE FROM sso_providers WHERE id=$1")
                    .bind(id)
                    .execute(&mut *$tx)
                    .await?
                    .rows_affected();
                $tx.commit().await?;
                Ok(rows != 0)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                delete!(tx)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT id FROM sso_providers WHERE id=$1 FOR UPDATE")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                delete!(tx)
            }
        }
    }
}

pub(in crate::local_auth) mod bootstrap;
