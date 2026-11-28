// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use zeroize::Zeroize;

use super::{flow::code_config, storage::OAuthGateway, *};
use crate::database::observed;
use crate::oauth_client::{IssuerMetadata, validate_endpoint};

pub(super) async fn configured_client(
    service: &GatewayService,
    principal: &Principal,
    id: &str,
) -> Result<(OAuthGateway, OAuthConfig), CatalogApiError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(35);
    let claim = Uuid::new_v4().simple().to_string();
    loop {
        let mut gateway = visible_gateway(service, principal, id).await?;
        let mut config = code_config(service, &gateway).await?;
        if config.client_id().is_some() {
            return Ok((gateway, config));
        }
        let issuer = config
            .issuer()
            .map(|issuer| issuer.trim_end_matches('/').to_owned())
            .ok_or_else(|| {
                CatalogApiError::detail(
                    StatusCode::BAD_REQUEST,
                    "OAuth configuration missing client_id",
                )
            })?;
        let redirect = config
            .redirect_uri()
            .unwrap_or(&service.gateway_oauth.redirect_uri)
            .to_owned();
        super::flow::valid_redirect(&redirect).ok_or_else(|| {
            CatalogApiError::detail(StatusCode::BAD_REQUEST, "OAuth callback URL is invalid")
        })?;
        if service
            .database
            .claim_client_registration(&gateway, &claim)
            .await?
        {
            let result = configure_missing_client(
                service,
                &mut gateway,
                &mut config,
                &issuer,
                &redirect,
                &claim,
            )
            .await;
            if let Err(error) = service
                .database
                .release_client_registration(&gateway.id, &claim)
                .await
            {
                tracing::warn!(%error, "could not release OAuth client registration claim");
            }
            result?;
            return Ok((gateway, config));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(CatalogApiError::detail(
                StatusCode::CONFLICT,
                "OAuth client registration is in progress",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn configure_missing_client(
    service: &GatewayService,
    gateway: &mut OAuthGateway,
    config: &mut OAuthConfig,
    issuer: &str,
    redirect: &str,
    claim: &str,
) -> Result<(), CatalogApiError> {
    let settings = &service.gateway_oauth;
    let upstream = service
        .upstream
        .with_timeout_cap(settings.request_timeout.min(Duration::from_secs(30)));
    let guard = settings.cimd.failed_guard(&settings.dcr, issuer, redirect);
    let method = config.registration_method();
    let force_cimd = method == Some("cimd");
    if force_cimd && let Some(reason) = guard {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            format!("CIMD registration is not permitted for this gateway ({reason})"),
        ));
    }
    let metadata = if method != Some("dcr")
        && guard.is_none()
        && (!force_cimd || !config.has_code_endpoints())
    {
        settings
            .issuer_metadata
            .discover(&upstream, issuer, settings.dcr.metadata_ttl)
            .await
            .ok()
    } else {
        None
    };
    if force_cimd
        || metadata.as_ref().is_some_and(|metadata| {
            metadata.client_id_metadata_document_supported == Some(Value::Bool(true))
        })
    {
        let failure = || {
            CatalogApiError::detail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to register OAuth client via CIMD",
            )
        };
        config
            .complete_registration_endpoints(&upstream, metadata.as_ref())
            .map_err(|_| failure())?;
        config.use_registered_client(
            settings.cimd.client_id.clone(),
            None,
            settings.cimd.auth_method().to_owned(),
            redirect.to_owned(),
            "cimd",
        );
        let vault = service
            .vault
            .as_ref()
            .ok_or_else(CatalogApiError::unavailable)?;
        let (encoded, _) = config.store(vault).await.map_err(|_| failure())?;
        return persist_config(service, gateway, claim, &encoded, None).await;
    }
    if !settings.dcr.enabled || !settings.dcr.auto_register {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "Gateway OAuth configuration is incomplete. Please provide client_id and client_secret, or enable registration: set CIMD_ENABLED=true for Client ID Metadata Documents, or DCR_ENABLED=true and DCR_AUTO_REGISTER_ON_MISSING_CREDENTIALS=true for Dynamic Client Registration.",
        ));
    }
    configure_dynamic_client(service, gateway, config, issuer, redirect, claim).await
}

async fn configure_dynamic_client(
    service: &GatewayService,
    gateway: &mut OAuthGateway,
    config: &mut OAuthConfig,
    issuer: &str,
    redirect: &str,
    claim: &str,
) -> Result<(), CatalogApiError> {
    let settings = &service.gateway_oauth;
    let vault = service
        .vault
        .as_ref()
        .ok_or_else(CatalogApiError::unavailable)?;
    let upstream = service
        .upstream
        .with_timeout_cap(settings.request_timeout.min(Duration::from_secs(30)));
    let existing = service
        .database
        .registered_credentials(&gateway.id, issuer)
        .await?;
    if existing.is_none() && !settings.dcr.allows_issuer(issuer) {
        return Err(registration_failed());
    }
    let metadata = settings
        .issuer_metadata
        .discover(&upstream, issuer, settings.dcr.metadata_ttl)
        .await
        .map_err(|_| registration_failed())?;
    config
        .complete_registration_endpoints(&upstream, Some(&metadata))
        .map_err(|_| registration_failed())?;
    let (credential, registration) = if let Some(credential) = existing {
        (credential, None)
    } else {
        let mut registered = register(
            &upstream,
            &settings.dcr,
            &metadata,
            issuer,
            &gateway.name,
            redirect,
            config.registration_scope(&settings.dcr.default_scopes),
        )
        .await
        .map_err(|_| registration_failed())?;
        let seal = async |secret: Option<&String>| match secret.filter(|secret| !secret.is_empty())
        {
            Some(secret) => vault.seal(Zeroizing::new(secret.clone())).await.map(Some),
            None => Ok(None),
        };
        let credential = ClientCredential {
            client_id: registered.response.client_id.clone(),
            client_secret_encrypted: seal(registered.response.client_secret.as_ref())
                .await
                .map_err(|_| registration_failed())?,
            auth_method: registered
                .response
                .token_endpoint_auth_method
                .as_ref()
                .unwrap_or(&settings.dcr.auth_method)
                .clone(),
        };
        let registration = RegisteredClientWrite {
            issuer,
            redirect_uris: json!(
                registered
                    .response
                    .redirect_uris
                    .take()
                    .unwrap_or_else(|| vec![redirect.to_owned()])
            )
            .to_string(),
            grant_types: json!(
                registered
                    .response
                    .grant_types
                    .take()
                    .unwrap_or(registered.grant_types)
            )
            .to_string(),
            response_types: json!(
                registered
                    .response
                    .response_types
                    .take()
                    .unwrap_or_else(|| vec!["code".to_owned()])
            )
            .to_string(),
            scope: registered.response.scope.take().or(Some(registered.scope)),
            management_uri: registered
                .response
                .registration_client_uri
                .take()
                .filter(|uri| {
                    uri.len() <= 500 && validate_endpoint(&upstream, uri, Some(issuer)).is_ok()
                }),
            management_token: seal(registered.response.registration_access_token.as_ref())
                .await
                .map_err(|_| registration_failed())?,
            expires_at: registered
                .response
                .client_secret_expires_at
                .filter(|&expiry| expiry > 0)
                .and_then(|expiry| Timestamp::from_second(expiry).ok())
                .map(|expiry| expiry.to_string()),
        };
        (credential, Some(registration))
    };
    let secret = match credential.client_secret_encrypted.as_ref() {
        Some(secret) => Some(
            vault
                .open(secret.clone())
                .await
                .map_err(|_| registration_failed())?
                .to_string(),
        ),
        None => None,
    };
    config.use_registered_client(
        credential.client_id.clone(),
        secret,
        credential.auth_method.clone(),
        redirect.to_owned(),
        "dcr",
    );
    if !config.valid() {
        return Err(registration_failed());
    }
    let (encoded, _) = config
        .store(vault)
        .await
        .map_err(|_| registration_failed())?;
    persist_config(
        service,
        gateway,
        claim,
        &encoded,
        registration
            .as_ref()
            .map(|registration| (&credential, registration)),
    )
    .await
}

async fn persist_config(
    service: &GatewayService,
    gateway: &mut OAuthGateway,
    claim: &str,
    encoded: &str,
    registration: Option<(&ClientCredential, &RegisteredClientWrite<'_>)>,
) -> Result<(), CatalogApiError> {
    gateway.version = service
        .database
        .persist_registered_config(gateway, claim, encoded, registration)
        .await?
        .ok_or_else(|| {
            CatalogApiError::detail(StatusCode::CONFLICT, "Gateway changed during authorization")
        })?;
    Ok(())
}

#[derive(Deserialize)]
struct RegistrationResponse {
    client_id: String,
    client_secret: Option<String>,
    client_secret_expires_at: Option<i64>,
    redirect_uris: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    scope: Option<String>,
    token_endpoint_auth_method: Option<String>,
    registration_client_uri: Option<String>,
    registration_access_token: Option<String>,
}

impl Drop for RegistrationResponse {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.registration_access_token.zeroize();
    }
}

struct Registration {
    response: RegistrationResponse,
    grant_types: Vec<String>,
    scope: String,
}

async fn register(
    upstream: &UpstreamClient,
    settings: &DcrSettings,
    metadata: &IssuerMetadata,
    issuer: &str,
    gateway_name: &str,
    redirect: &str,
    scope: String,
) -> Result<Registration, UpstreamError> {
    let endpoint = metadata
        .registration_endpoint
        .as_deref()
        .ok_or(UpstreamError::InvalidUrl)?;
    validate_endpoint(upstream, endpoint, Some(issuer))?;
    let advertised = metadata
        .grant_types_supported
        .as_deref()
        .unwrap_or_default();
    let mut grant_types = vec!["authorization_code".to_owned()];
    if advertised.iter().any(|grant| grant == "refresh_token")
        || advertised.is_empty() && settings.request_refresh_without_advertisement
    {
        grant_types.push("refresh_token".to_owned());
    }
    let application_type = match settings.application_type.as_str() {
        "auto" => match url::Url::parse(redirect)
            .ok()
            .and_then(|url| url.host().map(|host| host.to_owned()))
        {
            Some(url::Host::Domain(host))
                if host == "localhost" || host.ends_with(".localhost") =>
            {
                "native"
            }
            Some(url::Host::Ipv4(ip)) if ip.is_loopback() => "native",
            Some(url::Host::Ipv6(ip)) if ip.is_loopback() => "native",
            _ => "web",
        },
        configured => configured,
    };
    let form = json!({
        "client_name":settings.client_name_template.replace("{gateway_name}", gateway_name),
        "redirect_uris":[redirect], "grant_types":grant_types, "response_types":["code"],
        "token_endpoint_auth_method":settings.auth_method, "application_type":application_type,
        "scope":scope,
    });
    let response: RegistrationResponse = upstream
        .oauth_document(endpoint, None, None, Some(&form))
        .await?;
    if response.client_id.is_empty()
        || response.client_id.len() > 500
        || response
            .scope
            .as_ref()
            .is_some_and(|scope| scope.len() > 1000)
        || response
            .token_endpoint_auth_method
            .as_deref()
            .is_some_and(|method| {
                !matches!(
                    method,
                    "client_secret_basic" | "client_secret_post" | "none"
                )
            })
    {
        return Err(UpstreamError::InvalidResponse);
    }
    Ok(Registration {
        response,
        grant_types,
        scope,
    })
}

fn registration_failed() -> CatalogApiError {
    CatalogApiError::detail(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Dynamic Client Registration failed. Please configure client_id and client_secret manually or check your OAuth server supports RFC 7591.",
    )
}

#[derive(sqlx::FromRow)]
struct ClientCredential {
    client_id: String,
    client_secret_encrypted: Option<String>,
    auth_method: String,
}

struct RegisteredClientWrite<'a> {
    issuer: &'a str,
    redirect_uris: String,
    grant_types: String,
    response_types: String,
    scope: Option<String>,
    management_uri: Option<String>,
    management_token: Option<String>,
    expires_at: Option<String>,
}

impl Database {
    async fn registered_credentials(
        &self,
        gateway: &str,
        issuer: &str,
    ) -> Result<Option<ClientCredential>, sqlx::Error> {
        const SQL: &str =
            "SELECT client_id,client_secret_encrypted,token_endpoint_auth_method AS auth_method
            FROM registered_oauth_clients WHERE gateway_id=$1 AND issuer=$2 AND is_active";
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(SQL)
                    .bind(gateway)
                    .bind(issuer)
                    .fetch_optional(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(SQL)
                    .bind(gateway)
                    .bind(issuer)
                    .fetch_optional(observed(pool))
                    .await
            }
        }
    }

    async fn claim_client_registration(
        &self,
        gateway: &OAuthGateway,
        claim: &str,
    ) -> Result<bool, sqlx::Error> {
        macro_rules! write {
            ($pool:expr,$expires:literal,$expired:literal) => {
                sqlx::query(concat!("INSERT INTO cf_oauth_registration_claims(gateway_id,gateway_version,claim,expires_at)
                    SELECT $1,$2,$3,", $expires, " FROM gateways WHERE id=$1 AND version=$2 AND status='active'
                    ON CONFLICT(gateway_id) DO UPDATE SET gateway_version=excluded.gateway_version,claim=excluded.claim,expires_at=excluded.expires_at
                    WHERE ", $expired, " OR cf_oauth_registration_claims.gateway_version<>excluded.gateway_version"))
                    .bind(&gateway.id).bind(gateway.version).bind(claim).execute(observed($pool)).await?.rows_affected()!=0
            };
        }
        Ok(match self {
            Self::Sqlite(pool) => write!(
                pool,
                "datetime(CURRENT_TIMESTAMP,'+120 seconds')",
                "julianday(cf_oauth_registration_claims.expires_at)<=julianday(CURRENT_TIMESTAMP)"
            ),
            Self::Postgres(pool) => write!(
                pool,
                "clock_timestamp()+INTERVAL '120 seconds'",
                "cf_oauth_registration_claims.expires_at<=clock_timestamp()"
            ),
        })
    }

    async fn release_client_registration(
        &self,
        gateway: &str,
        claim: &str,
    ) -> Result<(), sqlx::Error> {
        const SQL: &str =
            "DELETE FROM cf_oauth_registration_claims WHERE gateway_id=$1 AND claim=$2";
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(SQL)
                    .bind(gateway)
                    .bind(claim)
                    .execute(observed(pool))
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(SQL)
                    .bind(gateway)
                    .bind(claim)
                    .execute(observed(pool))
                    .await?;
            }
        }
        Ok(())
    }

    async fn persist_registered_config(
        &self,
        gateway: &OAuthGateway,
        claim: &str,
        config: &str,
        registration: Option<(&ClientCredential, &RegisteredClientWrite<'_>)>,
    ) -> Result<Option<i32>, sqlx::Error> {
        macro_rules! persist {
            ($tx:ident,$json:literal,$timestamp:literal) => {{
                let version = sqlx::query_scalar(concat!("UPDATE gateways SET oauth_config=", $json, ",
                    auth_type='oauth',version=version+1,updated_at=CURRENT_TIMESTAMP
                    WHERE id=$1 AND version=$2 AND status='active'
                      AND EXISTS (SELECT 1 FROM cf_oauth_registration_claims WHERE gateway_id=$1 AND gateway_version=$2 AND claim=$4)
                    RETURNING version"))
                    .bind(&gateway.id).bind(gateway.version).bind(config).bind(claim)
                    .fetch_optional(observed(&mut *$tx)).await?;
                if version.is_none() {
                    return Ok(None);
                }
                if let Some((credential, registration)) = registration {
                    sqlx::query(concat!("INSERT INTO registered_oauth_clients
                        (id,gateway_id,issuer,client_id,client_secret_encrypted,redirect_uris,grant_types,
                         response_types,scope,token_endpoint_auth_method,registration_client_uri,
                         registration_access_token_encrypted,expires_at)
                        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,", $timestamp, ")
                        ON CONFLICT(gateway_id,issuer) DO UPDATE SET client_id=excluded.client_id,
                          client_secret_encrypted=excluded.client_secret_encrypted,redirect_uris=excluded.redirect_uris,
                          grant_types=excluded.grant_types,response_types=excluded.response_types,scope=excluded.scope,
                          token_endpoint_auth_method=excluded.token_endpoint_auth_method,
                          registration_client_uri=excluded.registration_client_uri,
                          registration_access_token_encrypted=excluded.registration_access_token_encrypted,
                          created_at=CURRENT_TIMESTAMP,expires_at=excluded.expires_at,is_active=TRUE"))
                        .bind(Uuid::new_v4().to_string()).bind(&gateway.id).bind(registration.issuer)
                        .bind(&credential.client_id).bind(credential.client_secret_encrypted.as_deref())
                        .bind(&registration.redirect_uris).bind(&registration.grant_types).bind(&registration.response_types)
                        .bind(registration.scope.as_deref()).bind(&credential.auth_method).bind(registration.management_uri.as_deref())
                        .bind(registration.management_token.as_deref()).bind(registration.expires_at.as_deref())
                        .execute(observed(&mut *$tx)).await?;
                }
                $tx.commit().await?;
                Ok(version)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                persist!(tx, "json($3)", "$13")
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                persist!(
                    tx,
                    "CAST(CAST($3 AS TEXT) AS JSON)",
                    "CAST(CAST($13 AS TEXT) AS TIMESTAMPTZ)"
                )
            }
        }
    }
}
