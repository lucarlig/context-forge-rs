// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::Map;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use super::{oidc, providers::Provider, *};
use crate::upstream_tls::TlsMaterial;

const SESSION_COOKIE: &str = "sso_session_id";

#[derive(Deserialize)]
pub(super) struct LoginQuery {
    redirect_uri: String,
    scopes: Option<String>,
}

pub(super) async fn login(
    State(accounts): State<Arc<Accounts>>,
    Path(id): Path<String>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AccountError> {
    let settings = accounts.sso()?;
    if !allowed_redirect(settings, &query.redirect_uri) {
        return Err(AccountError::bad_request(
            "Invalid redirect_uri. Must be a relative path or URL matching allowed origins.",
        ));
    }
    let provider = accounts
        .database
        .sso_provider(&id)
        .await?
        .filter(|provider| provider.config.is_enabled)
        .ok_or_else(|| {
            AccountError::detail(
                StatusCode::NOT_FOUND,
                format!("SSO provider '{id}' not found or disabled"),
            )
        })?;
    let config = &provider.config;
    let scope =
        resolve_scopes(&provider, query.scopes.as_deref()).ok_or_else(invalid_authorization)?;
    settings
        .upstream
        .check_endpoint(&config.authorization_url)
        .map_err(|_| invalid_authorization())?;
    let mut authorization =
        url::Url::parse(&config.authorization_url).map_err(|_| invalid_authorization())?;
    if authorization.fragment().is_some() {
        return Err(invalid_authorization());
    }
    let verifier = Zeroizing::new(random_urlsafe::<32>()?);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let binding = Zeroizing::new(random_urlsafe::<32>()?);
    let state_nonce = random_urlsafe::<24>()?;
    let signature = sign_state(settings, &provider.id, &binding, &state_nonce)
        .ok_or_else(AccountError::unavailable)?;
    let state = format!("{state_nonce}.{signature}");
    let nonce = if config.provider_type == "oidc" {
        Some(random_urlsafe::<16>()?)
    } else {
        None
    };
    authorization
        .query_pairs_mut()
        .clear()
        .append_pair("client_id", &config.client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", &query.redirect_uri)
        .append_pair("state", &state)
        .append_pair("scope", &scope)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .extend_pairs(nonce.as_deref().map(|nonce| ("nonce", nonce)));
    let transaction = SsoSession {
        code_verifier: Some(verifier.to_string()),
        nonce,
        redirect_uri: query.redirect_uri,
    };
    if !accounts
        .database
        .create_sso_session(&provider, &state, &transaction)
        .await?
    {
        return Err(invalid_authorization());
    }
    let cookie = make_cookie(settings, SESSION_COOKIE, &binding, None)
        .ok_or_else(AccountError::unavailable)?;
    Ok((
        [
            (header::SET_COOKIE, cookie),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(json!({"authorization_url":authorization.as_str(),"state":state})),
    )
        .into_response())
}

#[derive(Deserialize)]
pub(super) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub(super) async fn callback(
    State(accounts): State<Arc<Accounts>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AccountError> {
    let settings = accounts.sso()?;
    if let Some(error) = query.error {
        return redirect_to_login(
            settings,
            match error.as_str() {
                "access_denied" => "sso_cancelled",
                "invalid_request" => "sso_invalid_request",
                "unauthorized_client" => "sso_unauthorized",
                "unsupported_response_type" => "sso_config_error",
                "invalid_scope" => "sso_invalid_scope",
                "server_error" => "sso_server_error",
                "temporarily_unavailable" => "sso_unavailable",
                _ => "sso_failed",
            },
        );
    }
    let Some((code, state)) = query.code.as_deref().zip(query.state.as_deref()) else {
        return redirect_to_login(settings, "sso_failed");
    };
    let Some(binding) = read_cookie(&headers, SESSION_COOKIE) else {
        return redirect_to_login(settings, "sso_failed");
    };
    if !verify_state(settings, &id, binding, state) || code.is_empty() || code.len() > 4096 {
        return redirect_to_login(settings, "sso_failed");
    }
    let Some(provider) = accounts
        .database
        .sso_provider(&id)
        .await?
        .filter(|provider| provider.config.is_enabled)
    else {
        return redirect_to_login(settings, "sso_failed");
    };
    let Some(transaction) = accounts
        .database
        .consume_sso_session(&provider, state)
        .await?
    else {
        return redirect_to_login(settings, "sso_failed");
    };
    let Some(identity) = exchange_identity(settings, &provider, &transaction, code).await else {
        return redirect_to_login(settings, "sso_failed");
    };
    if !accounts
        .database
        .sso_provider(&id)
        .await?
        .is_some_and(|current| {
            current.config == provider.config
                && current.client_secret_encrypted == provider.client_secret_encrypted
        })
    {
        return redirect_to_login(settings, "sso_failed");
    }
    let Some(user) = authenticate_identity(&accounts, &provider, &identity).await? else {
        return redirect_to_login(settings, "user_creation_failed");
    };
    let (access, _, _) = issue_local_session(&accounts, &user).await?;
    let Some(cookie) = make_cookie(settings, "jwt_token", &access, Some(3600)) else {
        return redirect_to_login(settings, "token_too_large");
    };
    let mut response = redirect(&format!("{}/admin", settings.root_path))?;
    response.headers_mut().append(header::SET_COOKIE, cookie);
    Ok(response)
}

async fn authenticate_identity(
    accounts: &Accounts,
    provider: &Provider,
    claims: &Map<String, Value>,
) -> Result<Option<storage::LocalUser>, AccountError> {
    let raw_email = match provider
        .config
        .provider_metadata
        .get("email_claim")
        .and_then(Value::as_str)
    {
        Some(claim) => claims.get(claim).and_then(Value::as_str),
        None => ["email", "preferred_username", "upn", "unique_name", "mail"]
            .into_iter()
            .filter_map(|claim| claims.get(claim).and_then(Value::as_str))
            .find(|value| value.contains('@')),
    };
    let Some(email) = raw_email
        .map(|email| email.trim().to_ascii_lowercase())
        .filter(|email| valid_email(email))
    else {
        return Ok(None);
    };
    if claims
        .get("email_verified")
        .is_some_and(|claim| !email_verified(claim))
    {
        return Ok(None);
    }
    if !provider.config.trusted_domains.is_empty()
        && email.rsplit_once('@').is_none_or(|(_, domain)| {
            provider
                .config
                .trusted_domains
                .iter()
                .all(|trusted| !trusted.eq_ignore_ascii_case(domain))
        })
    {
        return Ok(None);
    }
    if let Some(user) = accounts.database.local_user(&email).await? {
        if user.auth_provider != provider.id || !user.is_active || user.locked(Timestamp::now()) {
            return Ok(None);
        }
        return Ok(accounts.database.record_successful_login(&user).await?);
    }
    if !provider.config.auto_create_users {
        return Ok(None);
    }
    let name = claims
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&email)
        .chars()
        .filter(|ch| !ch.is_control())
        .take(255)
        .collect();
    let user = storage::NewUser {
        email: email.clone(),
        full_name: Some(name),
        is_admin: false,
        is_active: true,
        password_hash: None,
        auth_provider: provider.id.clone(),
        password_change_required: false,
        granted_by: None,
        admin_origin: None,
    };
    accounts
        .database
        .create_local_user(&user, &accounts.settings)
        .await?;
    Ok(accounts.database.local_user(&email).await?.filter(|user| {
        user.auth_provider == provider.id && user.is_active && !user.locked(Timestamp::now())
    }))
}

fn email_verified(claim: &Value) -> bool {
    claim.as_bool().unwrap_or_else(|| {
        claim.as_i64() == Some(1)
            || claim.as_str().is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "true" | "1" | "yes"
                )
            })
    })
}

#[derive(Deserialize)]
struct ProviderToken {
    access_token: String,
    id_token: Option<String>,
}

impl Drop for ProviderToken {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.id_token.zeroize();
    }
}

async fn exchange_identity(
    settings: &SsoSettings,
    provider: &Provider,
    transaction: &SsoSession,
    code: &str,
) -> Option<Map<String, Value>> {
    let config = &provider.config;
    let secret = settings
        .vault
        .as_ref()?
        .open(provider.client_secret_encrypted.clone())
        .await
        .ok()?;
    let verifier = transaction.code_verifier.as_deref()?;
    let tls = TlsMaterial::from_pem(config.ca_certificate.as_deref(), None, None).ok()?;
    let mut fields = vec![
        ("code", code),
        ("grant_type", "authorization_code"),
        ("redirect_uri", transaction.redirect_uri.as_str()),
        ("code_verifier", verifier),
    ];
    let authorization = if !secret.is_empty()
        && config
            .provider_metadata
            .get("token_endpoint_auth_method")
            .and_then(Value::as_str)
            == Some("client_secret_basic")
    {
        let combined = Zeroizing::new(format!(
            "{}:{}",
            utf8_percent_encode(&config.client_id, NON_ALPHANUMERIC),
            utf8_percent_encode(&secret, NON_ALPHANUMERIC)
        ));
        let basic = Zeroizing::new(format!("Basic {}", STANDARD.encode(combined.as_bytes())));
        Some(sensitive_header(&basic)?)
    } else {
        fields.push(("client_id", &config.client_id));
        if !secret.is_empty() {
            fields.push(("client_secret", &secret));
        }
        None
    };
    let form = Zeroizing::new(
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish(),
    );
    let (response, _) = settings
        .upstream
        .oauth_token_response(
            &config.token_url,
            tls.as_ref(),
            &form,
            authorization.as_ref(),
        )
        .await
        .ok()?;
    let tokens: ProviderToken = serde_json::from_slice(&response).ok()?;
    let oidc_claims = if config.provider_type == "oidc" {
        Some(
            oidc::id_token_claims(
                settings,
                provider,
                tokens.id_token.as_deref()?,
                transaction.nonce.as_deref()?,
                tls.as_ref(),
            )
            .await?,
        )
    } else {
        None
    };
    if tokens.access_token.is_empty() {
        return None;
    }
    let bearer = Zeroizing::new(format!("Bearer {}", tokens.access_token));
    let authorization = sensitive_header(&bearer)?;
    let mut user_info = settings
        .upstream
        .oauth_document::<Map<String, Value>>(
            &config.userinfo_url,
            tls.as_ref(),
            Some(&authorization),
            None,
        )
        .await
        .ok()?;
    if let Some(claims) = oidc_claims {
        if user_info.get("sub").and_then(Value::as_str) != claims.get("sub").and_then(Value::as_str)
        {
            return None;
        }
        for (name, value) in claims {
            if name == "email_verified" && !email_verified(&value) {
                user_info.insert(name, value);
            } else {
                user_info.entry(name).or_insert(value);
            }
        }
    }
    Some(user_info)
}

fn sensitive_header(value: &str) -> Option<HeaderValue> {
    let mut header = HeaderValue::from_str(value).ok()?;
    header.set_sensitive(true);
    Some(header)
}

fn allowed_redirect(settings: &SsoSettings, target: &str) -> bool {
    if target.is_empty()
        || target.len() > 500
        || target.contains('\\')
        || target.starts_with("//")
        || target
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return false;
    }
    match url::Url::parse(target) {
        Ok(target)
            if matches!(target.scheme(), "http" | "https")
                && target.username().is_empty()
                && target.password().is_none()
                && target.fragment().is_none() =>
        {
            // Browser callback URLs are checked against configured origins rather than headers.
            target.origin() == settings.app_domain.origin()
                || settings.allowed_origins.iter().any(|allowed| {
                    let candidate = if allowed.contains("://") {
                        allowed.clone()
                    } else {
                        format!("https://{allowed}")
                    };
                    url::Url::parse(&candidate)
                        .is_ok_and(|allowed| allowed.origin() == target.origin())
                })
        }
        Err(url::ParseError::RelativeUrlWithoutBase) => true,
        _ => false,
    }
}

fn resolve_scopes(provider: &Provider, requested: Option<&str>) -> Option<String> {
    let mut seen = HashSet::new();
    let configured = provider
        .config
        .scope
        .split_whitespace()
        .filter(|scope| seen.insert(*scope));
    let metadata = provider.config.provider_metadata.get("allowed_scopes");
    let from_metadata = match metadata {
        Some(Value::String(values)) => values.split_whitespace().collect::<HashSet<_>>(),
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).collect(),
        _ => HashSet::new(),
    };
    let allowed: Vec<_> = configured
        .filter(|scope| from_metadata.is_empty() || from_metadata.contains(scope))
        .collect();
    if allowed.is_empty() || requested.is_some_and(|scopes| scopes.len() > 500) {
        return None;
    }
    let mut seen = HashSet::new();
    let requested: Vec<_> = requested
        .unwrap_or_default()
        .split_whitespace()
        .filter(|scope| seen.insert(*scope))
        .collect();
    if requested.is_empty() {
        return Some(allowed.join(" "));
    }
    requested
        .iter()
        .all(|scope| allowed.contains(scope))
        .then(|| requested.join(" "))
}

fn random_urlsafe<const SIZE: usize>() -> Result<String, AccountError> {
    let mut raw = Zeroizing::new([0_u8; SIZE]);
    SystemRandom::new()
        .fill(raw.as_mut())
        .map_err(|_| AccountError::unavailable())?;
    Ok(URL_SAFE_NO_PAD.encode(raw.as_ref()))
}

fn sign_state(
    settings: &SsoSettings,
    provider: &str,
    binding: &str,
    nonce: &str,
) -> Option<String> {
    use std::fmt::Write as _;
    let hmac = hmac::sign(
        settings.binding_key.as_ref()?,
        format!("{provider}:{binding}:{nonce}").as_bytes(),
    );
    let mut signature = String::with_capacity(64);
    for byte in hmac.as_ref() {
        write!(signature, "{byte:02x}").ok()?;
    }
    Some(signature)
}

fn verify_state(settings: &SsoSettings, provider: &str, binding: &str, state: &str) -> bool {
    state
        .split_once('.')
        .filter(|(nonce, signature)| {
            nonce.len() == 32 && signature.len() == 64 && binding.len() <= 128
        })
        .is_some_and(|(nonce, signature)| {
            sign_state(settings, provider, binding, nonce)
                .is_some_and(|expected| bool::from(expected.as_bytes().ct_eq(signature.as_bytes())))
        })
}

fn make_cookie(
    settings: &SsoSettings,
    name: &str,
    value: &str,
    age: Option<u32>,
) -> Option<HeaderValue> {
    use std::fmt::Write as _;
    let same_site = match settings.same_site.to_ascii_lowercase().as_str() {
        "strict" => "strict",
        "none" => "none",
        _ => "lax",
    };
    let path = if settings.root_path.is_empty() {
        "/"
    } else {
        &settings.root_path
    };
    let mut cookie = Zeroizing::new(format!(
        "{name}={value}; HttpOnly; Path={path}; SameSite={same_site}"
    ));
    if settings.secure_cookies {
        cookie.push_str("; Secure");
    }
    if let Some(age) = age {
        write!(*cookie, "; Max-Age={age}").ok()?;
    }
    (cookie.len() <= 4096)
        .then(|| sensitive_header(&cookie))
        .flatten()
}

fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

fn invalid_authorization() -> AccountError {
    AccountError::bad_request("Invalid OAuth authorization request")
}

fn redirect_to_login(settings: &SsoSettings, error: &str) -> Result<Response, AccountError> {
    redirect(&format!("{}/admin/login?error={error}", settings.root_path))
}

fn redirect(location: &str) -> Result<Response, AccountError> {
    let location = HeaderValue::from_str(location).map_err(|_| AccountError::unavailable())?;
    Ok((
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response())
}

#[derive(sqlx::FromRow)]
struct SsoSession {
    code_verifier: Option<String>,
    nonce: Option<String>,
    redirect_uri: String,
}

impl Drop for SsoSession {
    fn drop(&mut self) {
        self.code_verifier.zeroize();
    }
}

impl Database {
    async fn create_sso_session(
        &self,
        provider: &Provider,
        state: &str,
        session: &SsoSession,
    ) -> Result<bool, sqlx::Error> {
        macro_rules! write {
            ($pool:expr,$expiry:literal,$lock:literal) => {
                sqlx::query(concat!(
                    "INSERT INTO sso_auth_sessions(id,provider_id,state,code_verifier,nonce,redirect_uri,expires_at)
                     SELECT $1,$2,$3,$4,$5,$6,", $expiry, " FROM sso_providers
                     WHERE id=$2 AND is_enabled AND CAST(updated_at AS TEXT)=$7", $lock,
                )).bind(Uuid::new_v4().to_string()).bind(&provider.id).bind(state)
                    .bind(session.code_verifier.as_deref()).bind(session.nonce.as_deref()).bind(&session.redirect_uri)
                    .bind(&provider.updated_at).execute($pool).await?.rows_affected()!=0
            };
        }
        Ok(match self {
            Self::Sqlite(pool) => write!(pool, "datetime(CURRENT_TIMESTAMP,'+600 seconds')", ""),
            Self::Postgres(pool) => write!(
                pool,
                "clock_timestamp()+INTERVAL '600 seconds'",
                " FOR SHARE"
            ),
        })
    }

    async fn consume_sso_session(
        &self,
        provider: &Provider,
        state: &str,
    ) -> Result<Option<SsoSession>, sqlx::Error> {
        macro_rules! consume {
            ($pool:expr,$expiry:literal) => {
                sqlx::query_as(concat!("DELETE FROM sso_auth_sessions WHERE provider_id=$1 AND state=$2 AND ",
                    $expiry," AND EXISTS(SELECT 1 FROM sso_providers WHERE id=$1 AND is_enabled
                        AND CAST(updated_at AS TEXT)=$3) RETURNING code_verifier,nonce,redirect_uri"))
                    .bind(&provider.id).bind(state).bind(&provider.updated_at).fetch_optional($pool).await
            };
        }
        match self {
            Self::Sqlite(pool) => {
                consume!(pool, "julianday(expires_at)>julianday(CURRENT_TIMESTAMP)")
            }
            Self::Postgres(pool) => consume!(pool, "expires_at>clock_timestamp()"),
        }
    }
}
