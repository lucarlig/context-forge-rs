// SPDX-License-Identifier: Apache-2.0

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use jiff::Timestamp;
use jsonwebtoken::{Algorithm, Header, encode};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    access::Principal,
    auth::TeamVisibility,
    config::{IdentityForwarding, IdentityMode},
    credentials::UpstreamCredentials,
};

const CLAIM_HEADERS: &[(&str, &str)] = &[
    ("Id", "id"),
    ("Email", "email"),
    ("Full-Name", "full_name"),
    ("Groups", "groups"),
    ("Teams", "teams"),
    ("Roles", "roles"),
    ("Admin", "is_admin"),
    ("Auth-Method", "auth_method"),
    ("Service-Account", "service_account"),
    ("Delegation-Chain", "delegation_chain"),
    ("Claims-Signature", "claims_signature"),
];

#[derive(Default, Deserialize)]
struct IdentityOverride {
    enabled: Option<bool>,
    mode: Option<IdentityMode>,
    #[serde(alias = "headersPrefix")]
    headers_prefix: Option<String>,
    #[serde(alias = "signClaims")]
    sign_claims: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IdentityError {
    #[error("Invalid upstream identity propagation configuration")]
    Config,
    #[error("Identity claim signing requires a dedicated IDENTITY_CLAIMS_SECRET")]
    Signing,
}

struct IdentityOptions<'a> {
    enabled: bool,
    mode: IdentityMode,
    prefix: &'a str,
    sign_claims: bool,
}

impl IdentityForwarding {
    pub(crate) fn validate(&self, configured: &Value) -> Result<(), IdentityError> {
        let configured: IdentityOverride =
            serde_json::from_value(configured.clone()).map_err(|_| IdentityError::Config)?;
        self.options(&configured).map(|_| ())
    }

    fn options<'a>(
        &'a self,
        configured: &'a IdentityOverride,
    ) -> Result<IdentityOptions<'a>, IdentityError> {
        let prefix = configured
            .headers_prefix
            .as_deref()
            .unwrap_or(&self.headers_prefix);
        validate_prefix(prefix)?;
        let sign_claims = configured.sign_claims.unwrap_or(self.sign_claims);
        if sign_claims && self.signing_key.is_none() {
            return Err(IdentityError::Signing);
        }
        Ok(IdentityOptions {
            enabled: configured.enabled.unwrap_or(self.enabled),
            mode: configured.mode.unwrap_or(self.mode),
            prefix,
            sign_claims,
        })
    }

    pub(crate) fn apply(
        &self,
        credentials: &mut UpstreamCredentials,
        principal: Option<&Principal>,
        gateway: &str,
        configured: Option<&str>,
    ) -> Result<(), IdentityError> {
        let configured: Option<IdentityOverride> = configured
            .map(serde_json::from_str)
            .transpose()
            .map_err(|_| IdentityError::Config)?
            .flatten();
        let configured = configured.unwrap_or_default();
        let options = self.options(&configured)?;
        if !options.enabled {
            return Ok(());
        }
        for (suffix, _) in CLAIM_HEADERS {
            credentials
                .headers
                .remove(header_name(options.prefix, suffix)?);
        }
        let Some(principal) = principal else {
            return Ok(());
        };
        let mut claims = principal_claims(principal);
        if options.sign_claims {
            let key = self.signing_key.as_ref().ok_or(IdentityError::Signing)?;
            let now = Timestamp::now().as_second();
            let mut signed = claims.clone();
            signed.extend([
                ("iss".into(), json!("mcpgateway-identity-propagation")),
                ("aud".into(), json!(gateway)),
                ("iat".into(), json!(now)),
                ("exp".into(), json!(now + 60)),
                ("jti".into(), json!(Uuid::new_v4().simple().to_string())),
            ]);
            let token = encode(&Header::new(Algorithm::HS256), &signed, key)
                .map_err(|_| IdentityError::Signing)?;
            claims.insert("claims_signature".into(), token.into());
        }
        if matches!(options.mode, IdentityMode::Headers | IdentityMode::Both) {
            apply_headers(&mut credentials.headers, options.prefix, &claims)?;
            credentials.request_bound_headers = options.sign_claims;
        }
        if matches!(options.mode, IdentityMode::Meta | IdentityMode::Both) {
            credentials.identity_meta = Some(Value::Object(claims));
        }
        Ok(())
    }
}

pub(crate) fn validate_prefix(prefix: &str) -> Result<(), IdentityError> {
    let lowered = prefix.to_ascii_lowercase();
    if prefix.is_empty()
        || prefix.len() > 100
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || matches!(lowered.as_str(), "mcp" | "proxy")
        || ["mcp-", "proxy-"]
            .iter()
            .any(|blocked| lowered.starts_with(blocked))
    {
        return Err(IdentityError::Config);
    }
    Ok(())
}

fn principal_claims(principal: &Principal) -> Map<String, Value> {
    let mut claims = Map::from_iter([
        ("id".into(), json!(principal.email)),
        ("email".into(), json!(principal.email)),
        ("is_admin".into(), json!(principal.is_global_admin())),
        ("auth_method".into(), json!("jwt")),
    ]);
    if let Some(name) = principal
        .full_name
        .as_deref()
        .filter(|name| !name.is_empty())
    {
        claims.insert("full_name".into(), json!(name));
    }
    if let TeamVisibility::Teams(teams) = &principal.visibility
        && !teams.is_empty()
    {
        claims.insert("teams".into(), json!(teams));
    }
    claims
}

fn header_name(prefix: &str, suffix: &str) -> Result<HeaderName, IdentityError> {
    HeaderName::from_bytes(format!("{prefix}-{suffix}").as_bytes())
        .map_err(|_| IdentityError::Config)
}

fn apply_headers(
    headers: &mut HeaderMap,
    prefix: &str,
    claims: &Map<String, Value>,
) -> Result<(), IdentityError> {
    for (suffix, field) in CLAIM_HEADERS {
        let Some(claim) = claims.get(*field) else {
            continue;
        };
        let text = match claim {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
            _ => continue,
        };
        let Ok(mut value) = HeaderValue::from_str(&text) else {
            continue;
        };
        value.set_sensitive(true);
        headers.insert(header_name(prefix, suffix)?, value);
    }
    Ok(())
}
