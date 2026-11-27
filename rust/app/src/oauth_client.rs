// SPDX-License-Identifier: Apache-2.0

mod authorization_code;
mod discovery;

use std::time::Duration;

use axum::http::HeaderValue;
use base64::{Engine, prelude::BASE64_STANDARD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::form_urlencoded::Serializer;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    client_assertion::{AssertionAlgorithm, ClientAssertionSigner},
    secret_envelope::{EnvelopeError, SecretEnvelope},
    upstream::{UpstreamClient, UpstreamError},
    upstream_tls::TlsMaterial,
};
pub(crate) use authorization_code::UserOAuthTokens;
pub(crate) use discovery::{IssuerMetadata, IssuerMetadataCache, validate_endpoint};

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
const MASKED: &str = "*****";
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OAuthConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    token_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_signing_alg: Option<AssertionAlgorithm>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key_jwt_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<OAuthValues>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<OAuthValues>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dcr_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoints_discovered: Option<bool>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ClientAuth {
    ClientSecretPost,
    ClientSecretBasic,
    None,
    PrivateKeyJwt,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
enum OAuthValues {
    One(String),
    Many(Vec<String>),
}

impl Drop for OAuthConfig {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.private_key.zeroize();
    }
}

impl OAuthConfig {
    pub(crate) fn is_authorization_code(&self) -> bool {
        self.grant_type.as_deref() == Some("authorization_code")
    }

    pub(crate) fn resolve_masks(&mut self, stored: Option<&Self>) -> Result<(), EnvelopeError> {
        let keep_secret = self.client_secret.as_deref() == Some(MASKED);
        let keep_key = self.private_key.as_deref() == Some(MASKED);
        if !keep_secret && !keep_key {
            return Ok(());
        }
        let stored = stored.ok_or(EnvelopeError)?;
        let origin = |url| url::Url::parse(url).ok().map(|url| url.origin());
        if origin(&self.token_url) != origin(&stored.token_url)
            || self.is_authorization_code()
                && self.issuer.as_deref().and_then(origin)
                    != stored.issuer.as_deref().and_then(origin)
        {
            return Err(EnvelopeError);
        }
        if keep_secret {
            self.client_secret = Some(stored.client_secret.clone().ok_or(EnvelopeError)?);
        }
        if keep_key {
            self.private_key = Some(stored.private_key.clone().ok_or(EnvelopeError)?);
        }
        Ok(())
    }

    fn client_auth(&self) -> Option<ClientAuth> {
        let value = self
            .token_endpoint_auth_method
            .as_deref()
            .unwrap_or_default();
        match value.trim() {
            "" | "client_secret_post" => Some(ClientAuth::ClientSecretPost),
            "client_secret_basic" => Some(ClientAuth::ClientSecretBasic),
            "none" => Some(ClientAuth::None),
            "private_key_jwt" => Some(ClientAuth::PrivateKeyJwt),
            _ => None,
        }
    }

    pub(crate) fn matches_stored(new: &str, stored: &str) -> bool {
        let parsed = |value| {
            serde_json::from_str::<Value>(value)
                .ok()
                .filter(Value::is_object)
        };
        let (Some(new), Some(stored)) = (parsed(new), parsed(stored)) else {
            return false;
        };
        [
            "grant_type",
            "client_id",
            "authorization_url",
            "token_url",
            "scope",
            "target_audience",
            "subject_token_source",
        ]
        .iter()
        .all(|field| new[*field] == stored[*field])
    }

    pub(crate) fn valid(&self) -> bool {
        let Some(method) = self.client_auth() else {
            return false;
        };
        let client = self.client_id.as_ref().is_some_and(|id| !id.is_empty());
        let issuer = self
            .issuer
            .as_ref()
            .is_some_and(|issuer| !issuer.is_empty());
        let endpoints = if self.is_authorization_code() {
            (client || issuer)
                && (issuer
                    || (!self.token_url.is_empty()
                        && self
                            .authorization_url
                            .as_ref()
                            .is_some_and(|url| !url.is_empty())))
        } else {
            self.grant_type
                .as_deref()
                .is_none_or(|grant| grant == "client_credentials")
                && (method == ClientAuth::None || client)
                && !self.token_url.is_empty()
        };
        endpoints
            && self.client_secret.as_deref() != Some(MASKED)
            && self.private_key.as_deref() != Some(MASKED)
            && (method != ClientAuth::PrivateKeyJwt
                || self
                    .private_key
                    .as_ref()
                    .is_some_and(|pem| !pem.trim().is_empty()))
            && self
                .private_key_jwt_kid
                .as_ref()
                .is_none_or(|kid| !kid.trim().is_empty())
            && self.audience.as_ref().is_none_or(|audience| {
                let audience = audience.trim();
                audience.is_empty()
                    || (audience.len() <= 512
                        && audience.as_bytes()[0].is_ascii_alphanumeric()
                        && audience
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b".-_/:".contains(&byte)))
            })
    }

    pub(crate) async fn store(
        &self,
        vault: &SecretEnvelope,
    ) -> Result<(String, Value), EnvelopeError> {
        let mut stored = self.clone();
        for field in [&mut stored.client_secret, &mut stored.private_key] {
            if let Some(secret) = field.take() {
                *field = Some(vault.seal(Zeroizing::new(secret)).await?);
            }
        }
        let encoded = serde_json::to_string(&stored).map_err(|_| EnvelopeError)?;
        for field in [&mut stored.client_secret, &mut stored.private_key] {
            if field.is_some() {
                *field = Some(MASKED.to_owned());
            }
        }
        let masked = serde_json::to_value(&stored).map_err(|_| EnvelopeError)?;
        Ok((encoded, masked))
    }

    pub(crate) async fn load(vault: &SecretEnvelope, encoded: &str) -> Result<Self, EnvelopeError> {
        let mut config: Self = serde_json::from_str(encoded).map_err(|_| EnvelopeError)?;
        for field in [&mut config.client_secret, &mut config.private_key] {
            if let Some(secret) = field.take() {
                *field = Some(if SecretEnvelope::is_encrypted(&secret) {
                    vault.open(secret).await?.to_string()
                } else {
                    secret
                });
            }
        }
        config.valid().then_some(config).ok_or(EnvelopeError)
    }

    pub(crate) async fn authorization(
        &self,
        upstream: &UpstreamClient,
        tls: Option<&TlsMaterial>,
    ) -> Result<HeaderValue, UpstreamError> {
        if self.is_authorization_code() {
            return Err(UpstreamError::InvalidCredentials);
        }
        let method = self
            .client_auth()
            .ok_or(UpstreamError::InvalidCredentials)?;
        let assertion = if method == ClientAuth::PrivateKeyJwt {
            Some(ClientAssertionSigner::new(
                self.token_endpoint_auth_signing_alg.unwrap_or_default(),
                self.private_key
                    .as_deref()
                    .ok_or(UpstreamError::InvalidCredentials)?,
            )?)
        } else {
            None
        };
        let mut retries = [1, 2].into_iter();
        loop {
            let (form, basic) = self.token_request(method, assertion.as_ref())?;
            match upstream
                .exchange_oauth_token(&self.token_url, tls, &form, basic.as_ref())
                .await
            {
                Ok(token) => {
                    let value = Zeroizing::new(format!("Bearer {}", token.as_str()));
                    let mut header = HeaderValue::from_str(&value)
                        .map_err(|_| UpstreamError::InvalidResponse)?;
                    header.set_sensitive(true);
                    return Ok(header);
                }
                Err(
                    error @ (UpstreamError::Status(_)
                    | UpstreamError::Timeout
                    | UpstreamError::Resolve
                    | UpstreamError::Transport),
                ) => {
                    let delay = retries.next().ok_or(error)?;
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn token_request(
        &self,
        method: ClientAuth,
        assertion: Option<&ClientAssertionSigner>,
    ) -> Result<(Zeroizing<String>, Option<HeaderValue>), UpstreamError> {
        self.token_form("client_credentials", &[], method, assertion)
    }

    fn token_form(
        &self,
        grant: &str,
        fields: &[(&str, &str)],
        method: ClientAuth,
        assertion: Option<&ClientAssertionSigner>,
    ) -> Result<(Zeroizing<String>, Option<HeaderValue>), UpstreamError> {
        let mut form = Serializer::new(String::new());
        form.append_pair("grant_type", grant);
        form.extend_pairs(fields.iter().copied());
        let mut basic = None;
        let id = self.client_id.as_deref().filter(|id| !id.is_empty());
        let secret = self
            .client_secret
            .as_deref()
            .filter(|secret| !secret.is_empty());
        match (method, id, secret) {
            (ClientAuth::PrivateKeyJwt, Some(id), _) => {
                let assertion = assertion.ok_or(UpstreamError::InvalidCredentials)?.sign(
                    id,
                    &self.token_url,
                    self.private_key_jwt_kid.as_deref(),
                )?;
                form.append_pair("client_id", id);
                form.append_pair("client_assertion_type", ASSERTION_TYPE);
                form.append_pair("client_assertion", assertion.as_str());
            }
            (ClientAuth::PrivateKeyJwt, None, _) => {
                return Err(UpstreamError::InvalidCredentials);
            }
            (ClientAuth::ClientSecretBasic, Some(id), Some(secret)) => {
                let clear = Zeroizing::new(format!(
                    "{}:{}",
                    utf8_percent_encode(id, UNRESERVED),
                    utf8_percent_encode(secret, UNRESERVED),
                ));
                let value = Zeroizing::new(format!(
                    "Basic {}",
                    BASE64_STANDARD.encode(clear.as_bytes())
                ));
                let mut header =
                    HeaderValue::from_str(&value).map_err(|_| UpstreamError::Transport)?;
                header.set_sensitive(true);
                basic = Some(header);
            }
            (_, id, secret) => {
                if let Some(id) = id {
                    form.append_pair("client_id", id);
                }
                if let Some(secret) = secret.filter(|_| method != ClientAuth::None) {
                    form.append_pair("client_secret", secret);
                }
            }
        }
        if grant == "client_credentials"
            && let Some(scopes) = &self.scopes
        {
            let scope = match scopes {
                OAuthValues::One(value) => value.clone(),
                OAuthValues::Many(values) => values.join(" "),
            };
            if !scope.is_empty() {
                form.append_pair("scope", &scope);
            }
        }
        if let Some(audience) = self
            .audience
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            form.append_pair("audience", audience);
        }
        Ok((Zeroizing::new(form.finish()), basic))
    }
}
