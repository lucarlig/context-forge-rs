// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use axum::http::HeaderValue;
use base64::{Engine, prelude::BASE64_STANDARD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::form_urlencoded::Serializer;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    secret_envelope::{EnvelopeError, SecretEnvelope},
    upstream::{UpstreamClient, UpstreamError},
    upstream_tls::TlsMaterial,
};

const UNRESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');
const MASKED: &str = "*****";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OAuthConfig {
    token_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_endpoint_auth_method: Option<ClientAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<OAuthValues>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<OAuthValues>,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ClientAuth {
    #[default]
    ClientSecretPost,
    ClientSecretBasic,
    None,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum OAuthValues {
    One(String),
    Many(Vec<String>),
}

impl Drop for OAuthConfig {
    fn drop(&mut self) {
        self.client_secret.zeroize();
    }
}

impl OAuthConfig {
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
        self.grant_type
            .as_deref()
            .is_none_or(|grant| grant == "client_credentials")
            && (self.token_endpoint_auth_method == Some(ClientAuth::None)
                || self.client_id.as_ref().is_some_and(|id| !id.is_empty()))
            && self.client_secret.as_deref() != Some(MASKED)
            && !self.token_url.is_empty()
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
        if let Some(secret) = stored.client_secret.take() {
            stored.client_secret = Some(vault.seal(Zeroizing::new(secret)).await?);
        }
        let encoded = serde_json::to_string(&stored).map_err(|_| EnvelopeError)?;
        if stored.client_secret.is_some() {
            stored.client_secret = Some(MASKED.to_owned());
        }
        let masked = serde_json::to_value(&stored).map_err(|_| EnvelopeError)?;
        Ok((encoded, masked))
    }

    pub(crate) async fn load(vault: &SecretEnvelope, encoded: &str) -> Result<Self, EnvelopeError> {
        let mut config: Self = serde_json::from_str(encoded).map_err(|_| EnvelopeError)?;
        if let Some(secret) = config.client_secret.take() {
            config.client_secret = Some(if SecretEnvelope::is_encrypted(&secret) {
                vault.open(secret).await?.to_string()
            } else {
                secret
            });
        }
        config.valid().then_some(config).ok_or(EnvelopeError)
    }

    pub(crate) async fn authorization(
        &self,
        upstream: &UpstreamClient,
        tls: Option<&TlsMaterial>,
    ) -> Result<HeaderValue, UpstreamError> {
        let (form, basic) = self.token_request()?;
        let mut retries = [1, 2].into_iter();
        loop {
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

    fn token_request(&self) -> Result<(Zeroizing<String>, Option<HeaderValue>), UpstreamError> {
        let mut form = Serializer::new(String::new());
        form.append_pair("grant_type", "client_credentials");
        let mut basic = None;
        let id = self.client_id.as_deref().filter(|id| !id.is_empty());
        let secret = self
            .client_secret
            .as_deref()
            .filter(|secret| !secret.is_empty());
        let method = self.token_endpoint_auth_method.unwrap_or_default();
        match (method, id, secret) {
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
        if let Some(scopes) = &self.scopes {
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
