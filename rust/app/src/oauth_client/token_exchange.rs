// SPDX-License-Identifier: Apache-2.0

use super::*;

const EXCHANGE: &str = "token-exchange";
const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const ACCESS: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_TYPE_PREFIX: &str = "urn:ietf:params:oauth:token-type:";

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceOAuthOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_url: Option<String>,
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
}

impl Drop for ServiceOAuthOverride {
    fn drop(&mut self) {
        self.client_secret.zeroize();
        self.private_key.zeroize();
    }
}

pub(crate) struct ExchangedCredential {
    pub(crate) authorization: HeaderValue,
    pub(crate) expires_in: u64,
}

#[derive(Deserialize)]
struct ExchangeResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<Value>,
}

impl Drop for ExchangeResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

impl OAuthConfig {
    pub(crate) fn is_token_exchange(&self) -> bool {
        self.grant_type.as_deref() == Some(EXCHANGE)
    }

    pub(crate) fn defers_discovery(&self) -> bool {
        self.is_authorization_code() || self.is_token_exchange() && self.discovery.is_none()
    }

    pub(crate) fn normalize_exchange(&mut self) {
        if !self.is_token_exchange() {
            return;
        }
        self.subject_token_source
            .get_or_insert_with(|| "inbound_user_jwt".to_owned());
        self.subject_token_type
            .get_or_insert_with(|| JWT.to_owned());
        self.requested_token_type
            .get_or_insert_with(|| ACCESS.to_owned());
        match self
            .actor_token_source
            .get_or_insert_with(|| "none".to_owned())
            .as_str()
        {
            "none" => self.actor_token_type = None,
            "client_credentials" => {
                self.actor_token_type
                    .get_or_insert_with(|| ACCESS.to_owned());
            }
            "client_assertion" => {
                self.actor_token_type.get_or_insert_with(|| JWT.to_owned());
            }
            _ => {}
        }
    }

    pub(super) fn valid_exchange(&self) -> bool {
        let source = self.actor_token_source.as_deref().unwrap_or("none");
        let valid_type = |value: Option<&str>| {
            value.is_none_or(|value| {
                value.strip_prefix(TOKEN_TYPE_PREFIX).is_some_and(|kind| {
                    !kind.is_empty()
                        && kind.len() <= 100
                        && kind
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                })
            })
        };
        if self.token_url.is_empty()
            || self
                .target_audience
                .as_deref()
                .is_none_or(|target| target.trim().is_empty() || target.len() > 512)
            || self
                .subject_token_source
                .as_deref()
                .is_some_and(|source| source != "inbound_user_jwt")
            || !valid_type(self.subject_token_type.as_deref())
            || !valid_type(self.requested_token_type.as_deref())
            || !valid_type(self.actor_token_type.as_deref())
            || self.discovery.as_ref().is_some_and(|config| {
                config.grant_type.as_deref() != Some("client_credentials")
                    || !self.overrides_valid(config)
            })
            || self.actor.as_ref().is_some_and(|config| {
                source != "client_credentials"
                    || config
                        .client_id
                        .as_deref()
                        .is_none_or(|id| id.trim().is_empty())
                    || !self.overrides_valid(config)
            })
        {
            return false;
        }
        match source {
            "none" => true,
            "client_credentials" => self.service_oauth(self.actor.as_ref()).valid(),
            "client_assertion" => {
                self.client_id().is_some()
                    && self
                        .private_key
                        .as_deref()
                        .is_some_and(|key| !key.trim().is_empty())
            }
            _ => false,
        }
    }

    pub(crate) fn validate_exchange_endpoints(
        &self,
        upstream: &UpstreamClient,
    ) -> Result<(), UpstreamError> {
        if self.is_token_exchange() {
            validate_endpoint(upstream, &self.token_url, None)?;
            for config in [&self.discovery, &self.actor].into_iter().flatten() {
                if let Some(url) = config.token_url.as_deref().filter(|url| !url.is_empty()) {
                    validate_endpoint(upstream, url, None)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn discovery_config(&self) -> Option<Self> {
        self.discovery
            .as_ref()
            .map(|discovery| self.service_oauth(Some(discovery)))
    }

    fn overrides_valid(&self, config: &ServiceOAuthOverride) -> bool {
        if config.client_secret.as_deref() == Some(MASKED)
            || config.private_key.as_deref() == Some(MASKED)
        {
            return false;
        }
        if config
            .token_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .is_some_and(|endpoint| endpoint_origin(endpoint) != endpoint_origin(&self.token_url))
            && self
                .client_secret
                .as_ref()
                .is_some_and(|secret| !secret.is_empty())
            && config.client_secret.is_none()
        {
            return false;
        }
        self.service_oauth(Some(config)).valid()
    }

    fn service_oauth(&self, overrides: Option<&ServiceOAuthOverride>) -> Self {
        let mut config = self.clone();
        config.grant_type = Some("client_credentials".to_owned());
        config.discovery = None;
        config.actor = None;
        config.audience = None;
        if let Some(overrides) = overrides {
            if let Some(endpoint) = overrides
                .token_url
                .as_ref()
                .filter(|endpoint| !endpoint.is_empty())
            {
                config.token_url.clone_from(endpoint);
            }
            if let Some(secret) = &overrides.client_secret {
                config.client_secret.zeroize();
                config.client_secret = Some(secret.clone());
            }
            if let Some(private_key) = &overrides.private_key {
                config.private_key.zeroize();
                config.private_key = Some(private_key.clone());
            }
            if overrides.token_endpoint_auth_signing_alg.is_some() {
                config.token_endpoint_auth_signing_alg = overrides.token_endpoint_auth_signing_alg;
            }
            if overrides.client_id.is_some() {
                config.client_id.clone_from(&overrides.client_id);
            }
            if overrides.token_endpoint_auth_method.is_some() {
                config
                    .token_endpoint_auth_method
                    .clone_from(&overrides.token_endpoint_auth_method);
            }
            if overrides.private_key_jwt_kid.is_some() {
                config
                    .private_key_jwt_kid
                    .clone_from(&overrides.private_key_jwt_kid);
            }
            if overrides.scopes.is_some() {
                config.scopes.clone_from(&overrides.scopes);
            }
            config.audience.clone_from(&overrides.audience);
        }
        config
    }

    pub(super) fn secret_fields(&mut self) -> impl Iterator<Item = &mut Option<String>> {
        [&mut self.client_secret, &mut self.private_key]
            .into_iter()
            .chain(
                self.discovery
                    .iter_mut()
                    .chain(self.actor.iter_mut())
                    .flat_map(|config| [&mut config.client_secret, &mut config.private_key]),
            )
    }

    pub(super) fn resolve_service_masks(
        &mut self,
        stored: Option<&Self>,
    ) -> Result<(), EnvelopeError> {
        for (config, original) in [
            (
                &mut self.discovery,
                stored.and_then(|original| original.discovery.as_ref()),
            ),
            (
                &mut self.actor,
                stored.and_then(|original| original.actor.as_ref()),
            ),
        ] {
            let Some(config) = config else {
                continue;
            };
            let mask_secret = config.client_secret.as_deref() == Some(MASKED);
            let mask_key = config.private_key.as_deref() == Some(MASKED);
            if !mask_secret && !mask_key {
                continue;
            }
            let original = original.ok_or(EnvelopeError)?;
            let next_url = config
                .token_url
                .as_deref()
                .filter(|url| !url.is_empty())
                .unwrap_or(&self.token_url);
            let previous_url = original
                .token_url
                .as_deref()
                .filter(|url| !url.is_empty())
                .or_else(|| stored.map(|stored| stored.token_url.as_str()))
                .ok_or(EnvelopeError)?;
            if endpoint_origin(next_url) != endpoint_origin(previous_url) {
                return Err(EnvelopeError);
            }
            if mask_secret {
                config.client_secret = Some(original.client_secret.clone().ok_or(EnvelopeError)?);
            }
            if mask_key {
                config.private_key = Some(original.private_key.clone().ok_or(EnvelopeError)?);
            }
        }
        Ok(())
    }

    pub(crate) async fn exchange_subject(
        &self,
        upstream: &UpstreamClient,
        tls: Option<&TlsMaterial>,
        subject: &str,
    ) -> Result<ExchangedCredential, UpstreamError> {
        let method = self
            .client_auth()
            .ok_or(UpstreamError::InvalidCredentials)?;
        let actor_source = self.actor_token_source.as_deref().unwrap_or("none");
        let signer = if method == ClientAuth::PrivateKeyJwt || actor_source == "client_assertion" {
            Some(ClientAssertionSigner::new(
                self.token_endpoint_auth_signing_alg.unwrap_or_default(),
                self.private_key
                    .as_deref()
                    .ok_or(UpstreamError::InvalidCredentials)?,
            )?)
        } else {
            None
        };
        let actor = match actor_source {
            "none" => None,
            "client_credentials" => {
                let mut service = self.service_oauth(self.actor.as_ref());
                service.scopes = None;
                service.audience = None;
                let header = service.authorization(upstream, tls).await?;
                let token = header
                    .to_str()
                    .ok()
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .ok_or(UpstreamError::InvalidResponse)?;
                Some((
                    Zeroizing::new(token.to_owned()),
                    self.actor_token_type.as_deref().unwrap_or(ACCESS),
                ))
            }
            "client_assertion" => {
                let signed = signer
                    .as_ref()
                    .ok_or(UpstreamError::InvalidCredentials)?
                    .sign(
                        self.client_id().ok_or(UpstreamError::InvalidCredentials)?,
                        &self.token_url,
                        self.private_key_jwt_kid.as_deref(),
                    )?;
                Some((signed, self.actor_token_type.as_deref().unwrap_or(JWT)))
            }
            _ => return Err(UpstreamError::InvalidCredentials),
        };
        let audience = self
            .target_audience
            .as_deref()
            .ok_or(UpstreamError::InvalidCredentials)?;
        let scope = self.scope_string();
        let mut fields = vec![
            ("subject_token", subject),
            (
                "subject_token_type",
                self.subject_token_type.as_deref().unwrap_or(JWT),
            ),
            (
                "requested_token_type",
                self.requested_token_type.as_deref().unwrap_or(ACCESS),
            ),
            ("audience", audience),
        ];
        if !scope.is_empty() {
            fields.push(("scope", &scope));
        }
        if let Some((actor, kind)) = actor.as_ref() {
            fields.extend([("actor_token", actor.as_str()), ("actor_token_type", *kind)]);
        }
        let (form, basic) = self.token_form(GRANT, &fields, method, signer.as_ref())?;
        let (response, _) = upstream
            .oauth_token_response(&self.token_url, tls, &form, basic.as_ref())
            .await?;
        let token: ExchangeResponse =
            serde_json::from_slice(&response).map_err(|_| UpstreamError::InvalidResponse)?;
        if token.access_token.is_empty()
            || token
                .access_token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
            || !token.token_type.eq_ignore_ascii_case("Bearer")
        {
            return Err(UpstreamError::InvalidResponse);
        }
        let value = Zeroizing::new(format!("Bearer {}", token.access_token));
        let mut authorization =
            HeaderValue::from_str(&value).map_err(|_| UpstreamError::InvalidResponse)?;
        authorization.set_sensitive(true);
        Ok(ExchangedCredential {
            authorization,
            expires_in: token
                .expires_in
                .as_ref()
                .and_then(|value| {
                    value
                        .as_u64()
                        .or_else(|| value.as_str().and_then(|value| value.trim().parse().ok()))
                })
                .filter(|lifetime| *lifetime > 0)
                .unwrap_or(60),
        })
    }
}

fn endpoint_origin(endpoint: &str) -> Option<url::Origin> {
    url::Url::parse(endpoint).ok().map(|url| url.origin())
}
