// SPDX-License-Identifier: Apache-2.0

use url::Url;

use super::{authorization_code::token_claims, *};

#[derive(Clone, Copy)]
pub(crate) struct A2aTokenPolicy {
    pub(crate) attempts: u32,
    pub(crate) strict_resource: bool,
}

impl Default for A2aTokenPolicy {
    fn default() -> Self {
        Self {
            attempts: 3,
            strict_resource: false,
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
pub(crate) enum A2aOAuthError {
    Configuration,
    Request,
    Claims {
        audience: bool,
        scopes: bool,
        issuer: bool,
    },
}

#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<Value>,
}

impl Drop for TokenReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

impl OAuthConfig {
    pub(crate) fn supports_a2a(&self) -> bool {
        self.grant_type
            .as_deref()
            .is_none_or(|grant| grant == "client_credentials")
    }

    pub(crate) fn masked_a2a_secret(&self) -> bool {
        [&self.client_secret, &self.private_key]
            .into_iter()
            .any(|field| field.as_deref() == Some(MASKED))
    }

    pub(crate) fn check_a2a_endpoints(
        &self,
        upstream: &UpstreamClient,
    ) -> Result<(), UpstreamError> {
        if !self.supports_a2a() {
            return Err(UpstreamError::InvalidCredentials);
        }
        upstream.check_endpoint(&self.token_url)?;
        for endpoint in [
            &self.authorization_url,
            &self.issuer,
            &self.jwks_uri,
            &self.redirect_uri,
        ]
        .into_iter()
        .filter_map(Option::as_deref)
        .filter(|value| !value.is_empty())
        {
            upstream.check_endpoint(endpoint)?;
        }
        if let Some(issuers) = &self.token_issuer {
            match issuers {
                OAuthValues::One(issuer) => upstream.check_endpoint(issuer)?,
                OAuthValues::Many(issuers) if !issuers.is_empty() && issuers.len() <= 5 => {
                    for issuer in issuers {
                        upstream.check_endpoint(issuer)?;
                    }
                }
                OAuthValues::Many(_) => return Err(UpstreamError::InvalidUrl),
            }
        }
        Ok(())
    }

    pub(crate) async fn a2a_authorization(
        &self,
        upstream: &UpstreamClient,
        endpoint: &str,
        policy: A2aTokenPolicy,
    ) -> Result<(HeaderValue, u64), A2aOAuthError> {
        if !self.supports_a2a() {
            return Err(A2aOAuthError::Configuration);
        }
        if policy.attempts == 0 {
            return Err(A2aOAuthError::Request);
        }
        let method = self.client_auth().ok_or(A2aOAuthError::Configuration)?;
        let assertion = self
            .client_assertion(method)
            .map_err(|_| A2aOAuthError::Configuration)?;
        let origin = Url::parse(endpoint)
            .ok()
            .map(|url| url.origin().ascii_serialization());
        let configured = self.resources(None);
        let resources = self.resources(origin.as_deref());
        let fields: Vec<_> = if self.omits_a2a_resource() {
            Vec::new()
        } else {
            resources
                .iter()
                .copied()
                .filter(|resource| !resource.is_empty())
                .map(|resource| ("resource", resource))
                .collect()
        };
        let mut attempts = 0;
        let token = loop {
            attempts += 1;
            let (form, basic) = self
                .token_form("client_credentials", &fields, method, assertion.as_ref())
                .map_err(|_| A2aOAuthError::Configuration)?;
            match upstream
                .oauth_token_response(&self.token_url, None, &form, basic.as_ref())
                .await
            {
                Ok((body, is_form)) => break decode(&body, is_form)?,
                Err(
                    UpstreamError::Status(_)
                    | UpstreamError::Timeout
                    | UpstreamError::Resolve
                    | UpstreamError::Transport,
                ) if attempts < policy.attempts => {
                    tokio::time::sleep(Duration::from_secs(1 << (attempts - 1).min(10))).await;
                }
                Err(_) => return Err(A2aOAuthError::Request),
            }
        };
        if token.access_token.is_empty()
            || token
                .access_token
                .bytes()
                .any(|byte| byte.is_ascii_whitespace())
            || token
                .token_type
                .as_deref()
                .is_some_and(|kind| !kind.is_empty() && !kind.eq_ignore_ascii_case("bearer"))
        {
            return Err(A2aOAuthError::Request);
        }
        if token.access_token.split('.').count() == 3
            && let Some(claims) = token_claims(&token.access_token)
            && claims.is_object()
        {
            self.check_a2a_claims(
                &claims,
                &resources,
                !configured.is_empty() || policy.strict_resource,
            )?;
        }
        let value = Zeroizing::new(format!("Bearer {}", token.access_token));
        let mut authorization =
            HeaderValue::from_str(&value).map_err(|_| A2aOAuthError::Request)?;
        authorization.set_sensitive(true);
        let expires = token
            .expires_in
            .as_ref()
            .and_then(|value| {
                value
                    .as_i64()
                    .or_else(|| value.as_str().and_then(|value| value.trim().parse().ok()))
            })
            .filter(|seconds| *seconds != 0)
            .unwrap_or(60)
            .max(0) as u64;
        Ok((authorization, expires))
    }

    fn omits_a2a_resource(&self) -> bool {
        self.omit_resource.as_ref().is_some_and(|flag| {
            flag.as_bool() == Some(true)
                || flag.as_str().is_some_and(|flag| {
                    matches!(
                        flag.trim().to_ascii_lowercase().as_str(),
                        "1" | "true" | "yes" | "on"
                    )
                })
        }) || !self.scope_string().is_empty()
            && [
                Some(self.token_url.as_str()),
                self.authorization_url.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(entra_v2)
    }

    fn check_a2a_claims(
        &self,
        claims: &Value,
        resources: &[&str],
        enforce_audience: bool,
    ) -> Result<(), A2aOAuthError> {
        let audience = enforce_audience
            && !resources.is_empty()
            && !claims["aud"].is_null()
            && !strings(&claims["aud"]).any(|audience| resources.contains(&audience));
        let mut received = &claims["scope"];
        if received.is_null() {
            received = &claims["scp"];
        }
        let granted: Vec<_> = strings(received).flat_map(str::split_whitespace).collect();
        let scope = self.scope_string();
        let scopes = !received.is_null()
            && received.as_str() != Some("")
            && scope.split_whitespace().any(|scope| {
                !granted
                    .iter()
                    .any(|value| short_scope(value) == short_scope(scope))
            });
        let expected: Vec<_> = match &self.token_issuer {
            Some(OAuthValues::One(value)) if !value.is_empty() => vec![value.as_str()],
            Some(OAuthValues::Many(values)) if !values.is_empty() => {
                values.iter().map(String::as_str).collect()
            }
            _ => self
                .issuer
                .as_deref()
                .filter(|issuer| !issuer.is_empty())
                .into_iter()
                .collect(),
        };
        let derived = expected
            .is_empty()
            .then(|| derive_issuer(&self.token_url))
            .flatten();
        let issuer = claims["iss"]
            .as_str()
            .filter(|issuer| !issuer.is_empty())
            .is_some_and(|issuer| {
                let issuer = issuer.trim_end_matches('/');
                if expected.is_empty() {
                    derived
                        .as_deref()
                        .is_some_and(|expected| expected.trim_end_matches('/') != issuer)
                } else {
                    !expected
                        .iter()
                        .any(|expected| expected.trim_end_matches('/') == issuer)
                }
            });
        if audience || scopes || issuer {
            return Err(A2aOAuthError::Claims {
                audience,
                scopes,
                issuer,
            });
        }
        Ok(())
    }
}

fn decode(body: &[u8], is_form: bool) -> Result<TokenReply, A2aOAuthError> {
    if !is_form {
        return serde_json::from_slice(body).map_err(|_| A2aOAuthError::Request);
    }
    let mut reply = TokenReply {
        access_token: String::new(),
        token_type: None,
        expires_in: None,
    };
    for (field, value) in url::form_urlencoded::parse(body) {
        match field.as_ref() {
            "access_token" if reply.access_token.is_empty() => {
                reply.access_token = value.into_owned()
            }
            "token_type" if reply.token_type.is_none() => {
                reply.token_type = Some(value.into_owned())
            }
            "expires_in" if reply.expires_in.is_none() => {
                reply.expires_in = Some(Value::String(value.into_owned()))
            }
            _ => {}
        }
    }
    Ok(reply)
}

fn strings(value: &Value) -> impl Iterator<Item = &str> {
    value.as_str().into_iter().chain(
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    )
}

fn short_scope(scope: &str) -> &str {
    scope.rsplit('/').next().unwrap_or(scope)
}

fn derive_issuer(endpoint: &str) -> Option<String> {
    let url = Url::parse(endpoint).ok()?;
    let origin = url.origin().ascii_serialization();
    let paths: Vec<_> = url
        .path_segments()?
        .filter(|part| !part.is_empty())
        .collect();
    Some(match paths.as_slice() {
        [tenant, "oauth2", "v2.0", "token", ..] => format!("{origin}/{tenant}/v2.0"),
        _ => origin,
    })
}

fn entra_v2(endpoint: &str) -> bool {
    Url::parse(endpoint).is_ok_and(|endpoint| {
        matches!(
            endpoint.host_str(),
            Some(
                "login.microsoftonline.com"
                    | "login.microsoftonline.us"
                    | "login.partner.microsoftonline.cn"
                    | "login.microsoftonline.de"
            )
        ) && endpoint
            .path()
            .to_ascii_lowercase()
            .contains("/oauth2/v2.0/")
    })
}
