// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::Timestamp;

use super::*;

pub(crate) struct UserOAuthTokens {
    pub(crate) access_token: Zeroizing<String>,
    pub(crate) refresh_token: Option<Zeroizing<String>>,
    pub(crate) expires_at: Option<Timestamp>,
    pub(crate) scopes: Option<Vec<String>>,
    pub(crate) subject: String,
    pub(crate) learned_aud: Option<Value>,
    pub(crate) learned_iss: Option<String>,
}

#[derive(Default, Deserialize)]
struct ProviderReply {
    access_token: String,
    refresh_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<Seconds>,
    scope: Option<OAuthValues>,
    user_id: Option<String>,
}

impl Drop for ProviderReply {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Seconds {
    Number(i64),
    String(String),
}

impl Seconds {
    fn get(&self) -> Option<i64> {
        match self {
            Self::Number(seconds) => Some(*seconds),
            Self::String(seconds) => seconds.parse().ok(),
        }
    }
}

impl OAuthConfig {
    pub(crate) fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref().filter(|id| !id.is_empty())
    }

    pub(crate) fn redirect_uri(&self) -> Option<&str> {
        self.redirect_uri.as_deref().filter(|uri| !uri.is_empty())
    }

    pub(crate) fn verify_response_issuer(&self, received: Option<&str>) -> bool {
        let Some(expected) = self.issuer.as_deref().filter(|issuer| !issuer.is_empty()) else {
            return received.is_none();
        };
        match received {
            Some(received) => received == expected,
            None => !self
                .authorization_response_iss_parameter_supported
                .unwrap_or(false),
        }
    }

    pub(crate) fn authorize_url(
        &self,
        upstream: &UpstreamClient,
        redirect: &str,
        state: &str,
        challenge: &str,
        gateway_origin: Option<&str>,
    ) -> Result<url::Url, UpstreamError> {
        let endpoint = self
            .authorization_url
            .as_deref()
            .ok_or(UpstreamError::InvalidUrl)?;
        upstream.check_endpoint(endpoint)?;
        upstream.check_endpoint(&self.token_url)?;
        let mut url = url::Url::parse(endpoint).map_err(|_| UpstreamError::InvalidUrl)?;
        if url.fragment().is_some() {
            return Err(UpstreamError::InvalidUrl);
        }
        let scope = self.scope_string();
        let managed = [
            "response_type",
            "client_id",
            "redirect_uri",
            "state",
            "code_challenge",
            "code_challenge_method",
            "scope",
            "resource",
            "audience",
        ];
        let other: Vec<_> = url
            .query_pairs()
            .filter(|(name, _)| !managed.contains(&name.as_ref()))
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        url.set_query(None);
        {
            let mut query = url.query_pairs_mut();
            query.extend_pairs(other);
            query
                .append_pair("response_type", "code")
                .append_pair(
                    "client_id",
                    self.client_id().ok_or(UpstreamError::InvalidCredentials)?,
                )
                .append_pair("redirect_uri", redirect)
                .append_pair("state", state)
                .append_pair("code_challenge", challenge)
                .append_pair("code_challenge_method", "S256");
            if !scope.is_empty() {
                query.append_pair("scope", &scope);
            }
            if let Some(audience) = self
                .audience
                .as_deref()
                .filter(|audience| !audience.is_empty())
            {
                query.append_pair("audience", audience);
            }
            for resource in self.resources(gateway_origin) {
                query.append_pair("resource", resource);
            }
        }
        Ok(url)
    }

    pub(crate) async fn exchange_user_code(
        &self,
        upstream: &UpstreamClient,
        tls: Option<&TlsMaterial>,
        code: &str,
        verifier: &str,
        redirect: &str,
        origin: Option<&str>,
    ) -> Result<UserOAuthTokens, UpstreamError> {
        let mut fields = vec![
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
        ];
        fields.extend(
            self.resources(origin)
                .into_iter()
                .map(|resource| ("resource", resource)),
        );
        self.user_token_request(upstream, tls, "authorization_code", &fields)
            .await
    }

    pub(crate) async fn refresh_user_token(
        &self,
        upstream: &UpstreamClient,
        tls: Option<&TlsMaterial>,
        token: &str,
        origin: Option<&str>,
    ) -> Result<UserOAuthTokens, UpstreamError> {
        let mut fields = vec![("refresh_token", token)];
        fields.extend(
            self.resources(origin)
                .into_iter()
                .map(|resource| ("resource", resource)),
        );
        self.user_token_request(upstream, tls, "refresh_token", &fields)
            .await
    }

    async fn user_token_request(
        &self,
        upstream: &UpstreamClient,
        tls: Option<&TlsMaterial>,
        grant: &str,
        fields: &[(&str, &str)],
    ) -> Result<UserOAuthTokens, UpstreamError> {
        let method = self
            .client_auth()
            .ok_or(UpstreamError::InvalidCredentials)?;
        if self.client_id().is_none() {
            return Err(UpstreamError::InvalidCredentials);
        }
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
        let (encoded, basic) = self.token_form(grant, fields, method, assertion.as_ref())?;
        let (response, is_form) = upstream
            .oauth_token_response(&self.token_url, tls, &encoded, basic.as_ref())
            .await?;
        let mut reply = if is_form {
            let mut result = ProviderReply::default();
            for (name, value) in url::form_urlencoded::parse(&response) {
                match name.as_ref() {
                    "access_token" => result.access_token = value.into_owned(),
                    "refresh_token" => result.refresh_token = Some(value.into_owned()),
                    "token_type" => result.token_type = Some(value.into_owned()),
                    "expires_in" => result.expires_in = Some(Seconds::String(value.into_owned())),
                    "scope" => result.scope = Some(OAuthValues::One(value.into_owned())),
                    "user_id" => result.user_id = Some(value.into_owned()),
                    _ => {}
                }
            }
            result
        } else {
            serde_json::from_slice(&response).map_err(|_| UpstreamError::InvalidResponse)?
        };
        if reply.access_token.trim().is_empty()
            || reply
                .token_type
                .as_deref()
                .is_some_and(|ty| !ty.eq_ignore_ascii_case("bearer"))
            || HeaderValue::from_str(&reply.access_token).is_err()
        {
            return Err(UpstreamError::InvalidResponse);
        }
        let access = Zeroizing::new(std::mem::take(&mut reply.access_token));
        let claims = token_claims(&access);
        let learned_aud = claims
            .as_ref()
            .and_then(|claims| claims.get("aud"))
            .filter(|aud| {
                aud.is_string()
                    || aud.as_array().is_some_and(|values| {
                        !values.is_empty() && values.iter().all(Value::is_string)
                    })
            })
            .cloned();
        let learned_iss = claims
            .as_ref()
            .and_then(|claims| claims["iss"].as_str())
            .filter(|issuer| issuer.len() <= 500)
            .map(str::to_owned);
        let subject = reply
            .user_id
            .take()
            .or_else(|| {
                claims
                    .as_ref()
                    .and_then(|claims| claims["sub"].as_str())
                    .map(str::to_owned)
            })
            .filter(|id| !id.is_empty() && id.len() <= 255)
            .unwrap_or_else(|| "unknown".to_owned());
        let expires_at = reply
            .expires_in
            .as_ref()
            .and_then(Seconds::get)
            .and_then(|seconds| Timestamp::now().as_second().checked_add(seconds))
            .and_then(|expiry| Timestamp::from_second(expiry).ok());
        let scopes = reply
            .scope
            .as_ref()
            .or(self.scopes.as_ref())
            .map(|scope| match scope {
                OAuthValues::One(value) => {
                    value.split_ascii_whitespace().map(str::to_owned).collect()
                }
                OAuthValues::Many(values) => values.clone(),
            });
        Ok(UserOAuthTokens {
            access_token: access,
            refresh_token: reply
                .refresh_token
                .take()
                .filter(|token| !token.is_empty())
                .map(Zeroizing::new),
            expires_at,
            scopes,
            subject,
            learned_aud,
            learned_iss,
        })
    }

    pub(super) fn scope_string(&self) -> String {
        match &self.scopes {
            None => String::new(),
            Some(OAuthValues::One(value)) => value.clone(),
            Some(OAuthValues::Many(values)) => values.join(" "),
        }
    }

    fn resources<'a>(&'a self, default: Option<&'a str>) -> Vec<&'a str> {
        match &self.resource {
            Some(OAuthValues::One(value)) if !value.is_empty() => vec![value.as_str()],
            Some(OAuthValues::Many(values)) if !values.is_empty() => {
                values.iter().map(String::as_str).collect()
            }
            _ => default.into_iter().collect(),
        }
    }
}

fn token_claims(token: &str) -> Option<Value> {
    let payload = token
        .split('.')
        .nth(1)
        .filter(|payload| payload.len() <= 65_536)?;
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload).ok()?);
    serde_json::from_slice(&decoded).ok()
}
