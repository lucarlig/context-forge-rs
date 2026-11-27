// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashSet};

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    catalog::GatewayConnectionRow,
    oauth_client::OAuthConfig,
    sigv4::{SigV4, SigV4Config},
    upstream_tls::TlsMaterial,
};

mod update;
pub(crate) use update::UpdateAuthError;

pub(crate) struct CredentialCipher {
    key: LessSafeKey,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid or unavailable encrypted credential")]
pub(crate) struct CredentialError;

impl CredentialCipher {
    pub(crate) fn new(secret: &str) -> Self {
        let digest = Sha256::digest(secret.as_bytes());
        let key = UnboundKey::new(&AES_256_GCM, &digest).expect("SHA-256 yields a 256-bit key");
        Self {
            key: LessSafeKey::new(key),
        }
    }

    pub(crate) fn seal(&self, value: &impl Serialize) -> Result<String, CredentialError> {
        self.seal_scoped(value, &[])
    }

    pub(crate) fn seal_scoped(
        &self,
        value: &impl Serialize,
        context: &[u8],
    ) -> Result<String, CredentialError> {
        let mut nonce = [0; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| CredentialError)?;
        let mut plaintext = Zeroizing::new(serde_json::to_vec(value).map_err(|_| CredentialError)?);
        self.key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(context),
                &mut *plaintext,
            )
            .map_err(|_| CredentialError)?;
        let mut combined = Vec::with_capacity(NONCE_LEN + plaintext.len());
        combined.extend_from_slice(&nonce);
        combined.extend_from_slice(&plaintext);
        Ok(BASE64_URL_SAFE_NO_PAD.encode(combined))
    }

    pub(crate) fn open<T: DeserializeOwned>(&self, encoded: &str) -> Result<T, CredentialError> {
        self.open_scoped(encoded, &[])
    }

    pub(crate) fn open_scoped<T: DeserializeOwned>(
        &self,
        encoded: &str,
        context: &[u8],
    ) -> Result<T, CredentialError> {
        let mut bytes = Zeroizing::new(
            BASE64_URL_SAFE_NO_PAD
                .decode(encoded.trim_end_matches('='))
                .map_err(|_| CredentialError)?,
        );
        let (nonce, ciphertext) = bytes
            .split_first_chunk_mut::<NONCE_LEN>()
            .ok_or(CredentialError)?;
        let plaintext = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(context),
                ciphertext,
            )
            .map_err(|_| CredentialError)?;
        serde_json::from_slice(plaintext).map_err(|_| CredentialError)
    }
}

type HeaderValues = BTreeMap<String, String>;
pub(crate) type QueryValues = BTreeMap<String, String>;

#[derive(Default)]
pub(crate) struct UpstreamCredentials {
    pub(crate) headers: HeaderMap,
    pub(crate) query: QueryValues,
    pub(crate) identity_meta: Option<Value>,
    pub(crate) request_bound_header: Option<HeaderName>,
    pub(crate) tls: Option<TlsMaterial>,
    pub(crate) sigv4: Option<std::sync::Arc<SigV4>>,
}

#[derive(Deserialize)]
pub(crate) struct AuthInput {
    #[serde(alias = "authType")]
    auth_type: Option<String>,
    #[serde(alias = "authUsername")]
    auth_username: Option<String>,
    #[serde(alias = "authPassword")]
    auth_password: Option<String>,
    #[serde(alias = "authToken")]
    auth_token: Option<String>,
    #[serde(alias = "authHeaderKey")]
    auth_header_key: Option<String>,
    #[serde(alias = "authHeaderValue")]
    auth_header_value: Option<String>,
    #[serde(alias = "authHeaders")]
    auth_headers: Option<Vec<ConfiguredHeader>>,
    #[serde(alias = "authQueryParamKey")]
    auth_query_param_key: Option<String>,
    #[serde(alias = "authQueryParamValue")]
    auth_query_param_value: Option<String>,
    #[serde(alias = "sigv4Config")]
    sigv4_config: Option<SigV4Config>,
    #[serde(alias = "oauthConfig")]
    oauth_config: Option<OAuthConfig>,
}

#[derive(Deserialize)]
struct ConfiguredHeader {
    key: String,
    value: String,
}

pub(crate) struct PreparedAuth<'a> {
    pub(crate) kind: &'static str,
    pub(crate) encoded_headers: Option<String>,
    pub(crate) encoded_query: Option<String>,
    pub(crate) encoded_sigv4: Option<String>,
    pub(crate) encoded_oauth: Option<String>,
    pub(crate) credentials: UpstreamCredentials,
    pub(crate) masked: Value,
    cipher: &'a CredentialCipher,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthError {
    #[error("invalid upstream authentication credentials")]
    Invalid,
    #[error("unsupported upstream authentication method")]
    Unsupported,
    #[error("query parameter authentication is disabled")]
    QueryDisabled,
    #[error("query parameter authentication is not allowed for the upstream host")]
    QueryHost,
    #[error(transparent)]
    Encryption(#[from] CredentialError),
}

impl AuthInput {
    pub(crate) fn oauth_config(&self) -> Option<&OAuthConfig> {
        self.oauth_config.as_ref()
    }

    pub(crate) fn oauth_config_mut(&mut self) -> Option<&mut OAuthConfig> {
        self.oauth_config.as_mut()
    }

    pub(crate) fn is_one_time_marker(&self) -> bool {
        self.auth_type
            .as_deref()
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("one_time_auth"))
    }

    pub(crate) fn prepare<'a>(
        &self,
        cipher: Option<&'a CredentialCipher>,
        query_hosts: Option<&HashSet<String>>,
        url: &str,
    ) -> Result<Option<PreparedAuth<'a>>, AuthError> {
        let kind = self
            .auth_type
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if self.sigv4_config.is_some() && kind != "sigv4" {
            return Err(AuthError::Invalid);
        }
        if self.oauth_config.is_some() && kind != "oauth" {
            return Err(AuthError::Invalid);
        }
        let mut masked = json!({"authType": kind, "authValue": "*****"});
        let (kind, values) = match kind.as_str() {
            "" | "none" | "one_time_auth" => return Ok(None),
            "oauth" => {
                if !self.oauth_config.as_ref().is_some_and(OAuthConfig::valid) {
                    return Err(AuthError::Invalid);
                }
                return Ok(Some(PreparedAuth {
                    kind: "oauth",
                    encoded_headers: None,
                    encoded_query: None,
                    encoded_sigv4: None,
                    encoded_oauth: None,
                    credentials: UpstreamCredentials::default(),
                    masked: json!({"authType": "oauth"}),
                    cipher: cipher.ok_or(CredentialError)?,
                }));
            }
            "sigv4" => {
                let config = self.sigv4_config.as_ref().ok_or(AuthError::Invalid)?;
                if !config.valid() {
                    return Err(AuthError::Invalid);
                }
                let cipher = cipher.ok_or(CredentialError)?;
                let (signer, encoded, masked) = config.prepare(cipher)?;
                return Ok(Some(PreparedAuth {
                    kind: "sigv4",
                    encoded_headers: None,
                    encoded_query: None,
                    encoded_sigv4: Some(encoded),
                    encoded_oauth: None,
                    credentials: UpstreamCredentials {
                        sigv4: Some(signer),
                        ..UpstreamCredentials::default()
                    },
                    masked: json!({"authType": "sigv4", "sigv4Config": masked}),
                    cipher,
                }));
            }
            "query_param" => {
                validate_query_host(query_hosts, url)?;
                let key = required(self.auth_query_param_key.as_deref())?;
                let value = required(self.auth_query_param_value.as_deref())?;
                if !query_key(key) || value == "*****" {
                    return Err(AuthError::Invalid);
                }
                let cipher = cipher.ok_or(CredentialError)?;
                let query = QueryValues::from([(key.to_owned(), value.to_owned())]);
                let encoded = QueryValues::from([(key.to_owned(), cipher.seal(&query)?)]);
                return Ok(Some(PreparedAuth {
                    kind: "query_param",
                    encoded_headers: None,
                    encoded_query: Some(
                        serde_json::to_string(&encoded).map_err(|_| CredentialError)?,
                    ),
                    encoded_sigv4: None,
                    encoded_oauth: None,
                    credentials: UpstreamCredentials {
                        query,
                        ..UpstreamCredentials::default()
                    },
                    masked: json!({"authType":"query_param","authQueryParamKey": key, "authQueryParamValueMasked": "*****"}),
                    cipher,
                }));
            }
            "basic" => {
                let username = required(self.auth_username.as_deref())?;
                let password = required(self.auth_password.as_deref())?;
                if username.contains(':') {
                    return Err(AuthError::Invalid);
                }
                let encoded = BASE64_STANDARD.encode(format!("{username}:{password}"));
                masked["authUsername"] = username.into();
                masked["authPassword"] = "*****".into();
                (
                    "basic",
                    HeaderValues::from([("Authorization".into(), format!("Basic {encoded}"))]),
                )
            }
            "bearer" => {
                let token = required(self.auth_token.as_deref())?;
                masked["authToken"] = "*****".into();
                (
                    "bearer",
                    HeaderValues::from([("Authorization".into(), format!("Bearer {token}"))]),
                )
            }
            "authheaders" => {
                let legacy;
                let configured = match self
                    .auth_headers
                    .as_deref()
                    .filter(|headers| !headers.is_empty())
                {
                    Some(headers) => headers,
                    None => {
                        legacy = [ConfiguredHeader {
                            key: required(self.auth_header_key.as_deref())?.to_owned(),
                            value: required(self.auth_header_value.as_deref())?.to_owned(),
                        }];
                        &legacy
                    }
                };
                let mut values = HeaderValues::new();
                let mut response = Vec::with_capacity(configured.len());
                for entry in configured {
                    let name = required(Some(&entry.key))?;
                    let value = required(Some(&entry.value))?;
                    if values.insert(name.to_owned(), value.to_owned()).is_some() {
                        return Err(AuthError::Invalid);
                    }
                    response.push(json!({"key": name, "value": "*****"}));
                }
                masked["authHeaderKey"] = response[0]["key"].clone();
                masked["authHeaderValue"] = "*****".into();
                masked["authHeaders"] = response.into();
                ("authheaders", values)
            }
            _ => return Err(AuthError::Unsupported),
        };
        let headers = http_headers(values.iter()).map_err(|_| AuthError::Invalid)?;
        let cipher = cipher.ok_or(CredentialError)?;
        let encoded = cipher.seal(&values)?;
        Ok(Some(PreparedAuth {
            kind,
            encoded_headers: Some(json!(encoded).to_string()),
            encoded_query: None,
            encoded_sigv4: None,
            encoded_oauth: None,
            credentials: UpstreamCredentials {
                headers,
                ..UpstreamCredentials::default()
            },
            masked,
            cipher,
        }))
    }
}

impl PreparedAuth<'_> {
    pub(crate) fn matches_stored(
        &self,
        headers: Option<&str>,
        query: Option<&str>,
        sigv4: Option<&str>,
        oauth: Option<&str>,
    ) -> bool {
        if let Some(config) = &self.encoded_oauth {
            return oauth.is_some_and(|stored| OAuthConfig::matches_stored(config, stored));
        }
        if let Some(signer) = &self.credentials.sigv4 {
            return sigv4.is_some_and(|stored| signer.matches_stored(stored));
        }
        if self.kind == "query_param" {
            return query.is_some_and(|stored| {
                decode_query(Some(self.cipher), stored)
                    .is_ok_and(|query| self.credentials.query == query)
            });
        }
        headers.is_some_and(|stored| {
            decode_headers(Some(self.cipher), stored)
                .is_ok_and(|headers| self.credentials.headers == headers)
        })
    }
}

pub(crate) fn validate_query_host(
    hosts: Option<&HashSet<String>>,
    url: &str,
) -> Result<(), AuthError> {
    let hosts = hosts.ok_or(AuthError::QueryDisabled)?;
    if hosts.is_empty() {
        return Ok(());
    }
    let url = Url::parse(url).map_err(|_| AuthError::QueryHost)?;
    let host = url
        .host_str()
        .ok_or(AuthError::QueryHost)?
        .trim_matches(['[', ']']);
    if hosts
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(host))
    {
        Ok(())
    } else {
        Err(AuthError::QueryHost)
    }
}

pub(crate) fn decode_query(
    cipher: Option<&CredentialCipher>,
    stored: &str,
) -> Result<QueryValues, CredentialError> {
    let cipher = cipher.ok_or(CredentialError)?;
    let encoded: QueryValues = serde_json::from_str(stored).map_err(|_| CredentialError)?;
    if encoded.is_empty() {
        return Err(CredentialError);
    }
    encoded
        .into_iter()
        .map(|(key, ciphertext)| {
            if !query_key(&key) {
                return Err(CredentialError);
            }
            let mut pair: QueryValues = cipher.open(&ciphertext)?;
            let value = pair
                .remove(&key)
                .filter(|value| !value.is_empty())
                .ok_or(CredentialError)?;
            Ok((key, value))
        })
        .collect()
}

fn query_key(key: &str) -> bool {
    key.as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn decode_headers(
    cipher: Option<&CredentialCipher>,
    stored: &str,
) -> Result<HeaderMap, CredentialError> {
    http_headers(decode_header_values(cipher, stored)?.iter())
}

pub(crate) fn decode_header_values(
    cipher: Option<&CredentialCipher>,
    stored: &str,
) -> Result<HeaderValues, CredentialError> {
    let value: Value = serde_json::from_str(stored).map_err(|_| CredentialError)?;
    match value {
        Value::String(encoded) => cipher.ok_or(CredentialError)?.open(&encoded),
        Value::Object(_) => serde_json::from_value(value).map_err(|_| CredentialError),
        _ => Err(CredentialError),
    }
}

fn http_headers<'a>(
    values: impl Iterator<Item = (&'a String, &'a String)>,
) -> Result<HeaderMap, CredentialError> {
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| CredentialError)?;
        if name.as_str().starts_with("mcp-")
            || name.as_str().starts_with("proxy-")
            || [
                header::HOST,
                header::ACCEPT,
                header::CONNECTION,
                header::UPGRADE,
                header::CONTENT_LENGTH,
                header::CONTENT_TYPE,
                header::TRANSFER_ENCODING,
                header::TE,
                header::TRAILER,
            ]
            .contains(&name)
            || headers.contains_key(&name)
        {
            return Err(CredentialError);
        }
        let mut value = HeaderValue::from_str(value).map_err(|_| CredentialError)?;
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    if headers.is_empty() {
        return Err(CredentialError);
    }
    Ok(headers)
}

fn required(value: Option<&str>) -> Result<&str, AuthError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .ok_or(AuthError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_pinned_gateway_ciphertext_and_rejects_the_wrong_key() {
        let captured = "ulkmjUnOaqW3DiMsK7eQ10FqpUDjG81kpM25-CDex96eCSk55xrkQhWWl1YABYFDrWgm9Wj3rISlhhkZd9iO3c9hoxmoOhQ9DuoC";
        let cipher =
            CredentialCipher::new("context-forge-fixture-encryption-key-with-ample-entropy");
        let expected = HeaderValues::from([(
            "Authorization".to_owned(),
            "Bearer fixture-bearer-token".to_owned(),
        )]);
        assert_eq!(cipher.open::<HeaderValues>(captured).unwrap(), expected);
        assert!(
            CredentialCipher::new("other synthetic key")
                .open::<HeaderValues>(captured)
                .is_err()
        );
        let first = cipher.seal(&expected).unwrap();
        let second = cipher.seal(&expected).unwrap();
        assert_ne!(first, second);
        assert_eq!(cipher.open::<HeaderValues>(&first).unwrap(), expected);
    }

    #[test]
    fn query_credentials_require_an_allowed_host_and_are_sealed_separately() {
        let cipher = CredentialCipher::new("synthetic query encryption key");
        let input: AuthInput = serde_json::from_value(json!({
            "authType": "query_param", "authQueryParamKey": "api-key", "authQueryParamValue": "synthetic value"
        })).unwrap();
        let url = "https://upstream.example.test/mcp";
        assert!(matches!(
            input.prepare(Some(&cipher), None, url),
            Err(AuthError::QueryDisabled)
        ));
        let allowed = HashSet::from(["upstream.example.test".to_owned()]);
        assert!(matches!(
            input.prepare(
                Some(&cipher),
                Some(&allowed),
                "https://other.example.test/mcp"
            ),
            Err(AuthError::QueryHost)
        ));
        let auth = input
            .prepare(Some(&cipher), Some(&allowed), url)
            .unwrap()
            .unwrap();
        assert!(auth.encoded_headers.is_none());
        let stored = auth.encoded_query.as_deref().unwrap();
        assert!(!stored.contains("synthetic value"));
        assert!(auth.matches_stored(None, Some(stored), None, None));
        assert_eq!(
            decode_query(Some(&cipher), stored).unwrap(),
            auth.credentials.query
        );
    }
}
