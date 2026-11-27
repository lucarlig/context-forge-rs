// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::secret_envelope::SecretEnvelope;

const MASK: &str = "*****";

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpdateAuthError {
    #[error("{0}")]
    Validation(&'static str),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl AuthInput {
    pub(crate) fn clears_auth(&self) -> bool {
        self.auth_type.as_deref().is_some_and(|kind| {
            let kind = kind.trim();
            kind.is_empty() || kind.eq_ignore_ascii_case("none")
        })
    }

    pub(crate) async fn apply_agent_update(
        &mut self,
        current: &mut GatewayConnectionRow,
        cipher: Option<&CredentialCipher>,
        vault: Option<&SecretEnvelope>,
        query_hosts: Option<&HashSet<String>>,
        url: &str,
        url_changed: bool,
    ) -> Result<bool, UpdateAuthError> {
        let kind = self
            .auth_type
            .as_deref()
            .map(|kind| kind.trim().to_ascii_lowercase());
        if self.sigv4_config.is_some()
            || kind.as_deref().is_some_and(|kind| {
                !matches!(
                    kind,
                    "" | "none" | "basic" | "bearer" | "authheaders" | "query_param" | "oauth"
                )
            })
        {
            return Err(UpdateAuthError::Validation(
                "Unsupported A2A authentication method",
            ));
        }
        if url_changed && kind.as_deref().unwrap_or(&current.kind) == "query_param" {
            validate_query_host(query_hosts, url)?;
        }
        if kind.as_deref() == Some(current.kind.as_str()) {
            match current.kind.as_str() {
                "basic" if self.auth_password.is_none() && self.auth_username.is_none() => {
                    return Ok(false);
                }
                "basic" if self.auth_password.is_none() => {
                    self.auth_password = Some(MASK.to_owned())
                }
                "bearer" if self.auth_token.is_none() => return Ok(false),
                "authheaders"
                    if self.auth_headers.is_none() && self.auth_header_value.is_none() =>
                {
                    return Ok(false);
                }
                "query_param" => self.auth_type = None,
                _ => {}
            }
        }
        self.apply_update(current, cipher, vault, query_hosts, url)
            .await
    }

    pub(crate) fn has_update(&self) -> bool {
        self.auth_type.is_some()
            || self.auth_password.is_some()
            || self.auth_token.is_some()
            || self.auth_headers.is_some()
            || self.auth_header_value.is_some()
            || self.auth_query_param_key.is_some()
            || self.auth_query_param_value.is_some()
            || self.oauth_config.is_some()
            || self.sigv4_config.is_some()
    }

    pub(crate) async fn apply_update(
        &mut self,
        current: &mut GatewayConnectionRow,
        cipher: Option<&CredentialCipher>,
        vault: Option<&SecretEnvelope>,
        query_hosts: Option<&HashSet<String>>,
        url: &str,
    ) -> Result<bool, UpdateAuthError> {
        let explicit_kind = self.auth_type.as_deref();
        if explicit_kind.is_none()
            && [
                &self.auth_token,
                &self.auth_password,
                &self.auth_header_value,
            ]
            .into_iter()
            .any(|value| value.as_deref().is_some_and(|value| !value.is_empty()))
        {
            return Err(UpdateAuthError::Validation(
                "auth_type is required when setting auth_token, auth_password, or auth_header_value",
            ));
        }
        let kind = explicit_kind
            .unwrap_or(&current.kind)
            .trim()
            .to_ascii_lowercase();
        let query_update = kind == "query_param"
            && (self.auth_query_param_key.is_some() || self.auth_query_param_value.is_some());
        if self.oauth_config.is_some() && kind != "oauth" {
            return Err(UpdateAuthError::Validation(
                "oauth_config requires auth_type 'oauth'",
            ));
        }
        if self.sigv4_config.is_some() && kind != "sigv4" {
            return Err(UpdateAuthError::Validation(
                "sigv4_config requires auth_type 'sigv4'",
            ));
        }
        if explicit_kind.is_none()
            && self.auth_headers.is_none()
            && !query_update
            && self.oauth_config.is_none()
            && self.sigv4_config.is_none()
        {
            return Ok(false);
        }
        if matches!(kind.as_str(), "" | "none" | "one_time_auth") {
            let marker = if kind == "one_time_auth" {
                kind.as_str()
            } else {
                ""
            };
            return Ok(current.replace_auth(marker, None));
        }
        let same_kind = kind == current.kind;
        let mut stored_oauth = None;
        match kind.as_str() {
            "sigv4" => {
                let Some(config) = self.sigv4_config.as_mut() else {
                    return keep_existing_config(same_kind, current.sigv4.as_deref());
                };
                config
                    .resolve_masks(
                        cipher.ok_or(AuthError::from(CredentialError))?,
                        current.sigv4.as_deref().filter(|_| same_kind),
                    )
                    .map_err(|_| AuthError::Invalid)?;
            }
            "oauth" => {
                let Some(config) = self.oauth_config.as_mut() else {
                    return keep_existing_config(same_kind, current.oauth.as_deref());
                };
                let vault = vault.ok_or(AuthError::from(CredentialError))?;
                let existing = match current.oauth.as_deref().filter(|_| same_kind) {
                    Some(encoded) => OAuthConfig::load(vault, encoded).await.ok(),
                    None => None,
                };
                config
                    .resolve_masks(existing.as_ref())
                    .map_err(|_| AuthError::Invalid)?;
                if existing.as_ref() == Some(config) {
                    return Ok(false);
                }
                if !config.valid() {
                    return Err(AuthError::Invalid.into());
                }
                stored_oauth = Some(
                    config
                        .store(vault)
                        .await
                        .map_err(|_| AuthError::from(CredentialError))?
                        .0,
                );
            }
            "basic" => {
                if self.auth_password.as_deref() == Some(MASK) {
                    let headers = stored_header_values(current, cipher, same_kind)?;
                    let encoded = header_value(&headers, "Authorization")?
                        .strip_prefix("Basic ")
                        .ok_or(AuthError::Invalid)?;
                    let decoded = BASE64_STANDARD
                        .decode(encoded)
                        .map_err(|_| AuthError::Invalid)?;
                    let decoded = std::str::from_utf8(&decoded).map_err(|_| AuthError::Invalid)?;
                    let (_, password) = decoded.split_once(':').ok_or(AuthError::Invalid)?;
                    self.auth_password = Some(password.to_owned());
                }
            }
            "bearer" => {
                if self.auth_token.as_deref() == Some(MASK) {
                    let headers = stored_header_values(current, cipher, same_kind)?;
                    let token = header_value(&headers, "Authorization")?
                        .strip_prefix("Bearer ")
                        .ok_or(AuthError::Invalid)?;
                    self.auth_token = Some(token.to_owned());
                }
            }
            "authheaders" => {
                if self.auth_header_value.as_deref() == Some(MASK)
                    || self
                        .auth_headers
                        .as_ref()
                        .is_some_and(|headers| headers.iter().any(|header| header.value == MASK))
                {
                    let stored = stored_header_values(current, cipher, same_kind)?;
                    if self.auth_header_value.as_deref() == Some(MASK) {
                        self.auth_header_value = Some(
                            header_value(&stored, required(self.auth_header_key.as_deref())?)?
                                .to_owned(),
                        );
                    }
                    for header in self
                        .auth_headers
                        .iter_mut()
                        .flatten()
                        .filter(|header| header.value == MASK)
                    {
                        header.value = header_value(&stored, &header.key)?.to_owned();
                    }
                }
            }
            "query_param" => {
                if explicit_kind.is_some()
                    && (self.auth_query_param_key.is_none()
                        || self.auth_query_param_value.is_none())
                {
                    return Err(UpdateAuthError::Validation(
                        "auth_query_param_key and auth_query_param_value are required when setting auth_type to query_param",
                    ));
                }
                if same_kind
                    && (self.auth_query_param_key.is_none()
                        || self
                            .auth_query_param_value
                            .as_deref()
                            .is_none_or(|value| value == MASK))
                {
                    let stored = current.query.as_deref().ok_or(AuthError::Invalid)?;
                    let stored = decode_query(cipher, stored).map_err(AuthError::from)?;
                    let (name, value) = stored.first_key_value().ok_or(AuthError::Invalid)?;
                    self.auth_query_param_key
                        .get_or_insert_with(|| name.clone());
                    if self
                        .auth_query_param_value
                        .as_deref()
                        .is_none_or(|value| value == MASK)
                    {
                        self.auth_query_param_value = Some(value.clone());
                    }
                }
            }
            _ => return Err(AuthError::Unsupported.into()),
        }
        self.auth_type = Some(kind);
        let mut prepared = self
            .prepare(cipher, query_hosts, url)?
            .ok_or(AuthError::Invalid)?;
        let unchanged = if let Some(signer) = &prepared.credentials.sigv4 {
            cipher
                .zip(current.sigv4.as_deref())
                .is_some_and(|(cipher, stored)| {
                    SigV4Config::load(cipher, stored)
                        .is_ok_and(|existing| signer.fingerprint() == existing.fingerprint())
                })
        } else {
            prepared.matches_stored(
                current.headers.as_deref(),
                current.query.as_deref(),
                current.sigv4.as_deref(),
                current.oauth.as_deref(),
            )
        };
        if same_kind && unchanged {
            return Ok(false);
        }
        prepared.encoded_oauth = stored_oauth;
        Ok(current.replace_auth(prepared.kind, Some(prepared)))
    }
}

fn keep_existing_config(same_kind: bool, stored: Option<&str>) -> Result<bool, UpdateAuthError> {
    if same_kind && stored.is_some_and(|value| !matches!(value.trim(), "" | "null" | "{}")) {
        return Ok(false);
    }
    Err(AuthError::Invalid.into())
}

impl GatewayConnectionRow {
    fn replace_auth(&mut self, kind: &str, prepared: Option<PreparedAuth<'_>>) -> bool {
        if self.kind == kind
            && prepared.is_none()
            && [
                self.headers.as_deref(),
                self.query.as_deref(),
                self.sigv4.as_deref(),
                self.oauth.as_deref(),
            ]
            .into_iter()
            .all(|value| {
                value.is_none_or(|value| matches!(value.trim(), "" | "null" | "{}" | "\"\""))
            })
        {
            return false;
        }
        self.kind = kind.to_owned();
        let (headers, query, sigv4, oauth) = prepared
            .map(|auth| {
                (
                    auth.encoded_headers,
                    auth.encoded_query,
                    auth.encoded_sigv4,
                    auth.encoded_oauth,
                )
            })
            .unwrap_or_default();
        self.headers = headers;
        self.query = query;
        self.sigv4 = sigv4;
        self.oauth = oauth;
        true
    }
}

fn stored_header_values(
    current: &GatewayConnectionRow,
    cipher: Option<&CredentialCipher>,
    same_kind: bool,
) -> Result<HeaderValues, AuthError> {
    let stored = current
        .headers
        .as_deref()
        .filter(|_| same_kind)
        .ok_or(AuthError::Invalid)?;
    Ok(decode_header_values(cipher, stored)?)
}

fn header_value<'a>(headers: &'a HeaderValues, name: &str) -> Result<&'a str, AuthError> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .ok_or(AuthError::Invalid)
}
