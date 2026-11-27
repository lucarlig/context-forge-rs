// SPDX-License-Identifier: Apache-2.0

use super::*;

const MASK: &str = "*****";

#[derive(Debug, thiserror::Error)]
pub(crate) enum UpdateAuthError {
    #[error("{0}")]
    Validation(&'static str),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

impl AuthInput {
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

    pub(crate) fn apply_update(
        &mut self,
        current: &mut GatewayConnectionRow,
        cipher: Option<&CredentialCipher>,
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
        if self.oauth_config.is_some() || self.sigv4_config.is_some() {
            return Err(UpdateAuthError::Validation(
                "Unsupported gateway authentication configuration update",
            ));
        }
        if explicit_kind.is_none() && self.auth_headers.is_none() && !query_update {
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
        if matches!(kind.as_str(), "oauth" | "sigv4") {
            return if kind == current.kind {
                Ok(false)
            } else {
                Err(AuthError::Invalid.into())
            };
        }
        let same_kind = kind == current.kind;
        match kind.as_str() {
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
        let prepared = self
            .prepare(cipher, query_hosts, url)?
            .ok_or(AuthError::Invalid)?;
        if same_kind
            && prepared.matches_stored(
                current.headers.as_deref(),
                current.query.as_deref(),
                current.sigv4.as_deref(),
                current.oauth.as_deref(),
            )
        {
            return Ok(false);
        }
        Ok(current.replace_auth(prepared.kind, Some(prepared)))
    }
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
