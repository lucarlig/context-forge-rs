// SPDX-License-Identifier: Apache-2.0

use std::{sync::Arc, time::SystemTime};

use aws_credential_types::Credentials;
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningParams,
        SigningSettings, UriPathNormalizationMode, sign,
    },
    sign::v4,
};
use axum::http::{HeaderValue, header};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::credentials::{CredentialCipher, CredentialError};

const SECRET_KEY: &str = "secret_access_key";
const SESSION_TOKEN: &str = "session_token";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SigV4Config {
    access_key_id: String,
    secret_access_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_token: Option<String>,
    region: String,
    service: String,
}

impl Drop for SigV4Config {
    fn drop(&mut self) {
        self.secret_access_key.zeroize();
        self.session_token.zeroize();
    }
}

impl SigV4Config {
    pub(crate) fn resolve_masks(
        &mut self,
        cipher: &CredentialCipher,
        stored: Option<&str>,
    ) -> Result<(), CredentialError> {
        let keep_secret = self.secret_access_key == "*****";
        let keep_token = self.session_token.as_deref() == Some("*****");
        if !keep_secret && !keep_token {
            return Ok(());
        }
        let stored: Option<Self> = stored
            .map(|value| serde_json::from_str(value).map_err(|_| CredentialError))
            .transpose()?;
        if keep_secret {
            let existing = stored.as_ref().ok_or(CredentialError)?;
            self.secret_access_key =
                open_field(cipher, SECRET_KEY, &existing.secret_access_key)?.to_string();
        }
        if keep_token {
            self.session_token = stored
                .as_ref()
                .and_then(|config| config.session_token.as_deref())
                .map(|token| {
                    open_field(cipher, SESSION_TOKEN, token).map(|token| token.to_string())
                })
                .transpose()?;
        }
        Ok(())
    }

    pub(crate) fn prepare(
        &self,
        cipher: &CredentialCipher,
    ) -> Result<(Arc<SigV4>, String, Value), CredentialError> {
        let signer = self.signer(&self.secret_access_key, self.session_token.as_deref())?;
        let stored = Self {
            access_key_id: signer.credentials.access_key_id().to_owned(),
            secret_access_key: cipher.seal(&json!({
                SECRET_KEY: signer.credentials.secret_access_key()
            }))?,
            session_token: signer
                .credentials
                .session_token()
                .map(|token| cipher.seal(&json!({SESSION_TOKEN: token})))
                .transpose()?,
            region: signer.region.clone(),
            service: signer.service.clone(),
        };
        let encoded = serde_json::to_string(&stored).map_err(|_| CredentialError)?;
        let mut masked = json!({
            "access_key_id": &stored.access_key_id, "region": &stored.region, "service": &stored.service,
            SECRET_KEY: "*****",
        });
        if stored.session_token.is_some() {
            masked[SESSION_TOKEN] = "*****".into();
        }
        Ok((Arc::new(signer), encoded, masked))
    }

    pub(crate) fn load(
        cipher: &CredentialCipher,
        config: &str,
    ) -> Result<Arc<SigV4>, CredentialError> {
        let stored: Self = serde_json::from_str(config).map_err(|_| CredentialError)?;
        let secret = open_field(cipher, SECRET_KEY, &stored.secret_access_key)?;
        let token = stored
            .session_token
            .as_deref()
            .map(|encoded| open_field(cipher, SESSION_TOKEN, encoded))
            .transpose()?;
        stored
            .signer(&secret, token.as_ref().map(|token| token.as_str()))
            .map(Arc::new)
    }

    pub(crate) fn valid(&self) -> bool {
        valid_config(
            self.access_key_id.trim(),
            self.secret_access_key.trim(),
            self.session_token.as_deref().map(str::trim),
            self.region.trim(),
            self.service.trim(),
        )
    }

    fn signer(&self, secret: &str, session_token: Option<&str>) -> Result<SigV4, CredentialError> {
        let access_key_id = self.access_key_id.trim();
        let secret = secret.trim();
        let session_token = session_token
            .map(str::trim)
            .filter(|token| !token.is_empty());
        let region = self.region.trim();
        let service = self.service.trim();
        if !valid_config(access_key_id, secret, session_token, region, service) {
            return Err(CredentialError);
        }
        Ok(SigV4 {
            credentials: Credentials::new(
                access_key_id,
                secret,
                session_token.map(str::to_owned),
                None,
                "context-forge",
            ),
            region: region.to_owned(),
            service: service.to_owned(),
        })
    }
}

fn open_field(
    cipher: &CredentialCipher,
    name: &str,
    encoded: &str,
) -> Result<Zeroizing<String>, CredentialError> {
    let mut stored: serde_json::Map<String, Value> = cipher.open(encoded)?;
    match stored.remove(name) {
        Some(Value::String(clear)) => Ok(Zeroizing::new(clear)),
        _ => Err(CredentialError),
    }
}

fn valid_config(
    access_key_id: &str,
    secret: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
) -> bool {
    (16..=128).contains(&access_key_id.len())
        && access_key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
        && !secret.is_empty()
        && secret != "*****"
        && session_token
            .is_none_or(|token| token != "*****" && HeaderValue::from_str(token).is_ok())
        && scope_component(region)
        && scope_component(service)
}

fn scope_component(scope: &str) -> bool {
    (1..=63).contains(&scope.len())
        && !scope.starts_with('-')
        && scope
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) struct SigV4 {
    credentials: Credentials,
    region: String,
    service: String,
}

impl SigV4 {
    pub(crate) fn matches_stored(&self, encoded: &str) -> bool {
        serde_json::from_str::<SigV4Config>(encoded).is_ok_and(|stored| {
            self.credentials.access_key_id() == stored.access_key_id
                && self.region == stored.region
                && self.service == stored.service
        })
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        for value in [
            self.credentials.access_key_id(),
            self.credentials.secret_access_key(),
            self.credentials.session_token().unwrap_or_default(),
            &self.region,
            &self.service,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.finalize().into()
    }

    pub(crate) fn sign(&self, request: &mut reqwest::Request) -> Result<(), CredentialError> {
        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        if self.service == "s3" {
            settings.percent_encoding_mode = PercentEncodingMode::Single;
            settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        }
        let identity = self.credentials.clone().into();
        let params: SigningParams<'_> = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service)
            .time(SystemTime::now())
            .settings(settings)
            .build()
            .map_err(|_| CredentialError)?
            .into();
        for name in [
            "authorization",
            "x-amz-date",
            "x-amz-content-sha256",
            "x-amz-security-token",
        ] {
            request.headers_mut().remove(name);
        }
        let headers = request
            .headers()
            .iter()
            .filter(|(name, _)| {
                matches!(*name, &header::HOST | &header::CONTENT_TYPE)
                    || name.as_str().starts_with("x-amz-")
            })
            .map(|(name, value)| Ok((name.as_str(), value.to_str().map_err(|_| CredentialError)?)))
            .collect::<Result<Vec<_>, CredentialError>>()?;
        let body = match request.body() {
            Some(body) => body.as_bytes().ok_or(CredentialError)?,
            None => &[],
        };
        let signable = SignableRequest::new(
            request.method().as_str(),
            request.url().as_str(),
            headers.into_iter(),
            SignableBody::Bytes(body),
        )
        .map_err(|_| CredentialError)?;
        let (instructions, _) = sign(signable, &params)
            .map_err(|_| CredentialError)?
            .into_parts();
        let (headers, _) = instructions.into_parts();
        for header in headers {
            let mut value = HeaderValue::from_str(header.value()).map_err(|_| CredentialError)?;
            value.set_sensitive(header.sensitive() || header.name() == "authorization");
            request.headers_mut().insert(header.name(), value);
        }
        Ok(())
    }
}
