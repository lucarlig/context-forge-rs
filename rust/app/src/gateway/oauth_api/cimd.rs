// SPDX-License-Identifier: Apache-2.0

use std::{io::Read, path::Path};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use p256::elliptic_curve::sec1::ToSec1Point;
use rsa::{
    PrivateKey as RsaPrivateKey, PublicKey as RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};

use super::*;
use crate::{
    client_assertion::{AssertionAlgorithm, ClientAssertionSigner},
    oauth_client::validate_endpoint,
};

pub(crate) const DOCUMENT_PATH: &str = "/oauth/client-metadata.json";
const JWKS_PATH: &str = "/oauth/client-metadata/jwks.json";
const MAX_KEY_BYTES: u64 = 64 * 1024;

pub struct CimdSettings {
    pub(crate) enabled: bool,
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) signed: bool,
    pub(crate) private_key_path: String,
    pub(crate) previous_public_key_path: String,
    pub(crate) jwt_private_key_path: String,
    pub(crate) key_id: String,
    pub(crate) previous_key_id: String,
    pub(crate) algorithm: AssertionAlgorithm,
    pub(crate) cache_seconds: u64,
}

impl Default for CimdSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            client_id: format!("http://localhost:4444{DOCUMENT_PATH}"),
            client_name: "ContextForge".to_owned(),
            signed: false,
            private_key_path: String::new(),
            previous_public_key_path: String::new(),
            jwt_private_key_path: String::new(),
            key_id: "cimd-1".to_owned(),
            previous_key_id: String::new(),
            algorithm: AssertionAlgorithm::default(),
            cache_seconds: 3600,
        }
    }
}

impl CimdSettings {
    pub(super) fn redirect_uri(&self) -> String {
        format!("{}/oauth/callback", self.base())
    }

    pub(super) fn auth_method(&self) -> &'static str {
        if self.signed {
            "private_key_jwt"
        } else {
            "none"
        }
    }

    pub(super) fn failed_guard(
        &self,
        dcr: &DcrSettings,
        issuer: &str,
        redirect: &str,
    ) -> Option<&'static str> {
        if !self.enabled {
            Some("cimd_disabled")
        } else if !self.client_id.starts_with("https://") {
            Some("client_id_not_https")
        } else if redirect != self.redirect_uri() {
            Some("redirect_uri_mismatch")
        } else if !dcr.allows_issuer(issuer) {
            Some("issuer_not_allowed")
        } else {
            None
        }
    }

    pub(super) fn configure_assertion(
        &self,
        dcr: &DcrSettings,
        config: &mut OAuthConfig,
        upstream: &UpstreamClient,
    ) -> Result<(), UpstreamError> {
        if config.registration_method() != Some("cimd")
            || !config.uses_private_key_jwt()
            || config.client_id() != Some(self.client_id.as_str())
        {
            return Ok(());
        }
        let issuer = config
            .issuer()
            .filter(|issuer| dcr.allows_issuer(issuer))
            .ok_or(UpstreamError::InvalidCredentials)?;
        validate_endpoint(upstream, config.token_endpoint(), Some(issuer))?;
        let key = self
            .private_key()
            .ok_or(UpstreamError::InvalidCredentials)?;
        config.use_client_assertion(key, self.algorithm, &self.key_id);
        Ok(())
    }

    fn private_key(&self) -> Option<Zeroizing<String>> {
        let key = read_key(&self.private_key_path)?;
        if read_key(&self.jwt_private_key_path).is_some_and(|jwt| jwt.trim() == key.trim()) {
            return None;
        }
        ClientAssertionSigner::new(self.algorithm, &key).ok()?;
        Some(key)
    }

    fn base(&self) -> &str {
        self.client_id
            .strip_suffix(DOCUMENT_PATH)
            .unwrap_or(&self.client_id)
            .trim_end_matches('/')
    }

    fn respond(&self, payload: Value) -> Result<Response, CatalogApiError> {
        if !self.enabled {
            return Err(CatalogApiError::detail(StatusCode::NOT_FOUND, "Not found"));
        }
        Ok((
            [(
                header::CACHE_CONTROL,
                format!("public, max-age={}", self.cache_seconds),
            )],
            Json(payload),
        )
            .into_response())
    }
}

pub(super) async fn document(
    State(service): State<Arc<GatewayService>>,
) -> Result<Response, CatalogApiError> {
    let settings = &service.gateway_oauth.cimd;
    let mut payload = json!({
        "client_id":settings.client_id,"client_name":settings.client_name,
        "redirect_uris":[settings.redirect_uri()],
        "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
        "token_endpoint_auth_method":settings.auth_method(),
    });
    if settings.signed {
        payload["jwks_uri"] = format!("{}{JWKS_PATH}", settings.base()).into();
    }
    settings.respond(payload)
}

pub(super) async fn jwks(
    State(service): State<Arc<GatewayService>>,
) -> Result<Response, CatalogApiError> {
    let settings = &service.gateway_oauth.cimd;
    if !settings.enabled {
        return Err(CatalogApiError::detail(StatusCode::NOT_FOUND, "Not found"));
    }
    let mut keys = Vec::new();
    if let Some(private) = settings.private_key()
        && let Some(jwk) = jwk(&private, true, &settings.key_id, settings.algorithm)
    {
        keys.push(jwk);
    }
    let previous_id = if settings.previous_key_id.is_empty() {
        format!("{}-previous", settings.key_id)
    } else {
        settings.previous_key_id.clone()
    };
    if previous_id != settings.key_id
        && let Some(public) = read_key(&settings.previous_public_key_path)
        && let Some(jwk) = jwk(&public, false, &previous_id, settings.algorithm)
    {
        keys.push(jwk);
    }
    settings.respond(json!({"keys":keys}))
}

fn read_key(path: impl AsRef<Path>) -> Option<Zeroizing<String>> {
    let mut file = std::fs::File::open(path).ok()?.take(MAX_KEY_BYTES + 1);
    let mut pem = Zeroizing::new(String::new());
    (file.read_to_string(&mut pem).ok()? as u64 <= MAX_KEY_BYTES).then_some(pem)
}

fn jwk(pem: &str, private: bool, kid: &str, alg: AssertionAlgorithm) -> Option<Value> {
    macro_rules! elliptic {
        ($curve:ident, $name:literal) => {{
            let public = if private {
                $curve::SecretKey::from_pem(pem).ok()?.public_key()
            } else {
                $curve::PublicKey::from_public_key_pem(pem).ok()?
            };
            let point = public.to_sec1_point(false);
            json!({
                "kty":"EC","crv":$name,
                "x":BASE64_URL_SAFE_NO_PAD.encode(point.x()?),
                "y":BASE64_URL_SAFE_NO_PAD.encode(point.y()?),
            })
        }};
    }
    let mut jwk = match alg {
        AssertionAlgorithm::Es256 => elliptic!(p256, "P-256"),
        AssertionAlgorithm::Es384 => elliptic!(p384, "P-384"),
        AssertionAlgorithm::Es512 => elliptic!(p521, "P-521"),
        _ => {
            let key = if private {
                RsaPrivateKey::from_pkcs8_pem(pem)
                    .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
                    .ok()?
                    .to_public_key()
            } else {
                RsaPublicKey::from_public_key_pem(pem)
                    .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem))
                    .ok()?
            };
            json!({"kty":"RSA","n":BASE64_URL_SAFE_NO_PAD.encode(key.n_bytes()),
                "e":BASE64_URL_SAFE_NO_PAD.encode(key.e_bytes())})
        }
    };
    jwk["kid"] = kid.into();
    jwk["use"] = "sig".into();
    jwk["alg"] = json!(alg);
    Some(jwk)
}
