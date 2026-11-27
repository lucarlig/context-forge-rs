// SPDX-License-Identifier: Apache-2.0

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use jiff::Timestamp;
use p256::ecdsa::signature::Signer;
use ring::{rand::SystemRandom, signature};
use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::upstream::UpstreamError;

const LIFETIME_SECONDS: i64 = 300;

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum AssertionAlgorithm {
    #[default]
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Es256,
    Es384,
    Es512,
}

pub(crate) struct ClientAssertionSigner {
    algorithm: AssertionAlgorithm,
    key: Key,
}

enum Key {
    Rsa(
        Box<signature::RsaKeyPair>,
        &'static dyn signature::RsaEncoding,
    ),
    P256(Box<p256::ecdsa::SigningKey>),
    P384(Box<p384::ecdsa::SigningKey>),
    P521(Box<p521::ecdsa::SigningKey>),
}

impl ClientAssertionSigner {
    pub(crate) fn new(algorithm: AssertionAlgorithm, pem: &str) -> Result<Self, UpstreamError> {
        let key = match algorithm {
            AssertionAlgorithm::Rs256 => rsa_key(pem, &signature::RSA_PKCS1_SHA256)?,
            AssertionAlgorithm::Rs384 => rsa_key(pem, &signature::RSA_PKCS1_SHA384)?,
            AssertionAlgorithm::Rs512 => rsa_key(pem, &signature::RSA_PKCS1_SHA512)?,
            AssertionAlgorithm::Ps256 => rsa_key(pem, &signature::RSA_PSS_SHA256)?,
            AssertionAlgorithm::Es256 => {
                let key = p256::SecretKey::from_pem(pem)
                    .map_err(|_| UpstreamError::InvalidCredentials)?;
                Key::P256(Box::new(key.into()))
            }
            AssertionAlgorithm::Es384 => {
                let key = p384::SecretKey::from_pem(pem)
                    .map_err(|_| UpstreamError::InvalidCredentials)?;
                Key::P384(Box::new(key.into()))
            }
            AssertionAlgorithm::Es512 => {
                let key = p521::SecretKey::from_pem(pem)
                    .map_err(|_| UpstreamError::InvalidCredentials)?;
                Key::P521(Box::new(key.into()))
            }
        };
        Ok(Self { algorithm, key })
    }

    pub(crate) fn sign(
        &self,
        client_id: &str,
        token_url: &str,
        kid: Option<&str>,
    ) -> Result<Zeroizing<String>, UpstreamError> {
        let mut header = json!({"alg":self.algorithm,"typ":"JWT"});
        if let Some(key_id) = kid.map(str::trim).filter(|kid| !kid.is_empty()) {
            header["kid"] = key_id.into();
        }
        let now = Timestamp::now().as_second();
        let claims = json!({
            "iss":client_id, "sub":client_id, "aud":token_url,
            "iat":now, "exp":now + LIFETIME_SECONDS, "jti":Uuid::new_v4().simple().to_string(),
        });
        let signing_input = format!(
            "{}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(header.to_string()),
            BASE64_URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        let message = signing_input.as_bytes();
        let signature = match &self.key {
            Key::Rsa(key, encoding) => {
                let mut output = vec![0; key.public().modulus_len()];
                key.sign(*encoding, &SystemRandom::new(), message, &mut output)
                    .map_err(|_| UpstreamError::InvalidCredentials)?;
                output
            }
            Key::P256(key) => {
                let signature: p256::ecdsa::Signature = key
                    .try_sign(message)
                    .map_err(|_| UpstreamError::InvalidCredentials)?;
                signature.to_bytes().to_vec()
            }
            Key::P384(key) => {
                let signature: p384::ecdsa::Signature = key
                    .try_sign(message)
                    .map_err(|_| UpstreamError::InvalidCredentials)?;
                signature.to_bytes().to_vec()
            }
            Key::P521(key) => {
                let signature: p521::ecdsa::Signature = key
                    .try_sign(message)
                    .map_err(|_| UpstreamError::InvalidCredentials)?;
                signature.to_bytes().to_vec()
            }
        };
        Ok(Zeroizing::new(format!(
            "{signing_input}.{}",
            BASE64_URL_SAFE_NO_PAD.encode(signature)
        )))
    }
}

fn rsa_key(pem: &str, encoding: &'static dyn signature::RsaEncoding) -> Result<Key, UpstreamError> {
    let private_key = Zeroizing::new(
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| UpstreamError::InvalidCredentials)?,
    );
    let parsed = match &*private_key {
        PrivateKeyDer::Pkcs1(key) => signature::RsaKeyPair::from_der(key.secret_pkcs1_der()),
        PrivateKeyDer::Pkcs8(key) => signature::RsaKeyPair::from_pkcs8(key.secret_pkcs8_der()),
        _ => return Err(UpstreamError::InvalidCredentials),
    };
    let key = parsed.map_err(|_| UpstreamError::InvalidCredentials)?;
    Ok(Key::Rsa(Box::new(key), encoding))
}
