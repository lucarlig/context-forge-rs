// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE},
};
use fernet::Fernet;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::config::SecretKdf;

const PREFIX: &str = "v2:";
const WORKERS: usize = 2;

#[derive(Clone)]
pub(crate) struct SecretEnvelope {
    secret: Arc<Zeroizing<Vec<u8>>>,
    pub(crate) kdf: SecretKdf,
    workers: Arc<Semaphore>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid or unavailable encrypted secret")]
pub(crate) struct EnvelopeError;

#[derive(Deserialize, Serialize)]
struct Bundle {
    version: Option<String>,
    kdf: Option<String>,
    t: u32,
    m: u32,
    p: u32,
    salt: String,
    token: String,
}

impl SecretEnvelope {
    pub(crate) fn new(secret: &str) -> Self {
        Self {
            secret: Arc::new(Zeroizing::new(secret.as_bytes().to_vec())),
            kdf: SecretKdf::default(),
            workers: Arc::new(Semaphore::new(WORKERS)),
        }
    }

    pub(crate) fn is_encrypted(value: &str) -> bool {
        value.starts_with(PREFIX)
            || (value.starts_with('{')
                && serde_json::from_str::<Bundle>(value).is_ok_and(|bundle| {
                    bundle.version.as_deref() == Some("v2")
                        || bundle.kdf.as_deref() == Some("argon2id")
                }))
    }

    pub(crate) async fn seal(&self, plaintext: Zeroizing<String>) -> Result<String, EnvelopeError> {
        let permit = self
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| EnvelopeError)?;
        let secret = self.secret.clone();
        let kdf = self.kdf;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut salt = [0; 16];
            SystemRandom::new()
                .fill(&mut salt)
                .map_err(|_| EnvelopeError)?;
            let cipher = derive(&secret, &salt, kdf)?;
            let bundle = Bundle {
                version: Some("v2".to_owned()),
                kdf: Some("argon2id".to_owned()),
                t: kdf.time_cost,
                m: kdf.memory_cost,
                p: kdf.parallelism,
                salt: BASE64_STANDARD.encode(salt),
                token: cipher.encrypt(plaintext.as_bytes()),
            };
            let encoded = serde_json::to_string(&bundle).map_err(|_| EnvelopeError)?;
            Ok(format!("{PREFIX}{encoded}"))
        })
        .await
        .map_err(|_| EnvelopeError)?
    }

    pub(crate) async fn open(&self, encoded: String) -> Result<Zeroizing<String>, EnvelopeError> {
        let json = encoded.strip_prefix(PREFIX).unwrap_or(&encoded);
        let bundle: Bundle = serde_json::from_str(json).map_err(|_| EnvelopeError)?;
        if bundle.version.as_deref() != Some("v2")
            && (encoded.starts_with(PREFIX) || bundle.kdf.as_deref() != Some("argon2id"))
        {
            return Err(EnvelopeError);
        }
        let permit = self
            .workers
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| EnvelopeError)?;
        let secret = self.secret.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let salt = BASE64_STANDARD
                .decode(bundle.salt)
                .map_err(|_| EnvelopeError)?;
            let settings = SecretKdf {
                time_cost: bundle.t,
                memory_cost: bundle.m,
                parallelism: bundle.p,
            };
            let cipher = derive(&secret, &salt, settings)?;
            let clear = cipher.decrypt(&bundle.token).map_err(|_| EnvelopeError)?;
            match String::from_utf8(clear) {
                Ok(clear) => Ok(Zeroizing::new(clear)),
                Err(error) => {
                    let _ = Zeroizing::new(error.into_bytes());
                    Err(EnvelopeError)
                }
            }
        })
        .await
        .map_err(|_| EnvelopeError)?
    }
}

impl SecretKdf {
    pub(crate) fn params(self) -> Result<Params, EnvelopeError> {
        Params::new(self.memory_cost, self.time_cost, self.parallelism, Some(32))
            .map_err(|_| EnvelopeError)
    }
}

fn derive(secret: &[u8], salt: &[u8], kdf: SecretKdf) -> Result<Fernet, EnvelopeError> {
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, kdf.params()?)
        .hash_password_into(secret, salt, key.as_mut())
        .map_err(|_| EnvelopeError)?;
    let key = Zeroizing::new(BASE64_URL_SAFE.encode(key.as_ref()));
    Fernet::new(&key).ok_or(EnvelopeError)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_KEY: &str = "context-forge-fixture-encryption-key-with-ample-entropy";
    const PINNED_BUNDLE: &str = concat!(
        r#"v2:{"version":"v2","kdf":"argon2id","t":1,"m":1024,"p":1,"salt":"cyfU+VmdeDLq2lNchUpLyA==","#,
        r#""token":"gAAAAABrCNGYvJKRsJxgv6ocpO0w-We46ef_4FcsfJka93A9t3hKkp1CeN23EMsCdFZYJCpA5Bdg2BOJfbOHIwD5oNuVJtDpgJ3f5l7h9lOmm4Ad1U1FFPc="}"#,
    );

    #[tokio::test]
    async fn opens_pinned_argon2id_envelopes() {
        let cipher = SecretEnvelope::new(FIXTURE_KEY);
        let legacy = PINNED_BUNDLE
            .trim_start_matches(PREFIX)
            .replace(r#""version":"v2","#, "");
        for encrypted in [PINNED_BUNDLE.to_owned(), legacy] {
            let plaintext = cipher.open(encrypted).await.unwrap();
            assert_eq!(plaintext.as_str(), "synthetic fixture value");
        }
        let wrong_key = SecretEnvelope::new("unrelated fixture secret");
        assert!(wrong_key.open(PINNED_BUNDLE.to_owned()).await.is_err());
    }

    #[tokio::test]
    async fn seals_each_secret_with_a_random_salt() {
        let cipher = SecretEnvelope {
            kdf: SecretKdf {
                time_cost: 1,
                memory_cost: 1024,
                parallelism: 1,
            },
            ..SecretEnvelope::new(FIXTURE_KEY)
        };
        let plaintext = Zeroizing::new("synthetic fixture value".to_owned());
        let first = cipher.seal(plaintext.clone()).await.unwrap();
        let second = cipher.seal(plaintext.clone()).await.unwrap();
        let salt = |encoded: &str| {
            serde_json::from_str::<Bundle>(encoded.strip_prefix(PREFIX).unwrap())
                .unwrap()
                .salt
        };
        assert_ne!(salt(&first), salt(&second));
        assert_eq!(
            cipher.open(first).await.unwrap().as_str(),
            plaintext.as_str()
        );
    }
}
