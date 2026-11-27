// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use rustls_platform_verifier::{BuilderVerifierExt, Verifier};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
#[error("invalid upstream TLS certificate or private key")]
pub(crate) struct InvalidTlsMaterial;

pub(crate) struct TlsMaterial {
    roots: Vec<CertificateDer<'static>>,
    client: Option<ClientIdentity>,
}

struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl TlsMaterial {
    pub(crate) fn from_pem(
        ca_certificate: Option<&str>,
        client_cert: Option<&str>,
        client_key: Option<&str>,
    ) -> Result<Option<Self>, InvalidTlsMaterial> {
        let roots = ca_certificate
            .filter(|pem| !pem.is_empty())
            .map(certificates)
            .transpose()?
            .unwrap_or_default();
        let client = match (client_cert, client_key) {
            (None, None) => None,
            (Some(cert), Some(key)) => Some(ClientIdentity {
                chain: certificates(cert)?,
                private_key: PrivateKeyDer::from_pem_slice(key.as_bytes())
                    .map_err(|_| InvalidTlsMaterial)?,
            }),
            _ => return Err(InvalidTlsMaterial),
        };
        Ok((!roots.is_empty() || client.is_some()).then_some(Self { roots, client }))
    }

    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update((self.roots.len() as u64).to_be_bytes());
        for certificate in &self.roots {
            digest.update(Sha256::digest(certificate.as_ref()));
        }
        if let Some(client) = &self.client {
            digest.update((client.chain.len() as u64).to_be_bytes());
            for certificate in &client.chain {
                digest.update(Sha256::digest(certificate.as_ref()));
            }
            digest.update(Sha256::digest(client.private_key.secret_der()));
        }
        digest.finalize().into()
    }
}

pub(crate) fn client_config(
    material: Option<&TlsMaterial>,
) -> Result<rustls::ClientConfig, InvalidTlsMaterial> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| InvalidTlsMaterial)?;
    let builder = match material.filter(|material| !material.roots.is_empty()) {
        Some(material) => {
            let verifier = Verifier::new_with_extra_roots(material.roots.iter().cloned(), provider)
                .map_err(|_| InvalidTlsMaterial)?;
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
        }
        None => builder
            .with_platform_verifier()
            .map_err(|_| InvalidTlsMaterial)?,
    };
    let mut tls = match material.and_then(|material| material.client.as_ref()) {
        Some(client) => builder
            .with_client_auth_cert(client.chain.clone(), client.private_key.clone_key())
            .map_err(|_| InvalidTlsMaterial)?,
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

fn certificates(pem: &str) -> Result<Vec<CertificateDer<'static>>, InvalidTlsMaterial> {
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InvalidTlsMaterial)?;
    if certificates.is_empty() {
        return Err(InvalidTlsMaterial);
    }
    Ok(certificates)
}
