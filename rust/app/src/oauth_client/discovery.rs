// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use url::Url;

use super::{Deserialize, OAuthConfig, UpstreamClient, UpstreamError, Value};

const MAX_CACHED_ISSUERS: usize = 256;

#[derive(Clone, Deserialize)]
pub(crate) struct IssuerMetadata {
    issuer: String,
    pub(crate) authorization_endpoint: Option<String>,
    pub(crate) token_endpoint: Option<String>,
    pub(crate) registration_endpoint: Option<String>,
    jwks_uri: Option<String>,
    pub(crate) grant_types_supported: Option<Vec<String>>,
    pub(crate) client_id_metadata_document_supported: Option<Value>,
}

#[derive(Default)]
pub(crate) struct IssuerMetadataCache(Mutex<HashMap<String, (Instant, IssuerMetadata)>>);

impl IssuerMetadataCache {
    pub(crate) async fn discover(
        &self,
        upstream: &UpstreamClient,
        issuer: &str,
        ttl: Duration,
    ) -> Result<IssuerMetadata, UpstreamError> {
        let issuer = issuer.trim_end_matches('/');
        let base = issuer_url(upstream, issuer)?;
        if let Ok(entries) = self.0.lock()
            && let Some((stored, metadata)) = entries.get(issuer)
            && stored.elapsed() < ttl
        {
            return Ok(metadata.clone());
        }
        let origin = base.origin().ascii_serialization();
        let path = base.path().trim_end_matches('/');
        let rfc8414 = format!("{origin}/.well-known/oauth-authorization-server{path}");
        let metadata: IssuerMetadata = match upstream.oauth_document(&rfc8414, None).await {
            Ok(metadata) => metadata,
            Err(
                UpstreamError::Status(400..=599)
                | UpstreamError::Transport
                | UpstreamError::Timeout,
            ) => {
                upstream
                    .oauth_document(
                        &format!("{origin}{path}/.well-known/openid-configuration"),
                        None,
                    )
                    .await?
            }
            Err(error) => return Err(error),
        };
        if metadata.issuer.trim_end_matches('/') != issuer {
            return Err(UpstreamError::InvalidResponse);
        }
        if !ttl.is_zero()
            && let Ok(mut entries) = self.0.lock()
        {
            if entries.len() >= MAX_CACHED_ISSUERS
                && let Some((key, _)) = entries.iter().min_by_key(|(_, (inserted, _))| *inserted)
            {
                let key = key.clone();
                entries.remove(&key);
            }
            entries.insert(issuer.to_owned(), (Instant::now(), metadata.clone()));
        }
        Ok(metadata)
    }
}

impl OAuthConfig {
    pub(crate) fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref().filter(|issuer| !issuer.is_empty())
    }

    pub(crate) fn registration_method(&self) -> Option<&str> {
        self.registration_method.as_deref()
    }

    pub(crate) fn registration_scope(&self, fallback: &[String]) -> String {
        match &self.scopes {
            None => fallback.join(" "),
            Some(super::OAuthValues::One(scope)) => scope.clone(),
            Some(super::OAuthValues::Many(scopes)) => scopes.join(" "),
        }
    }

    pub(crate) fn complete_registration_endpoints(
        &mut self,
        upstream: &UpstreamClient,
        metadata: Option<&IssuerMetadata>,
    ) -> Result<(), UpstreamError> {
        let issuer = self.issuer().ok_or(UpstreamError::InvalidUrl)?;
        let token = (!self.token_url.is_empty())
            .then_some(self.token_url.as_str())
            .or_else(|| metadata.and_then(|metadata| metadata.token_endpoint.as_deref()))
            .ok_or(UpstreamError::InvalidUrl)?;
        let authorization = self
            .authorization_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .or_else(|| metadata.and_then(|metadata| metadata.authorization_endpoint.as_deref()))
            .ok_or(UpstreamError::InvalidUrl)?;
        validate_endpoint(upstream, token, Some(issuer))?;
        validate_endpoint(upstream, authorization, Some(issuer))?;
        self.token_url = token.to_owned();
        self.authorization_url = Some(authorization.to_owned());
        Ok(())
    }

    pub(crate) fn has_code_endpoints(&self) -> bool {
        !self.token_url.is_empty()
            && self
                .authorization_url
                .as_ref()
                .is_some_and(|url| !url.is_empty())
    }

    pub(crate) fn use_registered_client(
        &mut self,
        client_id: String,
        secret: Option<String>,
        auth_method: String,
        redirect: String,
        registration_method: &str,
    ) {
        self.client_id = Some(client_id);
        zeroize::Zeroize::zeroize(&mut self.client_secret);
        self.client_secret = secret;
        self.token_endpoint_auth_method = Some(auth_method);
        self.redirect_uri = Some(redirect);
        self.registration_method = Some(registration_method.to_owned());
    }

    pub(crate) async fn discover_endpoints(
        &mut self,
        upstream: &UpstreamClient,
        cache: &IssuerMetadataCache,
        ttl: Duration,
    ) {
        let Some(issuer) = self.issuer() else {
            return;
        };
        if self.has_code_endpoints() {
            return;
        }
        let Ok(metadata) = cache.discover(upstream, issuer, ttl).await else {
            return;
        };
        let scoped_issuer = self.client_id().is_none().then_some(issuer);
        let valid = |endpoint: &str, issuer| validate_endpoint(upstream, endpoint, issuer).is_ok();
        let token = metadata
            .token_endpoint
            .filter(|endpoint| valid(endpoint, scoped_issuer));
        let authorization = metadata
            .authorization_endpoint
            .filter(|endpoint| valid(endpoint, scoped_issuer));
        let jwks = metadata.jwks_uri.filter(|endpoint| valid(endpoint, None));
        if let Some(token) = token
            && self.token_url.is_empty()
        {
            self.token_url = token;
        }
        if self.authorization_url.as_ref().is_none_or(String::is_empty) && authorization.is_some() {
            self.authorization_url = authorization;
        }
        if self.jwks_uri.as_ref().is_none_or(String::is_empty)
            && let Some(jwks) = jwks
        {
            self.jwks_uri = Some(jwks);
        }
        self.dcr_available = Some(
            metadata
                .registration_endpoint
                .is_some_and(|url| !url.is_empty()),
        );
        self.endpoints_discovered = Some(true);
    }
}

pub(crate) fn validate_endpoint(
    upstream: &UpstreamClient,
    endpoint: &str,
    issuer: Option<&str>,
) -> Result<(), UpstreamError> {
    upstream.check_endpoint(endpoint)?;
    let url = Url::parse(endpoint).map_err(|_| UpstreamError::InvalidUrl)?;
    if url.fragment().is_some() {
        return Err(UpstreamError::InvalidUrl);
    }
    if let Some(issuer) = issuer
        && issuer_url(upstream, issuer)?.origin() != url.origin()
    {
        return Err(UpstreamError::BlockedDestination);
    }
    Ok(())
}

fn issuer_url(upstream: &UpstreamClient, issuer: &str) -> Result<Url, UpstreamError> {
    upstream.check_endpoint(issuer)?;
    let url = Url::parse(issuer).map_err(|_| UpstreamError::InvalidUrl)?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err(UpstreamError::InvalidUrl);
    }
    Ok(url)
}
