// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use axum::http::HeaderMap;
use jiff::Timestamp;
use rmcp::model::{ErrorCode, ErrorData};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{GatewayService, Principal, UpstreamUse, access, list_fingerprint};
use crate::{
    catalog::{CatalogServer, ContentGateway},
    proxy_catalog_cache::{Manifest, Reservation, SnapshotPage},
    upstream::{ProxyCatalogKind, UpstreamEndpoint, UpstreamError},
};

pub(crate) const GATEWAY_ID_HEADER: &str = "x-context-forge-gateway-id";

pub(super) enum DirectTarget {
    Fallback,
    Disabled,
    Denied,
    Found {
        gateway: ContentGateway,
        timeout: Duration,
        revision: String,
    },
}

impl GatewayService {
    pub(super) async fn direct_target(
        &self,
        headers: Option<&HeaderMap>,
        principal: Option<&Principal>,
    ) -> Result<DirectTarget, sqlx::Error> {
        let Some(id) = headers.and_then(target_id) else {
            return Ok(DirectTarget::Fallback);
        };
        let Some(gateway) = self.database.direct_gateway(id).await? else {
            return Ok(DirectTarget::Fallback);
        };
        let Some(timeout) = self.direct_proxy_timeout else {
            return Ok(DirectTarget::Disabled);
        };
        Ok(if gateway.is_visible(access::catalog_scope(principal)) {
            DirectTarget::Found {
                gateway: gateway.content,
                timeout,
                revision: gateway.revision,
            }
        } else {
            DirectTarget::Denied
        })
    }

    pub(crate) async fn direct_catalog(
        &self,
        kind: ProxyCatalogKind,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
        headers: Option<&HeaderMap>,
        cursor: Option<&str>,
    ) -> Result<Option<Value>, ErrorData> {
        let Some(server) = server else {
            return Ok(None);
        };
        let (gateway, timeout, revision) = match self
            .direct_target(headers, principal)
            .await
            .map_err(|_| unavailable("MCP catalog lookup failed"))?
        {
            DirectTarget::Fallback => return Ok(None),
            DirectTarget::Disabled => {
                return Err(ErrorData::new(
                    ErrorCode(-32003),
                    "Direct proxy is disabled",
                    None,
                ));
            }
            DirectTarget::Denied => {
                return Err(ErrorData::new(
                    ErrorCode(-32003),
                    "Access denied to direct-proxy gateway",
                    None,
                ));
            }
            DirectTarget::Found {
                gateway,
                timeout,
                revision,
            } => (gateway, timeout, revision),
        };
        let permission = match kind {
            ProxyCatalogKind::Tools => "tools.read",
            ProxyCatalogKind::Resources => "resources.read",
        };
        if principal.is_some_and(|principal| !principal.token_allows(permission)) {
            return Err(ErrorData::new(ErrorCode(0), "Access denied", None));
        }
        let transport = gateway
            .transport
            .filter(|_| gateway.available)
            .ok_or_else(|| unavailable("Upstream gateway unavailable"))?;
        let credentials = self
            .configured_upstream(
                &gateway.id,
                &gateway.url,
                true,
                headers,
                principal,
                UpstreamUse::Invocation,
            )
            .await
            .map_err(|_| unavailable("Upstream gateway unavailable"))?;
        let endpoint = UpstreamEndpoint {
            url: &gateway.url,
            transport,
            credentials: credentials.as_ref(),
        };
        let session = headers
            .and_then(|headers| headers.get("mcp-session-id"))
            .and_then(|value| value.to_str().ok());
        let scope: [u8; 32] = Sha256::digest(
            json!([
                list_fingerprint(
                    &format!("proxy:{}", kind.method()),
                    principal,
                    Some(&server.id)
                ),
                principal.map(Principal::authorization_fingerprint),
                gateway.id,
                gateway.url,
                revision,
                endpoint.catalog_fingerprint(),
                session,
            ])
            .to_string(),
        )
        .into();

        if let Some(cursor) = cursor {
            let position = self
                .pagination
                .decode(cursor, &scope)
                .map_err(|_| invalid_cursor())?;
            let (snapshot, page) = position
                .after_id
                .split_once(':')
                .ok_or_else(invalid_cursor)?;
            let snapshot = Uuid::parse_str(snapshot).map_err(|_| invalid_cursor())?;
            let page = page
                .parse::<usize>()
                .ok()
                .filter(|page| *page > 0)
                .ok_or_else(invalid_cursor)?;
            if !self.proxy_catalog.is_shared() {
                return Err(unavailable("MCP proxy pagination requires Redis"));
            }
            let payload = self
                .proxy_catalog
                .page(snapshot, page)
                .await
                .map_err(|error| unavailable(error.to_string()))?
                .ok_or_else(invalid_cursor)?;
            return self
                .proxy_catalog_page(kind, snapshot, page, &scope, payload)
                .map(Some);
        }

        let reservation = self
            .proxy_catalog
            .reserve(&scope, timeout)
            .await
            .map_err(|error| unavailable(error.to_string()))?;
        if let Reservation::Reuse(snapshot) = reservation {
            let payload = self
                .proxy_catalog
                .page(snapshot, 0)
                .await
                .map_err(|error| unavailable(error.to_string()))?
                .ok_or_else(|| {
                    unavailable("MCP proxy snapshot expired during reuse; restart traversal")
                })?;
            return self
                .proxy_catalog_page(kind, snapshot, 0, &scope, payload)
                .map(Some);
        }

        let client = self.upstream.with_timeout_cap(timeout);
        let items = client.collect_proxy_catalog(endpoint, kind, self.proxy_catalog.max_snapshot_bytes())
            .await.map_err(|error| match error {
                UpstreamError::DuplicateCatalogItems | UpstreamError::InvalidCatalogCursor
                | UpstreamError::CatalogByteLimit | UpstreamError::CatalogPageLimit => unavailable(error.to_string()),
                error => {
                    tracing::warn!(%error, gateway = %gateway.id, "direct-proxy catalog collection failed");
                    unavailable("Direct-proxy MCP catalog collection failed")
                }
            })?;
        let page_size = self.pagination.page_size as usize;
        if items.len() <= page_size {
            return Ok(Some(json!({ (kind.key()): items })));
        }
        let Reservation::Shared(lease) = reservation else {
            return Err(unavailable("Multi-page MCP proxy catalogs require Redis"));
        };
        let manifest = Manifest {
            scope,
            expires: Timestamp::now()
                .as_second()
                .saturating_add(self.pagination.ttl),
            pages: items.len().div_ceil(page_size),
        };
        self.proxy_catalog
            .save(&lease, &manifest, &items, page_size)
            .await
            .map_err(|error| unavailable(error.to_string()))?;
        let items = items.into_iter().take(page_size).collect();
        self.proxy_catalog_page(kind, lease.id, 0, &scope, SnapshotPage { manifest, items })
            .map(Some)
    }

    fn proxy_catalog_page(
        &self,
        kind: ProxyCatalogKind,
        snapshot: Uuid,
        page: usize,
        scope: &[u8; 32],
        payload: SnapshotPage,
    ) -> Result<Value, ErrorData> {
        let SnapshotPage { manifest, items } = payload;
        if &manifest.scope != scope
            || page >= manifest.pages
            || manifest.expires <= Timestamp::now().as_second()
        {
            return Err(invalid_cursor());
        }
        let mut result = json!({ (kind.key()): items });
        if page + 1 < manifest.pages {
            result["nextCursor"] = self
                .pagination
                .encode(
                    format!("{}:{}", snapshot.simple(), page + 1),
                    *scope,
                    manifest.expires,
                )
                .map_err(|_| unavailable("MCP proxy cursor signing failed"))?
                .into();
        }
        Ok(result)
    }
}

fn invalid_cursor() -> ErrorData {
    ErrorData::invalid_params("Invalid or expired MCP snapshot cursor", None)
}

fn unavailable(message: impl Into<std::borrow::Cow<'static, str>>) -> ErrorData {
    ErrorData::new(ErrorCode(-32000), message, None)
}

fn target_id(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(GATEWAY_ID_HEADER).iter();
    let id = values.next()?.to_str().ok()?;
    (values.next().is_none() && !id.is_empty() && id.len() <= 36).then_some(id)
}
