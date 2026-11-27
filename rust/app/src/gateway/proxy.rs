// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use axum::http::HeaderMap;

use super::{GatewayService, Principal, access};
use crate::catalog::ContentGateway;

pub(crate) const GATEWAY_ID_HEADER: &str = "x-context-forge-gateway-id";

pub(super) enum DirectTarget {
    Fallback,
    Denied,
    Found(ContentGateway, Duration),
}

impl GatewayService {
    pub(super) async fn direct_target(
        &self,
        headers: Option<&HeaderMap>,
        principal: Option<&Principal>,
    ) -> Result<DirectTarget, sqlx::Error> {
        let Some(timeout) = self.direct_proxy_timeout else {
            return Ok(DirectTarget::Fallback);
        };
        let Some(id) = headers.and_then(target_id) else {
            return Ok(DirectTarget::Fallback);
        };
        let Some(gateway) = self.database.direct_gateway(id).await? else {
            return Ok(DirectTarget::Fallback);
        };
        Ok(if gateway.is_visible(access::catalog_scope(principal)) {
            DirectTarget::Found(gateway.content, timeout)
        } else {
            DirectTarget::Denied
        })
    }
}

fn target_id(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(GATEWAY_ID_HEADER).iter();
    let id = values.next()?.to_str().ok()?;
    (values.next().is_none() && !id.is_empty() && id.len() <= 36).then_some(id)
}
