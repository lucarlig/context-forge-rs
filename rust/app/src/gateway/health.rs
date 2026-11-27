// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use futures_util::{StreamExt, stream};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::gateway_records::{CatalogRefreshCompletion, CatalogRefreshInput, GatewayRecord};

const PAGE_SIZE: i64 = 100;

pub struct GatewayHealth {
    pub interval: Duration,
    pub timeout: Duration,
    pub failure_threshold: Option<u32>,
    pub concurrency: usize,
    pub auto_refresh: bool,
}

#[derive(Clone, Copy, Default)]
pub(super) struct RefreshSelection {
    pub(super) resources: bool,
    pub(super) prompts: bool,
}

impl RefreshSelection {
    pub(super) const ALL: Self = Self {
        resources: true,
        prompts: true,
    };
}

impl GatewayService {
    pub async fn run_gateway_health(
        self: Arc<Self>,
        settings: GatewayHealth,
        stop: CancellationToken,
    ) {
        let mut ticks = interval(settings.interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut failures = HashMap::new();
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = ticks.tick() => {}
            }
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                result = self.health_cycle(&settings, &failures) => match result {
                    Ok(updated) => failures = updated,
                    Err(error) => tracing::warn!(%error, "could not read gateway health candidates"),
                }
            }
        }
    }

    async fn health_cycle(
        &self,
        settings: &GatewayHealth,
        failures: &HashMap<String, (i32, u32)>,
    ) -> Result<HashMap<String, (i32, u32)>, sqlx::Error> {
        let mut recent_failures = HashMap::new();
        let mut cursor = None;
        loop {
            let page = self
                .database
                .gateways_for_health(cursor.as_deref(), PAGE_SIZE)
                .await?;
            let last_page = page.len() < PAGE_SIZE as usize;
            cursor = page.last().map(|record| record.id.clone());
            let results = stream::iter(page.into_iter().map(|record| async move {
                let count = failures
                    .get(&record.id)
                    .filter(|(version, _)| *version == record.version)
                    .map_or(0, |(_, count)| *count);
                let count = self.check_gateway_health(&record, settings, count).await;
                (record.id, record.version, count)
            }))
            .buffer_unordered(settings.concurrency);
            futures_util::pin_mut!(results);
            while let Some((id, version, count)) = results.next().await {
                match count {
                    Ok(count) if count > 0 => {
                        recent_failures.insert(id, (version, count));
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::warn!(gateway = %id, %error, "could not save gateway health")
                    }
                }
            }
            if last_page {
                return Ok(recent_failures);
            }
        }
    }

    async fn check_gateway_health(
        &self,
        record: &GatewayRecord,
        settings: &GatewayHealth,
        failures: u32,
    ) -> Result<u32, sqlx::Error> {
        let Some(transport) = UpstreamTransport::from_name(&record.transport) else {
            return Ok(0);
        };
        let Some(connection) = self
            .database
            .gateway_connection(&record.id, &record.url, true, Some(record.version), None)
            .await?
        else {
            return Ok(0);
        };
        let upstream = self.upstream.with_timeout_cap(settings.timeout);
        let probe = timeout(settings.timeout, async {
            let credentials = self
                .connection_credentials(&record.id, &record.url, connection, None, None)
                .await
                .map_err(|_| "Could not load upstream authentication or TLS material".to_owned())?;
            let endpoint = UpstreamEndpoint {
                url: &record.url,
                transport,
                credentials: credentials.as_ref(),
            };
            match upstream.probe(endpoint).await {
                Ok(()) => Ok((true, credentials)),
                Err(UpstreamError::Status(401 | 403)) => Ok((false, credentials)),
                Err(UpstreamError::Status(status)) => {
                    Err(format!("server responded with HTTP {status}"))
                }
                Err(error) => Err(error.to_string()),
            }
        })
        .await
        .unwrap_or_else(|_| Err(UpstreamError::Timeout.to_string()));
        let (authenticated, credentials) = match probe {
            Ok(result) => result,
            Err(error) => {
                if let Some(threshold) = settings.failure_threshold
                    && record.enabled
                    && record.reachable
                {
                    let failures = failures.saturating_add(1);
                    if failures < threshold {
                        return Ok(failures);
                    }
                    if self
                        .database
                        .set_gateway_health(record, Some(&error))
                        .await?
                    {
                        self.publish_health_change(record);
                    }
                }
                return Ok(0);
            }
        };
        let recovering = record.enabled && !record.reachable;
        let should_refresh = record.enabled
            && authenticated
            && (recovering || settings.auto_refresh && self.auto_refresh_due(record));
        let endpoint = UpstreamEndpoint {
            url: &record.url,
            transport,
            credentials: credentials.as_ref(),
        };
        if should_refresh
            && self
                .refresh_healthy_gateway(
                    record,
                    &upstream,
                    endpoint,
                    recovering,
                    RefreshSelection::ALL,
                )
                .await?
        {
            return Ok(0);
        }
        if self.database.set_gateway_health(record, None).await? && recovering {
            self.publish_health_change(record);
        }
        Ok(0)
    }

    fn auto_refresh_due(&self, record: &GatewayRecord) -> bool {
        let interval = record
            .refresh_interval_seconds
            .unwrap_or(self.refresh.default_seconds);
        let Some(last) = record
            .last_refresh_at
            .as_deref()
            .and_then(parse_health_timestamp)
        else {
            return true;
        };
        Timestamp::now()
            .as_second()
            .saturating_sub(last.as_second())
            >= i64::from(interval)
    }

    pub(super) async fn refresh_healthy_gateway(
        &self,
        record: &GatewayRecord,
        upstream: &UpstreamClient,
        endpoint: UpstreamEndpoint<'_>,
        recovering: bool,
        selection: RefreshSelection,
    ) -> Result<bool, sqlx::Error> {
        let Some(_guard) = self.try_catalog_refresh(&record.id) else {
            return Ok(false);
        };
        let (catalog, metadata) = match upstream
            .discover_selected_catalog(endpoint, selection.resources, selection.prompts)
            .await
        {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(gateway = %record.id, %error, "could not refresh healthy gateway catalog");
                return Ok(false);
            }
        };
        let tools = match catalog
            .tools
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(tools) => tools,
            Err(_) => return Ok(false),
        };
        let completion = if recovering {
            CatalogRefreshCompletion::Recover
        } else {
            CatalogRefreshCompletion::Automatic
        };
        match self
            .database
            .refresh_catalog(
                record,
                CatalogRefreshInput {
                    tools: &tools,
                    capabilities: &catalog.capabilities,
                    metadata: &metadata,
                    include_resources: selection.resources,
                    include_prompts: selection.prompts,
                    completion,
                },
            )
            .await
        {
            Ok(Some(changes)) => {
                if recovering || changes.changed() {
                    self.publish_health_change(record);
                }
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(RegistrationError::Database(error)) => Err(error),
            Err(error) => {
                tracing::warn!(gateway = %record.id, %error, "could not reconcile healthy gateway catalog");
                Ok(false)
            }
        }
    }

    fn publish_health_change(&self, record: &GatewayRecord) {
        self.subscriptions.changed(
            &record.visibility,
            record.team_id.as_deref(),
            record.owner_email.as_deref(),
        );
    }
}

fn parse_health_timestamp(value: &str) -> Option<Timestamp> {
    value.parse().ok().or_else(|| {
        jiff::tz::TimeZone::UTC
            .to_timestamp(value.parse::<jiff::civil::DateTime>().ok()?)
            .ok()
    })
}
