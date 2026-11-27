// SPDX-License-Identifier: Apache-2.0

use futures_util::{StreamExt, stream};
use tokio::time::{MissedTickBehavior, interval, timeout};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::gateway_records::{CatalogRefreshCompletion, CatalogRefreshInput, GatewayRecord};

pub struct GatewayLifecycle {
    pub poll_interval: Duration,
    pub attempt_timeout: Duration,
    pub lease: Duration,
    pub concurrency: usize,
}

#[derive(Debug, thiserror::Error)]
enum LifecycleError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Registration(#[from] RegistrationError),
    #[error("{0}")]
    Discovery(String),
}

impl GatewayLifecycle {
    pub(super) fn accepted(&self, payload: Value) -> Response {
        let seconds = self
            .poll_interval
            .as_secs()
            .saturating_add(u64::from(self.poll_interval.subsec_nanos() != 0))
            .max(1);
        (
            StatusCode::ACCEPTED,
            [(header::RETRY_AFTER, seconds.to_string())],
            Json(payload),
        )
            .into_response()
    }
}

impl GatewayService {
    pub async fn run_gateway_lifecycle(self: Arc<Self>, stop: CancellationToken) {
        let Some(settings) = &self.lifecycle else {
            return;
        };
        let mut ticks = interval(settings.poll_interval);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = ticks.tick() => {}
            }
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                result = self.run_lifecycle_cycle(settings) => {
                    if let Err(error) = result {
                        tracing::warn!(%error, "could not claim gateway lifecycle records");
                    }
                }
            }
        }
    }

    async fn run_lifecycle_cycle(&self, settings: &GatewayLifecycle) -> Result<(), sqlx::Error> {
        let records = self
            .database
            .claim_gateway_lifecycle(settings.lease, settings.concurrency)
            .await?;
        let (deleting, pending): (Vec<_>, _) = records
            .into_iter()
            .partition(|record| record.status == "deleting");
        for batch in [deleting, pending] {
            stream::iter(batch)
                .for_each_concurrent(settings.concurrency, |record| async move {
                    if let Err(error) = self.run_lifecycle_job(&record, settings).await {
                        tracing::warn!(gateway = %record.id, %error, "could not complete gateway lifecycle job");
                    }
                })
                .await;
        }
        Ok(())
    }

    async fn run_lifecycle_job(
        &self,
        record: &GatewayRecord,
        settings: &GatewayLifecycle,
    ) -> Result<(), sqlx::Error> {
        if record.status == "deleting" {
            if self.database.delete_gateway(record).await? {
                self.subscriptions.removed(
                    &record.id,
                    &record.visibility,
                    record.team_id.as_deref(),
                    record.owner_email.as_deref(),
                );
            }
            return Ok(());
        }
        let result = timeout(
            settings.attempt_timeout,
            self.initialize_queued_gateway(record),
        )
        .await;
        let error = match result {
            Ok(Ok(true)) => {
                self.subscriptions.changed(
                    &record.visibility,
                    record.team_id.as_deref(),
                    record.owner_email.as_deref(),
                );
                return Ok(());
            }
            Ok(Ok(false)) => return Ok(()),
            Ok(Err(
                LifecycleError::Database(error)
                | LifecycleError::Registration(RegistrationError::Database(error)),
            )) => return Err(error),
            Ok(Err(error)) => error.to_string(),
            Err(_) => "upstream request timed out".to_owned(),
        };
        self.database.retry_gateway_lifecycle(record, &error).await
    }

    async fn initialize_queued_gateway(
        &self,
        record: &GatewayRecord,
    ) -> Result<bool, LifecycleError> {
        if record
            .oauth_config
            .as_deref()
            .is_some_and(oauth_api::defers_discovery)
        {
            return Ok(self.database.finish_deferred_gateway(record).await?);
        }
        let transport = UpstreamTransport::from_name(&record.transport)
            .ok_or(RegistrationError::Invalid("Unsupported gateway transport"))?;
        let connection = self
            .database
            .gateway_connection(
                &record.id,
                &record.url,
                true,
                Some(record.version),
                record.lifecycle_claimed_by.as_deref(),
            )
            .await?
            .ok_or(RegistrationError::Invalid("Gateway connection unavailable"))?;
        let credentials = self
            .connection_credentials(
                &record.id,
                &record.url,
                connection,
                None,
                None,
                UpstreamUse::Discovery,
            )
            .await
            .map_err(|_| {
                RegistrationError::Invalid("Could not load upstream authentication or TLS material")
            })?;
        let discovered = self
            .upstream
            .discover_catalog(UpstreamEndpoint {
                url: &record.url,
                transport,
                credentials: credentials.as_ref(),
            })
            .await;
        let (catalog, metadata) = discovered.map_err(|error| {
            let detail = match error {
                UpstreamError::Status(status) => format!("server responded with HTTP {status}"),
                error => error.to_string(),
            };
            LifecycleError::Discovery(format!(
                "Failed to initialize gateway at {}: {detail}",
                endpoint_for_error(&record.url)
            ))
        })?;
        let tools = catalog
            .tools
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| RegistrationError::Invalid("Upstream returned an invalid tool"))?;
        let result = self
            .database
            .refresh_catalog(
                record,
                CatalogRefreshInput {
                    tools: &tools,
                    capabilities: &catalog.capabilities,
                    metadata: &metadata,
                    include_resources: true,
                    include_prompts: true,
                    completion: CatalogRefreshCompletion::Initialize,
                },
            )
            .await?;
        Ok(result.is_some())
    }
}
