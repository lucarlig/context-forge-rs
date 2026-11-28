// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    error::Error,
    sync::atomic::{AtomicU64, Ordering::Relaxed},
    time::Instant,
};

use axum::extract::{OriginalUri, rejection::JsonRejection};
use tokio_util::sync::CancellationToken;

use super::{catalog_api::CatalogApiError, *};
use crate::{
    access::BrowserApiSession,
    catalog::maintenance::{MetricTable, RollupCounts},
    config::{flag, legacy_api_enabled, parse},
};

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

pub(super) struct MaintenanceSettings {
    cleanup: bool,
    cleanup_interval: u64,
    cleanup_batch_size: u64,
    cleanup_batch_sleep_ms: u64,
    pub(super) raw_retention_days: u64,
    rollup: bool,
    rollup_interval: u64,
    rollup_retention_days: u64,
    late_data_hours: u64,
    pub(super) delete_raw_after_rollup: bool,
    pub(super) delete_raw_hours: u64,
    native_percentiles: bool,
    legacy_api: bool,
}

impl Default for MaintenanceSettings {
    fn default() -> Self {
        Self {
            cleanup: true,
            cleanup_interval: 1,
            cleanup_batch_size: 10_000,
            cleanup_batch_sleep_ms: 50,
            raw_retention_days: 7,
            rollup: true,
            rollup_interval: 1,
            rollup_retention_days: 365,
            late_data_hours: 1,
            delete_raw_after_rollup: true,
            delete_raw_hours: 1,
            native_percentiles: true,
            legacy_api: true,
        }
    }
}

impl MaintenanceSettings {
    pub(super) fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        fn bounded(
            name: &str,
            default: u64,
            low: u64,
            high: u64,
        ) -> Result<u64, Box<dyn Error + Send + Sync>> {
            let value = parse(name, default)?;
            if !(low..=high).contains(&value) {
                return Err(format!("invalid {name}: expected {low} through {high}").into());
            }
            Ok(value)
        }

        let defaults = Self::default();
        Ok(Self {
            cleanup: flag("METRICS_CLEANUP_ENABLED")?.unwrap_or(defaults.cleanup),
            cleanup_interval: bounded(
                "METRICS_CLEANUP_INTERVAL_HOURS",
                defaults.cleanup_interval,
                1,
                168,
            )?,
            cleanup_batch_size: bounded(
                "METRICS_CLEANUP_BATCH_SIZE",
                defaults.cleanup_batch_size,
                100,
                100_000,
            )?,
            cleanup_batch_sleep_ms: bounded(
                "METRICS_CLEANUP_BATCH_SLEEP_MS",
                defaults.cleanup_batch_sleep_ms,
                0,
                5000,
            )?,
            raw_retention_days: bounded(
                "METRICS_RETENTION_DAYS",
                defaults.raw_retention_days,
                1,
                365,
            )?,
            rollup: flag("METRICS_ROLLUP_ENABLED")?.unwrap_or(defaults.rollup),
            rollup_interval: bounded(
                "METRICS_ROLLUP_INTERVAL_HOURS",
                defaults.rollup_interval,
                1,
                24,
            )?,
            rollup_retention_days: bounded(
                "METRICS_ROLLUP_RETENTION_DAYS",
                defaults.rollup_retention_days,
                30,
                3650,
            )?,
            late_data_hours: bounded(
                "METRICS_ROLLUP_LATE_DATA_HOURS",
                defaults.late_data_hours,
                1,
                48,
            )?,
            delete_raw_after_rollup: flag("METRICS_DELETE_RAW_AFTER_ROLLUP")?
                .unwrap_or(defaults.delete_raw_after_rollup),
            delete_raw_hours: bounded(
                "METRICS_DELETE_RAW_AFTER_ROLLUP_HOURS",
                defaults.delete_raw_hours,
                1,
                8760,
            )?,
            native_percentiles: flag("USE_POSTGRESDB_PERCENTILES")?
                .unwrap_or(defaults.native_percentiles),
            legacy_api: legacy_api_enabled()?,
        })
    }
}

#[derive(Default)]
pub(super) struct MaintenanceStats {
    rollup_runs: AtomicU64,
    cleanup_runs: AtomicU64,
    total_cleaned: AtomicU64,
}

pub(super) fn router(service: &Arc<GatewayService>) -> Router {
    let settings = &service.execution_metrics.maintenance;
    if !settings.cleanup && !settings.rollup {
        return Router::new();
    }
    let mut router = Router::new();
    let prefixes: &[_] = if settings.legacy_api {
        &["/v1", ""]
    } else {
        &["/v1"]
    };
    for prefix in prefixes {
        router = router
            .route(&format!("{prefix}/api/metrics/config"), get(configuration))
            .route(&format!("{prefix}/api/metrics/stats"), get(stats))
            .route(&format!("{prefix}/api/metrics/rollup"), post(rollup))
            .route(&format!("{prefix}/api/metrics/cleanup"), post(cleanup));
    }
    service
        .access
        .protect_browser_api(router.with_state(service.clone()), None)
}

#[derive(Deserialize)]
#[serde(default)]
struct RollupRequest {
    hours_back: i64,
    #[serde(rename = "force_reprocess")]
    _force_reprocess: bool,
}

impl Default for RollupRequest {
    fn default() -> Self {
        Self {
            hours_back: 24,
            _force_reprocess: false,
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
struct CleanupRequest {
    retention_days: Option<i64>,
    include_rollup: bool,
    table_type: Option<String>,
}

impl Default for CleanupRequest {
    fn default() -> Self {
        Self {
            retention_days: None,
            include_rollup: true,
            table_type: None,
        }
    }
}

type OptionalJson<T> = Result<Option<Json<Option<T>>>, JsonRejection>;

fn validate_range(field: &str, value: i64, min: i64, max: i64) -> Result<(), CatalogApiError> {
    if (min..=max).contains(&value) {
        return Ok(());
    }
    let (kind, comparison, limit, bound) = if value < min {
        ("greater_than_equal", "greater", min, json!({"ge":min}))
    } else {
        ("less_than_equal", "less", max, json!({"le":max}))
    };
    Err(CatalogApiError(
        StatusCode::UNPROCESSABLE_ENTITY,
        json!({"detail":[{
            "loc":["body",field], "type":kind, "ctx":bound,
            "msg":format!("Input should be {comparison} than or equal to {limit}"),
        }]}),
    ))
}

fn input<T: Default>(payload: OptionalJson<T>) -> Result<T, CatalogApiError> {
    payload
        .map(|payload| payload.and_then(|Json(input)| input).unwrap_or_default())
        .map_err(|_| {
            CatalogApiError::detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid metrics maintenance request",
            )
        })
}

async fn configuration(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, CatalogApiError> {
    service.check_execution_metrics(&principal).await?;
    let settings = &service.execution_metrics.maintenance;
    Ok(Json(json!({
        "cleanup": {
            "enabled":settings.cleanup, "retention_days":settings.raw_retention_days,
            "interval_hours":settings.cleanup_interval, "batch_size":settings.cleanup_batch_size,
        },
        "rollup": {
            "enabled":settings.rollup, "interval_hours":settings.rollup_interval,
            "retention_days":settings.rollup_retention_days, "late_data_hours":settings.late_data_hours,
            "delete_raw_after_rollup":settings.delete_raw_after_rollup,
            "delete_raw_after_rollup_hours":settings.delete_raw_hours,
        },
    })))
}

async fn stats(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, CatalogApiError> {
    service.check_execution_metrics(&principal).await?;
    let config = &service.execution_metrics.maintenance;
    let stats = &service.metrics_maintenance_stats;
    let mut cleanup = json!({"enabled":false});
    let mut rollup = json!({"enabled":false});
    let mut sizes = BTreeMap::new();
    if config.cleanup {
        cleanup = json!({
            "enabled":true, "retention_days":config.raw_retention_days,
            "rollup_retention_days": config.rollup_retention_days,
            "batch_size":config.cleanup_batch_size, "batch_sleep_ms":config.cleanup_batch_sleep_ms,
            "cleanup_interval_hours":config.cleanup_interval,
            "total_cleaned":stats.total_cleaned.load(Relaxed),
            "cleanup_runs":stats.cleanup_runs.load(Relaxed),
            "delete_raw_after_rollup":config.delete_raw_after_rollup,
            "delete_raw_after_rollup_hours":config.delete_raw_hours,
        });
        for table in MetricTable::ALL {
            for hourly in [false, true] {
                sizes.insert(
                    table.name(hourly),
                    service.database.metric_table_size(table, hourly).await?,
                );
            }
        }
    }
    if config.rollup {
        rollup = json!({
            "enabled":true, "rollup_interval_hours":config.rollup_interval,
            "delete_raw_after_rollup":config.delete_raw_after_rollup,
            "delete_raw_after_rollup_hours":config.delete_raw_hours,
            "total_rollups":0,
            "rollup_runs":stats.rollup_runs.load(Relaxed),
            "is_postgresql":matches!(service.database, Database::Postgres(_)),
        });
    }
    Ok(Json(
        json!({"cleanup":cleanup, "rollup":rollup, "table_sizes":sizes}),
    ))
}

async fn rollup(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    browser: Option<Extension<BrowserApiSession>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    payload: OptionalJson<RollupRequest>,
) -> Result<Json<Value>, CatalogApiError> {
    service.check_execution_metrics(&principal).await?;
    service.check_metrics_csrf(browser.is_some(), &uri, &headers)?;
    let input = input(payload)?;
    validate_range("hours_back", input.hours_back, 1, 8760)?;
    if !service.execution_metrics.maintenance.rollup {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "Metrics rollup is disabled",
        ));
    }
    Ok(Json(service.rollup_metrics(input.hours_back as u64).await))
}

async fn cleanup(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    browser: Option<Extension<BrowserApiSession>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    payload: OptionalJson<CleanupRequest>,
) -> Result<Json<Value>, CatalogApiError> {
    service.check_execution_metrics(&principal).await?;
    service.check_metrics_csrf(browser.is_some(), &uri, &headers)?;
    let input = input(payload)?;
    if let Some(days) = input.retention_days {
        validate_range("retention_days", days, 0, 365)?;
    }
    if !service.execution_metrics.maintenance.cleanup {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "Metrics cleanup is disabled",
        ));
    }
    let selected = input.table_type.as_deref().filter(|name| !name.is_empty()).map(|name| {
        MetricTable::ALL.into_iter().find(|table| table.kind() == name).ok_or_else(|| {
            CatalogApiError::detail(StatusCode::BAD_REQUEST, format!(
                "Unknown table type: {name}. Must be one of: ['tool', 'resource', 'prompt', 'server', 'a2a_agent']"
            ))
        })
    }).transpose()?;
    let (report, _) = service.cleanup_metrics(input, selected).await;
    Ok(Json(report))
}

impl GatewayService {
    pub async fn run_metrics_maintenance(self: Arc<Self>, shutdown: CancellationToken) {
        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = async {
                tokio::join!(self.rollup_loop(), self.cleanup_loop());
            } => {}
        }
    }

    async fn rollup_loop(&self) {
        let settings = &self.execution_metrics.maintenance;
        if settings.rollup {
            let mut hours = settings.raw_retention_days * 24;
            loop {
                self.rollup_metrics(hours).await;
                self.metrics_maintenance_stats
                    .rollup_runs
                    .fetch_add(1, Relaxed);
                hours = settings.late_data_hours;
                tokio::time::sleep(Duration::from_secs(settings.rollup_interval * HOUR)).await;
            }
        }
    }

    async fn cleanup_loop(&self) {
        let settings = &self.execution_metrics.maintenance;
        if settings.cleanup {
            loop {
                tokio::time::sleep(Duration::from_secs(settings.cleanup_interval * HOUR)).await;
                let (_, deleted) = self.cleanup_metrics(CleanupRequest::default(), None).await;
                let stats = &self.metrics_maintenance_stats;
                stats.cleanup_runs.fetch_add(1, Relaxed);
                stats.total_cleaned.fetch_add(deleted, Relaxed);
            }
        }
    }

    async fn rollup_metrics(&self, hours: u64) -> Value {
        let now = Timestamp::now();
        let started = Instant::now();
        let end = hour_start(now.as_second());
        let start = end - (hours * HOUR) as i64;
        let settings = &self.execution_metrics.maintenance;
        let delete_before = settings
            .delete_raw_after_rollup
            .then(|| now.as_second() - (settings.delete_raw_hours * HOUR) as i64);
        let mut tables = BTreeMap::new();
        let mut total = RollupCounts::default();
        for table in MetricTable::ALL {
            let table_start = Instant::now();
            let name = table.name(false);
            let result = self
                .database
                .rollup_metrics(
                    table,
                    start,
                    end,
                    delete_before,
                    settings.native_percentiles,
                )
                .await;
            let (counts, error) = match result {
                Ok(counts) => (counts, None),
                Err(error) => {
                    tracing::error!(%error, table=name, "Metrics rollup failed");
                    (RollupCounts::default(), Some("Metrics rollup failed"))
                }
            };
            total.hours += counts.hours;
            total.records += counts.records;
            total.rollups += counts.rollups;
            tables.insert(name, json!({
                "table_name":name, "hours_processed":counts.hours, "records_aggregated":counts.records,
                "rollups_created":0, "rollups_updated":counts.rollups, "raw_deleted":counts.deleted,
                "duration_seconds":table_start.elapsed().as_secs_f64(), "error":error,
            }));
        }
        json!({
            "total_hours_processed":total.hours, "total_records_aggregated":total.records,
            "total_rollups_created":0, "total_rollups_updated":total.rollups, "tables":tables,
            "duration_seconds":started.elapsed().as_secs_f64(), "started_at":utc(now),
            "completed_at":utc(Timestamp::now()),
        })
    }

    async fn cleanup_metrics(
        &self,
        request: CleanupRequest,
        selected: Option<MetricTable>,
    ) -> (Value, u64) {
        let now = Timestamp::now();
        let started = Instant::now();
        let settings = &self.execution_metrics.maintenance;
        let days = request
            .retention_days
            .unwrap_or(settings.raw_retention_days as i64);
        let raw_cutoff = if days == 0 {
            now.as_second() + HOUR as i64
        } else {
            hour_start(now.as_second() - days * DAY as i64)
        };
        let hourly_cutoff = if days == 0 {
            now.as_second()
        } else {
            now.as_second() - (settings.rollup_retention_days * DAY) as i64
        };
        let mut tables = BTreeMap::new();
        let mut total = 0;
        let work = if let Some(table) = selected {
            vec![(table, false, raw_cutoff)]
        } else {
            MetricTable::ALL
                .into_iter()
                .map(|table| (table, false, raw_cutoff))
                .chain(
                    MetricTable::ALL
                        .into_iter()
                        .filter(|_| request.include_rollup)
                        .map(|table| (table, true, hourly_cutoff)),
                )
                .collect()
        };
        for (table, hourly, cutoff) in work {
            let table_start = Instant::now();
            let name = table.name(hourly);
            let (deleted, remaining, error) = self.clean_metric_table(table, hourly, cutoff).await;
            total += deleted;
            tables.insert(name, json!({
                "table_name":name, "deleted_count":deleted, "remaining_count":remaining,
                "cutoff_date":utc(Timestamp::from_second(cutoff).expect("bounded metrics cutoff")),
                "duration_seconds":table_start.elapsed().as_secs_f64(), "error":error,
            }));
        }
        (
            json!({
                "total_deleted":total, "tables":tables, "duration_seconds":started.elapsed().as_secs_f64(),
                "started_at":utc(now), "completed_at":utc(Timestamp::now()),
            }),
            total,
        )
    }

    async fn clean_metric_table(
        &self,
        table: MetricTable,
        hourly: bool,
        cutoff: i64,
    ) -> (u64, i64, Option<&'static str>) {
        let settings = &self.execution_metrics.maintenance;
        let mut deleted = 0;
        let result = async {
            loop {
                let count = self
                    .database
                    .clean_metrics_batch(table, hourly, cutoff, settings.cleanup_batch_size as i64)
                    .await?;
                deleted += count;
                if count < settings.cleanup_batch_size {
                    break;
                }
                if settings.cleanup_batch_sleep_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(settings.cleanup_batch_sleep_ms))
                        .await;
                }
            }
            self.database.metric_table_size(table, hourly).await
        }
        .await;
        match result {
            Ok(remaining) => (deleted, remaining, None),
            Err(error) => {
                tracing::error!(%error, table=table.name(hourly), "Metrics cleanup failed");
                (deleted, -1, Some("Metrics cleanup failed"))
            }
        }
    }
}

fn hour_start(seconds: i64) -> i64 {
    seconds.div_euclid(HOUR as i64) * HOUR as i64
}

fn utc(time: Timestamp) -> String {
    time.to_string().replace('Z', "+00:00")
}
