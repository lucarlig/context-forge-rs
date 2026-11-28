// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
};

use axum::extract::{
    OriginalUri, Path, Query,
    rejection::{JsonRejection, QueryRejection},
};

use super::{catalog_api::CatalogApiError, *};
use crate::{
    access::BrowserApiSession,
    audit::parse_time,
    observability::{
        self,
        query::{Observation, SpanQuery, TraceQuery, TraceRow, date_wire, wire},
    },
};

impl GatewayService {
    pub fn with_observability(mut self) -> Result<Self, Box<dyn Error + Send + Sync>> {
        self.observability_enabled = observability::enabled()?;
        Ok(self)
    }
}

pub(super) fn router(service: &Arc<GatewayService>) -> Router {
    let mut router = Router::new();
    for prefix in ["/observability", "/v1/observability"] {
        router = router
            .route(&format!("{prefix}/metrics/timeseries"), get(timeseries))
            .route(&format!("{prefix}/metrics/percentiles"), get(latency));
        if service.observability_enabled {
            router = router
                .route(&format!("{prefix}/traces"), get(traces))
                .route(&format!("{prefix}/traces/query"), post(advanced))
                .route(&format!("{prefix}/traces/export"), post(export))
                .route(
                    &format!("{prefix}/traces/cleanup"),
                    axum::routing::delete(cleanup),
                )
                .route(&format!("{prefix}/traces/{{id}}"), get(trace))
                .route(&format!("{prefix}/spans"), get(spans))
                .route(&format!("{prefix}/stats"), get(stats))
                .route(
                    &format!("{prefix}/analytics/query-performance"),
                    get(performance),
                );
        }
    }
    service
        .access
        .protect_browser_api(router.with_state(service.clone()), None)
}

async fn authorize(
    service: &GatewayService,
    principal: &Principal,
    permission: &str,
) -> Result<(), CatalogApiError> {
    if principal.is_global_admin()
        && service
            .access
            .allows(principal, permission, RoleContext::Global, false)
            .await?
    {
        Ok(())
    } else {
        Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ))
    }
}

const SYSTEM: &str = "admin.system_config";

async fn traces(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    query: Result<Query<TraceQuery>, QueryRejection>,
) -> Result<Json<Vec<Value>>, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    let Query(query) = query.map_err(|_| invalid())?;
    if !query.valid() {
        return Err(invalid());
    }
    trace_list(&service, query).await
}

async fn advanced(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    query: Result<Json<TraceQuery>, JsonRejection>,
) -> Result<Json<Vec<Value>>, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    let Json(query) = query.map_err(|_| invalid_body())?;
    if !query.valid() {
        return Err(invalid_body());
    }
    trace_list(&service, query).await
}

async fn trace_list(
    service: &GatewayService,
    query: TraceQuery,
) -> Result<Json<Vec<Value>>, CatalogApiError> {
    let rows = service
        .database
        .traces(&query)
        .await
        .map_err(query_failed)?;
    let postgres = matches!(service.database, Database::Postgres(_));
    Ok(Json(rows.iter().map(|row| wire(row, postgres)).collect()))
}

async fn trace(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    let result = service
        .database
        .trace(&id)
        .await
        .map_err(query_failed)?
        .ok_or_else(|| CatalogApiError::detail(StatusCode::NOT_FOUND, "Trace not found"))?;
    let spans = service
        .database
        .spans(
            &SpanQuery {
                trace_id: Some(id),
                ..Default::default()
            },
            true,
        )
        .await
        .map_err(query_failed)?;
    let postgres = matches!(service.database, Database::Postgres(_));
    let mut result = wire(&result, postgres);
    result["spans"] = Value::Array(spans.iter().map(|row| wire(row, postgres)).collect());
    Ok(Json(result))
}

async fn spans(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    query: Result<Query<SpanQuery>, QueryRejection>,
) -> Result<Json<Vec<Value>>, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    let Query(query) = query.map_err(|_| invalid())?;
    if !query.valid() {
        return Err(invalid());
    }
    let rows = service
        .database
        .spans(&query, false)
        .await
        .map_err(query_failed)?;
    let postgres = matches!(service.database, Database::Postgres(_));
    Ok(Json(rows.iter().map(|row| wire(row, postgres)).collect()))
}

#[derive(Deserialize)]
struct Retention {
    #[serde(default = "seven")]
    days: i64,
}

fn seven() -> i64 {
    7
}

async fn cleanup(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    browser: Option<Extension<BrowserApiSession>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    query: Result<Query<Retention>, QueryRejection>,
) -> Result<Json<Value>, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    service.check_metrics_csrf(browser.is_some(), &uri, &headers)?;
    let Query(query) = query.map_err(|_| invalid())?;
    let cutoff = query
        .days
        .checked_mul(86_400)
        .filter(|days| *days > 0)
        .and_then(|delta| Timestamp::now().as_second().checked_sub(delta))
        .and_then(|time| Timestamp::from_second(time).ok())
        .ok_or_else(invalid)?;
    let deleted = service
        .database
        .delete_traces(cutoff)
        .await
        .map_err(query_failed)?;
    Ok(Json(
        json!({"deleted":deleted,"cutoff_time":date_wire(&cutoff.to_string(),false,false)}),
    ))
}

#[derive(Deserialize)]
struct Window {
    #[serde(default = "day")]
    hours: i64,
    #[serde(default = "hour")]
    interval_minutes: i64,
}

fn day() -> i64 {
    24
}
fn hour() -> i64 {
    60
}

impl Window {
    async fn rows(&self, service: &GatewayService) -> Result<Vec<Observation>, CatalogApiError> {
        if !(1..=168).contains(&self.hours) || !(5..=1440).contains(&self.interval_minutes) {
            return Err(invalid());
        }
        if !service.observability_enabled {
            return Ok(Vec::new());
        }
        let cutoff = Timestamp::now()
            .checked_sub(Duration::from_secs(self.hours as u64 * 3600))
            .map_err(|_| invalid())?;
        service
            .database
            .trace_window(cutoff)
            .await
            .map_err(query_failed)
    }
}

async fn stats(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    window: Result<Query<Window>, QueryRejection>,
) -> Result<Json<Value>, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    let Query(window) = window.map_err(|_| invalid())?;
    let rows = window.rows(&service).await?;
    let mut success = 0;
    let mut error = 0;
    let mut endpoints: HashMap<&str, (usize, f64)> = HashMap::new();
    let mut duration = 0.0;
    let mut observations = 0;
    for row in &rows {
        success += usize::from(row.status == "ok");
        error += usize::from(row.status == "error");
        if let Some(value) = row.duration_ms {
            observations += 1;
            duration += value;
            let (count, total) = endpoints.entry(&row.name).or_default();
            *count += 1;
            *total += value;
        }
    }
    let mut slowest: Vec<_> = endpoints
        .into_iter()
        .map(|(name, (count, sum))| (name, count, sum / count as f64))
        .collect();
    slowest.sort_unstable_by(|left, right| right.2.total_cmp(&left.2).then(left.0.cmp(right.0)));
    let slowest: Vec<_> = slowest
        .into_iter()
        .take(10)
        .map(|(name, count, avg)| json!({"name":name,"count":count,"avg_duration_ms":rounded(avg)}))
        .collect();
    Ok(Json(
        json!({"time_window_hours":window.hours,"total_traces":rows.len(),"success_count":success,"error_count":error,
        "error_rate":if rows.is_empty() { 0.0 } else { error as f64 / rows.len() as f64 * 100.0 },
        "avg_duration_ms":rounded(duration / observations.max(1) as f64),"slowest_endpoints":slowest}),
    ))
}

async fn performance(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    window: Result<Query<Window>, QueryRejection>,
) -> Result<Json<Value>, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    let Query(window) = window.map_err(|_| invalid())?;
    let rows = window.rows(&service).await?;
    let mut durations: Vec<_> = rows.into_iter().filter_map(|row| row.duration_ms).collect();
    durations.sort_unstable_by(f64::total_cmp);
    let percentiles = if durations.is_empty() {
        json!({})
    } else {
        let [p50, p75, p90, p95, p99] =
            [0.5, 0.75, 0.9, 0.95, 0.99].map(|percent| percentile(&durations, percent));
        json!({"p50":p50,"p75":p75,"p90":p90,"p95":p95,"p99":p99})
    };
    Ok(Json(
        json!({"time_window_hours":window.hours,"total_traces":durations.len(),"percentiles":percentiles,
        "avg_duration_ms":rounded(durations.iter().sum::<f64>() / durations.len().max(1) as f64),
        "min_duration_ms":rounded(durations.first().copied().unwrap_or_default()),
        "max_duration_ms":rounded(durations.last().copied().unwrap_or_default())}),
    ))
}

fn rounded(value: f64) -> f64 {
    (value * 100.0).round_ties_even() / 100.0
}

fn percentile(sorted: &[f64], percent: f64) -> f64 {
    let rank = (sorted.len() - 1) as f64 * percent;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    rounded(sorted[lower] + (rank - lower as f64) * (sorted[upper] - sorted[lower]))
}

fn buckets(rows: &[Observation], interval: i64) -> BTreeMap<i64, Vec<&Observation>> {
    let mut buckets: BTreeMap<i64, Vec<&Observation>> = BTreeMap::new();
    let interval = interval * 60;
    for row in rows {
        if let Some(time) = parse_time(&row.stamp) {
            buckets
                .entry(time.as_second().div_euclid(interval) * interval)
                .or_default()
                .push(row);
        }
    }
    buckets
}

fn bucket_stamp(stamp: i64) -> String {
    Timestamp::from_second(stamp)
        .map(|time| time.to_string().replace('Z', "+00:00"))
        .unwrap_or_default()
}

async fn timeseries(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    window: Result<Query<Window>, QueryRejection>,
) -> Result<Json<Value>, CatalogApiError> {
    authorize(&service, &principal, "metrics:read").await?;
    let Query(window) = window.map_err(|_| invalid())?;
    let rows = window.rows(&service).await?;
    let buckets = buckets(&rows, window.interval_minutes);
    let stamps: Vec<_> = buckets.keys().map(|stamp| bucket_stamp(*stamp)).collect();
    let values: Vec<_> = buckets.values().map(Vec::len).collect();
    let status_counts = |status| -> Vec<_> {
        buckets
            .values()
            .map(|rows| rows.iter().filter(|row| row.status == status).count())
            .collect()
    };
    Ok(Json(
        json!({"buckets":stamps,"values":values,"success_count":status_counts("ok"),"error_count":status_counts("error")}),
    ))
}

async fn latency(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    window: Result<Query<Window>, QueryRejection>,
) -> Result<Json<Value>, CatalogApiError> {
    authorize(&service, &principal, "metrics:read").await?;
    let Query(window) = window.map_err(|_| invalid())?;
    let rows = window.rows(&service).await?;
    let mut stamps = Vec::new();
    let mut p50 = Vec::new();
    let mut p95 = Vec::new();
    let mut p99 = Vec::new();
    for (stamp, rows) in buckets(&rows, window.interval_minutes) {
        let mut values: Vec<_> = rows.iter().filter_map(|row| row.duration_ms).collect();
        if values.is_empty() {
            continue;
        }
        values.sort_unstable_by(f64::total_cmp);
        stamps.push(bucket_stamp(stamp));
        p50.push(percentile(&values, 0.5));
        p95.push(percentile(&values, 0.95));
        p99.push(percentile(&values, 0.99));
    }
    Ok(Json(
        json!({"buckets":stamps,"p50":p50,"p95":p95,"p99":p99}),
    ))
}

#[derive(Deserialize)]
struct Export {
    #[serde(default = "json_format")]
    format: String,
}

fn json_format() -> String {
    "json".into()
}

async fn export(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    format: Result<Query<Export>, QueryRejection>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<Response, CatalogApiError> {
    authorize(&service, &principal, SYSTEM).await?;
    let Query(export) = format.map_err(|_| invalid())?;
    if !matches!(export.format.as_str(), "json" | "csv" | "ndjson") {
        return Err(invalid());
    }
    let Json(mut body) = body.map_err(|_| invalid_body())?;
    body.as_object_mut()
        .ok_or_else(invalid_body)?
        .entry("limit")
        .or_insert(json!(1000));
    let filters: TraceQuery = serde_json::from_value(body).map_err(|_| invalid_body())?;
    if !filters.valid() {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "Export failed",
        ));
    }
    let rows = service
        .database
        .traces(&filters)
        .await
        .map_err(query_failed)?;
    let postgres = matches!(service.database, Database::Postgres(_));
    let core = |row: &TraceRow| {
        json!({"trace_id":row.trace_id,"name":row.name,"start_time":date_wire(&row.start_time,postgres,true),
            "duration_ms":row.duration_ms,"status":row.status,"http_method":row.http_method,
            "http_status_code":row.http_status_code,"user_email":row.user_email})
    };
    if export.format == "json" {
        let values: Vec<_> = rows
            .iter()
            .map(|row| {
                let mut result = core(row);
                result["end_time"] = json!(
                    row.end_time
                        .as_deref()
                        .map(|date| date_wire(date, postgres, true))
                );
                result["http_url"] = json!(row.http_url);
                result
            })
            .collect();
        return Ok(Json(values).into_response());
    }
    let (mime, filename, body) = if export.format == "csv" {
        let mut csv = "trace_id,name,start_time,duration_ms,status,http_method,http_status_code,user_email\r\n".to_owned();
        for row in &rows {
            let mut fields = [
                row.trace_id.clone(),
                row.name.clone(),
                date_wire(&row.start_time, postgres, true),
                row.duration_ms
                    .filter(|value| *value != 0.0)
                    .map_or_else(String::new, |v| json!(v).to_string()),
                row.status.clone(),
                row.http_method.clone().unwrap_or_default(),
                row.http_status_code
                    .filter(|code| *code != 0)
                    .map_or_else(String::new, |code| code.to_string()),
                row.user_email.clone().unwrap_or_default(),
            ];
            for field in &mut fields {
                if field.contains([',', '"', '\r', '\n']) {
                    *field = format!("\"{}\"", field.replace('"', "\"\""));
                }
            }
            csv.push_str(&fields.join(","));
            csv.push_str("\r\n");
        }
        (
            "text/csv; charset=utf-8",
            "attachment; filename=traces.csv",
            csv,
        )
    } else {
        let mut ndjson = String::new();
        for row in &rows {
            ndjson.push_str(&core(row).to_string());
            ndjson.push('\n');
        }
        (
            "application/x-ndjson",
            "attachment; filename=traces.ndjson",
            ndjson,
        )
    };
    Ok((
        [
            (header::CONTENT_TYPE, mime),
            (header::CONTENT_DISPOSITION, filename),
        ],
        body,
    )
        .into_response())
}

fn invalid() -> CatalogApiError {
    CatalogApiError::detail(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Invalid observability query",
    )
}

fn invalid_body() -> CatalogApiError {
    CatalogApiError::detail(StatusCode::BAD_REQUEST, "Invalid request body")
}

fn query_failed(error: sqlx::Error) -> CatalogApiError {
    tracing::error!(%error, "Observability query failed");
    CatalogApiError::detail(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Observability query failed",
    )
}
