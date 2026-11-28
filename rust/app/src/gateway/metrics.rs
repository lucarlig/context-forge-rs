// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use axum::extract::{OriginalUri, Query};

use super::{catalog_api::CatalogApiError, *};
use crate::{
    access::BrowserApiSession,
    catalog::{MetricEntity, MetricReport},
    http_boundary::csrf::browser_proof_valid,
};

pub struct ExecutionMetricsSettings {
    pub(crate) record: bool,
    pub(crate) raw_window: Duration,
    pub(super) maintenance: super::metrics_maintenance::MaintenanceSettings,
}

impl Default for ExecutionMetricsSettings {
    fn default() -> Self {
        Self {
            record: true,
            raw_window: Duration::from_secs(3600),
            maintenance: Default::default(),
        }
    }
}

impl ExecutionMetricsSettings {
    pub(crate) fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        use crate::config::flag;

        let maintenance = super::metrics_maintenance::MaintenanceSettings::from_env()?;
        let mut raw_hours = maintenance.raw_retention_days * 24;
        if maintenance.delete_raw_after_rollup {
            raw_hours = raw_hours.min(maintenance.delete_raw_hours);
        }
        Ok(Self {
            record: flag("DB_METRICS_RECORDING_ENABLED")?.unwrap_or(true),
            raw_window: Duration::from_secs(raw_hours * 3600),
            maintenance,
        })
    }
}

const PERMISSION: &str = "admin.system_config";

pub(super) enum ExecutionTarget {
    Catalog(MetricEntity, String),
    Forwarded,
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut router = Router::new();
    for base in ["/admin/metrics", "/v1/admin/metrics"] {
        router = router
            .route(base, get(summary))
            .route(&format!("{base}/partial"), get(partial))
            .route(&format!("{base}/reset"), post(reset));
    }
    router
}

#[derive(Deserialize)]
struct MetricsQuery {
    entity_type: Option<String>,
    page: Option<usize>,
    per_page: Option<usize>,
}

impl MetricsQuery {
    fn parse(uri: &axum::http::Uri) -> Result<Self, CatalogApiError> {
        Query::<Self>::try_from_uri(uri)
            .map(|Query(query)| query)
            .map_err(|_| bad_page())
    }

    fn entity(&self) -> Result<MetricEntity, CatalogApiError> {
        let key = self.entity_type.as_deref().unwrap_or("tools");
        MetricEntity::ALL
            .into_iter()
            .find(|entity| entity.key() == key)
            .ok_or_else(|| {
                CatalogApiError::detail(
                    StatusCode::BAD_REQUEST,
                    "Invalid entity_type. Must be one of: tools, resources, prompts, servers",
                )
            })
    }

    fn page(&self, maximum: usize) -> Result<(usize, usize), CatalogApiError> {
        let page = self.page.unwrap_or(1);
        let size = self.per_page.unwrap_or(10);
        if page == 0 || !(1..=maximum).contains(&size) {
            return Err(bad_page());
        }
        Ok((page, size))
    }
}

fn bad_page() -> CatalogApiError {
    CatalogApiError::detail(
        StatusCode::UNPROCESSABLE_ENTITY,
        "Invalid metrics pagination",
    )
}

impl GatewayService {
    pub(crate) async fn can_administer_execution_metrics(
        &self,
        principal: &Principal,
    ) -> Result<bool, sqlx::Error> {
        Ok(principal.is_global_admin()
            && self
                .access
                .allows(principal, PERMISSION, RoleContext::Global, false)
                .await?)
    }

    pub(super) async fn check_execution_metrics(
        &self,
        principal: &Principal,
    ) -> Result<(), CatalogApiError> {
        if self.can_administer_execution_metrics(principal).await? {
            Ok(())
        } else {
            Err(CatalogApiError::detail(
                StatusCode::FORBIDDEN,
                "Access denied",
            ))
        }
    }

    pub(crate) async fn clear_execution_metrics(
        &self,
        principal: &Principal,
    ) -> Result<(), CatalogApiError> {
        self.check_execution_metrics(principal).await?;
        self.database.reset_execution_metrics().await?;
        tracing::info!(actor=%principal.email, "execution metrics reset");
        Ok(())
    }

    pub(crate) async fn execution_metrics_panel(
        &self,
        principal: &Principal,
        uri: &axum::http::Uri,
        base: &str,
        show_summary: bool,
    ) -> Result<Value, CatalogApiError> {
        self.check_execution_metrics(principal).await?;
        let query = MetricsQuery::parse(uri)?;
        let entity = query.entity()?;
        let (page, size) = query.page(self.management_max_page_size as usize)?;
        let selected = [entity];
        let entities = if show_summary {
            &MetricEntity::ALL[..]
        } else {
            &selected[..]
        };
        let reports = self
            .database
            .execution_reports(entities, self.execution_metrics.raw_window)
            .await?;
        let mut summaries = Vec::new();
        let mut performers = Vec::new();
        for (kind, report) in entities.iter().zip(reports) {
            if kind.key() == entity.key() {
                performers = report.performers;
            }
            if show_summary {
                summaries.push(json!({"name":kind.key(), "data":report.totals}));
            }
        }
        let total = performers.len();
        let pages = total.div_ceil(size);
        let offset = (page - 1).saturating_mul(size);
        let data: Vec<_> = performers.into_iter().skip(offset).take(size).collect();
        let link = |page: usize| {
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            if show_summary {
                query.append_pair("section", "metrics");
            }
            query
                .append_pair("entity_type", entity.key())
                .append_pair("per_page", &size.to_string())
                .append_pair("page", &page.to_string());
            format!("{base}?{}", query.finish())
        };
        Ok(json!({
            "summaries":summaries, "data":data, "entity_type":entity.key(),
            "page":page, "pages":pages, "size":size, "total":total,
            "previous":(page>1).then(|| link(page-1)),
            "next":(page<pages).then(|| link(page+1))
        }))
    }

    pub(super) async fn record_execution(
        &self,
        entity: Option<(MetricEntity, &str)>,
        server: Option<&str>,
        started: Instant,
        succeeded: bool,
    ) {
        if !self.execution_metrics.record {
            return;
        }
        let duration = started.elapsed();
        let rows = [entity, server.map(|id| (MetricEntity::Server, id))];
        if rows.iter().any(Option::is_some)
            && let Err(error) = self
                .database
                .record_execution_metrics(rows, duration, succeeded)
                .await
        {
            tracing::warn!(%error, "could not record execution metrics");
        }
    }

    pub(super) async fn record_target(
        &self,
        target: Option<ExecutionTarget>,
        server: Option<&CatalogServer>,
        started: Instant,
        succeeded: bool,
    ) {
        if let Some(target) = target {
            let entity = match &target {
                ExecutionTarget::Catalog(kind, id) => Some((*kind, id.as_str())),
                ExecutionTarget::Forwarded => None,
            };
            self.record_execution(
                entity,
                server.map(|server| server.id.as_str()),
                started,
                succeeded,
            )
            .await;
        }
    }

    pub(super) async fn record_rest_execution(
        &self,
        entity: (MetricEntity, &str),
        principal: &Principal,
        server: Option<&str>,
        started: Instant,
        succeeded: bool,
    ) {
        if !self.execution_metrics.record {
            return;
        }
        let server = match server {
            Some(id) => self
                .visible_server(id, Some(principal))
                .await
                .ok()
                .flatten(),
            None => None,
        };
        self.record_execution(
            Some(entity),
            server.as_ref().map(|server| server.id.as_str()),
            started,
            succeeded,
        )
        .await;
    }
}

async fn summary(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Value>, CatalogApiError> {
    service.check_execution_metrics(&principal).await?;
    let reports = service
        .database
        .execution_reports(&MetricEntity::ALL, service.execution_metrics.raw_window)
        .await?;
    let mut result = serde_json::Map::new();
    let mut top = serde_json::Map::new();
    for (
        entity,
        MetricReport {
            totals,
            mut performers,
        },
    ) in MetricEntity::ALL.into_iter().zip(reports)
    {
        performers.truncate(10);
        result.insert(entity.key().to_owned(), totals);
        top.insert(entity.key().to_owned(), json!(performers));
    }
    result.insert("topPerformers".into(), Value::Object(top));
    Ok(Json(Value::Object(result)))
}

async fn partial(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, CatalogApiError> {
    let report = service
        .execution_metrics_panel(&principal, &uri, uri.path(), false)
        .await?;
    Ok(crate::local_auth::browser::execution_metrics_partial(
        report,
    ))
}

async fn reset(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    browser: Option<Extension<BrowserApiSession>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<Value>, CatalogApiError> {
    service.check_metrics_csrf(browser.is_some(), &uri, &headers)?;
    service.clear_execution_metrics(&principal).await?;
    Ok(Json(
        json!({"message":"All metrics reset successfully", "success":true}),
    ))
}

impl GatewayService {
    pub(super) fn check_metrics_csrf(
        &self,
        browser: bool,
        uri: &axum::http::Uri,
        headers: &HeaderMap,
    ) -> Result<(), CatalogApiError> {
        let settings = &self.gateway_oauth;
        if browser
            && !browser_proof_valid(
                &settings.browser_origin,
                &settings.csrf_origins,
                uri,
                headers,
            )
        {
            return Err(CatalogApiError::detail(
                StatusCode::FORBIDDEN,
                "CSRF validation failed",
            ));
        }
        Ok(())
    }
}
