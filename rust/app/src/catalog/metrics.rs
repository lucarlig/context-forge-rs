// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde_json::json;

use super::*;

#[derive(Clone, Copy)]
pub(crate) enum MetricEntity {
    Server,
    Tool,
    Resource,
    Prompt,
}

impl MetricEntity {
    fn storage(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Server => ("server_metrics", "server_metrics_hourly", "server_id"),
            Self::Tool => ("tool_metrics", "tool_metrics_hourly", "tool_id"),
            Self::Resource => ("resource_metrics", "resource_metrics_hourly", "resource_id"),
            Self::Prompt => ("prompt_metrics", "prompt_metrics_hourly", "prompt_id"),
        }
    }
}

#[derive(Default, sqlx::FromRow)]
pub(crate) struct ExecutionMetrics {
    id: String,
    total: i64,
    successes: i64,
    minimum: Option<f64>,
    maximum: Option<f64>,
    average: Option<f64>,
    last_execution: Option<String>,
}

impl ExecutionMetrics {
    pub(crate) fn json(&self) -> Value {
        let failed = self.total.saturating_sub(self.successes);
        json!({
            "totalExecutions":self.total,
            "successfulExecutions":self.successes,
            "failedExecutions":failed,
            "failureRate":if self.total==0 {0.0} else {failed as f64 / self.total as f64},
            "minResponseTime":self.minimum,
            "maxResponseTime":self.maximum,
            "avgResponseTime":self.average,
            "lastExecutionTime":self.last_execution.as_deref().map(metric_timestamp),
        })
    }
}

fn metric_timestamp(timestamp: &str) -> String {
    let iso = timestamp.replacen(' ', "T", 1);
    iso.parse::<jiff::Timestamp>()
        .or_else(|_| format!("{iso}Z").parse())
        .map_or(iso, |timestamp| timestamp.to_string())
}

impl Database {
    pub(crate) async fn execution_metrics(
        &self,
        entity: MetricEntity,
        ids: &[&str],
    ) -> Result<HashMap<String, ExecutionMetrics>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let ids =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        let (raw, hourly, foreign) = entity.storage();
        macro_rules! read {
            ($pool:ident, $exists:literal, $ids:literal) => {{
                let (has_raw, has_hourly) = tokio::try_join!(
                    sqlx::query_scalar::<_, bool>($exists)
                        .bind(raw)
                        .fetch_one($pool),
                    sqlx::query_scalar::<_, bool>($exists)
                        .bind(hourly)
                        .fetch_one($pool),
                )?;
                let Some(query) = metrics_query(has_raw, has_hourly, raw, hourly, foreign, $ids)
                else {
                    return Ok(HashMap::new());
                };
                // Dynamic fragments are fixed schema identifiers and driver literals.
                sqlx::query_as::<_, ExecutionMetrics>(sqlx::AssertSqlSafe(query))
                    .bind(ids)
                    .fetch_all($pool)
                    .await?
            }};
        }
        let rows = match self {
            Self::Sqlite(pool) => read!(
                pool,
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=$1)",
                "SELECT value FROM json_each($1)"
            ),
            Self::Postgres(pool) => read!(
                pool,
                "SELECT to_regclass(CAST($1 AS TEXT)) IS NOT NULL",
                "SELECT json_array_elements_text(CAST($1 AS JSON))"
            ),
        };
        Ok(rows.into_iter().map(|row| (row.id.clone(), row)).collect())
    }
}

fn metrics_query(
    has_raw: bool,
    has_hourly: bool,
    raw: &str,
    hourly: &str,
    foreign: &str,
    ids: &str,
) -> Option<String> {
    let mut sources = Vec::with_capacity(2);
    if has_raw {
        sources.push(format!(
            "SELECT {foreign} AS id, 1 AS total, CASE WHEN is_success THEN 1 ELSE 0 END AS successes,
                 response_time AS minimum, response_time AS maximum, response_time AS subtotal,
                 timestamp AS happened FROM {raw} WHERE {foreign} IN (SELECT id FROM ids)"
        ));
    }
    if has_hourly {
        sources.push(format!(
            "SELECT {foreign} AS id, total_count AS total, success_count AS successes,
                 min_response_time AS minimum, max_response_time AS maximum,
                 avg_response_time*total_count AS subtotal, hour_start AS happened
              FROM {hourly} WHERE {foreign} IN (SELECT id FROM ids)"
        ));
    }
    if sources.is_empty() {
        return None;
    }
    let source = sources.join(" UNION ALL ");
    Some(format!(
        "WITH ids(id) AS ({ids}), components AS ({source})
         SELECT id,CAST(SUM(total) AS BIGINT) AS total,CAST(SUM(successes) AS BIGINT) AS successes,
             CAST(MIN(minimum) AS DOUBLE PRECISION) AS minimum,CAST(MAX(maximum) AS DOUBLE PRECISION) AS maximum,
             CAST(SUM(subtotal) AS DOUBLE PRECISION)/NULLIF(SUM(total),0) AS average,
             CAST(MAX(happened) AS TEXT) AS last_execution
         FROM components GROUP BY id"
    ))
}
