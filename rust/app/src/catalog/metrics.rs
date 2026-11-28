// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, time::Duration};

use jiff::Timestamp;
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
    pub(crate) const ALL: [Self; 4] = [Self::Tool, Self::Resource, Self::Prompt, Self::Server];

    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Server => "servers",
            Self::Tool => "tools",
            Self::Resource => "resources",
            Self::Prompt => "prompts",
        }
    }

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
    id: Option<String>,
    name: Option<String>,
    total: i64,
    successes: i64,
    minimum: Option<f64>,
    maximum: Option<f64>,
    subtotal: Option<f64>,
    timed: i64,
    last_execution: Option<String>,
}

impl ExecutionMetrics {
    fn recent(&self) -> Option<Timestamp> {
        let value = self.last_execution.as_deref()?.replacen(' ', "T", 1);
        value.parse().or_else(|_| format!("{value}Z").parse()).ok()
    }

    fn average(&self) -> Option<f64> {
        self.subtotal
            .filter(|_| self.timed > 0)
            .map(|time| time / self.timed as f64)
    }

    pub(crate) fn json(&self) -> Value {
        let failed = self.total.saturating_sub(self.successes);
        json!({
            "totalExecutions":self.total,
            "successfulExecutions":self.successes,
            "failedExecutions":failed,
            "failureRate":if self.total==0 {0.0} else {failed as f64 / self.total as f64},
            "minResponseTime":self.minimum,
            "maxResponseTime":self.maximum,
            "avgResponseTime":self.average(),
            "lastExecutionTime":self.recent().map(|time| time.to_string()),
        })
    }

    fn performer(&self) -> Option<Value> {
        let name = self.name.as_deref()?;
        Some(json!({
            "id":self.id.as_ref()?, "name":name,
            "executionCount":self.total, "avgResponseTime":self.average(),
            "successRate":if self.total==0 {0.0} else {self.successes as f64 * 100.0 / self.total as f64},
            "lastExecution":self.recent().map(|time| time.to_string())
        }))
    }
}

pub(crate) struct MetricReport {
    pub(crate) totals: Value,
    pub(crate) performers: Vec<Value>,
}

fn combine_optional(
    left: Option<f64>,
    right: Option<f64>,
    combine: fn(f64, f64) -> f64,
) -> Option<f64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(combine(left, right)),
        _ => left.or(right),
    }
}

fn summarize(rows: Vec<ExecutionMetrics>) -> MetricReport {
    let mut all = ExecutionMetrics::default();
    let mut recent = None;
    for row in &rows {
        all.total += row.total;
        all.successes += row.successes;
        all.minimum = combine_optional(all.minimum, row.minimum, f64::min);
        all.maximum = combine_optional(all.maximum, row.maximum, f64::max);
        if let Some(subtotal) = row.subtotal {
            *all.subtotal.get_or_insert(0.0) += subtotal;
        }
        all.timed += row.timed;
        recent = recent.max(row.recent());
    }
    all.last_execution = recent.map(|time| time.to_string());
    MetricReport {
        totals: all.json(),
        performers: rows
            .iter()
            .filter_map(ExecutionMetrics::performer)
            .collect(),
    }
}

enum MetricsDialect {
    Sqlite,
    Postgres,
}

impl MetricsDialect {
    fn query(&self, entity: MetricEntity, scoped: bool) -> String {
        let (raw, hourly, key) = entity.storage();
        let table = entity.key();
        let name = match entity {
            MetricEntity::Resource => "e.uri",
            _ => "e.name",
        };
        let (raw_window, hours, same_hour, selected) = match self {
            Self::Sqlite => (
                "julianday(m.timestamp) >= julianday($1)",
                "julianday(h.hour_start) < julianday($1)",
                "datetime(h.hour_start) = strftime('%Y-%m-%d %H:00:00',m.timestamp)",
                "SELECT value FROM json_each($2)",
            ),
            Self::Postgres => (
                "m.timestamp >= CAST(CAST($1 AS TEXT) AS TIMESTAMPTZ)",
                "h.hour_start < CAST(CAST($1 AS TEXT) AS TIMESTAMPTZ)",
                "h.hour_start = date_trunc('hour',m.timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",
                "SELECT json_array_elements_text(CAST($2 AS JSON))",
            ),
        };
        let ids = if scoped {
            format!("ids(id) AS ({selected}),")
        } else {
            String::new()
        };
        let raw_scope = if scoped {
            format!("AND m.{key} IN (SELECT id FROM ids)")
        } else {
            String::new()
        };
        let hourly_scope = if scoped {
            format!("AND h.{key} IN (SELECT id FROM ids)")
        } else {
            String::new()
        };
        format!(
            "WITH {ids} components AS (
               SELECT m.{key} AS id, 1 AS total, CASE WHEN m.is_success THEN 1 ELSE 0 END AS successes,
                 m.response_time AS minimum, m.response_time AS maximum, m.response_time AS subtotal,
                 m.timestamp AS happened
               FROM {raw} m WHERE ({raw_window} OR NOT EXISTS (
                   SELECT 1 FROM {hourly} h WHERE h.{key}=m.{key} AND {hours} AND {same_hour}
               )) {raw_scope}
               UNION ALL
               SELECT h.{key}, h.total_count, h.success_count, h.min_response_time, h.max_response_time,
                 h.avg_response_time * h.total_count, h.hour_start
               FROM {hourly} h WHERE {hours} {hourly_scope}
             ), grouped AS (
               SELECT id, CAST(SUM(total) AS BIGINT) AS total,
                   CAST(SUM(successes) AS BIGINT) AS successes,
                   CAST(MIN(minimum) AS DOUBLE PRECISION) AS minimum,
                   CAST(MAX(maximum) AS DOUBLE PRECISION) AS maximum,
                   CAST(SUM(subtotal) AS DOUBLE PRECISION) AS subtotal,
                   CAST(SUM(CASE WHEN subtotal IS NULL THEN 0 ELSE total END) AS BIGINT) AS timed,
                   CAST(MAX(happened) AS TEXT) AS last_execution
               FROM components GROUP BY id
             )
             SELECT g.*, {name} AS name FROM grouped g LEFT JOIN {table} e ON g.id=e.id
             ORDER BY g.total DESC, g.id"
        )
    }
}

fn cutoff(window: Duration) -> Result<String, sqlx::Error> {
    let elapsed = Timestamp::now().as_second() - window.as_secs() as i64;
    Timestamp::from_second(elapsed.div_euclid(3600) * 3600)
        .map(|time| time.to_string())
        .map_err(|error| sqlx::Error::Encode(Box::new(error)))
}

impl Database {
    pub(crate) async fn execution_metrics(
        &self,
        entity: MetricEntity,
        ids: &[&str],
        window: Duration,
    ) -> Result<HashMap<String, ExecutionMetrics>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let cutoff = cutoff(window)?;
        let ids = json!(ids).to_string();
        macro_rules! read {
            ($pool:ident, $dialect:expr) => {{
                // Identifiers and SQL fragments come from the enums. Request values are bound.
                let query = sqlx::AssertSqlSafe($dialect.query(entity, true));
                sqlx::query_as::<_, ExecutionMetrics>(query)
                    .bind(&cutoff)
                    .bind(&ids)
                    .fetch_all($pool)
                    .await?
            }};
        }
        let rows = match self {
            Self::Sqlite(pool) => read!(pool, MetricsDialect::Sqlite),
            Self::Postgres(pool) => read!(pool, MetricsDialect::Postgres),
        };
        Ok(rows
            .into_iter()
            .filter_map(|row| Some((row.id.clone()?, row)))
            .collect())
    }

    pub(crate) async fn execution_reports(
        &self,
        entities: &[MetricEntity],
        window: Duration,
    ) -> Result<Vec<MetricReport>, sqlx::Error> {
        let time = cutoff(window)?;
        macro_rules! report {
            ($tx:ident, $dialect:expr) => {{
                let mut reports = Vec::with_capacity(entities.len());
                for entity in entities {
                    let query = sqlx::AssertSqlSafe($dialect.query(*entity, false));
                    let rows = sqlx::query_as(query)
                        .bind(&time)
                        .fetch_all(&mut *$tx)
                        .await?;
                    reports.push(summarize(rows));
                }
                $tx.commit().await?;
                Ok(reports)
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                report!(tx, MetricsDialect::Sqlite)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .execute(&mut *tx)
                    .await?;
                report!(tx, MetricsDialect::Postgres)
            }
        }
    }

    pub(crate) async fn reset_execution_metrics(&self) -> Result<(), sqlx::Error> {
        macro_rules! reset {
            ($tx:ident) => {{
                for entity in MetricEntity::ALL {
                    let (raw, hourly, _) = entity.storage();
                    for table in [raw, hourly] {
                        sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
                            .execute(&mut *$tx)
                            .await?;
                    }
                }
                $tx.commit().await
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                reset!(tx)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                reset!(tx)
            }
        }
    }

    pub(crate) async fn record_execution_metrics(
        &self,
        items: [Option<(MetricEntity, &str)>; 2],
        duration: Duration,
        succeeded: bool,
    ) -> Result<(), sqlx::Error> {
        macro_rules! record {
            ($tx:ident) => {{
                for (entity, id) in items.into_iter().flatten() {
                    let (raw, _, key) = entity.storage();
                    let table = entity.key();
                    // An entity deleted during execution has no row to attach a metric to.
                    let sql = format!(
                        "INSERT INTO {raw} ({key},response_time,is_success)
                        SELECT id,$2,$3 FROM {table} WHERE id=$1"
                    );
                    sqlx::query(sqlx::AssertSqlSafe(sql))
                        .bind(id)
                        .bind(duration.as_secs_f64())
                        .bind(succeeded)
                        .execute(&mut *$tx)
                        .await?;
                }
                $tx.commit().await
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin().await?;
                record!(tx)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                record!(tx)
            }
        }
    }
}
