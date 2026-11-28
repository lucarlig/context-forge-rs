// SPDX-License-Identifier: Apache-2.0

use super::{Database, MetricEntity, MetricsDialect};
use crate::database::observed;
use sqlx::AssertSqlSafe;

pub(super) const MAINTENANCE_LOCK: &str = "SELECT pg_advisory_xact_lock(1128682317)";

#[derive(Clone, Copy)]
pub(crate) enum MetricTable {
    Catalog(MetricEntity),
    Agent,
}

impl MetricTable {
    pub(crate) const ALL: [Self; 5] = [
        Self::Catalog(MetricEntity::Tool),
        Self::Catalog(MetricEntity::Resource),
        Self::Catalog(MetricEntity::Prompt),
        Self::Catalog(MetricEntity::Server),
        Self::Agent,
    ];

    pub(crate) fn kind(self) -> &'static str {
        match self {
            Self::Catalog(MetricEntity::Tool) => "tool",
            Self::Catalog(MetricEntity::Resource) => "resource",
            Self::Catalog(MetricEntity::Prompt) => "prompt",
            Self::Catalog(MetricEntity::Server) => "server",
            Self::Agent => "a2a_agent",
        }
    }

    fn storage(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Catalog(entity) => entity.storage(),
            Self::Agent => (
                "a2a_agent_metrics",
                "a2a_agent_metrics_hourly",
                "a2a_agent_id",
            ),
        }
    }

    pub(crate) fn name(self, hourly: bool) -> &'static str {
        let (raw, summary, _) = self.storage();
        if hourly { summary } else { raw }
    }
}

#[derive(Default, sqlx::FromRow)]
pub(crate) struct RollupCounts {
    pub(crate) hours: i64,
    pub(crate) records: i64,
    pub(crate) rollups: i64,
    pub(crate) deleted: i64,
}

impl MetricsDialect {
    fn rollup_query(&self, table: MetricTable, native_percentiles: bool) -> String {
        let (raw, hourly, key) = table.storage();
        let (entity, name, partition, interaction) = match table {
            MetricTable::Catalog(entity) => {
                (entity.key(), format!("{}_name", table.kind()), "", "''")
            }
            MetricTable::Agent => (
                "a2a_agents",
                "agent_name".to_owned(),
                ",interaction_type",
                "m.interaction_type",
            ),
        };
        let (bucket, timestamp, start, end) = match self {
            Self::Sqlite => (
                "strftime('%Y-%m-%d %H:00:00.000000', m.timestamp)",
                "unixepoch(m.timestamp)",
                "$1",
                "$2",
            ),
            Self::Postgres => (
                "date_trunc('hour',m.timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",
                "m.timestamp",
                "to_timestamp($1::bigint)",
                "to_timestamp($2::bigint)",
            ),
        };
        let (ranks, source, percentiles) = if matches!(self, Self::Postgres) && native_percentiles {
            (
                "",
                "samples",
                "percentile_cont(0.50) WITHIN GROUP (ORDER BY response_time),
                     percentile_cont(0.95) WITHIN GROUP (ORDER BY response_time),
                     percentile_cont(0.99) WITHIN GROUP (ORDER BY response_time)"
                    .to_owned(),
            )
        } else {
            (
                    ", ranked AS (
                        SELECT *, ROW_NUMBER() OVER (metric_group ORDER BY response_time) - 1 AS rank,
                            COUNT(*) OVER metric_group - 1 AS span
                        FROM samples WINDOW metric_group AS (PARTITION BY entity_id, bucket, interaction_type)
                    )",
                    "ranked",
                    [50, 95, 99].map(interpolated_percentile).join(","),
                )
        };
        let output_hour = match self {
            // Match the logical hour if an adopted SQLite database uses another timestamp format.
            Self::Sqlite => format!(
                "COALESCE((SELECT h.hour_start FROM {hourly} h
                    WHERE h.{key}=s.entity_id AND unixepoch(h.hour_start)=unixepoch(s.bucket)
                    {match_interaction} ORDER BY h.id LIMIT 1), s.bucket)",
                match_interaction = if partition.is_empty() {
                    ""
                } else {
                    "AND h.interaction_type=s.interaction_type"
                }
            ),
            Self::Postgres => "s.bucket".to_owned(),
        };
        let upsert = format!(
            "INSERT INTO {hourly}
                ({key},{name},hour_start{partition},total_count,success_count,failure_count,
                 min_response_time,max_response_time,avg_response_time,
                 p50_response_time,p95_response_time,p99_response_time)
             SELECT s.entity_id, COALESCE(e.name,'unknown'), {output_hour}{partition},
                COUNT(*), SUM(succeeded), COUNT(*)-SUM(succeeded),
                MIN(response_time), MAX(response_time), AVG(response_time), {percentiles}
             FROM {source} s LEFT JOIN {entity} e ON e.id=s.entity_id
             GROUP BY s.entity_id, s.bucket, s.interaction_type, e.name
             ON CONFLICT ({key},hour_start{partition}) DO UPDATE SET
                {name}=excluded.{name}, total_count=excluded.total_count,
                success_count=excluded.success_count, failure_count=excluded.failure_count,
                min_response_time=excluded.min_response_time, max_response_time=excluded.max_response_time,
                avg_response_time=excluded.avg_response_time, p50_response_time=excluded.p50_response_time,
                p95_response_time=excluded.p95_response_time, p99_response_time=excluded.p99_response_time"
        );
        let samples = format!(
            "WITH samples AS (
                SELECT m.id, m.{key} AS entity_id, {bucket} AS bucket,
                    {interaction} AS interaction_type, m.response_time,
                    CASE WHEN m.is_success THEN 1 ELSE 0 END AS succeeded
                FROM {raw} m WHERE {timestamp} >= {start} AND {timestamp} < {end}
            ){ranks}"
        );
        match self {
            Self::Sqlite => format!(
                "{samples} {upsert}
                 RETURNING unixepoch(hour_start) AS hour, CAST(total_count AS BIGINT) AS records"
            ),
            // The two writes see the same snapshot. A concurrent metric insert stays in the raw table.
            Self::Postgres => format!(
                "{samples}, written AS (
                    {upsert} RETURNING hour_start, total_count
                 ), removed AS (
                    DELETE FROM {raw} m USING samples s WHERE m.id=s.id
                      AND s.bucket + INTERVAL '1 hour' < to_timestamp($3::bigint)
                      AND EXISTS (SELECT 1 FROM written)
                    RETURNING 1
                 )
                 SELECT COUNT(DISTINCT hour_start) AS hours,
                    COALESCE(SUM(total_count),0) AS records, COUNT(*) AS rollups,
                    (SELECT COUNT(*) FROM removed) AS deleted
                 FROM written"
            ),
        }
    }

    fn cleanup_query(&self, table: &'static str, column: &'static str) -> String {
        let comparison = match self {
            Self::Sqlite => format!("unixepoch({column}) < $1"),
            Self::Postgres => format!("{column} < to_timestamp($1::bigint)"),
        };
        format!(
            "DELETE FROM {table} WHERE id IN (
                SELECT id FROM {table} WHERE {comparison} ORDER BY {column},id LIMIT $2
            )"
        )
    }
}

fn interpolated_percentile(percent: i64) -> String {
    let lower = format!("MAX(CASE WHEN rank=span*{percent}/100 THEN response_time END)");
    let upper = format!("MAX(CASE WHEN rank=(span*{percent}+99)/100 THEN response_time END)");
    format!("{lower} + ((MAX(span)*{percent}) % 100)/100.0 * ({upper} - {lower})")
}

impl Database {
    pub(crate) async fn rollup_metrics(
        &self,
        table: MetricTable,
        start: i64,
        end: i64,
        delete_before: Option<i64>,
        native_percentiles: bool,
    ) -> Result<RollupCounts, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                let mut hours = std::collections::HashSet::new();
                let mut counts = RollupCounts::default();
                let query = MetricsDialect::Sqlite.rollup_query(table, false);
                let rows = sqlx::query_as::<_, (i64, i64)>(AssertSqlSafe(query))
                    .bind(start)
                    .bind(end)
                    .fetch_all(observed(&mut *tx))
                    .await?;
                for (hour, records) in rows {
                    hours.insert(hour);
                    counts.rollups += 1;
                    counts.records += records;
                }
                counts.hours = hours.len() as i64;
                if let Some(cutoff) = delete_before.filter(|_| counts.rollups > 0) {
                    let raw = table.name(false);
                    let query = format!(
                        "DELETE FROM {raw} WHERE unixepoch(timestamp) >= $1 AND unixepoch(timestamp) < $2
                         AND unixepoch(strftime('%Y-%m-%d %H:00:00',timestamp)) + 3600 < $3"
                    );
                    counts.deleted = sqlx::query(AssertSqlSafe(query))
                        .bind(start)
                        .bind(end)
                        .bind(cutoff)
                        .execute(observed(&mut *tx))
                        .await?
                        .rows_affected() as i64;
                }
                tx.commit().await?;
                Ok(counts)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(MAINTENANCE_LOCK)
                    .execute(observed(&mut *tx))
                    .await?;
                let query = MetricsDialect::Postgres.rollup_query(table, native_percentiles);
                let counts = sqlx::query_as(AssertSqlSafe(query))
                    .bind(start)
                    .bind(end)
                    .bind(delete_before)
                    .fetch_one(observed(&mut *tx))
                    .await?;
                tx.commit().await?;
                Ok(counts)
            }
        }
    }

    pub(crate) async fn clean_metrics_batch(
        &self,
        table: MetricTable,
        hourly: bool,
        cutoff: i64,
        limit: i64,
    ) -> Result<u64, sqlx::Error> {
        let column = if hourly { "hour_start" } else { "timestamp" };
        let table = table.name(hourly);
        let affected = match self {
            Self::Sqlite(pool) => sqlx::query(AssertSqlSafe(
                MetricsDialect::Sqlite.cleanup_query(table, column),
            ))
            .bind(cutoff)
            .bind(limit)
            .execute(observed(pool))
            .await?
            .rows_affected(),
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                sqlx::query(MAINTENANCE_LOCK)
                    .execute(observed(&mut *tx))
                    .await?;
                let result = sqlx::query(AssertSqlSafe(
                    MetricsDialect::Postgres.cleanup_query(table, column),
                ))
                .bind(cutoff)
                .bind(limit)
                .execute(observed(&mut *tx))
                .await?;
                tx.commit().await?;
                result.rows_affected()
            }
        };
        Ok(affected)
    }

    pub(crate) async fn metric_table_size(
        &self,
        table: MetricTable,
        hourly: bool,
    ) -> Result<i64, sqlx::Error> {
        let sql = format!("SELECT COUNT(*) FROM {}", table.name(hourly));
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(AssertSqlSafe(sql))
                    .fetch_one(observed(pool))
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(AssertSqlSafe(sql))
                    .fetch_one(observed(pool))
                    .await
            }
        }
    }
}
