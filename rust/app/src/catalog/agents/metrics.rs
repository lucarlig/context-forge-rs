// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::*;

pub(crate) struct AgentInteraction<'a> {
    pub(crate) response_time: Duration,
    pub(crate) kind: &'a str,
    pub(crate) failure: Option<&'static str>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct AgentAggregate {
    total_agents: i64,
    active_agents: i64,
    total_interactions: i64,
    successful_interactions: i64,
    failed_interactions: i64,
    minimum: f64,
    maximum: f64,
    average: f64,
}

impl AgentAggregate {
    pub(crate) fn wire(self) -> Value {
        let rate = if self.total_interactions > 0 {
            self.successful_interactions as f64 / self.total_interactions as f64 * 100.0
        } else {
            0.0
        };
        json!({
            "totalAgents":self.total_agents, "activeAgents":self.active_agents,
            "totalInteractions":self.total_interactions,
            "successfulInteractions":self.successful_interactions,
            "failedInteractions":self.failed_interactions,
            "successRate": rate, "avgResponseTime":self.average,
            "minResponseTime":self.minimum, "maxResponseTime":self.maximum,
        })
    }
}

// Use old raw observations until a rollup for the same agent, interaction and hour exists.
macro_rules! aggregate_sql {
    ($teams:literal, $raw_cutoff:literal, $hourly_cutoff:literal, $same_hour:literal) => {
        concat!(
            "WITH visible_teams(id) AS (", $teams, "), visible_agents AS (
                SELECT id, enabled FROM a2a_agents WHERE visibility='public'
                    OR (visibility='team' AND ($2 OR team_id IN (SELECT id FROM visible_teams)))
                    OR (visibility='private' AND $3 AND owner_email=$4)
            ), components AS (
                SELECT 1 AS total, CASE WHEN m.is_success THEN 1 ELSE 0 END AS successes,
                    CASE WHEN m.is_success THEN 0 ELSE 1 END AS failures,
                    m.response_time AS minimum, m.response_time AS maximum, m.response_time AS subtotal
                FROM a2a_agent_metrics m JOIN visible_agents v ON m.a2a_agent_id=v.id
                WHERE ", $raw_cutoff, " OR NOT EXISTS (
                    SELECT 1 FROM a2a_agent_metrics_hourly h
                    WHERE h.a2a_agent_id=m.a2a_agent_id AND h.interaction_type=m.interaction_type
                        AND ", $hourly_cutoff, " AND ", $same_hour, "
                )
                UNION ALL
                SELECT h.total_count, h.success_count, h.failure_count, h.min_response_time,
                    h.max_response_time, h.avg_response_time * h.total_count
                FROM a2a_agent_metrics_hourly h JOIN visible_agents v ON h.a2a_agent_id=v.id
                WHERE ", $hourly_cutoff, "
            )
            SELECT (SELECT COUNT(*) FROM visible_agents) AS total_agents,
                (SELECT COUNT(*) FROM visible_agents WHERE enabled) AS active_agents,
                CAST(COALESCE(SUM(total),0) AS BIGINT) AS total_interactions,
                CAST(COALESCE(SUM(successes),0) AS BIGINT) AS successful_interactions,
                CAST(COALESCE(SUM(failures),0) AS BIGINT) AS failed_interactions,
                CAST(COALESCE(MIN(minimum),0) AS DOUBLE PRECISION) AS minimum,
                CAST(COALESCE(MAX(maximum),0) AS DOUBLE PRECISION) AS maximum,
                COALESCE(CAST(SUM(subtotal) AS DOUBLE PRECISION)
                    / NULLIF(SUM(CASE WHEN subtotal IS NULL THEN 0 ELSE total END),0),0.0) AS average
            FROM components"
        )
    };
}

impl Database {
    pub(crate) async fn scoped_agent_metrics(
        &self,
        scope: CatalogScope<'_>,
        raw_window: Duration,
    ) -> Result<AgentAggregate, sqlx::Error> {
        let teams = visible_team_ids(scope)?;
        let cutoff = jiff::Timestamp::now().as_second() - raw_window.as_secs() as i64;
        let cutoff = jiff::Timestamp::from_second(cutoff.div_euclid(3600) * 3600)
            .map_err(|error| sqlx::Error::Encode(Box::new(error)))?;
        macro_rules! aggregate {
            ($pool:ident, $sql:expr) => {
                sqlx::query_as($sql)
                    .bind(&teams)
                    .bind(scope.visibility == &TeamVisibility::Admin)
                    .bind(scope.can_own())
                    .bind(scope.email)
                    .bind(cutoff.to_string())
                    .fetch_one($pool)
                    .await
            };
        }
        match self {
            Self::Sqlite(pool) => aggregate!(
                pool,
                aggregate_sql!(
                    "SELECT value FROM json_each($1)",
                    "julianday(m.timestamp) >= julianday($5)",
                    "julianday(h.hour_start) < julianday($5)",
                    "datetime(h.hour_start) = strftime('%Y-%m-%d %H:00:00',m.timestamp)"
                )
            ),
            Self::Postgres(pool) => aggregate!(
                pool,
                aggregate_sql!(
                    "SELECT json_array_elements_text(CAST($1 AS JSON))",
                    "m.timestamp >= CAST(CAST($5 AS TEXT) AS TIMESTAMPTZ)",
                    "h.hour_start < CAST(CAST($5 AS TEXT) AS TIMESTAMPTZ)",
                    "h.hour_start = date_trunc('hour',m.timestamp AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'"
                )
            ),
        }
    }

    pub(crate) async fn record_agent_interaction(
        &self,
        id: &str,
        metric: Option<AgentInteraction<'_>>,
    ) -> Result<(), sqlx::Error> {
        const UPDATE: &str =
            "UPDATE a2a_agents SET last_interaction = CURRENT_TIMESTAMP WHERE id=$1 AND enabled";
        const INSERT: &str = "INSERT INTO a2a_agent_metrics
            (a2a_agent_id,timestamp,response_time,is_success,error_message,interaction_type)
            SELECT id,CURRENT_TIMESTAMP,$2,$3,$4,$5 FROM a2a_agents WHERE id=$1";
        macro_rules! record {
            ($tx:ident) => {{
                sqlx::query(UPDATE).bind(id).execute(&mut *$tx).await?;
                if let Some(metric) = metric {
                    let kind: String = metric.kind.chars().take(50).collect();
                    sqlx::query(INSERT)
                        .bind(id)
                        .bind(metric.response_time.as_secs_f64())
                        .bind(metric.failure.is_none())
                        .bind(metric.failure)
                        .bind(kind)
                        .execute(&mut *$tx)
                        .await?;
                }
                $tx.commit().await
            }};
        }
        match self {
            Self::Sqlite(pool) => {
                let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
                record!(tx)
            }
            Self::Postgres(pool) => {
                let mut tx = pool.begin().await?;
                record!(tx)
            }
        }
    }
}
