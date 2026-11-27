// SPDX-License-Identifier: Apache-2.0

use serde_json::json;
use sqlx::types::Json;
use uuid::Uuid;

use super::Tier;
use crate::database::Database;

pub(super) struct RateLimitEvent<'a> {
    pub(super) ip: &'a str,
    pub(super) endpoint: &'a str,
    pub(super) method: &'a str,
    pub(super) team: Option<&'a str>,
    pub(super) tier: Tier,
    pub(super) limit: usize,
    pub(super) locked: bool,
}

impl RateLimitEvent<'_> {
    pub(super) async fn record(
        &self,
        database: &Database,
        dimension: &str,
    ) -> Result<(), sqlx::Error> {
        let (event_type, severity, score) = if self.locked {
            ("brute_force_attempt", "HIGH", 0.8_f64)
        } else {
            ("rate_limit_exceeded", "MEDIUM", 0.5)
        };
        let description = format!("Rate limit exceeded for {dimension} on {}", self.endpoint);
        let context = Json(json!({
            "dimension": dimension,
            "tier": self.tier.name(),
            "team_id": self.team,
            "limit": self.limit,
            "endpoint": self.endpoint,
            "method": self.method,
        }));
        const INSERT: &str = "INSERT INTO security_events
            (id, timestamp, detected_at, event_type, severity, category, client_ip,
             description, threat_score, threat_indicators, failed_attempts_count, resolved,
             alert_sent, context)
            VALUES ($1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, $2, $3, 'rate_limit', $4,
                    $5, $6, '{}', 0, FALSE, FALSE, $7)";
        macro_rules! insert {
            ($pool:ident) => {
                sqlx::query(INSERT)
                    .bind(Uuid::new_v4().simple().to_string())
                    .bind(event_type)
                    .bind(severity)
                    .bind(self.ip)
                    .bind(description)
                    .bind(score)
                    .bind(context)
                    .execute($pool)
                    .await?
            };
        }
        match database {
            Database::Sqlite(pool) => {
                insert!(pool);
            }
            Database::Postgres(pool) => {
                insert!(pool);
            }
        }
        Ok(())
    }
}
