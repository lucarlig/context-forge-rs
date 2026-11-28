// SPDX-License-Identifier: Apache-2.0

use jiff::Timestamp;
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::{auth::TeamVisibility, database::Database, http_boundary::CorrelationId};

pub(crate) struct AuditWrite<'a> {
    pub(crate) action: &'a str,
    pub(crate) resource_type: &'a str,
    pub(crate) id: &'a str,
    pub(crate) name: Option<&'a str>,
    pub(crate) user_id: &'a str,
    pub(crate) user_email: Option<&'a str>,
    pub(crate) team: Option<&'a str>,
    pub(crate) address: Option<&'a str>,
    pub(crate) user_agent: Option<&'a str>,
    pub(crate) before: Option<Value>,
    pub(crate) after: Option<Value>,
    pub(crate) context: Option<Value>,
}

impl AuditWrite<'_> {
    fn requires_review(&self) -> bool {
        matches!(
            self.action,
            "delete_server" | "delete_tool" | "delete_resource" | "delete_gateway"
        )
    }
}

#[derive(Default)]
pub(crate) struct AuditFilters {
    pub(crate) actions: Vec<String>,
    pub(crate) resource_types: Vec<String>,
    pub(crate) user: Option<String>,
    pub(crate) review: Option<bool>,
    pub(crate) since: Option<Timestamp>,
    pub(crate) until: Option<Timestamp>,
    pub(crate) limit: i64,
    pub(crate) offset: i64,
}

#[derive(sqlx::FromRow)]
pub(crate) struct StoredEvent {
    pub(crate) source: String,
    pub(crate) id: String,
    pub(crate) stamp: String,
    pub(crate) correlation_id: Option<String>,
    pub(crate) action: String,
    pub(crate) resource_type: String,
    pub(crate) resource_id: Option<String>,
    pub(crate) resource_name: Option<String>,
    pub(crate) user_id: String,
    pub(crate) user_email: Option<String>,
    pub(crate) success: bool,
    pub(crate) requires_review: bool,
    pub(crate) data_classification: Option<String>,
    pub(crate) severity: Option<String>,
    pub(crate) new_values: Option<String>,
    pub(crate) context: Option<String>,
    pub(crate) error_message: Option<String>,
}

impl StoredEvent {
    pub(crate) fn trail(&self, postgres: bool) -> Value {
        let timestamp = parse_time(&self.stamp).map(|time| {
            let time = time.to_string();
            if postgres {
                time
            } else {
                time.trim_end_matches('Z').to_owned()
            }
        });
        json!({
            "id":self.id, "timestamp":timestamp, "correlation_id":self.correlation_id,
            "action":self.action, "resource_type":self.resource_type, "resource_id":self.resource_id,
            "resource_name":self.resource_name, "user_id":self.user_id, "user_email":self.user_email,
            "success":self.success, "requires_review":self.requires_review,
            "data_classification":self.data_classification,
        })
    }
}

pub(crate) fn parse_time(value: &str) -> Option<Timestamp> {
    let value = value.replacen(' ', "T", 1);
    value.parse().or_else(|_| format!("{value}Z").parse()).ok()
}

#[derive(Clone, Copy)]
enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    fn time(self, time: Timestamp) -> String {
        match self {
            Self::Sqlite => time.strftime("%Y-%m-%d %H:%M:%S.%6f").to_string(),
            Self::Postgres => time.to_string(),
        }
    }

    fn time_argument(self, position: usize) -> String {
        match self {
            Self::Sqlite => format!("${position}"),
            Self::Postgres => format!("CAST(CAST(${position} AS TEXT) AS TIMESTAMPTZ)"),
        }
    }

    fn json_items(self, position: usize) -> String {
        match self {
            Self::Sqlite => format!("SELECT value FROM json_each(${position})"),
            Self::Postgres => {
                format!("SELECT json_array_elements_text(CAST(CAST(${position} AS TEXT) AS JSON))")
            }
        }
    }

    fn json_argument(self, position: usize) -> String {
        match self {
            Self::Sqlite => format!("${position}"),
            Self::Postgres => format!("CAST(CAST(${position} AS TEXT) AS JSON)"),
        }
    }

    fn write(self) -> String {
        let stamp = self.time_argument(2);
        let before = self.json_argument(13);
        let after = self.json_argument(14);
        let context = self.json_argument(15);
        format!(
            "INSERT INTO audit_trails (id,timestamp,correlation_id,action,resource_type,resource_id,
                resource_name,user_id,user_email,team_id,client_ip,user_agent,old_values,new_values,
                context,requires_review,success)
             VALUES ($1,{stamp},$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,{before},{after},{context},$16,TRUE)"
        )
    }

    fn trails(self) -> String {
        let actions = self.json_items(1);
        let types = self.json_items(2);
        let start = self.time_argument(5);
        let end = self.time_argument(6);
        format!(
            "SELECT {AUDIT_COLUMNS} FROM audit_trails
             WHERE ($1 = '[]' OR action IN ({actions}))
               AND ($2 = '[]' OR resource_type IN ({types}))
               AND (CAST($3 AS TEXT) IS NULL OR user_id = $3)
               AND (CAST($4 AS BOOLEAN) IS NULL OR requires_review = $4)
               AND ({start} IS NULL OR timestamp >= {start})
               AND ({end} IS NULL OR timestamp <= {end})
             ORDER BY timestamp DESC,id DESC LIMIT $7 OFFSET $8"
        )
    }

    fn activity(self) -> String {
        let teams = self.json_items(3);
        let start = self.time_argument(4);
        format!(
            "WITH items AS (
                SELECT {AUDIT_COLUMNS}, timestamp AS sort_time FROM audit_trails
                WHERE ({start} IS NULL OR timestamp > {start})
                  AND ($1 OR ((data_classification IS NULL OR data_classification != 'restricted')
                    AND ((team_id IS NULL AND user_email = $2) OR team_id IN ({teams}))))
                UNION ALL
                SELECT 'security', id, CAST(timestamp AS TEXT), correlation_id, event_type, category,
                    NULL, user_email, COALESCE(user_id,''), user_email, TRUE, FALSE, NULL, severity,
                    NULL, NULL, description, timestamp
                FROM security_events WHERE $5 AND ($1 OR user_email = $2)
                  AND ({start} IS NULL OR timestamp > {start})
             )
             SELECT * FROM items ORDER BY sort_time DESC,source DESC,id DESC LIMIT $6"
        )
    }
}

const AUDIT_COLUMNS: &str = "'audit' AS source,id,CAST(timestamp AS TEXT) AS stamp,correlation_id,
    action,resource_type,resource_id,resource_name,user_id,user_email,success,requires_review,
    data_classification,CAST(NULL AS TEXT) AS severity,CAST(new_values AS TEXT) AS new_values,
    CAST(context AS TEXT) AS context,error_message";

impl Database {
    pub(crate) async fn record_audit(&self, entry: AuditWrite<'_>) -> Result<(), sqlx::Error> {
        let now = Timestamp::now();
        let correlation = CorrelationId::current()
            .and_then(|id| {
                id.as_str()
                    .map(|text| text.chars().take(64).collect::<String>())
            })
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        macro_rules! insert {
            ($pool:ident, $dialect:expr) => {{
                sqlx::query(AssertSqlSafe($dialect.write()))
                    .bind(Uuid::new_v4().simple().to_string())
                    .bind($dialect.time(now))
                    .bind(correlation)
                    .bind(entry.action)
                    .bind(entry.resource_type)
                    .bind(entry.id)
                    .bind(entry.name)
                    .bind(entry.user_id)
                    .bind(entry.user_email)
                    .bind(entry.team)
                    .bind(entry.address)
                    .bind(entry.user_agent)
                    .bind(entry.before.as_ref().map(Value::to_string))
                    .bind(entry.after.as_ref().map(Value::to_string))
                    .bind(entry.context.as_ref().map(Value::to_string))
                    .bind(entry.requires_review())
                    .execute($pool)
                    .await?;
            }};
        }
        match self {
            Self::Sqlite(pool) => insert!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => insert!(pool, Dialect::Postgres),
        }
        Ok(())
    }

    pub(crate) async fn audit_trails(
        &self,
        filters: AuditFilters,
    ) -> Result<Vec<StoredEvent>, sqlx::Error> {
        macro_rules! list {
            ($pool:ident, $dialect:expr) => {{
                sqlx::query_as(AssertSqlSafe($dialect.trails()))
                    .bind(json!(filters.actions).to_string())
                    .bind(json!(filters.resource_types).to_string())
                    .bind(filters.user)
                    .bind(filters.review)
                    .bind(filters.since.map(|time| $dialect.time(time)))
                    .bind(filters.until.map(|time| $dialect.time(time)))
                    .bind(filters.limit)
                    .bind(filters.offset)
                    .fetch_all($pool)
                    .await
            }};
        }
        match self {
            Self::Sqlite(pool) => list!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => list!(pool, Dialect::Postgres),
        }
    }

    pub(crate) async fn audit_activity(
        &self,
        visibility: &TeamVisibility,
        actor: &str,
        security: bool,
        since: Option<Timestamp>,
        limit: i64,
    ) -> Result<Vec<StoredEvent>, sqlx::Error> {
        let teams = match visibility {
            TeamVisibility::Teams(teams) => json!(teams).to_string(),
            _ => "[]".into(),
        };
        macro_rules! list {
            ($pool:ident, $dialect:expr) => {{
                sqlx::query_as(AssertSqlSafe($dialect.activity()))
                    .bind(*visibility == TeamVisibility::Admin)
                    .bind(actor)
                    .bind(teams)
                    .bind(since.map(|time| $dialect.time(time)))
                    .bind(security)
                    .bind(limit)
                    .fetch_all($pool)
                    .await
            }};
        }
        match self {
            Self::Sqlite(pool) => list!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => list!(pool, Dialect::Postgres),
        }
    }
}
