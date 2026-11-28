// SPDX-License-Identifier: Apache-2.0

use jiff::{Timestamp, tz::Offset};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};
use sqlx::{AssertSqlSafe, QueryBuilder};

use super::store::Dialect;
use crate::{audit::parse_time, database::Database};

#[derive(Deserialize)]
#[serde(default)]
pub(crate) struct TraceQuery {
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub min_duration_ms: Option<f64>,
    pub max_duration_ms: Option<f64>,
    pub status: Option<String>,
    pub status_in: Vec<String>,
    pub status_not_in: Vec<String>,
    pub http_status_code: Option<i32>,
    pub http_status_code_in: Vec<i32>,
    pub http_method: Option<String>,
    pub http_method_in: Vec<String>,
    pub user_email: Option<String>,
    pub user_email_in: Vec<String>,
    pub attribute_search: Option<String>,
    pub name_contains: Option<String>,
    pub attribute_filters: Map<String, Value>,
    pub attribute_filters_or: Map<String, Value>,
    pub order_by: String,
    pub limit: i64,
    pub offset: i64,
}

impl Default for TraceQuery {
    fn default() -> Self {
        Self {
            start_time: None,
            end_time: None,
            min_duration_ms: None,
            max_duration_ms: None,
            status: None,
            status_in: Vec::new(),
            status_not_in: Vec::new(),
            http_status_code: None,
            http_status_code_in: Vec::new(),
            http_method: None,
            http_method_in: Vec::new(),
            user_email: None,
            user_email_in: Vec::new(),
            attribute_search: None,
            name_contains: None,
            attribute_filters: Map::new(),
            attribute_filters_or: Map::new(),
            order_by: "start_time_desc".into(),
            limit: 100,
            offset: 0,
        }
    }
}

impl TraceQuery {
    pub fn valid(&self) -> bool {
        (1..=1000).contains(&self.limit)
            && self.offset >= 0
            && self.order().is_some()
            && self
                .start_time
                .as_deref()
                .is_none_or(|time| parse_time(time).is_some())
            && self
                .end_time
                .as_deref()
                .is_none_or(|time| parse_time(time).is_some())
            && self
                .min_duration_ms
                .is_none_or(|duration| duration.is_finite() && duration >= 0.0)
            && self
                .max_duration_ms
                .is_none_or(|duration| duration.is_finite() && duration >= 0.0)
            && self.status_in.len()
                + self.status_not_in.len()
                + self.http_status_code_in.len()
                + self.http_method_in.len()
                + self.user_email_in.len()
                + 2 * (self.attribute_filters.len() + self.attribute_filters_or.len())
                <= 256
    }

    fn order(&self) -> Option<&'static str> {
        match self.order_by.as_str() {
            "start_time_desc" => {
                Some(" ORDER BY observability_traces.start_time DESC,trace_id DESC")
            }
            "start_time_asc" => Some(" ORDER BY observability_traces.start_time ASC,trace_id ASC"),
            "duration_desc" => Some(" ORDER BY duration_ms DESC,trace_id DESC"),
            "duration_asc" => Some(" ORDER BY duration_ms ASC,trace_id ASC"),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
pub(crate) struct SpanQuery {
    pub trace_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_name: Option<String>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub limit: i64,
    pub offset: i64,
}

impl Default for SpanQuery {
    fn default() -> Self {
        Self {
            trace_id: None,
            resource_type: None,
            resource_name: None,
            start_time: None,
            end_time: None,
            limit: 100,
            offset: 0,
        }
    }
}

impl SpanQuery {
    pub fn valid(&self) -> bool {
        (1..=1000).contains(&self.limit)
            && self.offset >= 0
            && self
                .start_time
                .as_deref()
                .is_none_or(|time| parse_time(time).is_some())
            && self
                .end_time
                .as_deref()
                .is_none_or(|time| parse_time(time).is_some())
    }
}

const TRACE_COLUMNS: &str = "SELECT trace_id,name,CAST(start_time AS TEXT) AS start_time,
    CAST(end_time AS TEXT) AS end_time,duration_ms,status,status_message,http_method,http_url,
    http_status_code,user_email,user_agent,ip_address,CAST(attributes AS TEXT) AS attributes,
    CAST(resource_attributes AS TEXT) AS resource_attributes,CAST(created_at AS TEXT) AS created_at
    FROM observability_traces WHERE TRUE";
const SPAN_COLUMNS: &str = "SELECT span_id,trace_id,parent_span_id,name,kind,CAST(start_time AS TEXT) AS start_time,
    CAST(end_time AS TEXT) AS end_time,duration_ms,status,status_message,CAST(attributes AS TEXT) AS attributes,
    resource_name,resource_type,resource_id,CAST(created_at AS TEXT) AS created_at FROM observability_spans WHERE TRUE";

#[derive(sqlx::FromRow, Serialize)]
pub(crate) struct TraceRow {
    pub trace_id: String,
    pub name: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub duration_ms: Option<f64>,
    pub status: String,
    status_message: Option<String>,
    pub http_method: Option<String>,
    pub http_url: Option<String>,
    pub http_status_code: Option<i32>,
    pub user_email: Option<String>,
    user_agent: Option<String>,
    ip_address: Option<String>,
    #[serde(serialize_with = "json_string")]
    attributes: Option<String>,
    #[serde(serialize_with = "json_string")]
    resource_attributes: Option<String>,
    created_at: String,
}

#[derive(sqlx::FromRow, Serialize)]
pub(crate) struct SpanRow {
    span_id: String,
    trace_id: String,
    parent_span_id: Option<String>,
    name: String,
    kind: String,
    start_time: String,
    end_time: Option<String>,
    duration_ms: Option<f64>,
    status: String,
    status_message: Option<String>,
    #[serde(serialize_with = "json_string")]
    attributes: Option<String>,
    resource_name: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    created_at: String,
}

fn json_string<S: Serializer>(value: &Option<String>, serializer: S) -> Result<S::Ok, S::Error> {
    value
        .as_deref()
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .serialize(serializer)
}

pub(crate) fn date_wire(value: &str, postgres: bool, export: bool) -> String {
    let Some(time) = parse_time(value) else {
        return value.to_owned();
    };
    let offset = if postgres {
        value
            .get(10..)
            .and_then(|stamp| stamp.rfind(['+', '-']))
            .and_then(|position| parse_time(&value[..position + 10]))
            .and_then(|local| i32::try_from(local.as_second() - time.as_second()).ok())
            .and_then(|seconds| Offset::from_seconds(seconds).ok())
            .unwrap_or(Offset::UTC)
    } else {
        Offset::UTC
    };
    let display = offset.to_datetime(time);
    let pattern = if time.subsec_nanosecond() / 1000 != 0 {
        "%Y-%m-%dT%H:%M:%S.%6f"
    } else {
        "%Y-%m-%dT%H:%M:%S"
    };
    let mut output = display.strftime(pattern).to_string();
    if postgres {
        if !export && offset == Offset::UTC {
            output.push('Z');
        } else {
            let seconds = offset.seconds();
            let sign = if seconds < 0 { '-' } else { '+' };
            let magnitude = seconds.unsigned_abs();
            let hours = magnitude / 3600;
            let minutes = magnitude / 60 % 60;
            output.push_str(&format!("{sign}{hours:02}:{minutes:02}"));
            if !magnitude.is_multiple_of(60) {
                output.push_str(&format!(":{:02}", magnitude % 60));
            }
        }
    }
    output
}

pub(crate) fn wire(row: &impl Serialize, postgres: bool) -> Value {
    let mut json = serde_json::to_value(row).expect("observable row is serializable");
    for column in ["start_time", "end_time", "created_at"] {
        if let Some(stamp) = json[column].as_str() {
            json[column] = Value::String(date_wire(stamp, postgres, false));
        }
    }
    json
}

macro_rules! filter {
    ($query:ident, $clause:literal, $value:expr) => {
        if let Some(value) = $value {
            $query.push($clause).push_bind(value);
        }
    };
}

macro_rules! filter_items {
    ($query:ident, $clause:literal, $values:expr) => {
        if !$values.is_empty() {
            $query.push($clause);
            let mut values = $query.separated(",");
            for value in $values {
                values.push_bind(value);
            }
            values.push_unseparated(")");
        }
    };
}

macro_rules! timestamp_filter {
    ($query:ident, $dialect:expr, $clause:literal, $value:expr) => {
        if let Some(value) = $value {
            $query.push($clause);
            let value = $dialect.time(value);
            if matches!($dialect, Dialect::Postgres) {
                $query
                    .push("CAST(CAST(")
                    .push_bind(value)
                    .push(" AS TEXT) AS TIMESTAMPTZ)");
            } else {
                $query.push_bind(value);
            }
        }
    };
}

macro_rules! attribute_filter {
    ($query:ident, $dialect:expr, $key:expr, $value:expr) => {{
        let value = $value
            .as_str()
            .map_or_else(|| $value.to_string(), str::to_owned);
        if matches!($dialect, Dialect::Postgres) {
            $query
                .push("(attributes ->> ")
                .push_bind($key.as_str())
                .push(") = ")
                .push_bind(value);
        } else {
            $query
                .push(
                    "EXISTS (SELECT 1 FROM json_each(observability_traces.attributes) WHERE key = ",
                )
                .push_bind($key.as_str())
                .push(" AND CAST(value AS TEXT) = ")
                .push_bind(value)
                .push(")");
        }
    }};
}

#[derive(sqlx::FromRow)]
pub(crate) struct Observation {
    pub name: String,
    pub stamp: String,
    pub status: String,
    pub duration_ms: Option<f64>,
}

impl Database {
    pub(crate) async fn traces(&self, filters: &TraceQuery) -> Result<Vec<TraceRow>, sqlx::Error> {
        macro_rules! query {
            ($pool:ident, $dialect:expr) => {{
                let mut query = QueryBuilder::new(TRACE_COLUMNS);
                timestamp_filter!(
                    query,
                    $dialect,
                    " AND start_time >= ",
                    filters.start_time.as_deref().and_then(parse_time)
                );
                timestamp_filter!(
                    query,
                    $dialect,
                    " AND start_time <= ",
                    filters.end_time.as_deref().and_then(parse_time)
                );
                filter!(query, " AND duration_ms >= ", filters.min_duration_ms);
                filter!(query, " AND duration_ms <= ", filters.max_duration_ms);
                filter!(query, " AND status = ", nonempty(filters.status.as_deref()));
                filter!(
                    query,
                    " AND http_status_code = ",
                    filters.http_status_code.filter(|code| *code != 0)
                );
                filter!(
                    query,
                    " AND http_method = ",
                    nonempty(filters.http_method.as_deref())
                );
                filter!(
                    query,
                    " AND user_email = ",
                    nonempty(filters.user_email.as_deref())
                );
                filter_items!(query, " AND status IN (", &filters.status_in);
                filter_items!(query, " AND status NOT IN (", &filters.status_not_in);
                filter_items!(
                    query,
                    " AND http_status_code IN (",
                    &filters.http_status_code_in
                );
                filter_items!(query, " AND http_method IN (", &filters.http_method_in);
                filter_items!(query, " AND user_email IN (", &filters.user_email_in);
                if let Some(name) = nonempty(filters.name_contains.as_deref()) {
                    query
                        .push(" AND LOWER(name) LIKE LOWER(")
                        .push_bind(format!("%{name}%"))
                        .push(")");
                }
                if let Some(text) = nonempty(filters.attribute_search.as_deref()) {
                    // Use a literal text search over serialized attributes on both dialects.
                    let text = text
                        .replace('!', "!!")
                        .replace('%', "!%")
                        .replace('_', "!_");
                    query
                        .push(" AND LOWER(CAST(attributes AS TEXT)) LIKE LOWER(")
                        .push_bind(format!("%{text}%"))
                        .push(") ESCAPE '!'");
                }
                for (key, value) in &filters.attribute_filters {
                    query.push(" AND ");
                    attribute_filter!(query, $dialect, key, value);
                }
                if !filters.attribute_filters_or.is_empty() {
                    query.push(" AND (");
                    for (index, (key, value)) in filters.attribute_filters_or.iter().enumerate() {
                        if index > 0 {
                            query.push(" OR ");
                        }
                        attribute_filter!(query, $dialect, key, value);
                    }
                    query.push(")");
                }
                query
                    .push(
                        filters.order().unwrap_or(
                            " ORDER BY observability_traces.start_time DESC,trace_id DESC",
                        ),
                    )
                    .push(" LIMIT ")
                    .push_bind(filters.limit)
                    .push(" OFFSET ")
                    .push_bind(filters.offset);
                query
                    .build_query_as()
                    .persistent(false)
                    .fetch_all($pool)
                    .await
            }};
        }
        match self {
            Self::Sqlite(pool) => query!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => query!(pool, Dialect::Postgres),
        }
    }

    pub(crate) async fn trace(&self, id: &str) -> Result<Option<TraceRow>, sqlx::Error> {
        let sql = format!("{TRACE_COLUMNS} AND trace_id=$1");
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(AssertSqlSafe(sql))
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(AssertSqlSafe(sql))
                    .bind(id)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    pub(crate) async fn spans(
        &self,
        filters: &SpanQuery,
        detail: bool,
    ) -> Result<Vec<SpanRow>, sqlx::Error> {
        macro_rules! query {
            ($pool:ident, $dialect:expr) => {{
                let mut query = QueryBuilder::new(SPAN_COLUMNS);
                filter!(
                    query,
                    " AND trace_id = ",
                    nonempty(filters.trace_id.as_deref())
                );
                filter!(
                    query,
                    " AND resource_type = ",
                    nonempty(filters.resource_type.as_deref())
                );
                filter!(
                    query,
                    " AND resource_name = ",
                    nonempty(filters.resource_name.as_deref())
                );
                timestamp_filter!(
                    query,
                    $dialect,
                    " AND start_time >= ",
                    filters.start_time.as_deref().and_then(parse_time)
                );
                timestamp_filter!(
                    query,
                    $dialect,
                    " AND start_time <= ",
                    filters.end_time.as_deref().and_then(parse_time)
                );
                if detail {
                    query.push(" ORDER BY observability_spans.start_time ASC,span_id ASC");
                } else {
                    query
                        .push(" ORDER BY observability_spans.start_time DESC,span_id DESC LIMIT ")
                        .push_bind(filters.limit)
                        .push(" OFFSET ")
                        .push_bind(filters.offset);
                }
                query
                    .build_query_as()
                    .persistent(false)
                    .fetch_all($pool)
                    .await
            }};
        }
        match self {
            Self::Sqlite(pool) => query!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => query!(pool, Dialect::Postgres),
        }
    }

    pub(crate) async fn delete_traces(&self, cutoff: Timestamp) -> Result<u64, sqlx::Error> {
        macro_rules! query {
            ($pool:ident, $dialect:expr) => {{
                let mut query = QueryBuilder::new("DELETE FROM observability_traces WHERE TRUE");
                timestamp_filter!(query, $dialect, " AND start_time < ", Some(cutoff));
                query
                    .build()
                    .execute($pool)
                    .await
                    .map(|result| result.rows_affected())
            }};
        }
        match self {
            Self::Sqlite(pool) => query!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => query!(pool, Dialect::Postgres),
        }
    }

    pub(crate) async fn trace_window(
        &self,
        cutoff: Timestamp,
    ) -> Result<Vec<Observation>, sqlx::Error> {
        macro_rules! query {
            ($pool:ident, $dialect:expr) => {{
                let mut query = QueryBuilder::new(
                    "SELECT name,CAST(start_time AS TEXT) AS stamp,status,duration_ms FROM observability_traces WHERE TRUE"
                );
                timestamp_filter!(query, $dialect, " AND start_time >= ", Some(cutoff));
                query.build_query_as().fetch_all($pool).await
            }};
        }
        match self {
            Self::Sqlite(pool) => query!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => query!(pool, Dialect::Postgres),
        }
    }
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::date_wire;

    #[test]
    fn trace_dates_preserve_postgres_offsets_and_export_format() {
        assert_eq!(
            date_wire("2024-04-02 03:00:00.123456+01", true, false),
            "2024-04-02T03:00:00.123456+01:00"
        );
        assert_eq!(
            date_wire("2024-04-02 03:00:00-03:30", true, true),
            "2024-04-02T03:00:00-03:30"
        );
        assert_eq!(
            date_wire("2024-04-02 03:00:00+00", true, true),
            "2024-04-02T03:00:00+00:00"
        );
        assert_eq!(
            date_wire("2024-04-02 03:00:00.000123", false, false),
            "2024-04-02T03:00:00.000123"
        );
    }
}
