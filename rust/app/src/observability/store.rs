// SPDX-License-Identifier: Apache-2.0

use jiff::Timestamp;
use serde_json::json;
use sqlx::AssertSqlSafe;

use super::RequestTrace;
use crate::database::Database;

#[derive(Clone, Copy)]
pub(super) enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    pub(super) fn time(self, time: Timestamp) -> String {
        match self {
            Self::Sqlite => time.strftime("%Y-%m-%d %H:%M:%S.%6f").to_string(),
            Self::Postgres => time.to_string(),
        }
    }

    fn cast(self, index: u8, ty: &str) -> String {
        match self {
            Self::Sqlite => format!("${index}"),
            Self::Postgres => format!("CAST(CAST(${index} AS TEXT) AS {ty})"),
        }
    }

    fn start_trace(self) -> String {
        let time = self.cast(3, "TIMESTAMPTZ");
        let attributes = self.cast(8, "JSON");
        let resource = self.cast(9, "JSON");
        format!("INSERT INTO observability_traces
            (trace_id,name,start_time,http_method,http_url,user_agent,ip_address,attributes,resource_attributes,created_at,status)
            VALUES ($1,$2,{time},$4,$5,$6,$7,{attributes},{resource},{time},'unset')
            ON CONFLICT (trace_id) DO NOTHING")
    }

    fn start_span(self) -> String {
        let time = self.cast(3, "TIMESTAMPTZ");
        let attributes = self.cast(4, "JSON");
        format!(
            "INSERT INTO observability_spans
            (span_id,trace_id,name,kind,start_time,created_at,attributes,status)
            VALUES ($1,$2,'http.request','server',{time},{time},{attributes},'unset')"
        )
    }

    fn finish(self, span: bool) -> String {
        let time = self.cast(2, "TIMESTAMPTZ");
        let attrs = self.cast(5, "JSON");
        if span {
            format!("UPDATE observability_spans SET end_time={time},duration_ms=$3,status=$4,attributes={attrs}
                WHERE span_id=$1")
        } else {
            format!("UPDATE observability_traces SET end_time={time},duration_ms=$3,status=$4,attributes={attrs},
                http_status_code=$6 WHERE trace_id=$1")
        }
    }
}

impl Database {
    pub(super) async fn start_http_trace(&self, trace: &RequestTrace) -> Result<bool, sqlx::Error> {
        let resource =
            json!({"service.name":"mcp-gateway","service.version":env!("CARGO_PKG_VERSION")})
                .to_string();
        macro_rules! start {
            ($pool:ident, $dialect:expr) => {{
                let mut tx = $pool.begin().await?;
                let stamp = $dialect.time(trace.started_at);
                let inserted = sqlx::query(AssertSqlSafe($dialect.start_trace()))
                    .bind(&trace.id)
                    .bind(&trace.name)
                    .bind(&stamp)
                    .bind(&trace.method)
                    .bind(&trace.url)
                    .bind(&trace.agent)
                    .bind(&trace.ip)
                    .bind(trace.attributes.to_string())
                    .bind(&resource)
                    .execute(&mut *tx)
                    .await?
                    .rows_affected();
                sqlx::query(AssertSqlSafe($dialect.start_span()))
                    .bind(&trace.span)
                    .bind(&trace.id)
                    .bind(&stamp)
                    .bind(trace.span_attrs.to_string())
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
                Ok(inserted > 0)
            }};
        }
        match self {
            Self::Sqlite(pool) => start!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => start!(pool, Dialect::Postgres),
        }
    }

    pub(super) async fn finish_http_trace(
        &self,
        trace: &RequestTrace,
        owns: bool,
        code: u16,
        duration: f64,
    ) -> Result<(), sqlx::Error> {
        let now = Timestamp::now();
        let status = if code < 400 { "ok" } else { "error" };
        macro_rules! finish {
            ($pool:ident, $dialect:expr) => {{
                let stamp = $dialect.time(now);
                let mut tx = $pool.begin().await?;
                sqlx::query(AssertSqlSafe($dialect.finish(true)))
                    .bind(&trace.span)
                    .bind(&stamp)
                    .bind(duration)
                    .bind(status)
                    .bind(trace.span_attrs.to_string())
                    .execute(&mut *tx)
                    .await?;
                if owns {
                    sqlx::query(AssertSqlSafe($dialect.finish(false)))
                        .bind(&trace.id)
                        .bind(&stamp)
                        .bind(duration)
                        .bind(status)
                        .bind(trace.attributes.to_string())
                        .bind(i32::from(code))
                        .execute(&mut *tx)
                        .await?;
                }
                tx.commit().await
            }};
        }
        match self {
            Self::Sqlite(pool) => finish!(pool, Dialect::Sqlite),
            Self::Postgres(pool) => finish!(pool, Dialect::Postgres),
        }
    }
}
