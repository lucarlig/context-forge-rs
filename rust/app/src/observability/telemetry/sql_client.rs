// SPDX-License-Identifier: Apache-2.0

use std::{
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use futures_util::{FutureExt, Stream, StreamExt, future::BoxFuture, stream::BoxStream};
use opentelemetry::{
    KeyValue,
    global::BoxedSpan,
    trace::{Span, SpanKind, Status},
};
use sqlx::{Database, Either, Error, Execute, Executor, SqlStr, error::BoxDynError};

use super::{ExportSpan, SemanticConventions};
use crate::observability::operation::sql_trace;

pub(crate) fn observed<'c, E: Executor<'c>>(
    executor: E,
) -> impl Executor<'c, Database = E::Database> {
    Observed(executor)
}

#[derive(Debug)]
struct Observed<E>(E);

impl<'c, Inner: Executor<'c>> Executor<'c> for Observed<Inner> {
    type Database = Inner::Database;

    fn fetch_many<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxStream<
        'e,
        Result<
            Either<<Self::Database as Database>::QueryResult, <Self::Database as Database>::Row>,
            Error,
        >,
    >
    where
        'c: 'e,
        E: 'q + Execute<'q, Self::Database>,
    {
        let Some(trace) = QuerySpan::start::<Self::Database>() else {
            return self.0.fetch_many(query);
        };
        let rows = self.0.fetch_many(trace.wrap(query));
        TracedRows { rows, trace }.boxed()
    }

    fn fetch_optional<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<Option<<Self::Database as Database>::Row>, Error>>
    where
        'c: 'e,
        E: 'q + Execute<'q, Self::Database>,
    {
        let Some(mut trace) = QuerySpan::start::<Self::Database>() else {
            return self.0.fetch_optional(query);
        };
        let fetch = self.0.fetch_optional(trace.wrap(query));
        async move {
            let result = fetch.await;
            trace.finish(result.is_err().then_some("SQL statement failed"));
            result
        }
        .boxed()
    }

    fn prepare_with<'e>(
        self,
        sql: SqlStr,
        parameters: &'e [<Self::Database as Database>::TypeInfo],
    ) -> BoxFuture<'e, Result<<Self::Database as Database>::Statement, Error>>
    where
        'c: 'e,
    {
        self.0.prepare_with(sql, parameters)
    }
}

struct TracedRows<'e, T> {
    rows: BoxStream<'e, Result<T, Error>>,
    trace: QuerySpan,
}

impl<T> Stream for TracedRows<'_, T> {
    type Item = Result<T, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = self.rows.as_mut().poll_next(cx);
        match &next {
            Poll::Ready(None) => self.trace.finish(None),
            Poll::Ready(Some(Err(_))) => self.trace.finish(Some("SQL statement failed")),
            _ => {}
        }
        next
    }
}

struct TracedQuery<E> {
    query: E,
    operation: Arc<OnceLock<&'static str>>,
}

impl<'q, DB: Database, E: Execute<'q, DB>> Execute<'q, DB> for TracedQuery<E> {
    fn sql(self) -> SqlStr {
        let sql = self.query.sql();
        let _ = self.operation.set(sql_operation(sql.as_str()));
        sql
    }

    fn statement(&self) -> Option<&DB::Statement> {
        self.query.statement()
    }

    fn take_arguments(&mut self) -> Result<Option<DB::Arguments>, BoxDynError> {
        self.query.take_arguments()
    }

    fn persistent(&self) -> bool {
        self.query.persistent()
    }
}

struct QuerySpan {
    span: Option<BoxedSpan>,
    operation: Arc<OnceLock<&'static str>>,
    mode: SemanticConventions,
}

impl QuerySpan {
    fn start<DB: Database>() -> Option<Self> {
        let (mode, parent) = sql_trace()?;
        let system = match DB::NAME {
            "SQLite" => "sqlite",
            "PostgreSQL" => "postgresql",
            _ => return None,
        };
        let mut attributes = Vec::new();
        if mode.legacy() {
            attributes.push(KeyValue::new("db.system", system));
        }
        if mode.standard() {
            attributes.push(KeyValue::new("db.system.name", system));
        }
        let ExportSpan::Recording(span) = parent.start_span("SQL", SpanKind::Client, attributes)
        else {
            return None;
        };
        Some(Self {
            span: Some(span),
            operation: Arc::new(OnceLock::new()),
            mode,
        })
    }

    fn wrap<E>(&self, query: E) -> TracedQuery<E> {
        TracedQuery {
            query,
            operation: self.operation.clone(),
        }
    }

    fn finish(&mut self, failure: Option<&'static str>) {
        let Some(mut span) = self.span.take() else {
            return;
        };
        let operation = self.operation.get().copied().unwrap_or("SQL");
        span.update_name(operation);
        if self.mode.legacy() {
            span.set_attribute(KeyValue::new("db.operation", operation));
        }
        if self.mode.standard() {
            span.set_attributes([
                KeyValue::new("db.operation.name", operation),
                KeyValue::new("db.query.summary", operation),
            ]);
        }
        if let Some(error) = failure {
            span.set_status(Status::error(error));
        }
        span.end();
    }
}

impl Drop for QuerySpan {
    fn drop(&mut self) {
        self.finish(Some("SQL statement interrupted"));
    }
}

fn sql_operation(mut sql: &str) -> &'static str {
    loop {
        sql = sql.trim_start();
        if let Some(comment) = sql.strip_prefix("--") {
            sql = comment.split_once('\n').map_or("", |(_, after)| after);
        } else if let Some(comment) = sql.strip_prefix("/*") {
            sql = comment.split_once("*/").map_or("", |(_, after)| after);
        } else {
            break;
        }
    }
    let word = sql
        .split(|character: char| !character.is_ascii_alphabetic())
        .next()
        .unwrap_or("");
    const OPERATIONS: &[&str] = &[
        "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "WITH", "PRAGMA", "EXPLAIN", "CREATE",
        "ALTER", "DROP", "TRUNCATE", "SET", "SHOW", "ANALYZE", "VACUUM",
    ];
    OPERATIONS
        .iter()
        .copied()
        .find(|name| word.eq_ignore_ascii_case(name))
        .unwrap_or("SQL")
}

#[cfg(test)]
mod tests {
    use super::sql_operation;

    #[test]
    fn sql_span_names_omit_statement_text() {
        for (sql, name) in [
            (" /* comment with secret */\n select 'private'", "SELECT"),
            (
                "-- private data\n\nINSERT INTO private VALUES ($1)",
                "INSERT",
            ),
            ("WITH seed AS (SELECT 1) DELETE FROM records", "WITH"),
            ("some_private_value SELECT 1", "SQL"),
            ("/* open comment", "SQL"),
        ] {
            assert_eq!(sql_operation(sql), name);
        }
    }
}
