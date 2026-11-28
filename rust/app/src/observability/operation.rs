// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, time::Instant};

use jiff::Timestamp;
use opentelemetry::{
    KeyValue,
    global::BoxedSpan,
    trace::{Span, Status},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::{bounded, telemetry::ExportContext};
use crate::database::Database;

#[derive(Clone, Default, Deserialize, Serialize)]
pub(crate) struct TraceContext {
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub(super) stored: Option<StoredTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) exported: Option<ExportContext>,
}

#[derive(Clone, Deserialize, Serialize)]
pub(super) struct StoredTrace {
    pub(super) trace_id: String,
    pub(super) span_id: String,
}

impl TraceContext {
    pub(super) fn with_stored(mut self, trace_id: String, span_id: String) -> Self {
        self.stored = Some(StoredTrace { trace_id, span_id });
        self
    }
}

tokio::task_local! { static TRACE: TraceContext; }

pub(crate) fn current_trace() -> Option<TraceContext> {
    TRACE.try_with(Clone::clone).ok()
}

pub(crate) async fn with_trace<T>(
    context: Option<TraceContext>,
    operation: impl Future<Output = T>,
) -> T {
    match context {
        Some(context) => TRACE.scope(context, operation).await,
        None => operation.await,
    }
}

pub(crate) struct SpanResource<'a> {
    pub kind: &'static str,
    pub name: &'a str,
    pub id: Option<&'a str>,
}

#[derive(Clone, Copy)]
pub(crate) enum Outcome {
    Ok,
    Error(&'static str),
    Cancelled,
    InputRequired,
}

impl Outcome {
    pub(super) fn status(self) -> &'static str {
        match self {
            Self::Ok | Self::InputRequired => "ok",
            Self::Error(_) => "error",
            Self::Cancelled => "cancelled",
        }
    }

    pub(super) fn message(self) -> Option<&'static str> {
        match self {
            Self::Error(message) => Some(message),
            _ => None,
        }
    }

    pub(crate) fn completed(ok: bool, error: &'static str) -> Self {
        if ok { Self::Ok } else { Self::Error(error) }
    }
}

pub(super) struct Operation {
    database: Database,
    pub(super) parent: StoredTrace,
    pub(super) id: String,
    pub(super) name: &'static str,
    pub(super) kind: &'static str,
    pub(super) resource_type: Option<&'static str>,
    pub(super) resource_name: Option<String>,
    pub(super) resource_id: Option<String>,
    pub(super) started_at: Timestamp,
    started: Instant,
    attributes: Value,
}

#[derive(Default)]
pub(crate) struct OperationSpan {
    active: Option<Operation>,
    exported: Option<ExportedOperation>,
}

struct ExportedOperation {
    span: BoxedSpan,
    started: Instant,
    tool: bool,
}

impl ExportedOperation {
    fn finish(mut self, outcome: Outcome) {
        if self.tool {
            self.span.set_attributes([
                KeyValue::new("success", matches!(outcome, Outcome::Ok)),
                KeyValue::new("cancelled", matches!(outcome, Outcome::Cancelled)),
                KeyValue::new("duration.ms", self.started.elapsed().as_secs_f64() * 1000.0),
            ]);
        }
        if matches!(outcome, Outcome::InputRequired) {
            self.span
                .set_attribute(KeyValue::new("input_required", true));
        }
        self.span.set_status(match outcome {
            Outcome::Error(message) => Status::error(message),
            Outcome::Cancelled => Status::error("Operation cancelled"),
            Outcome::Ok | Outcome::InputRequired => Status::Ok,
        });
        self.span.end();
    }
}

impl OperationSpan {
    pub(crate) async fn start(
        database: &Database,
        name: &'static str,
        kind: &'static str,
        resource: Option<SpanResource<'_>>,
        attrs: impl FnOnce() -> Value,
    ) -> Self {
        let Some(context) = current_trace() else {
            return Self::default();
        };
        let mut attributes = attrs();
        let resource_type = resource.as_ref().map(|resource| resource.kind);
        let resource_name = resource
            .as_ref()
            .map(|resource| bounded(resource.name, 255));
        let resource_id = resource
            .as_ref()
            .and_then(|resource| resource.id)
            .map(|id| bounded(id, 36));
        let tool = name == "tool.invoke";
        if tool {
            attributes["tool.name"] = json!(resource_name);
            attributes["tool.id"] = json!(resource_id);
        }
        let started = Instant::now();
        let exported = context.exported.map(|parent| ExportedOperation {
            span: parent.start_operation(name, &attributes),
            started,
            tool,
        });
        let mut result = Self {
            active: None,
            exported,
        };
        let Some(parent) = context.stored else {
            return result;
        };
        let operation = Operation {
            database: database.clone(),
            parent,
            id: Uuid::new_v4().hyphenated().to_string(),
            name,
            kind,
            resource_type,
            resource_name,
            resource_id,
            started_at: Timestamp::now(),
            started,
            attributes,
        };
        match Box::pin(database.start_operation(&operation, &operation.attributes)).await {
            Ok(true) => result.active = Some(operation),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%error, operation=name,"Operation span could not start");
            }
        }
        result
    }

    pub(crate) async fn scope<T>(&self, operation: impl Future<Output = T>) -> T {
        let child = current_trace().map(|mut context| {
            if let Some(span) = &self.active {
                context.stored = Some(StoredTrace {
                    trace_id: span.parent.trace_id.clone(),
                    span_id: span.id.clone(),
                });
            }
            if let Some(span) = &self.exported {
                context.exported = Some(ExportContext::from_span(span.span.span_context()));
            }
            context
        });
        with_trace(child, operation).await
    }

    pub(crate) fn inject_trace_context(&self, headers: &mut axum::http::HeaderMap) {
        if let Some(exported) = &self.exported {
            ExportContext::from_span(exported.span.span_context()).inject(headers);
        }
    }

    pub(crate) async fn finish(mut self, outcome: Outcome) {
        if let Some(span) = self.exported.take() {
            span.finish(outcome);
        }
        if let Some(span) = &self.active {
            span.finish(outcome).await;
        }
        self.active = None;
    }
}

impl Drop for OperationSpan {
    fn drop(&mut self) {
        if let Some(span) = self.exported.take() {
            span.finish(Outcome::Cancelled);
        }
        if let Some(span) = self.active.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            // Detached MCP requests may be dropped by the protocol worker on cancellation.
            handle.spawn(async move {
                span.finish(Outcome::Cancelled).await;
            });
        }
    }
}

impl Operation {
    async fn finish(&self, outcome: Outcome) {
        let duration = self.started.elapsed().as_secs_f64() * 1000.0;
        let mut attributes = self.attributes.clone();
        if self.name == "tool.invoke" {
            attributes["success"] = json!(matches!(outcome, Outcome::Ok));
            attributes["cancelled"] = json!(matches!(outcome, Outcome::Cancelled));
            attributes["duration_ms"] = json!(duration);
        }
        if matches!(outcome, Outcome::InputRequired) {
            attributes["input_required"] = json!(true);
        }
        if let Err(error) =
            Box::pin(
                self.database
                    .finish_operation(&self.id, duration, outcome, &attributes),
            )
            .await
        {
            tracing::warn!(%error, operation=self.name,"Operation span could not finish");
        }
    }
}
