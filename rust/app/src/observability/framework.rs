// SPDX-License-Identifier: Apache-2.0

use std::time::SystemTime;

use opentelemetry::{
    InstrumentationScope, KeyValue,
    global::{self, BoxedSpan},
    propagation::TextMapPropagator,
    trace::{Span, SpanKind, TraceContextExt, Tracer},
};
use opentelemetry_sdk::propagation::TraceContextPropagator;

use super::{current_trace, telemetry::ExportContext, with_trace};

pub(crate) const RPC: &str = "context_forge_rs::gateway::public_rpc::handle";

#[derive(Clone)]
pub(super) struct RequestTrace {
    pub(super) root: ExportContext,
    pub(super) dispatch_started: SystemTime,
    pub(super) handler: Option<&'static str>,
}

pub(super) fn scope() -> InstrumentationScope {
    InstrumentationScope::builder("axum")
        .with_schema_url("https://opentelemetry.io/schemas/1.44.0")
        .build()
}

pub(crate) fn dependencies(function: &'static str) {
    if let Some(framework) = current_trace().and_then(|trace| trace.framework) {
        framework.phase(
            "axum.dependencies",
            function,
            Some(framework.dispatch_started),
        );
    }
}

pub(crate) async fn handler<T>(function: &'static str, operation: impl Future<Output = T>) -> T {
    let Some(mut trace) = current_trace() else {
        return operation.await;
    };
    let Some(framework) = &mut trace.framework else {
        return operation.await;
    };
    let Some(phase) = framework.phase("axum.handler", function, None) else {
        return operation.await;
    };
    framework.handler = Some(function);
    trace.exported = Some(phase.context());
    with_trace(Some(trace), operation).await
}

pub(crate) fn serialize<T>(function: &'static str, operation: impl FnOnce() -> T) -> T {
    let _phase = current_trace()
        .and_then(|trace| trace.framework)
        .and_then(|framework| framework.phase("axum.serialization", function, None));
    operation()
}

pub(crate) fn serialize_rpc<T>(operation: impl FnOnce() -> T) -> T {
    let _phase = current_trace()
        .and_then(|trace| trace.framework)
        .filter(|framework| framework.handler == Some(RPC))
        .and_then(|framework| framework.phase("axum.serialization", RPC, None));
    operation()
}

impl RequestTrace {
    fn phase(
        &self,
        name: &'static str,
        function: &'static str,
        started: Option<SystemTime>,
    ) -> Option<Phase> {
        Phase::start(
            &self.root,
            scope(),
            name,
            SpanKind::Internal,
            Some(KeyValue::new("code.function.name", function)),
            started,
        )
    }
}

pub(crate) struct Phase(BoxedSpan);

impl Phase {
    fn start(
        parent: &ExportContext,
        scope: InstrumentationScope,
        name: &'static str,
        kind: SpanKind,
        attribute: Option<KeyValue>,
        started: Option<SystemTime>,
    ) -> Option<Self> {
        let context = TraceContextPropagator::new().extract(parent);
        if !context.span().span_context().is_sampled() {
            return None;
        }
        let attributes = attribute.into_iter();
        let tracer = global::tracer_with_scope(scope);
        let mut builder = tracer
            .span_builder(name)
            .with_kind(kind)
            .with_attributes(attributes);
        if let Some(started) = started {
            builder = builder.with_start_time(started);
        }
        Some(Self(builder.start_with_context(&tracer, &context)))
    }

    fn context(&self) -> ExportContext {
        ExportContext::from_span(self.0.span_context())
    }

    pub(crate) fn mcp(name: &'static str, route: Option<&str>) -> Option<Self> {
        let exported = current_trace()?.exported?;
        let attribute = route.map(|path| KeyValue::new("http.route", super::bounded(path, 2000)));
        Self::start(
            &exported,
            super::telemetry::scope(),
            name,
            SpanKind::Internal,
            attribute,
            None,
        )
    }

    pub(crate) fn initialize(&self) -> Option<Self> {
        Self::start(
            &self.context(),
            InstrumentationScope::builder("rmcp").build(),
            "initialize",
            SpanKind::Server,
            None,
            None,
        )
    }
}

impl Drop for Phase {
    fn drop(&mut self) {
        self.0.end();
    }
}
