// SPDX-License-Identifier: Apache-2.0

use opentelemetry::{
    KeyValue,
    global::BoxedSpan,
    trace::{Span as _, Status},
};
use serde_json::Value;

use crate::access::Principal;

use super::{
    TraceContext, current_trace,
    telemetry::{ExportSpan, exported_attributes, langfuse},
    with_trace,
};

#[derive(Default)]
pub(crate) struct ScopedSpan {
    span: Option<ExportSpan>,
    context: Option<TraceContext>,
}

impl ScopedSpan {
    pub(crate) fn start(name: &'static str, attributes: impl FnOnce() -> Value) -> Self {
        let Some(mut context) = current_trace() else {
            return Self::default();
        };
        if context.exported.is_none() && !context.system_root {
            return Self::default();
        }
        let attributes = attributes();
        let mut span = match &context.exported {
            Some(parent) => parent.start_operation(name, &attributes),
            None => ExportSpan::root(name, exported_attributes(&attributes)),
        };
        if let ExportSpan::Recording(recording) = &mut span
            && let Some(policy) = langfuse::policy()
        {
            policy.label(name, &attributes, None, recording);
        }
        context.exported = Some(span.context());
        Self {
            span: Some(span),
            context: Some(context),
        }
    }

    pub(crate) fn context(&self) -> Option<TraceContext> {
        self.context.clone()
    }

    pub(crate) fn authenticated(
        name: &'static str,
        principal: &Principal,
        attributes: impl FnOnce() -> Value,
    ) -> Self {
        let mut span = Self::start(name, attributes);
        if let Some(recording) = span.recording() {
            if let Some(policy) = langfuse::policy() {
                policy.identify(principal, recording);
            } else {
                recording.set_attribute(KeyValue::new("auth.method", "jwt"));
            }
        }
        span
    }

    pub(crate) async fn run<T, E>(
        mut self,
        operation: impl Future<Output = Result<T, E>>,
        failure: &'static str,
    ) -> Result<T, E> {
        let result = with_trace(self.context(), operation).await;
        self.finish(result.is_err().then_some(failure));
        result
    }

    pub(crate) fn recording(&mut self) -> Option<&mut BoxedSpan> {
        match self.span.as_mut()? {
            ExportSpan::Recording(span) if span.is_recording() => Some(span),
            _ => None,
        }
    }

    pub(crate) fn finish(&mut self, failure: Option<&'static str>) {
        if let Some(ExportSpan::Recording(mut span)) = self.span.take() {
            span.set_status(failure.map_or(Status::Ok, Status::error));
            span.end();
        }
    }
}
