// SPDX-License-Identifier: Apache-2.0

use opentelemetry::{global::BoxedSpan, trace::Span as _};
use serde_json::Value;

use super::{
    TraceContext, current_trace,
    telemetry::{ExportSpan, exported_attributes, langfuse},
};

#[derive(Default)]
pub(crate) struct SystemSpan {
    span: Option<ExportSpan>,
    context: Option<TraceContext>,
}

impl SystemSpan {
    pub(crate) fn start(name: &'static str, attributes: impl FnOnce() -> Value) -> Self {
        let Some(mut context) = current_trace() else {
            return Self::default();
        };
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

    pub(crate) fn recording(&mut self) -> Option<&mut BoxedSpan> {
        match self.span.as_mut()? {
            ExportSpan::Recording(span) if span.is_recording() => Some(span),
            _ => None,
        }
    }
}
