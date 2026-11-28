// SPDX-License-Identifier: Apache-2.0

use serde_json::json;

use crate::observability::{scoped::ScopedSpan, with_trace};

pub(super) struct ToolPhases {
    name: String,
    pub(super) id: Option<String>,
    integration: &'static str,
    result_ready: bool,
}

impl ToolPhases {
    pub(super) fn new(name: &str, id: Option<&str>, integration: &'static str) -> Self {
        Self {
            name: name.to_owned(),
            id: id.map(str::to_owned),
            integration,
            result_ready: false,
        }
    }

    pub(super) fn start(&self, name: &'static str) -> ScopedSpan {
        ScopedSpan::start(name, || {
            json!({
                "tool.name": self.name,
                "tool.id": self.id,
                "tool.integration_type": (name != "tool.post_process").then_some(self.integration),
            })
        })
    }

    pub(super) fn mark_result_ready(&mut self) {
        self.result_ready = true;
    }

    pub(super) fn result_ready(&self) -> bool {
        self.result_ready
    }

    pub(super) fn post_process(&self) -> ScopedSpan {
        if self.result_ready() {
            self.start("tool.post_process")
        } else {
            ScopedSpan::default()
        }
    }

    pub(super) async fn observe<T, E>(
        &self,
        name: &'static str,
        operation: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        let mut span = self.start(name);
        let result = with_trace(span.context(), operation).await;
        span.finish(result.is_err().then_some("Tool invocation phase failed"));
        result
    }
}
