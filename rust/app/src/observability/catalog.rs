// SPDX-License-Identifier: Apache-2.0

use opentelemetry::{KeyValue, trace::Span as _};
use serde_json::{Value, json};

use super::{scoped::ScopedSpan, with_trace};

pub(crate) async fn page<T, E>(
    method: &'static str,
    page_size: u32,
    continuation: bool,
    operation: impl Future<Output = Result<T, E>>,
    summary: impl FnOnce(&T) -> (usize, bool),
) -> Result<T, E> {
    let name = match method {
        "tools/list" => "tool.list",
        "prompts/list" => "prompt.list",
        _ => "resource.list",
    };
    let mut span = ScopedSpan::start(name, || {
        json!({
            "mcp.method": method,
            "mcp.catalog.page_size": page_size,
            "mcp.catalog.continuation": continuation,
        })
    });
    let result = with_trace(span.context(), operation).await;
    if let Ok(page) = &result
        && let Some(recording) = span.recording()
    {
        let (count, has_more) = summary(page);
        recording.set_attributes([
            KeyValue::new(
                "mcp.catalog.count",
                i64::try_from(count).unwrap_or(i64::MAX),
            ),
            KeyValue::new("mcp.catalog.has_more", has_more),
        ]);
    }
    span.finish(result.is_err().then_some("MCP catalog listing failed"));
    result
}

pub(crate) fn page_summary(page: &Value, key: &str) -> (usize, bool) {
    (
        page[key].as_array().map_or(0, Vec::len),
        page.get("nextCursor").is_some(),
    )
}
