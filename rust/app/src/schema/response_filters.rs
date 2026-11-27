// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use regex::Regex;

macro_rules! translate_filters {
    ($transaction:ident) => {{
        let mut after: Option<String> = None;
        loop {
            let rows: Vec<(String, String)> = sqlx::query_as(
                "SELECT id, jsonpath_filter FROM tools
                 WHERE jsonpath_filter <> ''
                    AND (CAST($1 AS TEXT) IS NULL OR id > $1)
                 ORDER BY id LIMIT 500",
            )
            .bind(after.as_deref())
            .fetch_all(&mut *$transaction)
            .await?;
            if rows.is_empty() {
                break;
            }
            for (id, expression) in rows {
                let expression = expression.trim();
                if let Some(cel) = $crate::schema::response_filters::translate_jq(expression) {
                    sqlx::query("UPDATE tools SET jsonpath_filter = $1 WHERE id = $2")
                        .bind(cel)
                        .bind(&id)
                        .execute(&mut *$transaction)
                        .await?;
                } else if expression.starts_with(['.', '$']) {
                    tracing::warn!(tool_id = %id, "Stored response filter requires a manual CEL rewrite");
                }
                after = Some(id);
            }
        }
    }};
}

pub(super) use translate_filters;

pub(super) fn translate_jq(expression: &str) -> Option<String> {
    static SEGMENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d*)\])").expect("jq path segment pattern")
    });
    if expression == "." {
        return Some("[response]".to_owned());
    }
    if !expression.starts_with('.') {
        return None;
    }
    let mut body = if expression.starts_with(".[") {
        &expression[1..]
    } else {
        expression
    };
    let mut base = "response".to_owned();
    let mut item_path = String::new();
    let mut iterate = false;
    while !body.is_empty() {
        let segment = SEGMENT.captures(body)?;
        let matched = segment.get(0)?;
        if let Some(field) = segment.get(1) {
            if matches!(field.as_str(), "true" | "false" | "null" | "in") {
                return None;
            }
        } else if matched.as_str() == "[]" {
            if iterate {
                return None;
            }
            iterate = true;
            body = &body[matched.end()..];
            continue;
        }
        if iterate {
            item_path.push_str(matched.as_str());
        } else {
            base.push_str(matched.as_str());
        }
        body = &body[matched.end()..];
    }
    if !iterate {
        return Some(format!("[{base}]"));
    }
    if item_path.is_empty() {
        return Some(base);
    }
    Some(format!("{base}.map(x, x{item_path})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_jq_paths_with_the_reference_result_shape() {
        for (old, new) in [
            (".", "[response]"),
            (".a[0].b", "[response.a[0].b]"),
            (".[0]", "[response[0]]"),
            (".[]", "response"),
            (".a[]", "response.a"),
            (".a[].b[1]", "response.a.map(x, x.b[1])"),
        ] {
            assert_eq!(translate_jq(old).as_deref(), Some(new), "{old}");
        }
        for unsupported in [".a[].b[]", ".a | length", ".a.true", "$.a", "response.a"] {
            assert_eq!(translate_jq(unsupported), None, "{unsupported}");
        }
    }
}
