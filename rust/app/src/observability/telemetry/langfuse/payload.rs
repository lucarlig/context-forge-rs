// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

use crate::observability::QueryRedaction;

static CREDENTIALS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(bearer|basic)\s+[-a-z0-9._~+/=]+").expect("valid credential pattern")
});
static URLS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s<>"']+"#).expect("valid URL pattern"));
static LABELED_FIELDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)(?P<prefix>(?P<key>[a-z][a-z0-9_.-]*)["']?\s*[:=]\s*)(?:"(?:[^"\\]|\\.)*(?:"|\\?\z)|'(?:[^'\\]|\\.)*(?:'|\\?\z)|[^\s&,;}\]]+)"#,
    )
    .expect("valid labeled value pattern")
});

impl QueryRedaction {
    pub(super) fn text(&self, text: &str) -> String {
        let text = URLS.replace_all(text, |captures: &Captures<'_>| {
            let raw = &captures[0];
            let Ok(mut url) = Url::parse(raw) else {
                return "***".to_owned();
            };
            let _ = url.set_password(None);
            let _ = url.set_username("");
            if let Some(query) = url.query() {
                url.set_query(Some(&self.query(query)));
            }
            url.set_fragment(None);
            url.to_string()
        });
        let text = CREDENTIALS.replace_all(&text, "$1 ***");
        LABELED_FIELDS
            .replace_all(&text, |captures: &Captures<'_>| {
                if self.sensitive_key(&captures["key"]) {
                    format!("{}***", &captures["prefix"])
                } else {
                    captures[0].to_owned()
                }
            })
            .into_owned()
    }

    pub(super) fn serialize_payload<T: Serialize + ?Sized>(
        &self,
        value: &T,
        maximum: usize,
    ) -> Option<String> {
        let mut value = serde_json::to_value(value).ok()?;
        self.redact_value(&mut value, 128);
        let serialized = serde_json::to_string(&value).ok()?;
        let length = serialized.chars().count();
        if length <= maximum {
            return Some(serialized);
        }
        let preview: String = serialized.chars().take(maximum / 4).collect();
        Some(json!({"_truncated":true, "_original_size":length, "_preview":preview}).to_string())
    }

    fn redact_value(&self, value: &mut Value, remaining: usize) {
        if remaining == 0 {
            *value = json!("***");
            return;
        }
        match value {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if self.sensitive_key(key) {
                        *value = json!("***");
                    } else {
                        self.redact_value(value, remaining - 1);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.redact_value(item, remaining - 1);
                }
            }
            Value::String(text) => {
                if matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['))
                    && let Ok(mut nested) = serde_json::from_str::<Value>(text)
                {
                    self.redact_value(&mut nested, remaining - 1);
                    *text = nested.to_string();
                } else {
                    *text = self.text(text);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn payload_redacts_structured_and_text_credentials_before_truncation() {
        let redaction = QueryRedaction(Arc::new(
            ["password", "apikey", "token", "customfield"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
        ));
        let input = json!({
            "safe": "sample",
            "nested": [{"API-KEY": "private-key"}],
            "text": "Bearer outside.private custom-field='private-field'",
            "url": "http://user:private-url@host.test/path?token=private-query&safe=1",
            "embedded": "{\"password\":\"private-inner\"}",
            "malformed": "password=\"private first\nprivate second",
        });
        let encoded = redaction.serialize_payload(&input, 32_768).unwrap();
        assert!(!encoded.contains("private"));
        assert!(encoded.contains("safe=1"));
        let bounded = redaction
            .serialize_payload(
                &json!({"password":"private-first","long":"\\\"λ".repeat(200)}),
                256,
            )
            .unwrap();
        assert!(bounded.chars().count() <= 256);
        assert!(!bounded.contains("private"));
        let preview: Value = serde_json::from_str(&bounded).unwrap();
        assert_eq!(preview["_truncated"], true);
    }
}
