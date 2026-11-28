// SPDX-License-Identifier: Apache-2.0

use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

pub(super) const MASK: &str = "*****";

static URL_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)([a-z][a-z0-9+.-]*://[^:@/?#\s"']*):[^@/?#\s"']+@"#)
        .expect("valid URL credential regex")
});
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r#"(?i)\b[a-z0-9_.-]*(?:password|passwd|passphrase|secret|credential|authorization|token|api[_-]?key|private[_-]?key)[a-z0-9_.-]*["']?[ \t]*[:=][ \t]*"#,
        r#"(?P<value>"(?:[^"\\\r\n]|\\.)*"|'(?:[^'\\\r\n]|\\.)*'|(?:basic|bearer)[ \t]+[^\s"',&;}]+|[^\s"',&;}]+)"#,
    ))
    .expect("valid credential assignment regex")
});
static AUTH_SCHEME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(bearer|basic)[ \t]+[a-z0-9._~+/=-]+")
        .expect("valid authorization scheme regex")
});
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").expect("valid JWT regex")
});
static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----")
        .expect("valid private key regex")
});

pub(super) struct Redactor {
    literals: Vec<Zeroizing<String>>,
}

impl Redactor {
    pub(super) fn new(mut literals: Vec<Zeroizing<String>>) -> Self {
        // Short words and flags are common in unrelated diagnostic text.
        literals.retain(|value| value.trim().len() >= 8);
        literals.sort_by(|a, b| {
            b.len()
                .cmp(&a.len())
                .then_with(|| a.as_str().cmp(b.as_str()))
        });
        literals.dedup_by(|a, b| a.as_str() == b.as_str());
        Self { literals }
    }

    pub(super) fn text(&self, input: &str) -> String {
        let urls = URL_PASSWORD.replace_all(input, "${1}:*****@");
        let assignments = ASSIGNMENT.replace_all(&urls, redact_assignment);
        let headers = AUTH_SCHEME.replace_all(&assignments, "${1} *****");
        let tokens = JWT.replace_all(&headers, "eyJ*****");
        let mut safe = PRIVATE_KEY.replace_all(&tokens, MASK).into_owned();
        for literal in &self.literals {
            if safe.contains(literal.as_str()) {
                let redacted = safe.replace(literal.as_str(), MASK);
                safe.zeroize();
                safe = redacted;
            }
        }
        safe
    }

    pub(super) fn value(&self, value: Value) -> Value {
        match value {
            Value::String(mut text) => {
                let safe = self.text(&text);
                text.zeroize();
                Value::String(safe)
            }
            Value::Array(items) => {
                Value::Array(items.into_iter().map(|item| self.value(item)).collect())
            }
            Value::Object(items) => Value::Object(
                items
                    .into_iter()
                    .map(|(mut name, item)| {
                        let safe = self.text(&name);
                        let item = if secret_name(&name, &["token", "key", "auth"]) {
                            Value::from(MASK)
                        } else {
                            self.value(item)
                        };
                        name.zeroize();
                        (safe, item)
                    })
                    .collect(),
            ),
            other => other,
        }
    }
}

fn redact_assignment(captures: &Captures<'_>) -> String {
    let field = captures.get(0).expect("matched assignment");
    let value = captures.name("value").expect("matched assignment value");
    let prefix = &field.as_str()[..value.start() - field.start()];
    match value.as_str().chars().next() {
        Some(quote @ ('"' | '\'')) => format!("{prefix}{quote}{MASK}{quote}"),
        _ => format!("{prefix}{MASK}"),
    }
}

pub(super) fn secret_name(name: &str, extra: &[&str]) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "passwd",
        "credential",
        "passphrase",
        "private_key",
        "api_key",
    ]
    .iter()
    .chain(extra)
    .any(|word| name.contains(word))
}
