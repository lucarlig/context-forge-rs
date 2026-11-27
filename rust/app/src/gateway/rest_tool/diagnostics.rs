// SPDX-License-Identifier: Apache-2.0

pub(super) fn parse_error(error: &str, text: &str, bounded: &str, limit: usize) -> String {
    if text.is_empty() {
        return "Empty response body".into();
    }
    let total = text.chars().count();
    if total > limit {
        format!(
            "Response body is not valid JSON: {error}. Showing the first {limit} of {total} characters:\n{bounded}"
        )
    } else {
        format!("Response body is not valid JSON: {error}.\n{bounded}")
    }
}

pub(super) fn syntax_error(error: &serde_json::Error, text: &str) -> String {
    let rendered = error.to_string();
    let reason = rendered.split(" at line ").next().unwrap_or(&rendered);
    let line_start: usize = text
        .split_inclusive('\n')
        .take(error.line().saturating_sub(1))
        .map(str::len)
        .sum();
    let offset = if error.is_eof() {
        text.len()
    } else {
        (line_start + error.column().saturating_sub(1)).min(text.len())
    };
    let (reason, offset) = match reason {
        "expected value" | "EOF while parsing a value" => ("Expecting value", offset),
        "expected ident" => {
            let start = text.as_bytes()[..offset]
                .iter()
                .rposition(|byte| !byte.is_ascii_alphabetic())
                .map_or(0, |index| index + 1);
            ("Expecting value", start)
        }
        "key must be a string" => ("Expecting property name enclosed in double quotes", offset),
        "EOF while parsing an object" => {
            let trimmed = text.trim_ascii_end();
            let reason = if trimmed.ends_with(['{', ',']) {
                "Expecting property name enclosed in double quotes"
            } else if trimmed.ends_with('"')
                && let Some(start) = last_string_start(trimmed)
                && trimmed[..start].trim_ascii_end().ends_with(['{', ','])
            {
                "Expecting ':' delimiter"
            } else {
                "Expecting ',' delimiter"
            };
            (reason, offset)
        }
        "EOF while parsing an array" if text.trim_ascii_end().ends_with(['[', ',']) => {
            ("Expecting value", offset)
        }
        "EOF while parsing an array" => ("Expecting ',' delimiter", offset),
        "EOF while parsing a string" => (
            "Unterminated string starting at",
            last_string_start(text).unwrap_or(offset),
        ),
        "expected `:`" => ("Expecting ':' delimiter", offset),
        "expected `,` or `]`" | "expected `,` or `}`" => ("Expecting ',' delimiter", offset),
        "trailing comma" => {
            let reason = if text.as_bytes().get(offset) == Some(&b'}') {
                "Illegal trailing comma before end of object"
            } else {
                "Illegal trailing comma before end of array"
            };
            let comma = text.as_bytes()[..offset]
                .iter()
                .rposition(|byte| *byte == b',')
                .unwrap_or(offset);
            (reason, comma)
        }
        "trailing characters" => ("Extra data", offset),
        "invalid escape" => {
            let unicode = text.as_bytes()[..offset]
                .windows(2)
                .rposition(|pair| pair == b"\\u")
                .filter(|start| offset - start <= 5);
            if let Some(start) = unicode {
                ("Invalid \\uXXXX escape", start + 1)
            } else {
                ("Invalid \\escape", offset.saturating_sub(1))
            }
        }
        "control character (\\u0000-\\u001F) found while parsing a string" => {
            ("Invalid control character at", offset)
        }
        reason => (reason, offset),
    };
    let mut line = 1;
    let mut column = 1;
    let mut position = 0;
    for (_, character) in text.char_indices().take_while(|(index, _)| *index < offset) {
        position += 1;
        column += 1;
        if character == '\n' {
            line += 1;
            column = 1;
        }
    }
    format!("{reason}: line {line} column {column} (char {position})")
}

fn last_string_start(text: &str) -> Option<usize> {
    let mut escaped = false;
    let mut in_string = false;
    let mut last_start = None;
    for (index, byte) in text.bytes().enumerate() {
        match byte {
            _ if escaped => escaped = false,
            b'\\' if in_string => escaped = true,
            b'"' => {
                in_string = !in_string;
                if in_string {
                    last_start = Some(index);
                }
            }
            _ => {}
        }
    }
    last_start
}
