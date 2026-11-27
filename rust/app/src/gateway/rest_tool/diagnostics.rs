// SPDX-License-Identifier: Apache-2.0

use std::{cmp::Reverse, fmt::Write};

use jsonschema::{ValidationError, error::ValidationErrorKind};
use serde::Serialize;
use serde_json::{Value, json};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    Input,
    Output,
}

#[derive(Serialize)]
struct Diagnostic<'a> {
    code: Option<&'a str>,
    expected: Option<&'a Value>,
    received: Option<&'static str>,
    path: Vec<Value>,
    message: String,
}

pub(super) fn parse_error(
    error: &serde_json::Error,
    text: &str,
    bounded: &str,
    limit: usize,
) -> String {
    if text.is_empty() {
        return "Empty response body".into();
    }
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
        "invalid escape" => ("Invalid \\escape", offset.saturating_sub(1)),
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
    let total = text.chars().count();
    let error = format!("{reason}: line {line} column {column} (char {position})");
    if total > limit {
        format!(
            "Response body is not valid JSON: {error}. Showing the first {limit} of {total} characters:\n{bounded}"
        )
    } else {
        format!("Response body is not valid JSON: {error}.\n{bounded}")
    }
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

pub(super) fn validate(
    schema: &Value,
    data: &Value,
    target: Target,
    regex_max_subject_bytes: usize,
) -> Option<String> {
    let regex = uses_regex(schema);
    if regex {
        let bytes = data.to_string().len();
        if bytes > regex_max_subject_bytes {
            let message = format!(
                "instance of {bytes} bytes exceeds the {regex_max_subject_bytes} byte limit for pattern validation"
            );
            return Some(for_target(message, target));
        }
    }
    let validator = match jsonschema::options()
        .offline()
        .should_validate_formats(false)
        .build(schema)
    {
        Ok(validator) => validator,
        Err(error) => {
            tracing::warn!(
                keyword = error.kind().keyword(),
                "REST tool schema did not compile"
            );
            return Some(match target {
                Target::Input => "REST inputSchema is invalid".into(),
                Target::Output => "Output validation error: REST outputSchema is invalid".into(),
            });
        }
    };

    let best = validator.iter_errors(data).reduce(|best, candidate| {
        if relevance(&candidate, schema, data) > relevance(&best, schema, data) {
            candidate
        } else {
            best
        }
    })?;
    let mut error = &best;
    loop {
        let context = match error.kind() {
            ValidationErrorKind::AnyOf { context }
            | ValidationErrorKind::OneOfNotValid { context } => context,
            ValidationErrorKind::PropertyNames { error: inner } => {
                error = inner;
                continue;
            }
            _ => break,
        };
        let mut children = context.iter().flatten().collect::<Vec<_>>();
        children.sort_by_cached_key(|child| relevance(child, schema, data));
        let Some(child) = children.first() else { break };
        if children
            .get(1)
            .is_some_and(|next| relevance(child, schema, data) == relevance(next, schema, data))
        {
            break;
        }
        error = child;
    }

    let schema_node = error_schema(error, schema);
    let code = match error.kind() {
        ValidationErrorKind::FalseSchema => None,
        ValidationErrorKind::Required { .. } => Some(schema_keyword(error)),
        ValidationErrorKind::ExclusiveMinimum { .. } if schema_node["exclusiveMinimum"] == true => {
            Some("minimum")
        }
        ValidationErrorKind::ExclusiveMaximum { .. } if schema_node["exclusiveMaximum"] == true => {
            Some("maximum")
        }
        kind => Some(kind.keyword()),
    };
    let mut diagnostic = Diagnostic {
        code,
        expected: schema_node.get("type"),
        received: received_type(error.instance()),
        path: instance_path(error, data),
        message: validation_message(error, schema_node),
    };
    adapt_array_failure(error, data, schema_node, &mut diagnostic);
    if regex || target == Target::Input {
        let schema_pointer = error.evaluation_path();
        let schema_path = pointer_path(schema_pointer.as_str(), schema);
        let message = if let Some(code) = diagnostic.code {
            let schema_path = indexing(&schema_path[..schema_path.len().saturating_sub(1)]);
            let instance_path = indexing(&diagnostic.path);
            let message = diagnostic.message;
            format!(
                "{message}\n\nFailed validating {} in schema{schema_path}:\n    {}\n\nOn instance{instance_path}:\n    {}",
                quoted(code),
                pretty_value(schema_node, 0).replace('\n', "\n    "),
                pretty_value(error.instance(), 0).replace('\n', "\n    "),
            )
        } else {
            diagnostic.message
        };
        return Some(for_target(message, target));
    }

    Some(serde_json::to_string(&diagnostic).expect("serialize validation diagnostic"))
}

fn for_target(message: String, target: Target) -> String {
    match target {
        Target::Input => message,
        Target::Output => format!(
            "{{'code': <unset>, 'expected': None, 'received': 'unset', 'path': [], 'message': {}}}",
            quoted(&message),
        ),
    }
}

fn uses_regex(schema: &Value) -> bool {
    match schema {
        Value::Object(fields) => {
            fields.contains_key("pattern")
                || fields.contains_key("patternProperties")
                || fields.values().any(uses_regex)
        }
        Value::Array(items) => items.iter().any(uses_regex),
        _ => false,
    }
}

fn error_schema<'a>(error: &ValidationError<'_>, schema: &'a Value) -> &'a Value {
    let path = error.schema_path().as_str();
    if matches!(error.kind(), ValidationErrorKind::FalseSchema) && schema_keyword(error) != "items"
    {
        return &Value::Bool(false);
    }
    path.rsplit_once('/')
        .and_then(|(parent, _)| schema.pointer(parent))
        .unwrap_or(schema)
}

fn schema_keyword<'a>(error: &'a ValidationError<'_>) -> &'a str {
    error
        .schema_path()
        .as_str()
        .rsplit('/')
        .next()
        .unwrap_or_default()
}

fn adapt_array_failure<'a>(
    error: &ValidationError<'_>,
    data: &Value,
    schema: &'a Value,
    diagnostic: &mut Diagnostic<'a>,
) {
    match error.kind() {
        ValidationErrorKind::FalseSchema if schema["items"] == false => {
            let array = diagnostic
                .path
                .iter()
                .try_fold(data, |node, segment| {
                    if let Some(index) = segment.as_u64() {
                        node.get(index as usize)
                    } else {
                        node.get(segment.as_str()?)
                    }
                })
                .and_then(Value::as_array);
            if let Some(array) = array {
                let prefix = schema["prefixItems"].as_array().map_or(0, Vec::len);
                let rest = &array[prefix.min(array.len())..];
                let extra = rest.len();
                let value = if let [value] = rest {
                    display_value(value)
                } else {
                    display_value(&json!(rest))
                };
                let noun = if prefix == 1 { "item" } else { "items" };
                diagnostic.code = Some("items");
                diagnostic.received = Some("list");
                diagnostic.message =
                    format!("Expected at most {prefix} {noun} but found {extra} extra: {value}");
            }
        }
        ValidationErrorKind::MinContains { limit } => {
            if let Some(items) = error.instance().as_array()
                && let Ok(validator) = jsonschema::options()
                    .offline()
                    .should_validate_formats(false)
                    .build(&schema["contains"])
            {
                let count = items
                    .iter()
                    .filter(|item| validator.is_valid(*item))
                    .count();
                if count == 0 {
                    diagnostic.code = Some("contains");
                    diagnostic.message = format!(
                        "{} does not contain items matching the given schema",
                        display_value(error.instance())
                    );
                } else {
                    diagnostic.message = format!(
                        "Too few items match the given schema (expected at least {limit} but only {count} matched)"
                    );
                }
            }
        }
        _ => {}
    }
}

fn pointer_path(pointer: &str, mut value: &Value) -> Vec<Value> {
    pointer
        .split('/')
        .skip(1)
        .map(|segment| {
            let key = segment.replace("~1", "/").replace("~0", "~");
            if value.is_array()
                && let Ok(index) = key.parse::<usize>()
            {
                value = value.get(index).unwrap_or(&Value::Null);
                return json!(index);
            }
            value = value.get(&key).unwrap_or(&Value::Null);
            Value::String(key)
        })
        .collect()
}

fn instance_path(error: &ValidationError<'_>, data: &Value) -> Vec<Value> {
    let mut path = pointer_path(error.instance_path().as_str(), data);
    if matches!(error.kind(), ValidationErrorKind::FalseSchema) {
        path.pop();
    }
    path
}

fn indexing(path: &[Value]) -> String {
    path.iter()
        .map(|index| format!("[{}]", display_value(index)))
        .collect()
}

fn relevance(
    error: &ValidationError<'_>,
    schema: &Value,
    data: &Value,
) -> (Reverse<usize>, Vec<String>, bool, bool) {
    let path = instance_path(error, data);
    let actual = error.instance();
    let is_type = |expected: &Value| match expected.as_str() {
        Some("null") => actual.is_null(),
        Some("object") => actual.is_object(),
        Some("array") => actual.is_array(),
        Some("string") => actual.is_string(),
        Some("boolean") => actual.is_boolean(),
        Some("number") => actual.is_number(),
        Some("integer") => actual.as_f64().is_some_and(|number| number.fract() == 0.0),
        _ => false,
    };
    let expected = &error_schema(error, schema)["type"];
    let matches_type = expected
        .as_array()
        .map_or_else(|| is_type(expected), |types| types.iter().any(is_type));
    let order = path
        .iter()
        .map(|segment| {
            segment.as_u64().map_or_else(
                || segment.as_str().unwrap_or_default().to_owned(),
                |index| format!("{index:020}"),
            )
        })
        .collect();
    (
        Reverse(path.len()),
        order,
        !matches!(error.kind().keyword(), "anyOf" | "oneOf"),
        !matches_type,
    )
}

fn received_type(value: &Value) -> Option<&'static str> {
    Some(match value {
        Value::Null => return None,
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    })
}

fn validation_message(error: &ValidationError<'_>, schema: &Value) -> String {
    use ValidationErrorKind as Kind;

    let value = || display_value(error.instance());
    match error.kind() {
        Kind::Type { .. } => {
            let expected = &schema["type"];
            let types = expected.as_array().map_or_else(
                || display_value(expected),
                |items| {
                    items
                        .iter()
                        .map(display_value)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            );
            format!("{} is not of type {types}", value())
        }
        Kind::Required { property } => {
            let keyword = schema_keyword(error);
            if let Some(dependencies) = schema[keyword].as_object()
                && let Some((trigger, _)) = dependencies.iter().find(|(trigger, required)| {
                    error.instance().get(*trigger).is_some()
                        && required
                            .as_array()
                            .is_some_and(|values| values.contains(property))
                })
            {
                return format!(
                    "{} is a dependency of {}",
                    display_value(property),
                    quoted(trigger)
                );
            }
            format!("{} is a required property", display_value(property))
        }
        Kind::Enum { options } => format!("{} is not one of {}", value(), display_value(options)),
        Kind::Constant { expected_value } => {
            format!("{} was expected", display_value(expected_value))
        }
        Kind::Pattern { pattern } => format!("{} does not match {}", value(), quoted(pattern)),
        Kind::AnyOf { .. } | Kind::OneOfNotValid { .. } => {
            format!("{} is not valid under any of the given schemas", value())
        }
        Kind::OneOfMultipleValid { context } => {
            let mut matching = schema["oneOf"]
                .as_array()
                .into_iter()
                .flatten()
                .zip(context)
                .filter_map(|(schema, errors)| errors.is_empty().then_some(schema))
                .map(display_value)
                .collect::<Vec<_>>();
            if !matching.is_empty() {
                matching.rotate_left(1);
            }
            format!("{} is valid under each of {}", value(), matching.join(", "))
        }
        Kind::Not { schema } => format!(
            "{} should not be valid under {}",
            value(),
            display_value(schema)
        ),
        Kind::Contains => format!(
            "{} does not contain items matching the given schema",
            value()
        ),
        Kind::MaxContains { limit } => {
            format!("Too many items match the given schema (expected at most {limit})")
        }
        Kind::UniqueItems => format!("{} has non-unique elements", value()),
        Kind::FalseSchema => format!("False schema does not allow {}", value()),
        Kind::MinItems { limit } | Kind::MinLength { limit } => {
            if *limit == 1 {
                format!("{} should be non-empty", value())
            } else {
                format!("{} is too short", value())
            }
        }
        Kind::MaxItems { limit } | Kind::MaxLength { limit } => {
            if *limit == 0 {
                format!("{} is expected to be empty", value())
            } else {
                format!("{} is too long", value())
            }
        }
        Kind::MinProperties { limit } if *limit == 1 => format!("{} should be non-empty", value()),
        Kind::MinProperties { .. } => format!("{} does not have enough properties", value()),
        Kind::MaxProperties { limit } if *limit == 0 => {
            format!("{} is expected to be empty", value())
        }
        Kind::MaxProperties { .. } => format!("{} has too many properties", value()),
        Kind::AdditionalProperties { unexpected } => {
            let names = unexpected
                .iter()
                .map(|name| quoted(name))
                .collect::<Vec<_>>();
            let count = names.len();
            let mut names = names;
            names.sort_unstable();
            let names = names.join(", ");
            if let Some(patterns) = schema["patternProperties"].as_object() {
                let patterns = patterns
                    .keys()
                    .map(|pattern| quoted(pattern))
                    .collect::<Vec<_>>()
                    .join(", ");
                let verb = if count == 1 { "does" } else { "do" };
                format!("{names} {verb} not match any of the regexes: {patterns}")
            } else {
                let verb = if count == 1 { "was" } else { "were" };
                format!("Additional properties are not allowed ({names} {verb} unexpected)")
            }
        }
        _ => error.to_string(),
    }
}

fn display_value(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(text) => quoted(text),
        Value::Array(items) => {
            let items = items
                .iter()
                .map(display_value)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{items}]")
        }
        Value::Object(fields) => {
            let items = fields
                .iter()
                .map(|(key, value)| format!("{}: {}", quoted(key), display_value(value)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{items}}}")
        }
        Value::Number(number) => number.to_string(),
    }
}

fn pretty_value(value: &Value, column: usize) -> String {
    let inline = display_value(value);
    if column + inline.chars().count() <= 72 {
        return inline;
    }
    let separator = format!(",\n{}", " ".repeat(column + 1));
    match value {
        Value::Object(fields) => {
            let members = fields
                .iter()
                .map(|(name, field)| {
                    let prefix = format!("{}: ", quoted(name));
                    let child = pretty_value(field, column + 1 + prefix.chars().count());
                    format!("{prefix}{child}")
                })
                .collect::<Vec<_>>()
                .join(&separator);
            format!("{{{members}}}")
        }
        Value::Array(items) => {
            let members = items
                .iter()
                .map(|item| pretty_value(item, column + 1))
                .collect::<Vec<_>>()
                .join(&separator);
            format!("[{members}]")
        }
        _ => inline,
    }
}

fn quoted(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut output = String::with_capacity(text.len() + 2);
    output.push(quote);
    for character in text.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character == quote => {
                output.push('\\');
                output.push(character);
            }
            character if character.is_control() => {
                write!(output, "\\x{:02x}", character as u32).expect("format diagnostic");
            }
            character => output.push(character),
        }
    }
    output.push(quote);
    output
}
