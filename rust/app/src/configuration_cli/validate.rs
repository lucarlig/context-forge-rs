// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashSet,
    io::{self, Write},
    path::Path,
};

use jsonschema::{ValidationError, error::ValidationErrorKind};
use serde::Serialize;
use serde_json::{Map, Number, Value};
use zeroize::{Zeroize, Zeroizing};

use super::SETTINGS_SCHEMA;
use crate::{environment::Environment, secret_policy};

mod rules;

#[derive(Serialize)]
struct Issue {
    #[serde(rename = "type")]
    kind: String,
    loc: Vec<Value>,
    msg: String,
}

impl Issue {
    fn value(field: &str, message: &str) -> Self {
        Self {
            kind: "value_error".into(),
            loc: (!field.is_empty())
                .then(|| field.into())
                .into_iter()
                .collect(),
            msg: message.into(),
        }
    }

    fn constraint(error: ValidationError<'_>) -> Self {
        use ValidationErrorKind as Kind;

        let loc = error
            .instance_path()
            .as_str()
            .split('/')
            .skip(1)
            .map(|part| {
                part.parse::<u64>().map_or_else(
                    |_| part.replace("~1", "/").replace("~0", "~").into(),
                    Value::from,
                )
            })
            .collect();
        let kind = error.kind();
        let msg = match kind {
            Kind::Maximum { limit } => format!("Expected a value at most {limit}"),
            Kind::Minimum { limit } => format!("Expected a value at least {limit}"),
            Kind::ExclusiveMaximum { limit } => format!("Expected a value below {limit}"),
            Kind::ExclusiveMinimum { limit } => format!("Expected a value above {limit}"),
            Kind::MaxLength { limit } => format!("Expected at most {limit} characters"),
            Kind::MinLength { limit } => format!("Expected at least {limit} characters"),
            Kind::Enum { options } => format!("Expected one of {options}"),
            Kind::Format { .. } => "Expected a valid URL".into(),
            Kind::Type { .. } | Kind::AnyOf { .. } => "Unexpected value type or format".into(),
            _ => "Value does not satisfy the configuration schema".into(),
        };
        Self {
            kind: kind.keyword().into(),
            loc,
            msg,
        }
    }
}

enum ResultKind {
    Valid,
    Invalid(Vec<Issue>),
    Json(String),
    Security(&'static str, String),
}

pub fn run(path: &Path) -> io::Result<bool> {
    let result = validate(path)?;
    let shown = path.display();
    let mut stderr = io::stderr().lock();
    match result {
        ResultKind::Valid => {
            writeln!(io::stdout().lock(), "✅ Configuration in {shown} is valid")?;
            return Ok(true);
        }
        ResultKind::Invalid(issues) => {
            writeln!(stderr, "❌ Invalid configuration in {shown}")?;
            serde_json::to_writer_pretty(&mut stderr, &issues)?;
            writeln!(stderr)?;
        }
        ResultKind::Json(field) => {
            writeln!(
                stderr,
                "❌ Invalid configuration in {shown}: error parsing value for field \"{field}\". Expected JSON."
            )?;
        }
        ResultKind::Security(field, problem) => {
            writeln!(
                stderr,
                "❌ Security configuration error in {shown}: {field}: {problem}."
            )?;
            if field == "auth_encryption_secret" {
                writeln!(
                    stderr,
                    "Use rotate-credentials before replacing an existing encryption key."
                )?;
            }
            writeln!(
                stderr,
                "Run 'context-forge-rs init-secrets --patch-env PATH' to generate strong deployment secrets."
            )?;
        }
    }
    Ok(false)
}

fn validate(path: &Path) -> io::Result<ResultKind> {
    let source = Environment::from_file(path)?;
    let schema: Value = serde_json::from_str(SETTINGS_SCHEMA)?;
    let properties = schema["properties"]
        .as_object()
        .ok_or_else(|| io::Error::other("configuration schema lacks properties"))?;
    let validator = jsonschema::options()
        .should_validate_formats(true)
        .with_format("uri", rules::is_http_url)
        .build(&schema)
        .map_err(io::Error::other)?;

    let mut issues = Vec::new();
    let mut values = Values {
        explicit: Value::Object(Map::new()),
        properties,
    };
    for (field, property) in properties {
        let name = field.to_ascii_uppercase();
        let raw = match field.as_str() {
            "host" => source.listener("HOST", "MCG_HOST"),
            "port" => source.listener("PORT", "MCG_PORT"),
            _ => source.var_os(&name),
        };
        let Some(raw) = raw else { continue };
        let Ok(raw) = raw.into_string() else {
            issues.push(Issue::value(field, "Expected UTF-8 text"));
            continue;
        };
        let Ok(value) = parse(field, property, Zeroizing::new(raw)) else {
            return Ok(ResultKind::Json(field.to_owned()));
        };
        values.explicit[field] = value;
        if let Some(file) = source.overridden_file_value(&name)
            && matches!(schema_type(property), Some("array" | "object"))
        {
            match rules::collection(field, property, file) {
                Ok(mut discarded) => clear(&mut discarded),
                Err(_) => return Ok(ResultKind::Json(field.to_owned())),
            }
        }
    }

    let mut reported = HashSet::new();
    for error in validator.iter_errors(&values.explicit) {
        let issue = Issue::constraint(error);
        if reported.insert(issue.loc.clone()) {
            issues.push(issue);
        }
    }
    rules::fields(&values, &mut issues);
    if !issues.is_empty() {
        return Ok(ResultKind::Invalid(issues));
    }
    if values.flag("cimd_enabled")
        && values.text("cimd_token_endpoint_auth_method") == "private_key_jwt"
        && values.text("cimd_private_key_path").is_empty()
    {
        return Ok(rules::incompatible(
            "CIMD_TOKEN_ENDPOINT_AUTH_METHOD=private_key_jwt requires CIMD_PRIVATE_KEY_PATH",
        ));
    }
    if let Some(result) = security(&values) {
        return Ok(result);
    }
    if values.flag("enable_sensitive_header_passthrough")
        && !values.flag("enable_header_passthrough")
    {
        return Ok(rules::incompatible(
            "ENABLE_SENSITIVE_HEADER_PASSTHROUGH=true requires ENABLE_HEADER_PASSTHROUGH=true",
        ));
    }
    if values.flag("root_allow_file_scheme") && values.list("root_allowed_file_prefixes").is_empty()
    {
        return Ok(rules::incompatible(
            "ROOT_ALLOW_FILE_SCHEME=true requires ROOT_ALLOWED_FILE_PREFIXES",
        ));
    }
    Ok(ResultKind::Valid)
}

fn schema_type(property: &Value) -> Option<&str> {
    property["type"].as_str().or_else(|| {
        property["anyOf"]
            .as_array()?
            .iter()
            .filter_map(|choice| choice["type"].as_str())
            .find(|kind| *kind != "null")
    })
}

fn parse(field: &str, property: &Value, mut raw: Zeroizing<String>) -> serde_json::Result<Value> {
    let value = match (field, schema_type(property)) {
        ("sqlalchemy_echo", _) => Value::Bool(matches!(
            raw.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )),
        ("log_level", _) => {
            raw.make_ascii_uppercase();
            Value::String(std::mem::take(&mut raw))
        }
        ("ui_base_url" | "ssl_context_cache_ttl", _) if raw.trim().is_empty() => Value::Null,
        (_, Some("boolean")) => match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "t" | "y" | "yes" => Value::Bool(true),
            "0" | "false" | "off" | "f" | "n" | "no" => Value::Bool(false),
            _ => Value::String(std::mem::take(&mut raw)),
        },
        (_, Some("integer")) => integer(raw.trim())
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(std::mem::take(&mut raw))),
        (_, Some("number")) => raw
            .trim()
            .parse()
            .ok()
            .and_then(Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(std::mem::take(&mut raw))),
        (_, Some("array" | "object")) => rules::collection(field, property, &raw)?,
        _ => Value::String(std::mem::take(&mut raw)),
    };
    Ok(value)
}

fn integer(text: &str) -> Option<Number> {
    let normalized;
    let text = if text.contains('_') {
        let bytes = text.as_bytes();
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'_'
                && !(index > 0
                    && bytes[index - 1].is_ascii_digit()
                    && bytes.get(index + 1).is_some_and(u8::is_ascii_digit))
            {
                return None;
            }
        }
        normalized = Zeroizing::new(text.replace('_', ""));
        normalized.as_str()
    } else {
        text
    };
    let digits = text.split_once('.').map_or(text, |(digits, fraction)| {
        if fraction.bytes().all(|digit| digit == b'0') {
            digits
        } else {
            text
        }
    });
    digits
        .parse::<i64>()
        .map(Number::from)
        .or_else(|_| digits.parse::<u64>().map(Number::from))
        .ok()
}

struct Values<'a> {
    explicit: Value,
    properties: &'a Map<String, Value>,
}

impl Values<'_> {
    fn get(&self, field: &str) -> &Value {
        self.explicit
            .get(field)
            .or_else(|| self.properties.get(field)?.get("default"))
            .unwrap_or(&Value::Null)
    }

    fn text(&self, field: &str) -> &str {
        self.get(field).as_str().unwrap_or_default()
    }

    fn flag(&self, field: &str) -> bool {
        self.get(field).as_bool().unwrap_or_default()
    }

    fn list(&self, field: &str) -> &[Value] {
        self.get(field).as_array().map_or(&[], Vec::as_slice)
    }

    fn minimum(&self, field: &str) -> usize {
        self.get(field)
            .as_u64()
            .and_then(|value| value.try_into().ok())
            .unwrap_or_default()
    }

    fn secret(&self, field: &str, default: &'static str) -> &str {
        self.explicit
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or(default)
    }
}

impl Drop for Values<'_> {
    fn drop(&mut self) {
        clear(&mut self.explicit);
    }
}

fn clear(value: &mut Value) {
    match value {
        Value::Object(fields) => fields.values_mut().for_each(clear),
        Value::Array(items) => items.iter_mut().for_each(clear),
        Value::String(text) => text.zeroize(),
        _ => {}
    }
}

fn security(values: &Values<'_>) -> Option<ResultKind> {
    let minimum = values
        .minimum("min_secret_length")
        .max(secret_policy::MIN_SECRET_LENGTH);
    let password_length = values.minimum("password_min_length_user");
    let jwt = values.secret(
        "jwt_secret_key",
        "__REPLACE_ME__run_init-secrets_before_starting",
    );
    let encryption = values.secret(
        "auth_encryption_secret",
        "__REPLACE_ME__run_init-secrets_before_starting",
    );
    let check = |field, secret, length, check_entropy| {
        secret_policy::problem(secret, length, check_entropy)
            .map(|problem| ResultKind::Security(field, problem.to_string()))
    };
    for (field, secret) in [
        ("jwt_secret_key", jwt),
        ("auth_encryption_secret", encryption),
    ] {
        if let Some(issue) = check(field, secret, minimum, true) {
            return Some(issue);
        }
    }
    if values.flag("api_allow_basic_auth") || values.flag("docs_allow_basic_auth") {
        let field = "basic_auth_password";
        if let Some(issue) = check(
            field,
            values.secret(field, "changeme"),
            password_length,
            false,
        ) {
            return Some(issue);
        }
    }
    if values.flag("email_auth_enabled") {
        for field in ["platform_admin_password", "default_user_password"] {
            if let Some(issue) = check(
                field,
                values.secret(field, "changeme"),
                password_length,
                false,
            ) {
                return Some(issue);
            }
        }
    }
    let field = "identity_claims_secret";
    let claims = values.secret(field, "");
    if values.flag("identity_sign_claims") || !claims.is_empty() {
        if let Some(issue) = check(field, claims, minimum, true) {
            return Some(issue);
        }
        if subtle::ConstantTimeEq::ct_eq(claims.as_bytes(), jwt.as_bytes()).into() {
            return Some(ResultKind::Security(
                field,
                "must differ from jwt_secret_key".into(),
            ));
        }
    }
    None
}
