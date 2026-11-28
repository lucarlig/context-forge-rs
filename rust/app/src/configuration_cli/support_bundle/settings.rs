// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashSet, env, io};

use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

use crate::{config::Settings, environment, http_boundary::allowed_origins};

use super::{
    Redactor,
    redaction::{MASK, secret_name},
};
use crate::configuration_cli::{SETTINGS_SCHEMA, validate};

const DEFAULTS: &str = include_str!("../../config/support-defaults-v1.1.2.json");

pub(super) struct Snapshot {
    properties: Map<String, Value>,
    dynamic_defaults: Map<String, Value>,
    secrets: HashSet<String>,
}

impl Snapshot {
    pub(super) fn new() -> io::Result<Self> {
        let mut schema: Value = serde_json::from_str(SETTINGS_SCHEMA)?;
        let Value::Object(properties) = schema["properties"].take() else {
            return Err(io::Error::other("configuration schema lacks properties"));
        };
        let secrets = properties
            .iter()
            .filter_map(|(name, property)| {
                let field = name.to_ascii_lowercase();
                let protected = typed_secret(property)
                    || (string_property(property)
                        && !matches!(
                            field.as_str(),
                            "jwt_private_key_path" | "cimd_private_key_path"
                        )
                        && secret_name(&field, &[]));
                protected.then_some(name.to_ascii_uppercase())
            })
            .collect();
        Ok(Self {
            properties,
            dynamic_defaults: serde_json::from_str(DEFAULTS)?,
            secrets,
        })
    }

    pub(super) fn text(&self, name: &str, default: &str) -> Zeroizing<String> {
        read(name).unwrap_or_else(|| Zeroizing::new(default.to_owned()))
    }

    pub(super) fn redactor(&self) -> Redactor {
        let mut values: Vec<_> = self.secrets.iter().filter_map(|name| read(name)).collect();
        values.extend(env::vars_os().filter_map(|(name, value)| {
            let name = name.into_string().ok()?.to_ascii_uppercase();
            (self.secret_env(&name) && !name.ends_with("_URL") && name != "BASIC_AUTH_USER")
                .then(|| value.into_string().ok().map(Zeroizing::new))
                .flatten()
        }));
        Redactor::new(values)
    }

    pub(super) fn settings(&self, redactor: &Redactor) -> Value {
        let mut fields = Map::new();
        for (key, property) in &self.properties {
            let name = key.to_ascii_uppercase();
            if self.secrets.contains(&name) {
                continue;
            }
            let field = if key == "DEPLOYMENT_ENV" {
                "deployment_env"
            } else {
                key
            };
            let raw = match name.as_str() {
                "HOST" => environment::listener("HOST", "MCG_HOST")
                    .ok()
                    .flatten()
                    .map(Zeroizing::new),
                "PORT" => environment::listener("PORT", "MCG_PORT")
                    .ok()
                    .flatten()
                    .map(Zeroizing::new),
                "DEPLOYMENT_ENV" => read("DEPLOYMENT_ENV").or_else(|| read("ENVIRONMENT")),
                _ => read(&name),
            };
            let value = if let Some(raw) = raw {
                validate::parse(field, property, raw).unwrap_or_default()
            } else {
                self.dynamic_defaults
                    .get(field)
                    .or_else(|| property.get("default"))
                    .cloned()
                    .unwrap_or_default()
            };
            fields.insert(field.to_owned(), redactor.value(value));
        }

        // These values depend on other fields and are populated at gateway startup.
        if fields["mcp_require_auth"].is_null()
            && let Ok(required) = Settings::mcp_requires_auth()
        {
            fields.insert("mcp_require_auth".into(), required.into());
        }
        if fields["sso_issuers"].is_null() {
            fields.insert("sso_issuers".into(), Value::Array(Vec::new()));
        }
        if read("REQUIRE_STRONG_SECRETS").is_none() && fields["environment"] == "production" {
            fields.insert("require_strong_secrets".into(), true.into());
        }
        if read("ALLOWED_ORIGINS").is_none() {
            let port = fields["port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .unwrap_or(4444);
            if let Ok(origins) = allowed_origins(port) {
                let mut origins: Vec<_> = origins
                    .into_iter()
                    .map(|origin| redactor.text(&origin))
                    .collect();
                origins.sort_unstable();
                fields.insert("allowed_origins".into(), Value::from(origins));
            }
        }
        Value::Object(fields)
    }

    pub(super) fn process_environment(&self, redactor: &Redactor) -> Value {
        Value::Object(
            env::vars_os()
                .filter_map(|(name, value)| {
                    let name = name.into_string().ok()?;
                    let mut value = value.into_string().ok()?;
                    let safe = if self.secret_env(&name.to_ascii_uppercase()) {
                        MASK.to_owned()
                    } else {
                        redactor.text(&value)
                    };
                    value.zeroize();
                    Some((redactor.text(&name), safe.into()))
                })
                .collect(),
        )
    }

    fn secret_env(&self, name: &str) -> bool {
        self.secrets.contains(name)
            || name.ends_with("_URL")
            || name == "BASIC_AUTH_USER"
            || secret_name(name, &["pass", "key", "token", "authorization"])
    }
}

fn read(name: &str) -> Option<Zeroizing<String>> {
    environment::var(name).ok().map(Zeroizing::new)
}

fn typed_secret(property: &Value) -> bool {
    property["format"] == "password"
        || property["writeOnly"] == true
        || property["anyOf"]
            .as_array()
            .is_some_and(|choices| choices.iter().any(typed_secret))
        || property.get("items").is_some_and(typed_secret)
        || property
            .get("additionalProperties")
            .is_some_and(typed_secret)
}

fn string_property(property: &Value) -> bool {
    property["type"] == "string"
        || property["anyOf"]
            .as_array()
            .is_some_and(|choices| choices.iter().any(string_property))
}
