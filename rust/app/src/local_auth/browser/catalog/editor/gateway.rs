// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) fn fields(form: &Form, fields: &mut Map<String, Value>) -> Result<(), CatalogApiError> {
    copy(
        form,
        fields,
        &[
            ("url", "url"),
            ("transport", "transport"),
            ("gateway_mode", "gateway_mode"),
            ("tool_validation_policy", "tool_validation_policy"),
        ],
    );
    for name in [
        "auth_type",
        "auth_username",
        "auth_password",
        "auth_token",
        "auth_header_key",
        "auth_header_value",
        "auth_query_param_key",
        "auth_query_param_value",
        "ca_certificate",
        "ca_certificate_sig",
        "client_cert",
        "client_key",
        "signing_algorithm",
    ] {
        if let Some(value) = nonempty(form, name) {
            fields.insert(name.to_owned(), value.into());
        }
    }
    for name in [
        "auth_headers",
        "identity_propagation",
        "sigv4_config",
        "oauth_config",
    ] {
        json_field(form, fields, name)?;
    }
    if let Some(value) = nonempty(form, "one_time_auth") {
        let enabled = match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "on" | "yes" => true,
            "false" | "0" | "off" | "no" => false,
            _ => return Err(invalid("Invalid one_time_auth")),
        };
        fields.insert("one_time_auth".to_owned(), enabled.into());
    }
    if let Some(interval) = nonempty(form, "refresh_interval_seconds") {
        let interval: i32 = interval
            .trim()
            .parse()
            .map_err(|_| invalid("Invalid refresh interval"))?;
        fields.insert("refresh_interval_seconds".to_owned(), interval.into());
    }
    if let Some(headers) = nonempty(form, "passthrough_headers") {
        let headers = serde_json::from_str(headers)
            .unwrap_or_else(|_| json!(comma_separated(headers).collect::<Vec<_>>()));
        fields.insert("passthrough_headers".to_owned(), headers);
    }
    if !fields.contains_key("oauth_config")
        && let Some(oauth) = oauth_fields(form)
    {
        fields.insert("oauth_config".to_owned(), oauth);
    }
    Ok(())
}

fn oauth_fields(form: &Form) -> Option<Value> {
    let mut oauth = Map::new();
    for name in [
        "grant_type",
        "issuer",
        "token_url",
        "authorization_url",
        "redirect_uri",
        "client_id",
        "client_secret",
        "audience",
        "registration_method",
        "target_audience",
        "subject_token_type",
        "requested_token_type",
        "subject_token_source",
        "token_endpoint_auth_method",
        "actor_token_type",
        "actor_token_source",
        "private_key",
        "private_key_jwt_kid",
    ] {
        if let Some(value) = nonempty(form, &format!("oauth_{name}")) {
            oauth.insert(name.to_owned(), value.trim().into());
        }
    }
    for name in ["scopes", "token_issuer", "resource"] {
        if let Some(values) = nonempty(form, &format!("oauth_{name}")) {
            let values = values
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            let data = match values.as_slice() {
                [value] if name != "scopes" => (*value).into(),
                _ => json!(values),
            };
            oauth.insert(name.to_owned(), data);
        }
    }
    if oauth.get("grant_type").and_then(Value::as_str) == Some("token-exchange") {
        for section in ["discovery", "actor"] {
            let values: Map<String, Value> =
                ["token_url", "client_id", "client_secret", "audience"]
                    .into_iter()
                    .filter_map(|name| {
                        let value = nonempty(form, &format!("oauth_{section}_{name}"))?;
                        Some((name.to_owned(), value.into()))
                    })
                    .collect();
            if !values.is_empty() {
                oauth.insert(section.to_owned(), Value::Object(values));
            }
        }
    }
    (!oauth.is_empty()).then_some(Value::Object(oauth))
}
