// SPDX-License-Identifier: Apache-2.0

use serde_json::{Map, Value, json};

const METHODS: [(&str, &str); 11] = [
    ("message/send", "SendMessage"),
    ("message/stream", "SendStreamingMessage"),
    ("tasks/get", "GetTask"),
    ("tasks/list", "ListTasks"),
    ("tasks/cancel", "CancelTask"),
    ("tasks/resubscribe", "SubscribeToTask"),
    (
        "tasks/pushNotificationConfig/set",
        "CreateTaskPushNotificationConfig",
    ),
    (
        "tasks/pushNotificationConfig/get",
        "GetTaskPushNotificationConfig",
    ),
    (
        "tasks/pushNotificationConfig/list",
        "ListTaskPushNotificationConfigs",
    ),
    (
        "tasks/pushNotificationConfig/delete",
        "DeleteTaskPushNotificationConfig",
    ),
    ("agent/getAuthenticatedExtendedCard", "GetExtendedAgentCard"),
];

pub(super) fn version_header(version: &str) -> String {
    let version = version.trim().trim_start_matches(['v', 'V']);
    let mut parts = version.split('.').filter(|part| !part.is_empty());
    match (parts.next(), parts.next()) {
        (None, _) => "1.0".into(),
        (Some(major), Some(minor)) => format!("{major}.{minor}"),
        (Some(major), None) if major.bytes().all(|byte| byte.is_ascii_digit()) => {
            format!("{major}.0")
        }
        _ => version.to_owned(),
    }
}

pub(super) fn rpc_request(mut input: Map<String, Value>, version: &str) -> Value {
    let modern = is_modern(version);
    let id = input.remove("id").unwrap_or_else(|| json!(1));
    let mut method = input
        .remove("method")
        .and_then(|method| method.as_str().map(str::trim).map(str::to_owned));
    let raw = input.remove("jsonrpc").is_some() && method.is_some();
    if modern && method.as_deref() == Some("agent/getExtendedCard") {
        method = Some("GetExtendedAgentCard".into());
    }
    let method = match method.as_deref().filter(|method| !method.is_empty()) {
        Some(method) => METHODS
            .iter()
            .find_map(|&(legacy, current)| {
                if modern && method == legacy {
                    Some(current)
                } else if !modern && method == current {
                    Some(legacy)
                } else {
                    None
                }
            })
            .unwrap_or(method),
        None if modern => "SendMessage",
        None => "message/send",
    };
    let mut params = if raw {
        input.remove("params").unwrap_or_else(|| json!({}))
    } else if let Some(explicit) = input.remove("params").filter(|value| !value.is_null()) {
        explicit
    } else if let Some(message) = input.remove("message").filter(|value| !value.is_null()) {
        json!({"message":message})
    } else {
        let text_key = ["query", "text"]
            .into_iter()
            .find(|key| input.get(*key).is_some_and(Value::is_string));
        if let Some(key) = text_key {
            let query = input.remove(key).expect("validated query field");
            let message_id = input
                .remove("messageId")
                .filter(|value| value.as_str().is_some_and(|value| !value.is_empty()))
                .unwrap_or_else(|| {
                    json!(format!("contextforge-{}", uuid::Uuid::new_v4().simple()))
                });
            input.insert(
                "message".into(),
                json!({"messageId":message_id,"role":"user","parts":[{"text":query}]}),
            );
        }
        Value::Object(input)
    };
    if let Some(message) = params.get_mut("message").and_then(Value::as_object_mut) {
        normalize_message(message, modern);
    }
    json!({"jsonrpc":"2.0","method":method,"params":params,"id":id})
}

pub(super) fn is_modern(version: &str) -> bool {
    let version = version_header(version);
    let major = version.split('.').next().unwrap_or(&version);
    major
        .parse::<u32>()
        .map_or_else(|_| major.starts_with('1'), |major| major >= 1)
}

fn normalize_message(message: &mut Map<String, Value>, modern: bool) {
    if modern {
        message.remove("kind");
    } else {
        message.entry("kind").or_insert_with(|| json!("message"));
    }
    if let Some(role) = message.get_mut("role")
        && let Some(value) = role.as_str().map(str::trim).filter(|role| !role.is_empty())
    {
        let lower = value.to_ascii_lowercase();
        *role = json!(match (modern, lower.as_str()) {
            (true, "user") => "ROLE_USER",
            (true, "agent") => "ROLE_AGENT",
            (true, "system") => "ROLE_SYSTEM",
            (true, _) => value,
            (false, "role_user") => "user",
            (false, "role_agent") => "agent",
            (false, "role_system") => "system",
            (false, _) => lower.as_str(),
        });
    }
    if let Some(parts) = message.get_mut("parts").and_then(Value::as_array_mut) {
        for part in parts.iter_mut().filter_map(Value::as_object_mut) {
            let kind = part.remove("kind");
            let alias = part.remove("type");
            if modern {
                continue;
            }
            let discriminator = kind.or(alias).filter(|value| !value.is_null()).or_else(|| {
                if part.contains_key("text") {
                    Some(json!("text"))
                } else if part.contains_key("data") {
                    Some(json!("data"))
                } else if ["file", "fileId", "uri", "url"]
                    .iter()
                    .any(|key| part.contains_key(*key))
                {
                    Some(json!("file"))
                } else {
                    None
                }
            });
            if let Some(discriminator) = discriminator {
                part.insert("kind".into(), discriminator);
            }
        }
    }
}
