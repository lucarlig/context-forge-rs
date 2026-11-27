// SPDX-License-Identifier: Apache-2.0

use std::process::{Command, Stdio};

use context_forge_rs::schema_validation::WORKER_ARG;
use serde_json::{Value, json};

fn validate(schema: &Value, data: &Value, target: &str) -> Value {
    let mut worker = Command::new(env!("CARGO_BIN_EXE_context-forge-rs"))
        .arg(WORKER_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        worker.stdin.take().unwrap(),
        &json!({"schema":schema,"data":data,"target":target}),
    )
    .unwrap();
    let output = worker.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn worker_applies_pattern_properties_with_gateway_diagnostics() {
    let schema = json!({
        "type":"object",
        "patternProperties":{"^item$":{"type":"string"}}
    });
    assert_eq!(
        validate(&schema, &json!({"item":"ok"}), "Output"),
        Value::Null,
    );
    let error = validate(&schema, &json!({"item":0}), "Input");
    let error = error.as_str().unwrap();
    assert!(error.starts_with("0 is not of type 'string'"), "{error}");
    assert!(error.ends_with("On instance['item']:\n    0"), "{error}");
}
