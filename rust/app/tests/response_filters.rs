// SPDX-License-Identifier: Apache-2.0

use std::process::{Command, Stdio};

use context_forge_rs::response_filter::WORKER_ARG;
use serde_json::{Value, json};

fn filter_worker(expression: &str, job: Value) -> Value {
    let mut worker = Command::new(env!("CARGO_BIN_EXE_context-forge-rs"))
        .arg(WORKER_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    serde_json::to_writer(
        worker.stdin.take().unwrap(),
        &json!({"expression":expression,"job":job}),
    )
    .unwrap();
    let output = worker.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn filter_worker_binds_only_the_response_and_macro_variables() {
    assert_eq!(
        filter_worker(
            "response.items.map(item, item.count + 1)",
            json!({"Evaluate":{"items":[{"count":2},{"count":7}]}}),
        ),
        json!({"Ok":[3,8]})
    );
    assert_eq!(
        filter_worker("response == null", json!({"Evaluate":null})),
        json!({"Ok":true})
    );
    assert_eq!(
        filter_worker("response.map(x, x) + x", json!("Check")),
        json!({"Err":{"UnknownVariable":"x"}})
    );
}

#[test]
fn filter_worker_aborts_a_comprehension_that_exceeds_the_iteration_budget() {
    let row = vec![0; 320];
    let payload = vec![row; 320];
    assert_eq!(
        filter_worker(
            "response.all(row, row.all(value, value == 0)) || true",
            json!({"Evaluate":payload}),
        ),
        json!({"Err":"Timeout"})
    );
}
