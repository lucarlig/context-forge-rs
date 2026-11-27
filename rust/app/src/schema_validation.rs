// SPDX-License-Identifier: Apache-2.0

mod diagnostics;

use std::{io, time::Duration};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::task::JoinError;

use crate::process_sandbox::{self, ProcessSandbox, SandboxError};

#[doc(hidden)]
pub const WORKER_ARG: &str = "--schema-validation-worker";
const MAX_PACKET: usize = 16 * 1024 * 1024;

pub struct SchemaValidation {
    sandbox: ProcessSandbox,
    max_subject_bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub(crate) enum Target {
    Input,
    Output,
}

#[derive(Deserialize, Serialize)]
struct Work<T> {
    schema: T,
    data: T,
    target: Target,
}

impl Default for SchemaValidation {
    fn default() -> Self {
        Self::new(2, Duration::from_secs(1), 262_144)
    }
}

impl SchemaValidation {
    pub(crate) fn new(workers: usize, deadline: Duration, max_subject_bytes: usize) -> Self {
        Self {
            sandbox: ProcessSandbox::new(workers, deadline),
            max_subject_bytes,
        }
    }

    pub(crate) async fn validate(
        &self,
        schema: Value,
        data: Value,
        target: Target,
    ) -> Result<(Value, Option<String>), JoinError> {
        if !diagnostics::uses_regex(&schema) {
            return tokio::task::spawn_blocking(move || {
                let error = diagnostics::validate(&schema, &data, target, false);
                (data, error)
            })
            .await;
        }
        let error = self.validate_regex(&schema, &data, target).await;
        Ok((data, error))
    }

    async fn validate_regex(&self, schema: &Value, data: &Value, target: Target) -> Option<String> {
        let bytes = data.to_string().len();
        let limit = self.max_subject_bytes;
        if bytes > limit {
            let message = format!(
                "instance of {bytes} bytes exceeds the {limit} byte limit for pattern validation"
            );
            return Some(diagnostics::for_target(message, target));
        }
        let work = Work {
            schema,
            data,
            target,
        };
        match self.sandbox.run(WORKER_ARG, MAX_PACKET, work).await {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(%error, "Schema validation failed closed");
                let reason = match error {
                    SandboxError::Busy => "schema validation sandbox has no free worker",
                    SandboxError::Timeout => "schema validation exceeded the execution time limit",
                    SandboxError::Worker(_) => "schema validation sandbox is unavailable",
                };
                let message = format!("schema validation could not be completed safely: {reason}");
                Some(diagnostics::for_target(message, target))
            }
        }
    }
}

#[doc(hidden)]
pub fn worker() -> io::Result<()> {
    process_sandbox::worker(MAX_PACKET, |work: Work<Value>| {
        diagnostics::validate(&work.schema, &work.data, work.target, true)
    })
}
