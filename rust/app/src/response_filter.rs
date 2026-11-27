// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Read},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use cel::{Context, Env, ExecutionError, RuntimeOptions, Value as CelValue, objects::Key};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
    time::timeout,
};

#[doc(hidden)]
pub const WORKER_ARG: &str = "--cel-response-filter-worker";
const MAX_EXPRESSION: usize = 4096;
const MAX_PACKET: usize = 4 * 1024 * 1024 + 64 * 1024;
const MAX_ITERATIONS: u64 = 100_000;

pub struct ResponseFilters {
    workers: Semaphore,
    timeout: Duration,
}

#[derive(Debug, Serialize, Deserialize, thiserror::Error)]
pub(crate) enum FilterError {
    #[error("jsonpath filter is not a valid CEL expression")]
    Syntax,
    #[error("unknown variable {0:?}; available: [\"response\"]")]
    UnknownVariable(String),
    #[error("Input data must be a JSON string, dictionary, or list.")]
    InvalidInput,
    #[error("Invalid JSON string provided.")]
    InvalidJson,
    #[error("jsonpath filter exceeded the execution time limit")]
    Timeout,
    #[error("jsonpath filter sandbox is busy, try again")]
    Busy,
    #[error("Error applying jsonpath filter")]
    Evaluation,
}

impl FilterError {
    pub(crate) fn invocation_message(&self) -> String {
        match self {
            Self::UnknownVariable(_) => Self::Evaluation.to_string(),
            error => error.to_string(),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Work {
    expression: String,
    job: Job,
}

#[derive(Deserialize, Serialize)]
enum Job {
    Check,
    Evaluate(Value),
}

impl Default for ResponseFilters {
    fn default() -> Self {
        Self::new(2, Duration::from_secs(2))
    }
}

impl ResponseFilters {
    pub(crate) fn new(workers: usize, timeout: Duration) -> Self {
        Self {
            workers: Semaphore::new(workers),
            timeout,
        }
    }

    pub(crate) async fn validate(&self, expression: &str) -> Result<(), FilterError> {
        let expression = expression.trim();
        if expression.is_empty() {
            return Ok(());
        }
        self.run(expression, None).await.map(|_| ())
    }

    pub(crate) async fn apply(
        &self,
        expression: &str,
        response: Value,
    ) -> Result<Value, FilterError> {
        let expression = expression.trim();
        if expression.is_empty() {
            return Ok(response);
        }
        let response = match response {
            Value::String(json) => {
                serde_json::from_str(&json).map_err(|_| FilterError::InvalidJson)?
            }
            input @ (Value::Object(_) | Value::Array(_)) => input,
            _ => return Err(FilterError::InvalidInput),
        };
        self.run(expression, Some(response)).await
    }

    async fn run(&self, expression: &str, input: Option<Value>) -> Result<Value, FilterError> {
        if expression.chars().count() > MAX_EXPRESSION || expression.starts_with(['.', '$']) {
            return Err(FilterError::Syntax);
        }
        let _permit = self.workers.try_acquire().map_err(|_| FilterError::Busy)?;
        let job = input.map_or(Job::Check, Job::Evaluate);
        let data = serde_json::to_vec(&Work {
            expression: expression.to_owned(),
            job,
        })
        .map_err(|_| FilterError::Evaluation)?;
        if data.len() > MAX_PACKET {
            return Err(FilterError::Evaluation);
        }
        let bytes = timeout(self.timeout, exchange(&data))
            .await
            .map_err(|_| FilterError::Timeout)?
            .map_err(|_| FilterError::Evaluation)?;
        serde_json::from_slice(&bytes).map_err(|_| FilterError::Evaluation)?
    }
}

async fn exchange(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg(WORKER_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut stdin = child.stdin.take().expect("piped worker input");
    let mut stdout = child
        .stdout
        .take()
        .expect("piped worker output")
        .take(MAX_PACKET as u64 + 1);
    let mut bytes = Vec::new();
    tokio::try_join!(
        async move { stdin.write_all(data).await },
        stdout.read_to_end(&mut bytes),
    )?;
    if bytes.len() > MAX_PACKET || !child.wait().await?.success() {
        return Err(io::Error::other("CEL response filter worker failed"));
    }
    Ok(bytes)
}

#[doc(hidden)]
pub fn worker() -> io::Result<()> {
    #[cfg(unix)]
    limit_worker()?;
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_PACKET as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PACKET {
        return Err(io::Error::other("CEL request exceeds its size limit"));
    }
    let work: Work = serde_json::from_slice(&bytes)?;
    let reply = evaluate(work);
    serde_json::to_writer(io::stdout().lock(), &reply)?;
    Ok(())
}

#[cfg(unix)]
fn limit_worker() -> io::Result<()> {
    let set_limit = |resource, ceiling| {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // The pointer addresses a live rlimit object through both system calls.
        unsafe {
            if libc::getrlimit(resource, &mut limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            limit.rlim_max = limit.rlim_max.min(ceiling);
            limit.rlim_cur = limit.rlim_cur.min(limit.rlim_max);
            if libc::setrlimit(resource, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    };
    set_limit(libc::RLIMIT_CORE, 0)?;
    #[cfg(target_os = "linux")]
    set_limit(libc::RLIMIT_AS, 256 * 1024 * 1024)?;
    Ok(())
}

fn evaluate(work: Work) -> Result<Value, FilterError> {
    if work.expression.chars().count() > MAX_EXPRESSION || work.expression.starts_with(['.', '$']) {
        return Err(FilterError::Syntax);
    }
    let mut env = Env::stdlib();
    env.set_options(RuntimeOptions::default().with_max_iterations(MAX_ITERATIONS));
    let program = env
        .compile(&work.expression)
        .map_err(|_| FilterError::Syntax)?;
    if let Some(name) = program
        .references()
        .variables()
        .into_iter()
        .filter(|name| *name != "response")
        .min()
    {
        return Err(FilterError::UnknownVariable(name.to_owned()));
    }
    let Job::Evaluate(input) = work.job else {
        return Ok(Value::Null);
    };
    let mut context = Context::with_env(Arc::new(env));
    context.add_variable_from_value("response", cel_value(input));
    let value = program.execute(&context).map_err(|error| match error {
        ExecutionError::IterationBudgetExceeded { .. } | ExecutionError::Interrupted => {
            FilterError::Timeout
        }
        _ => FilterError::Evaluation,
    })?;
    let mut remaining = MAX_PACKET;
    response_json(&value, &mut remaining)
}

fn cel_value(value: Value) -> CelValue {
    match value {
        Value::Null => CelValue::Null,
        Value::Bool(flag) => CelValue::Bool(flag),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                CelValue::Int(integer)
            } else if let Some(integer) = number.as_u64() {
                CelValue::UInt(integer)
            } else {
                CelValue::Float(number.as_f64().expect("JSON number is finite"))
            }
        }
        Value::String(text) => text.into(),
        Value::Array(values) => {
            CelValue::List(Arc::new(values.into_iter().map(cel_value).collect()))
        }
        Value::Object(values) => {
            let map: std::collections::HashMap<_, _> = values
                .into_iter()
                .map(|(key, value)| (key, cel_value(value)))
                .collect();
            CelValue::Map(map.into())
        }
    }
}

fn charge(remaining: &mut usize, bytes: usize) -> Result<(), FilterError> {
    *remaining = remaining
        .checked_sub(bytes)
        .ok_or(FilterError::Evaluation)?;
    Ok(())
}

fn response_json(value: &CelValue, remaining: &mut usize) -> Result<Value, FilterError> {
    charge(remaining, 1)?;
    match value {
        CelValue::String(value) => {
            charge(remaining, value.len())?;
            Ok(value.as_str().into())
        }
        CelValue::Bytes(value) => {
            charge(remaining, value.len().saturating_mul(3))?;
            Ok(String::from_utf8_lossy(value).into_owned().into())
        }
        CelValue::Duration(value) => {
            charge(remaining, 24)?;
            Ok((value.num_seconds() as f64 + f64::from(value.subsec_nanos()) / 1e9).into())
        }
        CelValue::Timestamp(value) => {
            let text = value.to_rfc3339();
            charge(remaining, text.len())?;
            Ok(text.into())
        }
        CelValue::List(values) => values
            .iter()
            .map(|value| response_json(value, remaining))
            .collect(),
        CelValue::Map(map) => map
            .map
            .iter()
            .map(|(key, value)| {
                let key = match key {
                    Key::Bool(true) => "True".to_owned(),
                    Key::Bool(false) => "False".to_owned(),
                    key => key.to_string(),
                };
                charge(remaining, key.len())?;
                Ok((key, response_json(value, remaining)?))
            })
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(Value::Object),
        CelValue::Null => Ok(Value::Null),
        CelValue::Bool(flag) => Ok((*flag).into()),
        CelValue::Int(value) => Ok((*value).into()),
        CelValue::UInt(value) => Ok((*value).into()),
        CelValue::Float(value) => Ok((*value).into()),
        _ => Err(FilterError::Evaluation),
    }
}
