// SPDX-License-Identifier: Apache-2.0

use std::{
    io::{self, Read},
    process::Stdio,
    time::Duration,
};

use serde::{Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::Semaphore,
    time::timeout,
};

pub(crate) struct ProcessSandbox {
    slots: Semaphore,
    deadline: Duration,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SandboxError {
    #[error("no free worker")]
    Busy,
    #[error("execution deadline exceeded")]
    Timeout,
    #[error("worker exchange failed")]
    Worker(#[from] io::Error),
}

impl ProcessSandbox {
    pub(crate) fn new(workers: usize, deadline: Duration) -> Self {
        Self {
            slots: Semaphore::new(workers),
            deadline,
        }
    }

    pub(crate) async fn run<Reply: DeserializeOwned>(
        &self,
        worker: &str,
        limit: usize,
        work: impl Serialize,
    ) -> Result<Reply, SandboxError> {
        let _permit = self.slots.try_acquire().map_err(|_| SandboxError::Busy)?;
        let request = serde_json::to_vec(&work).map_err(io::Error::from)?;
        if request.len() > limit {
            return Err(io::Error::other("worker request exceeds its size limit").into());
        }
        let reply = timeout(self.deadline, exchange(worker, &request, limit))
            .await
            .map_err(|_| SandboxError::Timeout)??;
        serde_json::from_slice(&reply)
            .map_err(io::Error::from)
            .map_err(Into::into)
    }
}

async fn exchange(worker: &str, data: &[u8], limit: usize) -> io::Result<Vec<u8>> {
    let mut child = Command::new(std::env::current_exe()?)
        .arg(worker)
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
        .take(limit as u64 + 1);
    let mut bytes = Vec::new();
    tokio::try_join!(
        async move { stdin.write_all(data).await },
        stdout.read_to_end(&mut bytes),
    )?;
    if bytes.len() > limit || !child.wait().await?.success() {
        return Err(io::Error::other("sandbox worker failed"));
    }
    Ok(bytes)
}

pub(crate) fn worker<Work, Reply>(
    limit: usize,
    evaluate: impl FnOnce(Work) -> Reply,
) -> io::Result<()>
where
    Work: DeserializeOwned,
    Reply: Serialize,
{
    #[cfg(unix)]
    limit_worker()?;
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::other("worker request exceeds its size limit"));
    }
    let work = serde_json::from_slice(&bytes)?;
    serde_json::to_writer(io::stdout().lock(), &evaluate(work))?;
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
