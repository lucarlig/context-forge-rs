// SPDX-License-Identifier: Apache-2.0
//! Bounded history for reconnecting to legacy MCP streams.

use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use axum::{body::Bytes, response::sse::Event};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use uuid::Uuid;

use crate::redis_events::RedisEventJournal;

pub(crate) const HISTORY_BUDGET: usize = 64 * 1024 * 1024;
const ENTRY_OVERHEAD: usize = 128;

pub(crate) enum PassiveEvents {
    Local(Arc<Journal>),
    Redis(RedisEventJournal),
}

impl PassiveEvents {
    pub(crate) async fn publish(&self, data: String) {
        match self {
            Self::Local(journal) => {
                journal.publish(Some(Arc::from(data)));
            }
            Self::Redis(journal) => {
                if let Err(error) = journal.publish(&data).await {
                    tracing::warn!(%error, "MCP passive event could not be recorded");
                }
            }
        }
    }

    pub(crate) fn local(&self) -> Option<&Arc<Journal>> {
        match self {
            Self::Local(journal) => Some(journal),
            Self::Redis(_) => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct Frame {
    stream: Uuid,
    sequence: u64,
    data: Option<Arc<str>>,
}

impl Frame {
    fn id(&self) -> String {
        format!("{}.{}", self.stream.simple(), self.sequence)
    }

    pub(crate) fn into_event(self) -> Event {
        let event = Event::default().id(self.id());
        match self.data {
            Some(data) => event.event("message").data(&*data),
            None => event.data(""),
        }
    }
}

struct StoredFrame {
    frame: Frame,
    published: Instant,
    _memory: OwnedSemaphorePermit,
}

#[derive(Default)]
struct History {
    next: u64,
    frames: VecDeque<StoredFrame>,
    finished_at: Option<Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalMode {
    Response { needs_tool_execution: bool },
    Passive,
}

pub(crate) struct Journal {
    pub(crate) key: Uuid,
    pub(crate) authorization: Option<[u8; 32]>,
    mode: JournalMode,
    capacity: usize,
    retention: Duration,
    budget: Arc<Semaphore>,
    history: Mutex<History>,
    changed: watch::Sender<()>,
    post_open: AtomicBool,
}

impl Journal {
    pub(crate) fn new(
        authorization: Option<[u8; 32]>,
        mode: JournalMode,
        capacity: usize,
        retention: Duration,
        budget: Arc<Semaphore>,
    ) -> Self {
        Self {
            key: Uuid::new_v4(),
            authorization,
            mode,
            capacity,
            retention,
            budget,
            history: Mutex::new(History::default()),
            changed: watch::Sender::new(()),
            post_open: AtomicBool::new(matches!(mode, JournalMode::Response { .. })),
        }
    }

    pub(crate) fn needs_tool_execution(&self) -> bool {
        !matches!(
            self.mode,
            JournalMode::Response {
                needs_tool_execution: false
            }
        )
    }

    fn prune_old_frames(&self, history: &mut History) {
        if self.mode == JournalMode::Passive {
            while history
                .frames
                .front()
                .is_some_and(|frame| frame.published.elapsed() >= self.retention)
            {
                history.frames.pop_front();
            }
        }
    }

    pub(crate) fn prune(&self) {
        self.prune_old_frames(&mut self.history.lock().expect("event history lock"));
    }

    pub(crate) fn is_post_open(&self) -> bool {
        self.post_open.load(Ordering::Acquire)
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.history
            .lock()
            .expect("event history lock")
            .finished_at
            .is_some()
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.history
            .lock()
            .expect("event history lock")
            .finished_at
            .is_some_and(|finished| finished.elapsed() >= self.retention)
    }

    pub(crate) fn publish(&self, data: Option<Arc<str>>) -> Frame {
        let mut history = self.history.lock().expect("event history lock");
        self.prune_old_frames(&mut history);
        let frame = Frame {
            stream: self.key,
            sequence: history.next,
            data,
        };
        history.next += 1;
        if history.frames.len() == self.capacity {
            history.frames.pop_front();
        }
        let cost = frame.data.as_ref().map_or(0, |data| data.len()) + ENTRY_OVERHEAD;
        let memory = u32::try_from(cost)
            .ok()
            .and_then(|cost| self.budget.clone().try_acquire_many_owned(cost).ok());
        if let Some(memory) = memory {
            history.frames.push_back(StoredFrame {
                frame: frame.clone(),
                published: Instant::now(),
                _memory: memory,
            });
        } else {
            // Invalidate earlier cursors when an event cannot be retained.
            // The current connection still receives the event.
            history.frames.clear();
        }
        drop(history);
        self.changed.send_replace(());
        frame
    }

    pub(crate) fn finish(&self) {
        self.history.lock().expect("event history lock").finished_at = Some(Instant::now());
        self.changed.send_replace(());
    }

    pub(crate) fn prime(&self) -> Bytes {
        let id = self.publish(None).id();
        // Axum's Event omits an empty data field. MCP priming requires one.
        Bytes::from(format!("id: {id}\ndata: \n\n"))
    }

    pub(crate) fn live_post(self: &Arc<Self>) -> LivePost {
        LivePost(self.clone())
    }

    pub(crate) fn resume(self: &Arc<Self>, sequence: u64) -> Option<Replay> {
        let changed = self.changed.subscribe();
        let mut history = self.history.lock().expect("event history lock");
        self.prune_old_frames(&mut history);
        if !history
            .frames
            .iter()
            .any(|entry| entry.frame.sequence == sequence)
        {
            return None;
        }
        Some(Replay {
            journal: self.clone(),
            next: sequence + 1,
            changed,
        })
    }

    pub(crate) fn listen(self: &Arc<Self>, include_backlog: bool) -> Replay {
        let changed = self.changed.subscribe();
        let mut history = self.history.lock().expect("event history lock");
        self.prune_old_frames(&mut history);
        let next = if include_backlog {
            history
                .frames
                .front()
                .map_or(history.next, |frame| frame.frame.sequence)
        } else {
            history.next
        };
        Replay {
            journal: self.clone(),
            next,
            changed,
        }
    }
}

pub(crate) struct LivePost(Arc<Journal>);

impl Drop for LivePost {
    fn drop(&mut self) {
        self.0.post_open.store(false, Ordering::Release);
    }
}

pub(crate) struct Replay {
    journal: Arc<Journal>,
    next: u64,
    changed: watch::Receiver<()>,
}

impl Replay {
    pub(crate) async fn next(&mut self) -> Option<Frame> {
        loop {
            {
                let history = self.journal.history.lock().expect("event history lock");
                if let Some(frame) = history.frames.front()
                    && let Some(offset) = self.next.checked_sub(frame.frame.sequence)
                    && let Ok(index) = usize::try_from(offset)
                    && let Some(entry) = history.frames.get(index)
                {
                    self.next += 1;
                    return Some(entry.frame.clone());
                }
                // A gap is possible when the listener falls behind the ring.
                if self.next < history.next || history.finished_at.is_some() {
                    return None;
                }
            }
            self.changed.changed().await.ok()?;
        }
    }
}

pub(crate) fn parse_cursor(value: &str) -> Option<(Uuid, u64)> {
    let (key, sequence) = value.split_once('.')?;
    Some((Uuid::parse_str(key).ok()?, sequence.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replay_stops_at_an_evicted_cursor_and_drains_a_retained_stream() {
        let journal = Arc::new(Journal::new(
            None,
            JournalMode::Response {
                needs_tool_execution: false,
            },
            2,
            Duration::from_secs(60),
            Arc::new(Semaphore::new(4096)),
        ));
        journal.prime();
        let progress = journal.publish(Some(Arc::from("progress")));
        let result = journal.publish(Some(Arc::from("result")));
        journal.finish();
        assert!(journal.resume(0).is_none());
        let mut replay = journal.resume(progress.sequence).unwrap();
        assert_eq!(replay.next().await.unwrap().id(), result.id());
        assert!(replay.next().await.is_none());
    }
}
