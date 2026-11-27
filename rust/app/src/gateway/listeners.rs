// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
};

use redis::AsyncConnectionConfig;
use tokio::{
    sync::Notify,
    task::JoinHandle,
    time::{Instant, MissedTickBehavior, interval, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

use super::health::RefreshSelection;
use super::*;
use crate::{
    config::RedisSettings,
    gateway_records::GatewayRecord,
    upstream::{CatalogListenChange, ListenEnd},
};

const RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
const FIRST_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const UNSUPPORTED_REPROBE: Duration = Duration::from_secs(3600);

pub struct GatewayListeners {
    pub election: ListenerElection,
}

pub enum ListenerElection {
    File(PathBuf),
    Redis {
        connection: Option<RedisSettings>,
        key: String,
        lease: Duration,
        heartbeat: Duration,
        file_fallback: Option<PathBuf>,
    },
}

struct ListenerTask {
    version: i32,
    task: JoinHandle<()>,
}

impl Drop for ListenerTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl GatewayService {
    pub async fn run_gateway_listeners(
        self: Arc<Self>,
        settings: Option<GatewayListeners>,
        shutdown: CancellationToken,
    ) {
        let Some(settings) = settings.filter(|_| self.upstream.can_listen_catalog()) else {
            return;
        };
        let mut leader = ElectionState::default();
        let worker = Uuid::new_v4().simple().to_string();
        let mut watchers = HashMap::new();
        let period = match &settings.election {
            ListenerElection::File(_) => RECONCILE_INTERVAL,
            ListenerElection::Redis { heartbeat, .. } => *heartbeat,
        };
        let mut ticks = interval(period);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut next_reconcile = Instant::now();
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = ticks.tick() => {}
            }
            let primary = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                primary = timeout(period, leader.poll(&settings.election, &worker)) => primary.unwrap_or(false),
            };
            if !primary {
                stop_watchers(&mut watchers).await;
                next_reconcile = Instant::now();
                continue;
            }
            if Instant::now() >= next_reconcile {
                match timeout(period, self.reconcile_catalog_listeners(&mut watchers)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "could not reconcile upstream catalog listeners")
                    }
                    Err(_) => tracing::warn!("upstream catalog listener reconciliation timed out"),
                }
                next_reconcile = Instant::now() + RECONCILE_INTERVAL;
            }
        }
        stop_watchers(&mut watchers).await;
        leader.release(&settings.election, &worker).await;
    }

    async fn reconcile_catalog_listeners(
        self: &Arc<Self>,
        watchers: &mut HashMap<String, ListenerTask>,
    ) -> Result<(), sqlx::Error> {
        let mut active = HashSet::new();
        let mut after = None;
        loop {
            let page = self
                .database
                .gateways_for_health(after.as_deref(), 100)
                .await?;
            let done = page.len() < 100;
            after = page.last().map(|record| record.id.clone());
            for record in page.into_iter().filter(listener_eligible) {
                let id = record.id.clone();
                let retain = watchers.get(&id).is_some_and(|watcher| {
                    watcher.version == record.version && !watcher.task.is_finished()
                });
                if !retain {
                    watchers.remove(&id);
                    let version = record.version;
                    let service = self.clone();
                    let task = tokio::spawn(async move { service.watch_gateway(record).await });
                    watchers.insert(id.clone(), ListenerTask { version, task });
                }
                active.insert(id);
            }
            if done {
                watchers.retain(|id, _| active.contains(id));
                return Ok(());
            }
        }
    }

    async fn watch_gateway(self: Arc<Self>, record: GatewayRecord) {
        let Some(connection) = self
            .database
            .gateway_connection(&record.id, &record.url, true, Some(record.version), None)
            .await
            .ok()
            .flatten()
        else {
            return;
        };
        let Ok(credentials) = self
            .connection_credentials(
                &record.id,
                &record.url,
                connection,
                None,
                None,
                UpstreamUse::Discovery,
            )
            .await
        else {
            tracing::warn!(gateway = %record.id, "could not load upstream catalog listener credentials");
            return;
        };
        let endpoint = UpstreamEndpoint {
            url: &record.url,
            transport: UpstreamTransport::StreamableHttp,
            credentials: credentials.as_ref(),
        };
        let pending = Notify::new();
        let selection = Mutex::new(None::<RefreshSelection>);
        let listen = async {
            let mut backoff = FIRST_BACKOFF;
            loop {
                let started = Instant::now();
                let outcome = self
                    .upstream
                    .listen_catalog(endpoint, |change| {
                        let mut selection = selection.lock().expect("catalog listener selection");
                        let queued = selection.get_or_insert_default();
                        match change {
                            CatalogListenChange::All => *queued = RefreshSelection::ALL,
                            CatalogListenChange::Resources => queued.resources = true,
                            CatalogListenChange::Prompts => queued.prompts = true,
                        }
                        pending.notify_one();
                    })
                    .await;
                match outcome {
                    Ok(ListenEnd::Legacy | ListenEnd::Declined) => {
                        sleep(UNSUPPORTED_REPROBE).await;
                        backoff = FIRST_BACKOFF;
                        continue;
                    }
                    Ok(ListenEnd::Disconnected) => {}
                    Err(error) => {
                        tracing::debug!(gateway = %record.id, %error, "upstream catalog listen failed")
                    }
                }
                if started.elapsed() >= MAX_BACKOFF {
                    backoff = FIRST_BACKOFF;
                }
                let jitter = f64::from(Uuid::new_v4().as_bytes()[0]) / 1020.0;
                sleep(backoff.mul_f64(1.0 + jitter)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        };
        let refresh = async {
            loop {
                pending.notified().await;
                sleep(Duration::from_millis(200)).await;
                let Some(selection) = selection.lock().expect("catalog listener selection").take()
                else {
                    continue;
                };
                let current = match self.database.gateway_records(&record.id).await {
                    Ok(records) => records.into_iter().find(|row| row.id == record.id),
                    Err(error) => {
                        tracing::warn!(gateway = %record.id, %error, "could not load gateway catalog for notification");
                        continue;
                    }
                };
                let Some(current) = current.filter(|current| {
                    listener_eligible(current) && current.version == record.version
                }) else {
                    return;
                };
                let recovering = !current.reachable;
                if let Err(error) = self
                    .refresh_healthy_gateway(
                        &current,
                        &self.upstream,
                        endpoint,
                        recovering,
                        if recovering {
                            RefreshSelection::ALL
                        } else {
                            selection
                        },
                    )
                    .await
                {
                    tracing::warn!(gateway = %record.id, %error, "could not refresh upstream catalog after notification");
                }
            }
        };
        tokio::select! {
            () = listen => {}
            () = refresh => {}
        }
    }
}

async fn stop_watchers(watchers: &mut HashMap<String, ListenerTask>) {
    let mut stopped = watchers
        .drain()
        .map(|(_, watcher)| watcher)
        .collect::<Vec<_>>();
    for watcher in &stopped {
        watcher.task.abort();
    }
    for watcher in &mut stopped {
        let _ = (&mut watcher.task).await;
    }
}

fn listener_eligible(record: &GatewayRecord) -> bool {
    record.enabled
        && record.status == "active"
        && UpstreamTransport::from_name(&record.transport)
            == Some(UpstreamTransport::StreamableHttp)
        && !matches!(record.auth_type.as_deref(), Some("oauth" | "sigv4"))
}

#[derive(Default)]
struct ElectionState {
    lock: Option<File>,
    redis: Option<redis::aio::MultiplexedConnection>,
}

impl ElectionState {
    async fn poll(&mut self, election: &ListenerElection, worker: &str) -> bool {
        match election {
            ListenerElection::File(path) => self.file_lock(path),
            ListenerElection::Redis {
                connection,
                key,
                lease,
                file_fallback,
                ..
            } => {
                let acquired = match connection {
                    Some(settings) => self.redis_lock(settings, key, worker, *lease).await,
                    None => Ok(false),
                };
                match acquired {
                    Ok(primary) if connection.is_some() => {
                        self.lock = None;
                        primary
                    }
                    Err(error) => {
                        self.redis = None;
                        tracing::warn!(%error, "upstream listener Redis election failed");
                        file_fallback
                            .as_deref()
                            .is_some_and(|path| self.file_lock(path))
                    }
                    Ok(_) => file_fallback
                        .as_deref()
                        .is_some_and(|path| self.file_lock(path)),
                }
            }
        }
    }

    fn file_lock(&mut self, path: &Path) -> bool {
        if self.lock.is_some() {
            return true;
        }
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
        {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!(%error, "could not open upstream listener election lock");
                return false;
            }
        };
        match file.try_lock() {
            Ok(()) => {
                self.lock = Some(file);
                true
            }
            Err(TryLockError::WouldBlock) => false,
            Err(TryLockError::Error(error)) => {
                tracing::warn!(%error, "could not acquire upstream listener election lock");
                false
            }
        }
    }

    async fn redis_lock(
        &mut self,
        settings: &RedisSettings,
        key: &str,
        worker: &str,
        lease: Duration,
    ) -> redis::RedisResult<bool> {
        const ELECT: &str = "
            local current = redis.call('GET', KEYS[1])
            if current == ARGV[1] then
                return redis.call('PEXPIRE', KEYS[1], ARGV[2])
            end
            if not current and redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2], 'NX') then
                return 1
            end
            return 0
        ";
        if self.redis.is_none() {
            let config = AsyncConnectionConfig::new()
                .set_connection_timeout(Some(settings.connect_timeout))
                .set_response_timeout(Some(settings.response_timeout));
            self.redis = Some(
                redis::Client::open(settings.url.as_str())?
                    .get_multiplexed_async_connection_with_config(&config)
                    .await?,
            );
        }
        let connection = self.redis.as_mut().expect("Redis connection initialized");
        redis::cmd("EVAL")
            .arg(ELECT)
            .arg(1)
            .arg(key)
            .arg(worker)
            .arg(lease.as_millis().min(u128::from(u64::MAX)) as u64)
            .query_async(connection)
            .await
    }

    async fn release(&mut self, election: &ListenerElection, worker: &str) {
        if let ListenerElection::Redis { key, .. } = election
            && let Some(mut connection) = self.redis.take()
        {
            let _: redis::RedisResult<()> = redis::cmd("EVAL")
                .arg("if redis.call('GET', KEYS[1]) == ARGV[1] then redis.call('DEL', KEYS[1]) end")
                .arg(1)
                .arg(key)
                .arg(worker)
                .query_async(&mut connection)
                .await;
        }
        self.lock = None;
    }
}
