// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use rmcp::service::{SubscriptionContext, SubscriptionSendError};
use tokio::{
    sync::broadcast,
    task::JoinHandle,
    time::{Instant, sleep},
};
use uuid::Uuid;

use crate::{
    catalog::ResourceSubscriptionTarget,
    credentials::UpstreamCredentials,
    upstream::{
        ResourceListenEnd, ResourceListenEvent, UpstreamClient, UpstreamEndpoint, UpstreamError,
        UpstreamTransport,
    },
};

const MAX_WATCHES: usize = 256;
const LEGACY_REPROBE: Duration = Duration::from_secs(3600);
const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
type Target = Arc<WatchTarget>;
type GatewayScope = (String, String, Option<[u8; 32]>);

#[derive(Eq, Hash, PartialEq)]
struct WatchTarget {
    resource: ResourceSubscriptionTarget,
    credentials: Option<[u8; 32]>,
}

impl WatchTarget {
    fn gateway_scope(&self) -> GatewayScope {
        (
            self.resource.gateway_id.clone(),
            self.resource.url.clone(),
            self.credentials,
        )
    }
}

pub(crate) struct ResourceRelay {
    state: Arc<Mutex<RelayState>>,
    updates: broadcast::Sender<Target>,
}

#[derive(Default)]
struct RelayState {
    watches: HashMap<Target, Watch>,
    legacy: HashMap<GatewayScope, Instant>,
}

struct Watch {
    listeners: usize,
    task: JoinHandle<()>,
}

impl ResourceRelay {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::default(),
            updates: broadcast::channel(256).0,
        }
    }

    pub(crate) fn watch(
        &self,
        targets: Vec<(ResourceSubscriptionTarget, Option<UpstreamCredentials>)>,
        upstream: &UpstreamClient,
    ) -> ResourceWatches {
        let mut active = ResourceWatches {
            state: self.state.clone(),
            targets: HashSet::new(),
            updates: self.updates.subscribe(),
        };
        let mut state = self.state.lock().expect("resource watches");
        let now = Instant::now();
        state.legacy.retain(|_, until| *until > now);
        for (resource, credentials) in targets {
            let endpoint = UpstreamEndpoint {
                url: &resource.url,
                transport: UpstreamTransport::StreamableHttp,
                credentials: credentials.as_ref(),
            };
            let fingerprint = endpoint.credential_fingerprint();
            let target = Arc::new(WatchTarget {
                resource,
                credentials: fingerprint,
            });
            if state.legacy.contains_key(&target.gateway_scope())
                || active.targets.contains(&target)
            {
                continue;
            }
            let full = state.watches.len() >= MAX_WATCHES;
            match state.watches.entry(target.clone()) {
                Entry::Occupied(mut watch) => watch.get_mut().listeners += 1,
                Entry::Vacant(watch) if !full => {
                    let task = tokio::spawn(relay_forever(
                        upstream.clone(),
                        target.clone(),
                        credentials,
                        Arc::downgrade(&self.state),
                        self.updates.clone(),
                    ));
                    watch.insert(Watch { listeners: 1, task });
                }
                Entry::Vacant(_) => continue,
            }
            active.targets.insert(target);
        }
        active
    }
}

pub(crate) struct ResourceWatches {
    state: Arc<Mutex<RelayState>>,
    targets: HashSet<Target>,
    updates: broadcast::Receiver<Target>,
}

impl ResourceWatches {
    pub(crate) fn contains_uri(&self, uri: &str) -> bool {
        self.targets.iter().any(|target| target.resource.uri == uri)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub(crate) async fn publish_updates(
        &mut self,
        context: &SubscriptionContext,
    ) -> Result<(), SubscriptionSendError> {
        let sink = context.sink();
        loop {
            let target = match self.updates.recv().await {
                Ok(target) => target,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            };
            if self.targets.contains(&target) {
                sink.notify_resource_updated(target.resource.uri.clone())
                    .await?;
            }
        }
    }
}

impl Drop for ResourceWatches {
    fn drop(&mut self) {
        let mut state = self.state.lock().expect("resource watches");
        for target in &self.targets {
            if let Entry::Occupied(mut watch) = state.watches.entry(target.clone()) {
                watch.get_mut().listeners -= 1;
                if watch.get().listeners == 0 {
                    watch.remove().task.abort();
                }
            }
        }
    }
}

async fn relay_forever(
    upstream: UpstreamClient,
    target: Target,
    credentials: Option<UpstreamCredentials>,
    state: Weak<Mutex<RelayState>>,
    updates: broadcast::Sender<Target>,
) {
    let mut backoff = INITIAL_BACKOFF;
    let mut relisten = false;
    let endpoint = UpstreamEndpoint {
        url: &target.resource.url,
        transport: UpstreamTransport::StreamableHttp,
        credentials: credentials.as_ref(),
    };
    loop {
        let mut acknowledged = None;
        let result = upstream
            .listen_resource(endpoint, &target.resource.uri, |event| match event {
                ResourceListenEvent::Acknowledged => {
                    acknowledged = Some(Instant::now());
                    if relisten {
                        let _ = updates.send(target.clone());
                    }
                }
                ResourceListenEvent::Updated => {
                    let _ = updates.send(target.clone());
                }
            })
            .await;
        match result {
            Ok(ResourceListenEnd::Legacy) => {
                if let Some(state) = state.upgrade() {
                    state
                        .lock()
                        .expect("resource watches")
                        .legacy
                        .insert(target.gateway_scope(), Instant::now() + LEGACY_REPROBE);
                }
                return;
            }
            Ok(ResourceListenEnd::Declined)
            | Err(UpstreamError::BlockedDestination | UpstreamError::InvalidUrl) => return,
            Ok(ResourceListenEnd::Disconnected) => {}
            Err(error) => {
                tracing::debug!(%error, gateway = %target.resource.gateway_id, "upstream resource subscription disconnected");
            }
        }
        if acknowledged.is_some_and(|at| at.elapsed() >= MAX_BACKOFF) {
            backoff = INITIAL_BACKOFF;
        }
        relisten = true;
        let jitter = 0.5 + f64::from(Uuid::new_v4().as_bytes()[0]) / 256.0;
        sleep(backoff.mul_f64(jitter).min(MAX_BACKOFF)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}
