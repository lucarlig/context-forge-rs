// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use jiff::Timestamp;
use rmcp::{
    model::{
        CancelledNotification, CancelledNotificationParam, ErrorData, NotificationMetaObject,
        SubscriptionFilter,
    },
    service::{SubscriptionContext, SubscriptionSendError},
};
use tokio::{
    sync::broadcast,
    time::{Instant, sleep_until, timeout},
};
use tokio_util::sync::CancellationToken;

use crate::{
    access::{self, Principal},
    catalog::{CatalogScope, CatalogServer, GatewayRegistration},
    credentials::{CredentialCipher, UpstreamCredentials, decode_headers},
    database::Database,
    resource_relay::{ResourceRelay, ResourceWatches},
    upstream::UpstreamClient,
};

const MAX_RESOURCE_URIS_PER_LISTEN: usize = 64;

pub struct ListenSettings {
    pub max_lifetime: Duration,
    pub max_per_principal: usize,
    pub max_anonymous: usize,
    pub shutdown: CancellationToken,
}

impl Default for ListenSettings {
    fn default() -> Self {
        Self {
            max_lifetime: Duration::from_secs(3600),
            max_per_principal: 32,
            max_anonymous: 256,
            shutdown: CancellationToken::new(),
        }
    }
}

pub(crate) struct CatalogSubscriptions {
    settings: ListenSettings,
    active: Arc<Mutex<HashMap<Option<String>, usize>>>,
    registrations: broadcast::Sender<RegistrationChange>,
    resources: ResourceRelay,
}

#[derive(Clone)]
struct RegistrationChange {
    visibility: String,
    team_id: Option<String>,
    owner: String,
}

impl CatalogSubscriptions {
    pub(crate) fn new(settings: ListenSettings) -> Self {
        Self {
            settings,
            active: Arc::default(),
            registrations: broadcast::channel(256).0,
            resources: ResourceRelay::new(),
        }
    }

    pub(crate) fn registered(&self, registration: &GatewayRegistration<'_>) {
        let _ = self.registrations.send(RegistrationChange {
            visibility: registration.visibility.to_owned(),
            team_id: registration.team_id.map(str::to_owned),
            owner: registration.owner_email.to_owned(),
        });
    }

    pub(crate) async fn prepare(
        &self,
        database: &Database,
        upstream: &UpstreamClient,
        cipher: Option<&CredentialCipher>,
        requested: SubscriptionFilter,
        principal: Option<&Principal>,
        server: Option<&CatalogServer>,
    ) -> Result<AcceptedSubscription, ErrorData> {
        let allowed =
            |permission| principal.is_none_or(|principal| principal.token_allows(permission));
        let mut filter = SubscriptionFilter::new();
        filter.tools_list_changed =
            (requested.tools_list_changed == Some(true) && allowed("tools.read")).then_some(true);
        filter.prompts_list_changed = (requested.prompts_list_changed == Some(true)
            && allowed("prompts.read"))
        .then_some(true);
        filter.resources_list_changed = (requested.resources_list_changed == Some(true)
            && allowed("resources.read"))
        .then_some(true);
        let any_requested = wants_list_changes(&requested)
            || requested
                .resource_subscriptions
                .as_ref()
                .is_some_and(|uris| !uris.is_empty());
        let permitted_resources = requested
            .resource_subscriptions
            .as_ref()
            .is_some_and(|uris| !uris.is_empty())
            && allowed("resources.read");
        if any_requested && !wants_list_changes(&filter) && !permitted_resources {
            return Err(ErrorData::internal_error("Internal server error", None));
        }

        let key = principal.map(|principal| principal.email.clone());
        let limit = if key.is_some() {
            self.settings.max_per_principal
        } else {
            self.settings.max_anonymous
        };
        {
            let mut active = self.active.lock().expect("subscription slots");
            if active.get(&key).copied().unwrap_or_default() >= limit {
                return Err(ErrorData::internal_error(
                    "Subscription limit reached",
                    None,
                ));
            }
            *active.entry(key.clone()).or_default() += 1;
        }
        let slot = Slot {
            key,
            active: self.active.clone(),
        };
        let mut distinct = HashSet::new();
        let wanted = requested
            .resource_subscriptions
            .iter()
            .flatten()
            .map(String::as_str)
            .filter(|uri| permitted_resources && distinct.insert(*uri))
            .take(MAX_RESOURCE_URIS_PER_LISTEN)
            .collect::<Vec<_>>();
        let targets = if wanted.is_empty() {
            Vec::new()
        } else {
            database
                .resource_subscription_targets(
                    access::catalog_scope(principal),
                    server.map(|server| server.id.as_str()),
                    &wanted,
                )
                .await
                .map_err(|error| {
                    tracing::error!(%error, "resource subscription target lookup failed");
                    ErrorData::internal_error("Internal server error", None)
                })?
        };
        let targets = targets
            .into_iter()
            .filter_map(|(target, stored)| {
                let credentials = match stored {
                    Some(encoded) => match decode_headers(cipher, &encoded) {
                        Ok(headers) => Some(UpstreamCredentials {
                            headers,
                            ..UpstreamCredentials::default()
                        }),
                        Err(_) => {
                            tracing::debug!(gateway = %target.gateway_id, "could not load upstream resource subscription credentials");
                            return None;
                        }
                    },
                    None => None,
                };
                Some((target, credentials))
            })
            .collect();
        let resources = self.resources.watch(targets, upstream);
        let accepted_uris: Vec<_> = wanted
            .into_iter()
            .filter(|uri| resources.contains_uri(uri))
            .map(str::to_owned)
            .collect();
        filter.resource_subscriptions = (!accepted_uris.is_empty()).then_some(accepted_uris);
        let lifetime = principal
            .and_then(|principal| principal.expires_at)
            .map_or(self.settings.max_lifetime, |expiry| {
                let remaining = expiry
                    .saturating_mul(1000)
                    .saturating_sub(Timestamp::now().as_millisecond());
                self.settings
                    .max_lifetime
                    .min(Duration::from_millis(remaining.max(0) as u64))
            })
            .max(Duration::from_secs(5));
        Ok(AcceptedSubscription {
            filter,
            stream: Arc::new(Mutex::new(Some(SubscriptionStream {
                _slot: slot,
                registrations: self.registrations.subscribe(),
                resources,
                principal: principal.cloned(),
                server_scoped: server.is_some(),
                expires: Instant::now() + lifetime,
                shutdown: self.settings.shutdown.clone(),
            }))),
        })
    }
}

fn wants_list_changes(filter: &SubscriptionFilter) -> bool {
    [
        filter.tools_list_changed,
        filter.prompts_list_changed,
        filter.resources_list_changed,
    ]
    .contains(&Some(true))
}

struct Slot {
    key: Option<String>,
    active: Arc<Mutex<HashMap<Option<String>, usize>>>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut active = self.active.lock().expect("subscription slots");
        if let Some(count) = active.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                active.remove(&self.key);
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct AcceptedSubscription {
    pub(crate) filter: SubscriptionFilter,
    stream: Arc<Mutex<Option<SubscriptionStream>>>,
}

impl AcceptedSubscription {
    pub(crate) async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let stream = self
            .stream
            .lock()
            .expect("subscription stream")
            .take()
            .ok_or_else(|| ErrorData::internal_error("Subscription already consumed", None))?;
        stream.run(context).await;
        Ok(())
    }
}

struct SubscriptionStream {
    _slot: Slot,
    registrations: broadcast::Receiver<RegistrationChange>,
    resources: ResourceWatches,
    principal: Option<Principal>,
    server_scoped: bool,
    expires: Instant,
    shutdown: CancellationToken,
}

impl SubscriptionStream {
    async fn run(mut self, context: SubscriptionContext) {
        let shutdown = self.shutdown.clone();
        let receives_catalog_changes =
            !self.server_scoped && wants_list_changes(context.accepted());
        let receives_resource_updates = !self.resources.is_empty();
        let scope = access::catalog_scope(self.principal.as_ref());
        tokio::select! {
            biased;
            () = context.cancelled() => return,
            () = sleep_until(self.expires) => {},
            () = shutdown.cancelled() => {},
            _ = publish_changes(&mut self.registrations, scope, &context), if receives_catalog_changes => return,
            _ = self.resources.publish_updates(&context), if receives_resource_updates => return,
        }
        let request = context.request_context();
        let mut meta = NotificationMetaObject::new();
        meta.set_subscription_id(request.id.clone());
        let mut params = CancelledNotificationParam::new(
            Some(request.id.clone()),
            Some("Subscription closed by server".into()),
        );
        params.meta = Some(meta);
        let _ = timeout(
            Duration::from_secs(5),
            request
                .peer
                .send_notification(CancelledNotification::new(params).into()),
        )
        .await;
    }
}

async fn publish_changes(
    registrations: &mut broadcast::Receiver<RegistrationChange>,
    scope: CatalogScope<'_>,
    context: &SubscriptionContext,
) -> Result<(), SubscriptionSendError> {
    let filter = context.accepted();
    let sink = context.sink();
    loop {
        let change = match registrations.recv().await {
            Ok(change) => change,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        };
        if !scope.visible(
            &change.visibility,
            change.team_id.as_deref(),
            Some(&change.owner),
        ) {
            continue;
        }
        if filter.prompts_list_changed == Some(true) {
            sink.notify_prompt_list_changed().await?;
        }
        if filter.resources_list_changed == Some(true) {
            sink.notify_resource_list_changed().await?;
        }
        if filter.tools_list_changed == Some(true) {
            sink.notify_tool_list_changed().await?;
        }
    }
}
