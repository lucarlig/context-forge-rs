// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;

use axum::response::{Sse, sse::Event};
use futures_util::stream;
use tokio::sync::broadcast;

use super::*;

pub(crate) struct ResourceEvents {
    events: broadcast::Sender<Value>,
    shutdown: CancellationToken,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ResourceEvent {
    Added,
    Updated,
    Activated,
    Deactivated,
    Deleted,
}

impl ResourceEvents {
    pub(crate) fn new(shutdown: CancellationToken) -> Self {
        Self {
            events: broadcast::channel(128).0,
            shutdown,
        }
    }

    pub(super) fn publish(&self, event: ResourceEvent, resource: &ResourceRecord) {
        let kind = match event {
            ResourceEvent::Added => "resource_added",
            ResourceEvent::Updated => "resource_updated",
            ResourceEvent::Activated => "resource_activated",
            ResourceEvent::Deactivated => "resource_deactivated",
            ResourceEvent::Deleted => "resource_deleted",
        };
        let mut data = json!({
            "id":resource.id,"uri":resource.uri,"visibility":resource.visibility,
            "team_id":resource.team_id,"owner_email":resource.owner_email
        });
        if event != ResourceEvent::Updated {
            data["name"] = json!(resource.name);
        }
        if event != ResourceEvent::Deleted {
            data["enabled"] = json!(resource.enabled);
        }
        if event == ResourceEvent::Added {
            data["description"] = json!(resource.description);
        }
        let now = Timestamp::now().to_string();
        let timestamp = format!("{}+00:00", now.trim_end_matches('Z'));
        let _ = self
            .events
            .send(json!({"type":kind,"data":data,"timestamp":timestamp}));
    }
}

pub(super) async fn subscribe(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Response, ResourceError> {
    require_resources(&service, &principal, "resources.read", true).await?;
    let event_stream = &service.resource_events;
    let subscription = (
        event_stream.events.subscribe(),
        principal,
        event_stream.shutdown.clone(),
    );
    let events = stream::unfold(
        subscription,
        |(mut receiver, principal, shutdown)| async move {
            loop {
                let event = tokio::select! {
                    biased;
                    _ = shutdown.cancelled() => return None,
                    event = receiver.recv() => event.ok()?,
                };
                let data = &event["data"];
                if access::catalog_scope(Some(&principal)).visible(
                    data["visibility"].as_str().unwrap_or_default(),
                    data["team_id"].as_str(),
                    data["owner_email"].as_str(),
                ) {
                    return Some((
                        Ok::<_, Infallible>(Event::default().data(event.to_string())),
                        (receiver, principal, shutdown),
                    ));
                }
            }
        },
    );
    Ok(Sse::new(events).into_response())
}
