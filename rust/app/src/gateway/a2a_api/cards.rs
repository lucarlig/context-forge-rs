// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::catalog::NewAgentCard;

mod discovery;
mod document;
mod generated;

use discovery::{CardDocument, ExtendedFailure, FetchFailure, FoundCard};
pub(super) use generated::read as generated;

#[derive(Deserialize)]
pub(super) struct CardRequest {
    #[serde(alias = "baseUrl")]
    base_url: String,
    path: Option<String>,
    #[serde(default)]
    headers: Option<std::collections::BTreeMap<String, String>>,
}

pub(super) async fn discover(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Json(request): Json<CardRequest>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.create").await?;
    let base = discovery::base_url(&request.base_url)?;
    let headers = discovery::headers(request.headers.unwrap_or_default())?;
    let result = discovery::fetch(&app, base, request.path.as_deref(), &headers).await?;
    Ok(Json(discovery::wire(result)))
}

pub(super) async fn registration(
    app: &GatewayService,
    card_url: Option<&str>,
    endpoint: &str,
    headers: Option<&HeaderMap>,
) -> Result<Option<FoundCard>, CatalogApiError> {
    let Some(card_url) = card_url.filter(|url| !url.trim().is_empty()) else {
        return Ok(None);
    };
    let base = discovery::base_url(card_url)?;
    let headers = headers.filter(|_| {
        url::Url::parse(endpoint).is_ok_and(|endpoint| base.origin() == endpoint.origin())
    });
    let empty = HeaderMap::new();
    let message = match discovery::fetch(app, base, None, headers.unwrap_or(&empty)).await? {
        Ok(card) => {
            if !matches!(card.extended, Some(Err(ExtendedFailure::AuthRejected))) {
                return Ok(Some(card));
            }
            "The agent rejected the credentials when the extended Agent Card was requested. Supply valid credentials."
        }
        Err(FetchFailure::NoCard) => "No A2A Agent Card was found at the given card URL",
        Err(FetchFailure::AuthRequired(_)) => {
            "The Agent Card requires credentials. Supply valid credentials for the card URL."
        }
        Err(FetchFailure::Unreachable) => "The Agent Card URL could not be reached",
    };
    Err(CatalogApiError::detail(StatusCode::BAD_REQUEST, message))
}

pub(super) fn stored_rows(found: Option<&FoundCard>) -> Vec<NewAgentCard<'_>> {
    let Some(found) = found else {
        return Vec::new();
    };
    let public = &found.public;
    let mut rows = vec![stored_row("public", public, public)];
    if let Some(Ok(extended)) = &found.extended {
        rows.push(stored_row("extended", extended, public));
    }
    rows
}

fn stored_row<'a>(
    kind: &'static str,
    card: &'a CardDocument,
    public: &'a CardDocument,
) -> NewAgentCard<'a> {
    NewAgentCard {
        kind,
        document: card.raw.as_ref().unwrap_or(&card.normalized),
        detected_version: public.version,
        source_url: public.source.as_str(),
        etag: card.etag.as_deref(),
        max_age: card.max_age,
    }
}

pub(super) async fn stored(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    require(&app, &principal, "a2a.read").await?;
    find(&app, Some(&principal), AgentLookup::Id(&id)).await?;
    load(&app, &id, "public", "No stored Agent Card for this agent").await
}

pub(super) async fn stored_extended(
    State(app): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, CatalogApiError> {
    tasks::manageable(&app, &principal, &id, "a2a.update").await?;
    let response = load(
        &app,
        &id,
        "extended",
        "No stored extended Agent Card for this agent",
    )
    .await?;
    tracing::info!(actor = %principal.email, agent_id = %id, "stored extended A2A card read");
    Ok(response)
}

async fn load(
    app: &GatewayService,
    id: &str,
    kind: &str,
    missing: &'static str,
) -> Result<Json<Value>, CatalogApiError> {
    let card = app
        .database
        .stored_agent_card(id, kind)
        .await?
        .ok_or_else(|| CatalogApiError::detail(StatusCode::NOT_FOUND, missing))?;
    Ok(Json(card.wire()))
}
