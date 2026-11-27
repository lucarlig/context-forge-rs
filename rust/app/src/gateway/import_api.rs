// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use axum::{
    extract::{Path, Query, rejection::JsonRejection},
    response::IntoResponse,
};
use serde_json::Map;

use super::{catalog_api::CatalogApiError, *};

mod gateway;

const ORDER: [Entity; 6] = [
    Entity::Roots,
    Entity::Gateways,
    Entity::Tools,
    Entity::Resources,
    Entity::Prompts,
    Entity::Servers,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Entity {
    Roots,
    Gateways,
    Tools,
    Resources,
    Prompts,
    Servers,
}

struct Entry {
    kind: Entity,
    fields: Map<String, Value>,
}

impl Entity {
    fn key(self) -> &'static str {
        match self {
            Self::Roots => "roots",
            Self::Gateways => "gateways",
            Self::Tools => "tools",
            Self::Resources => "resources",
            Self::Prompts => "prompts",
            Self::Servers => "servers",
        }
    }

    fn singular(self) -> &'static str {
        self.key().trim_end_matches('s')
    }

    fn identity(self) -> &'static str {
        match self {
            Self::Roots | Self::Resources => "uri",
            _ => "name",
        }
    }

    fn fields(self) -> &'static [&'static str] {
        match self {
            Self::Roots | Self::Resources => &["uri", "name"],
            Self::Gateways => &["name", "url"],
            Self::Tools => &["name", "url", "integration_type"],
            Self::Prompts => &["name", "template"],
            Self::Servers => &["name"],
        }
    }

    fn bulk(self) -> bool {
        matches!(self, Self::Tools | Self::Resources | Self::Prompts)
    }
}

#[derive(Deserialize)]
struct Request {
    import_data: Map<String, Value>,
    #[serde(default = "update_strategy")]
    conflict_strategy: String,
    #[serde(default)]
    dry_run: bool,
    rekey_secret: Option<String>,
    selected_entities: Option<BTreeMap<String, Vec<String>>>,
}

fn update_strategy() -> String {
    "update".into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Strategy {
    Skip,
    Update,
    Rename,
    Fail,
}

impl Strategy {
    fn parse(value: &str) -> Result<Self, CatalogApiError> {
        match value.to_ascii_lowercase().as_str() {
            "skip" => Ok(Self::Skip),
            "update" => Ok(Self::Update),
            "rename" => Ok(Self::Rename),
            "fail" => Ok(Self::Fail),
            _ => Err(CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                "Invalid conflict strategy. Must be one of: ['skip', 'update', 'rename', 'fail']",
            )),
        }
    }
}

#[derive(Clone, Default, Serialize)]
struct Progress {
    total: usize,
    processed: usize,
    created: usize,
    updated: usize,
    skipped: usize,
    failed: usize,
}

#[derive(Clone, Serialize)]
struct Job {
    import_id: String,
    #[serde(skip)]
    owner: String,
    status: &'static str,
    progress: Progress,
    errors: Vec<String>,
    warnings: Vec<String>,
    started_at: String,
    completed_at: Option<String>,
    #[serde(skip)]
    completed: Option<i64>,
}

impl Job {
    fn new(owner: &str) -> Self {
        Self {
            import_id: Uuid::new_v4().to_string(),
            owner: owner.to_owned(),
            status: "pending",
            progress: Progress::default(),
            errors: Vec::new(),
            warnings: Vec::new(),
            started_at: timestamp(),
            completed_at: None,
            completed: None,
        }
    }

    fn finish(&mut self, status: &'static str) {
        self.status = status;
        self.completed_at = Some(timestamp());
        self.completed = Some(Timestamp::now().as_second());
    }

    fn report(&mut self, kind: Entity, name: &str, outcome: Result<Outcome, CatalogApiError>) {
        match outcome {
            Ok(Outcome::Created) => self.progress.created += 1,
            Ok(Outcome::Updated) => self.progress.updated += 1,
            Ok(Outcome::Skipped) => {
                self.progress.skipped += 1;
                if !kind.bulk() {
                    self.warnings
                        .push(format!("Skipped existing {}: {name}", kind.singular()));
                }
            }
            Ok(Outcome::Renamed(new_name)) => {
                self.progress.created += 1;
                if !kind.bulk() {
                    self.warnings
                        .push(format!("Renamed {} {name} to {new_name}", kind.singular()));
                }
            }
            Err(error) => {
                self.progress.failed += 1;
                let detail = error.1["detail"].as_str().unwrap_or("Import failed");
                if kind.bulk() && matches!(error.0, StatusCode::FORBIDDEN | StatusCode::CONFLICT) {
                    self.errors.push(detail.to_owned());
                } else {
                    self.errors
                        .push(format!("Failed to process {} entity: {detail}", kind.key()));
                }
                return;
            }
        }
        self.progress.processed += 1;
    }

    fn visible(&self, principal: &Principal) -> bool {
        principal.is_global_admin() || self.owner == principal.email
    }
}

pub(super) enum Outcome {
    Created,
    Updated,
    Skipped,
    Renamed(String),
}

#[derive(Default)]
pub(super) struct Imports(Mutex<Vec<Job>>);

impl Imports {
    fn save(&self, job: &Job) {
        let mut jobs = self.0.lock().expect("configuration imports");
        if let Some(existing) = jobs
            .iter_mut()
            .find(|existing| existing.import_id == job.import_id)
        {
            *existing = job.clone();
        } else {
            jobs.push(job.clone());
        }
    }
}

pub(super) fn router() -> Router<Arc<GatewayService>> {
    let mut routes = Router::new();
    for base in ["/import", "/v1/import"] {
        routes = routes
            .route(base, post(import))
            .route(&format!("{base}/status"), get(list))
            .route(&format!("{base}/status/{{id}}"), get(status))
            .route(&format!("{base}/cleanup"), post(cleanup));
    }
    routes
}

async fn authorize(service: &GatewayService, principal: &Principal) -> Result<(), CatalogApiError> {
    if !service
        .access
        .allows_global_only(principal, "admin.import")
        .await?
    {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    Ok(())
}

async fn import(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    payload: Result<Json<Request>, JsonRejection>,
) -> Result<Json<Job>, CatalogApiError> {
    authorize(&service, &principal).await?;
    let Json(request) =
        payload.map_err(|error| CatalogApiError::detail(error.status(), error.body_text()))?;
    if request.import_data.is_empty() {
        return Err(CatalogApiError::detail(
            StatusCode::BAD_REQUEST,
            "Missing 'import_data' in request body",
        ));
    }
    let root_requested = request
        .import_data
        .get("entities")
        .and_then(|value| value.get("roots"))
        .and_then(Value::as_array)
        .is_some_and(|roots| !roots.is_empty())
        && request
            .selected_entities
            .as_ref()
            .is_none_or(|selection| selection.is_empty() || selection.contains_key("roots"));
    if root_requested && !principal.is_global_admin() {
        return Err(CatalogApiError::detail(
            StatusCode::FORBIDDEN,
            "Access denied",
        ));
    }
    let strategy = Strategy::parse(&request.conflict_strategy)?;
    let mut job = Job::new(&principal.email);
    let entries = match entries(&service, &request) {
        Ok(entries) => entries,
        Err(detail) => {
            job.finish("failed");
            job.errors.push(detail);
            service.imports.save(&job);
            return Err(CatalogApiError::detail(
                StatusCode::BAD_REQUEST,
                "Import failed",
            ));
        }
    };

    job.status = "running";
    job.progress.total = entries.len();
    service.imports.save(&job);
    let rekey = request.rekey_secret.map(Zeroizing::new);
    let batch_id = job.import_id.clone();
    let team_id = if !request.dry_run && entries.iter().any(|entry| entry.kind != Entity::Roots) {
        match service
            .database
            .personal_import_team(&principal.email)
            .await
        {
            Ok(team) => team,
            Err(error) => {
                job.finish("failed");
                job.errors.push("Import database unavailable".into());
                service.imports.save(&job);
                return Err(error.into());
            }
        }
    } else {
        None
    };
    let context = ImportScope {
        principal: &principal,
        team_id: team_id.as_deref(),
        strategy,
        rekey: rekey.as_ref().map(|value| value.as_str()),
        batch_id: &batch_id,
    };
    for Entry {
        kind,
        fields: mut entry,
    } in entries
    {
        let name = entry[kind.identity()]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if request.dry_run {
            let warning = if kind == Entity::Roots {
                "Would import root".to_owned()
            } else {
                format!("Would import {}: {name}", kind.singular())
            };
            job.warnings.push(warning);
            job.progress.processed += usize::from(!kind.bulk());
        } else {
            for field in [
                "owner_email",
                "ownerEmail",
                "team_id",
                "teamId",
                "team",
                "visibility",
                "id",
                "gateway_id",
                "gatewayId",
                "mcp_server_id",
                "mcpServerId",
            ] {
                entry.remove(field);
            }
            let result = match kind {
                Entity::Roots => service
                    .roots
                    .import_root(&name, entry["name"].as_str(), strategy),
                Entity::Tools => super::tool_api::import_tool(&service, &context, entry).await,
                Entity::Resources => {
                    super::resource_api::import_resource(&service, &context, entry).await
                }
                Entity::Prompts => {
                    super::prompt_api::import_prompt(&service, &context, entry).await
                }
                Entity::Servers => {
                    super::server_api::import_server(&service, &context, entry).await
                }
                Entity::Gateways => gateway::import_gateway(&service, &context, entry).await,
            };
            job.report(kind, &name, result);
        }
        service.imports.save(&job);
    }
    job.finish("completed");
    service.imports.save(&job);
    Ok(Json(job))
}

pub(super) struct ImportScope<'a> {
    pub(super) principal: &'a Principal,
    pub(super) team_id: Option<&'a str>,
    pub(super) strategy: Strategy,
    pub(super) rekey: Option<&'a str>,
    pub(super) batch_id: &'a str,
}

impl ImportScope<'_> {
    pub(super) fn visibility(&self) -> &'static str {
        if self.team_id.is_some() {
            "team"
        } else {
            "private"
        }
    }

    pub(super) fn owns(&self, owner: Option<&str>) -> bool {
        self.principal.is_global_admin() || owner == Some(self.principal.email.as_str())
    }
}

fn entries(service: &GatewayService, request: &Request) -> Result<Vec<Entry>, String> {
    let bundle = &request.import_data;
    if !bundle
        .get("version")
        .and_then(Value::as_str)
        .is_some_and(|version| !version.is_empty())
        || !bundle.contains_key("exported_at")
    {
        return Err("Import failed: missing version or exported_at".to_owned());
    }
    let entities = bundle
        .get("entities")
        .and_then(Value::as_object)
        .ok_or("Import failed: invalid entities")?;
    if entities
        .keys()
        .any(|key| !ORDER.iter().any(|kind| kind.key() == key))
    {
        return Err("Import failed: invalid entity type".to_owned());
    }
    let mut planned = Vec::new();
    for kind in ORDER {
        let Some(records) = entities.get(kind.key()) else {
            continue;
        };
        let records = records
            .as_array()
            .ok_or("Import failed: invalid entity list")?;
        let selection = request
            .selected_entities
            .as_ref()
            .filter(|value| !value.is_empty());
        for record in records {
            let fields = record.as_object().ok_or("Import failed: invalid entity")?;
            if kind
                .fields()
                .iter()
                .any(|field| !fields.contains_key(*field))
            {
                return Err(format!(
                    "Import failed: required field missing from {}",
                    kind.key()
                ));
            }
            let name = fields[kind.identity()]
                .as_str()
                .ok_or("Import failed: invalid entity identifier")?;
            if kind == Entity::Roots
                && !fields["name"]
                    .as_str()
                    .is_some_and(|label| service.roots.valid_import_root(name, label))
            {
                return Err("Import failed: invalid root".to_owned());
            }
            if selection.is_none_or(|selection| {
                selection
                    .get(kind.key())
                    .is_some_and(|ids| ids.is_empty() || ids.iter().any(|id| id == name))
            }) {
                planned.push(Entry {
                    kind,
                    fields: fields.clone(),
                });
            }
        }
    }
    Ok(planned)
}

async fn status(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Job>, CatalogApiError> {
    authorize(&service, &principal).await?;
    service
        .imports
        .0
        .lock()
        .expect("configuration imports")
        .iter()
        .find(|job| job.visible(&principal) && job.import_id == id)
        .cloned()
        .map(Json)
        .ok_or_else(|| {
            CatalogApiError::detail(StatusCode::NOT_FOUND, format!("Import {id} not found"))
        })
}

async fn list(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<Vec<Job>>, CatalogApiError> {
    authorize(&service, &principal).await?;
    Ok(Json(
        service
            .imports
            .0
            .lock()
            .expect("configuration imports")
            .iter()
            .filter(|job| job.visible(&principal))
            .cloned()
            .collect(),
    ))
}

#[derive(Deserialize)]
struct Cleanup {
    max_age_hours: Option<i64>,
}

async fn cleanup(
    State(service): State<Arc<GatewayService>>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<Cleanup>,
) -> Result<impl IntoResponse, CatalogApiError> {
    authorize(&service, &principal).await?;
    let cutoff = Timestamp::now()
        .as_second()
        .saturating_sub(query.max_age_hours.unwrap_or(24).saturating_mul(3600));
    let mut jobs = service.imports.0.lock().expect("configuration imports");
    let before = jobs.len();
    jobs.retain(|job| {
        !job.visible(&principal) || job.completed.is_none_or(|completed| completed > cutoff)
    });
    let count = before - jobs.len();
    Ok(Json(json!({
        "status":"success",
        "message":format!("Cleaned up {count} completed import statuses"),
        "removed_count":count,
    })))
}

fn timestamp() -> String {
    Timestamp::now().to_string().replace('Z', "+00:00")
}

impl Database {
    async fn personal_import_team(&self, owner: &str) -> Result<Option<String>, sqlx::Error> {
        const QUERY: &str = "SELECT id FROM email_teams
            WHERE created_by=$1 AND is_personal=TRUE AND is_active=TRUE ORDER BY id LIMIT 1";
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar(QUERY)
                    .bind(owner)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar(QUERY)
                    .bind(owner)
                    .fetch_optional(pool)
                    .await
            }
        }
    }
}
