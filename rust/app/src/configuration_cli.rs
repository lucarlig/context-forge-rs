// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use clap::{Parser, ValueEnum};
use reqwest::{Client, Method, RequestBuilder, Url, header};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::{
    config::{Settings, flag, value},
    environment, private_file,
};

type CliError = Box<dyn Error + Send + Sync>;
const SETTINGS_SCHEMA: &str = include_str!("config/settings-v1.1.2.json");

pub fn write_settings_schema(output: Option<&Path>) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    if let Some(path) = output.filter(|path| !path.as_os_str().is_empty()) {
        fs::write(path, SETTINGS_SCHEMA)?;
        writeln!(stdout, "✅ Schema written to {}", path.display())
    } else {
        writeln!(stdout, "{SETTINGS_SCHEMA}")
    }
}

#[derive(Parser)]
#[command(
    name = "context-forge-rs export",
    about = "Export gateway configuration"
)]
struct ExportArgs {
    #[arg(short, long, visible_alias = "out")]
    output: Option<PathBuf>,
    #[arg(long, visible_alias = "type")]
    types: Option<String>,
    #[arg(long)]
    exclude_types: Option<String>,
    #[arg(long)]
    tags: Option<String>,
    #[arg(long)]
    include_inactive: bool,
    #[arg(long)]
    no_dependencies: bool,
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Parser)]
#[command(
    name = "context-forge-rs import",
    about = "Import gateway configuration"
)]
struct ImportArgs {
    input_file: PathBuf,
    #[arg(long, value_enum, default_value = "update")]
    conflict_strategy: Conflict,
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    rekey_secret: Option<String>,
    #[arg(long)]
    include: Option<String>,
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Clone, Copy, ValueEnum, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Conflict {
    Skip,
    Update,
    Rename,
    Fail,
}

pub async fn run(command: &str, args: impl Iterator<Item = String>) -> Result<(), CliError> {
    let args = std::iter::once(format!("context-forge-rs {command}")).chain(args);
    match command {
        "export" => export(ExportArgs::parse_from(args)).await,
        "import" => import(ImportArgs::parse_from(args)).await,
        _ => Err("unknown configuration command".into()),
    }
}

struct GatewayApi {
    client: Client,
    base: Url,
    authorization: header::HeaderValue,
}

impl GatewayApi {
    fn new() -> Result<Self, CliError> {
        environment::load(None)?;
        let token = Zeroizing::new(value("MCPGATEWAY_BEARER_TOKEN", "")?);
        let mut authorization = if !token.is_empty() {
            if token.starts_with("Basic ") {
                header::HeaderValue::from_str(&token)?
            } else {
                header::HeaderValue::from_str(&format!("Bearer {}", token.as_str()))?
            }
        } else if flag("API_ALLOW_BASIC_AUTH")?.unwrap_or(false) {
            use base64::{Engine, prelude::BASE64_STANDARD};

            let user = value("BASIC_AUTH_USER", "")?;
            let password = Zeroizing::new(value("BASIC_AUTH_PASSWORD", "")?);
            if user.is_empty() || password.is_empty() {
                return Err("No gateway authentication configured".into());
            }
            let credentials = Zeroizing::new(format!("{user}:{}", password.as_str()));
            let encoded = Zeroizing::new(BASE64_STANDARD.encode(credentials.as_bytes()));
            header::HeaderValue::from_str(&format!("Basic {}", encoded.as_str()))?
        } else {
            return Err(
                "No gateway authentication configured. Set MCPGATEWAY_BEARER_TOKEN.".into(),
            );
        };
        authorization.set_sensitive(true);

        let settings = Settings::from_env()?;
        let host = settings.host;
        let address = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host
        };
        let base = Url::parse(&format!("http://{address}:{}/", settings.port))?;
        if !base.username().is_empty()
            || base.password().is_some()
            || base.path() != "/"
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err("Invalid gateway host".into());
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            client,
            base,
            authorization,
        })
    }

    fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.client
            .request(method, url)
            .header(header::AUTHORIZATION, self.authorization.clone())
            .header(header::ACCEPT, "application/json")
    }
}

async fn send(request: RequestBuilder) -> Result<Value, CliError> {
    let response = request.send().await.map_err(reqwest::Error::without_url)?;
    if !response.status().is_success() {
        return Err(format!(
            "Gateway request failed (HTTP {})",
            response.status().as_u16()
        )
        .into());
    }
    Ok(serde_json::from_slice(&response.bytes().await?)?)
}

async fn export(args: ExportArgs) -> Result<(), CliError> {
    let api = GatewayApi::new()?;
    let mut query = Vec::new();
    for (key, value) in [
        ("types", args.types),
        ("exclude_types", args.exclude_types),
        ("tags", args.tags),
    ] {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            query.push((key, value));
        }
    }
    if args.include_inactive {
        query.push(("include_inactive", "true".to_owned()));
    }
    if args.no_dependencies {
        query.push(("include_dependencies", "false".to_owned()));
    }
    println!("Exporting gateway configuration from {}", api.base);
    let mut url = api.base.join("export")?;
    if !query.is_empty() {
        url.query_pairs_mut().extend_pairs(query);
    }
    let configuration = send(api.request(Method::GET, url)).await?;
    if !configuration["entities"].is_object() {
        return Err("Gateway returned an invalid configuration export".into());
    }
    let output = args.output.unwrap_or_else(|| {
        let now = jiff::ZonedDateTime::now();
        format!("mcpgateway-export-{}.json", now.strftime("%Y%m%d-%H%M%S")).into()
    });
    let contents = serde_json::to_vec_pretty(&configuration)?;
    write_export(&output, &contents)?;
    println!("Export written to {}", output.display());
    if let Some(counts) = configuration["metadata"]["entity_counts"].as_object() {
        let total = counts.values().filter_map(Value::as_u64).sum::<u64>();
        println!("Exported {total} configuration items");
        for (entity, count) in counts {
            if let Some(count) = count.as_u64().filter(|count| *count > 0) {
                println!("{entity} {count}");
            }
        }
    }
    if args.verbose {
        for key in ["version", "exported_at", "exported_by", "source_gateway"] {
            if let Some(detail) = configuration[key].as_str() {
                println!("{key} {detail}");
            }
        }
    }
    Ok(())
}

fn write_export(destination: &Path, contents: &[u8]) -> Result<(), CliError> {
    fs::create_dir_all(private_file::parent(destination))?;
    Ok(private_file::write(destination, contents, true)?)
}

async fn import(args: ImportArgs) -> Result<(), CliError> {
    let configuration: Value = serde_json::from_slice(&fs::read(&args.input_file)?)?;
    let mut request = json!({
        "import_data":configuration,
        "conflict_strategy":args.conflict_strategy,
        "dry_run":args.dry_run,
    });
    if let Some(secret) = args.rekey_secret.map(Zeroizing::new) {
        request["rekey_secret"] = secret.as_str().into();
    }
    if let Some(selection) = args.include {
        request["selected_entities"] = parse_selection(&selection)?;
    }
    let api = GatewayApi::new()?;
    println!(
        "Importing gateway configuration from {}",
        args.input_file.display()
    );
    let body = serde_json::to_vec(&request)?;
    let result = send(
        api.request(Method::POST, api.base.join("import")?)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body),
    )
    .await?;
    if args.dry_run {
        println!("Dry run completed");
    } else {
        println!("Import {}", result["status"].as_str().unwrap_or("finished"));
    }
    let progress = &result["progress"];
    for field in [
        "total",
        "processed",
        "created",
        "updated",
        "skipped",
        "failed",
    ] {
        println!("{field} {}", progress[field].as_u64().unwrap_or_default());
    }
    for field in ["warnings", "errors"] {
        if let Some(messages) = result[field].as_array() {
            for message in messages.iter().filter_map(Value::as_str).take(5) {
                println!("{message}");
            }
        }
    }
    if args.verbose {
        for key in ["import_id", "started_at", "completed_at"] {
            if let Some(detail) = result[key].as_str() {
                println!("{key} {detail}");
            }
        }
    }
    if progress["failed"].as_u64().unwrap_or_default() > 0 {
        return Err("Some configuration items failed to import".into());
    }
    if result["status"] != "completed" {
        return Err("Gateway did not complete the configuration import".into());
    }
    Ok(())
}

fn parse_selection(input: &str) -> Result<Value, CliError> {
    let mut selections = BTreeMap::new();
    for selector in input.split(';').filter(|value| !value.trim().is_empty()) {
        let (kind, names) = selector.split_once(':').ok_or("Invalid import selection")?;
        let kind = kind.trim();
        if !matches!(
            kind,
            "tools" | "gateways" | "servers" | "prompts" | "resources" | "roots"
        ) {
            return Err("Unknown entity type in import selection".into());
        }
        let names = names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .collect::<Vec<_>>();
        if selections.insert(kind, names).is_some() {
            return Err("Duplicate entity type in import selection".into());
        }
    }
    if selections.is_empty() {
        return Err("Empty import selection".into());
    }
    Ok(serde_json::to_value(selections)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_selection_cannot_import_everything() {
        for input in ["", "tools", "unknown:example", "tools:one;tools:two"] {
            assert!(parse_selection(input).is_err(), "{input}");
        }
        assert_eq!(
            parse_selection("tools:first, second;resources:").unwrap(),
            json!({"tools":["first","second"],"resources":[]}),
        );
    }
}
