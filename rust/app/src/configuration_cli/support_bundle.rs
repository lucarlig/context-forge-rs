// SPDX-License-Identifier: Apache-2.0

use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
};

use clap::Parser;
use jiff::Timestamp;
use serde_json::{Value, json};
use sysinfo::System;
use uuid::Uuid;
use zeroize::Zeroizing;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{diagnostics::system, environment, private_file};

use super::CliError;

mod redaction;
mod settings;

use redaction::Redactor;
use settings::Snapshot;

const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const RUST_MINIMUM: &str = env!("CARGO_PKG_RUST_VERSION");
const MAX_LOG_BYTES: u64 = 10 * 1_048_576;
const REVIEW_NOTICE: &str = "This bundle may contain sensitive information. Review before sharing.";

#[derive(Parser)]
#[command(
    name = "context-forge-rs --support-bundle",
    about = "Create a sanitized diagnostic ZIP archive"
)]
struct Options {
    /// Directory for the archive, defaults to the system temporary directory.
    #[arg(long, value_name = "PATH")]
    output_dir: Option<OsString>,
    /// Number of log lines to include. Use 0 for all lines within the size limit.
    #[arg(long, default_value_t = 1000, allow_negative_numbers = true)]
    log_lines: i64,
    /// Omit log files.
    #[arg(long)]
    no_logs: bool,
    /// Omit application settings and process environment.
    #[arg(long)]
    no_env: bool,
    /// Omit system metrics and database information.
    #[arg(long)]
    no_system: bool,
}

pub fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), CliError> {
    let options = Options::parse_from(std::iter::once("context-forge-rs".into()).chain(args));
    environment::load(None)?;
    let snapshot = Snapshot::new()?;
    let redactor = snapshot.redactor();
    let now = Timestamp::now();
    let archive = archive(&options, &snapshot, &redactor, now)?;
    let directory = options
        .output_dir
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    fs::create_dir_all(&directory)?;
    let name = format!("mcpgateway-support-{}", now.strftime("%Y-%m-%d-%H%M%S"));
    let mut path = directory.join(format!("{name}.zip"));
    match private_file::write(&path, &archive, false) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            path = directory.join(format!("{name}-{}.zip", Uuid::new_v4()));
            private_file::write(&path, &archive, false)?;
        }
        Err(error) => return Err(error.into()),
    }

    let mut stdout = io::stdout().lock();
    writeln!(stdout, "✅ Support bundle created: {}", path.display())?;
    writeln!(
        stdout,
        "📦 Bundle size: {:.2} KB",
        archive.len() as f64 / 1024.0
    )?;
    writeln!(stdout)?;
    writeln!(stdout, "⚠️  Security Notice:")?;
    writeln!(stdout, "   {REVIEW_NOTICE}")?;
    Ok(())
}

fn archive(
    options: &Options,
    snapshot: &Snapshot,
    redactor: &Redactor,
    now: Timestamp,
) -> Result<Vec<u8>, CliError> {
    let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
    let hostname = redactor.text(&System::host_name().unwrap_or_default());
    let timestamp = now.to_string();
    json_entry(
        &mut zip,
        "MANIFEST.json",
        &json!({
            "bundle_version": "1.0",
            "generated_at": timestamp,
            "hostname": hostname,
            "app_version": APP_VERSION,
            "configuration": {
                "include_logs": !options.no_logs,
                "include_env": !options.no_env,
                "include_system_info": !options.no_system,
                "log_tail_lines": options.log_lines,
            },
            "warning": REVIEW_NOTICE,
        }),
    )?;
    json_entry(
        &mut zip,
        "version.json",
        &json!({
            "app_name": redactor.text(&snapshot.text("APP_NAME", "ContextForge")),
            "app_version": APP_VERSION,
            "mcp_protocol_version": redactor.text(&snapshot.text("PROTOCOL_VERSION", "2025-11-25")),
            "runtime": "Rust",
            "rust_minimum_version": RUST_MINIMUM,
            "platform": system::platform(),
            "hostname": hostname,
            "timestamp": timestamp,
        }),
    )?;
    if !options.no_system {
        json_entry(
            &mut zip,
            "system_info.json",
            &system_info(snapshot, redactor),
        )?;
    }
    if !options.no_env {
        json_entry(&mut zip, "settings.json", &snapshot.settings(redactor))?;
        json_entry(
            &mut zip,
            "environment.json",
            &snapshot.process_environment(redactor),
        )?;
    }
    if !options.no_logs {
        let folder = snapshot.text("LOG_FOLDER", "");
        let file = snapshot.text("LOG_FILE", "");
        let folder = if folder.is_empty() { "logs" } else { &folder };
        let file = if file.is_empty() {
            "mcpgateway.log"
        } else {
            &file
        };
        let path = Path::new(folder).join(file);
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("mcpgateway.log");
        let name = redactor.text(name).replace(
            |ch: char| ch.is_control() || matches!(ch, '/' | '\\' | ':'),
            "_",
        );
        let text = read_log(&path, options.log_lines, redactor);
        entry(&mut zip, &format!("logs/{name}"), text.as_bytes())?;
    }
    let readme = format!(
        "# ContextForge Support Bundle\n\n\
        MANIFEST.json and version.json describe this archive.\n\
        Optional system_info.json, settings.json, environment.json, and logs/ contain diagnostics.\n\n\
        Settings exclude credential fields. Environment values and log text use credential redaction.\n\
        {REVIEW_NOTICE}\n\n\
        Generated: {timestamp}\nHostname: {hostname}\nVersion: {APP_VERSION}\n"
    );
    entry(&mut zip, "README.md", readme.as_bytes())?;
    Ok(zip.finish()?.into_inner())
}

type ArchiveWriter = ZipWriter<Cursor<Vec<u8>>>;

fn json_entry(zip: &mut ArchiveWriter, name: &str, value: &Value) -> Result<(), CliError> {
    entry(zip, name, &serde_json::to_vec_pretty(value)?)
}

fn entry(zip: &mut ArchiveWriter, name: &str, data: &[u8]) -> Result<(), CliError> {
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o600);
    zip.start_file(name, options)?;
    zip.write_all(data)?;
    Ok(())
}

fn system_info(snapshot: &Snapshot, redactor: &Redactor) -> Value {
    let url = snapshot.text("DATABASE_URL", "sqlite:///./mcp.db");
    let dialect = url.split_once(":").map_or("unknown", |(scheme, _)| {
        scheme.split('+').next().unwrap_or("unknown")
    });
    let metrics = system::Metrics::default().sample();
    let system = if sysinfo::IS_SUPPORTED_SYSTEM {
        json!({
            "cpu_count": metrics["cpu_count"],
            "cpu_percent": metrics["cpu_percent"],
            "memory_total_mb": metrics["mem_total_mb"],
            "memory_used_mb": metrics["mem_used_mb"],
            "disk_total_gb": metrics["disk_total_gb"],
            "disk_used_gb": metrics["disk_used_gb"],
        })
    } else {
        json!({"note": "System metrics unavailable on this platform"})
    };
    json!({
        "platform": {
            "system": System::name(),
            "release": System::kernel_version(),
            "version": System::os_version(),
            "machine": System::cpu_arch(),
            "processor": env::consts::ARCH,
        },
        "rust": {"minimum_version": RUST_MINIMUM, "architecture": env::consts::ARCH},
        "database": {"dialect": redactor.text(dialect), "url": redactor.text(&url)},
        "system": system,
    })
}

fn read_log(path: &Path, tail: i64, redactor: &Redactor) -> String {
    match log_content(path, tail, redactor) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => "[Log file not found]\n".into(),
        Err(error) => format!("[Error reading log file: {error}]\n"),
        Ok(content) => content,
    }
}

fn log_content(path: &Path, tail: i64, redactor: &Redactor) -> io::Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("expected a regular log file"));
    }
    if metadata.len() > MAX_LOG_BYTES {
        return Ok(oversized_log(metadata.len()));
    }
    let mut raw = Zeroizing::new(Vec::new());
    file.take(MAX_LOG_BYTES + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_LOG_BYTES {
        return Ok(oversized_log(raw.len() as u64));
    }
    let decoded = Zeroizing::new(
        raw.utf8_chunks()
            .map(|chunk| chunk.valid())
            .collect::<String>(),
    );
    let text = Zeroizing::new(decoded.replace("\r\n", "\n").replace('\r', "\n"));
    let boundary = usize::try_from(tail)
        .ok()
        .filter(|count| *count > 0)
        .and_then(|count| {
            let lines = text.strip_suffix('\n').unwrap_or(&text);
            lines
                .rmatch_indices('\n')
                .nth(count - 1)
                .map(|(index, _)| index + 1)
        });
    Ok(match boundary {
        Some(index) => format!(
            "[Showing last {tail} lines]\n{}",
            redactor.text(&text[index..])
        ),
        None => redactor.text(text.as_str()),
    })
}

fn oversized_log(size: u64) -> String {
    format!(
        "[Log file too large: {:.2} MB > 10.0 MB limit]\n",
        size as f64 / 1_048_576.0
    )
}
