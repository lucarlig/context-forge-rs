// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, error::Error};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    config::{SecretKdf, Settings, value},
    credentials::CredentialCipher,
    database::Database,
    secret_envelope::SecretEnvelope,
};

type CommandError = Box<dyn Error + Send + Sync>;
const HELP: &str =
    "Usage: context-forge-rs rotate-credentials [--dry-run] [--database-url URL] [--force]

Re-encrypt stored credentials using OLD_AUTH_ENCRYPTION_SECRET and NEW_AUTH_ENCRYPTION_SECRET.
The command also accepts --old-key and --new-key. Prefer the environment for keys.
--dry-run reports the changes without writing. --force permits a weak new key for rollback.";

pub async fn cli(mut args: impl Iterator<Item = String>) -> Result<(), CommandError> {
    let mut old = None;
    let mut new = None;
    let mut url = None;
    let mut dry_run = false;
    let mut force = false;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--help" | "-h" => {
                println!("{HELP}");
                return Ok(());
            }
            "--old-key" => {
                old = Some(Zeroizing::new(
                    args.next().ok_or("--old-key requires a value")?,
                ))
            }
            "--new-key" => {
                new = Some(Zeroizing::new(
                    args.next().ok_or("--new-key requires a value")?,
                ))
            }
            "--database-url" => url = Some(args.next().ok_or("--database-url requires a value")?),
            "--dry-run" => dry_run = true,
            "--force" => force = true,
            _ => return Err("unknown rotation option. See rotate-credentials --help.".into()),
        }
    }
    let old = old.map_or_else(
        || value("OLD_AUTH_ENCRYPTION_SECRET", "").map(Zeroizing::new),
        Ok,
    )?;
    let new = new.map_or_else(
        || value("NEW_AUTH_ENCRYPTION_SECRET", "").map(Zeroizing::new),
        Ok,
    )?;
    if old.is_empty() || new.is_empty() {
        return Err("rotation requires both the old and new encryption secrets".into());
    }
    if old == new {
        return Err("the old and new encryption secrets must differ".into());
    }
    if !force && !strong_secret(&new) {
        return Err(
            "the new encryption secret must have at least 32 characters and sufficient entropy"
                .into(),
        );
    }
    let mut settings = Settings::from_env()?;
    if let Some(url) = url {
        settings.database_url = url;
    }
    let database = Database::for_credential_rotation(&settings, dry_run)?;
    let keys = RotationKeys::new(&old, &new, Settings::secret_kdf()?);
    drop(old);
    drop(new);
    let summary = rotate(&database, &keys, dry_run).await?;
    if dry_run {
        println!("DRY RUN SUMMARY (no changes written)");
    } else if summary.errors == 0 {
        println!("ROTATION SUMMARY");
    } else {
        println!("ROTATION SUMMARY (all changes rolled back)");
    }
    println!("Rows scanned   {}", summary.rows);
    println!("Values migrated {}", summary.migrated);
    println!("Values skipped  {}", summary.skipped);
    println!("Errors          {}", summary.errors);
    if summary.errors == 0 {
        Ok(())
    } else {
        Err("one or more stored credentials could not be rotated".into())
    }
}

fn strong_secret(secret: &str) -> bool {
    let mut frequencies = BTreeMap::<char, usize>::new();
    for character in secret.chars() {
        *frequencies.entry(character).or_default() += 1;
    }
    let length: usize = frequencies.values().sum();
    if length < 32
        || secret.eq_ignore_ascii_case("my-test-key-but-now-longer-than-32-bytes")
        || secret.to_ascii_lowercase().starts_with("__replace_me__")
    {
        return false;
    }
    let entropy = frequencies
        .values()
        .map(|count| {
            let ratio = *count as f64 / length as f64;
            -ratio * ratio.log2()
        })
        .sum::<f64>();
    entropy >= 3.5
}

#[derive(Default)]
struct Summary {
    rows: usize,
    migrated: usize,
    skipped: usize,
    errors: usize,
}

#[derive(Clone, Copy)]
enum Encoding {
    Envelope,
    Aes,
    AesScalar,
    OAuth,
    QueryParameters,
    SigV4,
    Sentinel(&'static str),
}

const FIELDS: &[(&str, &str, Encoding)] = &[
    (
        "a2a_agent_auth",
        "auth_query_params",
        Encoding::QueryParameters,
    ),
    ("a2a_agent_auth", "auth_value", Encoding::Aes),
    ("a2a_agent_auth", "oauth_config", Encoding::OAuth),
    ("a2a_agents", "auth_query_params", Encoding::QueryParameters),
    ("a2a_agents", "auth_value", Encoding::Aes),
    ("a2a_agents", "oauth_config", Encoding::OAuth),
    ("a2a_push_notification_configs", "auth_token", Encoding::Aes),
    ("gateways", "auth_query_params", Encoding::QueryParameters),
    ("gateways", "auth_value", Encoding::AesScalar),
    ("gateways", "client_key", Encoding::Envelope),
    ("gateways", "oauth_config", Encoding::OAuth),
    ("gateways", "sigv4_config", Encoding::SigV4),
    ("llm_providers", "api_key", Encoding::Aes),
    (
        "llm_providers",
        "config",
        Encoding::Sentinel("_mcpgateway_encrypted_value_v1"),
    ),
    ("oauth_tokens", "access_token", Encoding::Envelope),
    ("oauth_tokens", "refresh_token", Encoding::Envelope),
    (
        "registered_oauth_clients",
        "client_secret_encrypted",
        Encoding::Envelope,
    ),
    (
        "registered_oauth_clients",
        "registration_access_token_encrypted",
        Encoding::Envelope,
    ),
    ("servers", "oauth_config", Encoding::OAuth),
    (
        "sso_providers",
        "client_secret_encrypted",
        Encoding::Envelope,
    ),
    ("tools", "auth_value", Encoding::Aes),
    ("tools", "sigv4_config", Encoding::SigV4),
    (
        "tools",
        "headers",
        Encoding::Sentinel("_mcpgateway_encrypted_header_value_v1"),
    ),
];

struct RotationKeys {
    old_envelope: SecretEnvelope,
    new_envelope: SecretEnvelope,
    old_aes: CredentialCipher,
    new_aes: CredentialCipher,
}

impl RotationKeys {
    fn new(old: &str, new: &str, kdf: SecretKdf) -> Self {
        let old_envelope = SecretEnvelope::new(old);
        let mut new_envelope = SecretEnvelope::new(new);
        new_envelope.kdf = kdf;
        Self {
            old_envelope,
            new_envelope,
            old_aes: CredentialCipher::new(old),
            new_aes: CredentialCipher::new(new),
        }
    }

    async fn envelope(&self, encoded: &str) -> Result<Option<String>, ()> {
        if !SecretEnvelope::is_encrypted(encoded) {
            // Unwrapped Fernet tokens need the historical schema migration.
            if encoded.starts_with('g')
                && BASE64_URL_SAFE_NO_PAD
                    .decode(encoded.trim_end_matches('='))
                    .is_ok_and(|bytes| bytes.len() >= 57 && bytes[0] == 0x80)
            {
                return Err(());
            }
            return Ok(None);
        }
        match self.old_envelope.open(encoded.to_owned()).await {
            Ok(plaintext) => self
                .new_envelope
                .seal(plaintext)
                .await
                .map(Some)
                .map_err(|_| ()),
            Err(_) => self
                .new_envelope
                .open(encoded.to_owned())
                .await
                .map(|_| None)
                .map_err(|_| ()),
        }
    }

    fn aes(&self, encoded: &str) -> Result<Option<String>, ()> {
        if encoded.len() < 39
            || BASE64_URL_SAFE_NO_PAD
                .decode(encoded.trim_end_matches('='))
                .is_err()
        {
            return Ok(None);
        }
        match self.old_aes.open::<Value>(encoded) {
            Ok(plaintext) => self.new_aes.seal(&plaintext).map(Some).map_err(|_| ()),
            Err(_) => self
                .new_aes
                .open::<Value>(encoded)
                .map(|_| None)
                .map_err(|_| ()),
        }
    }
}

async fn rotate(
    database: &Database,
    keys: &RotationKeys,
    dry_run: bool,
) -> Result<Summary, sqlx::Error> {
    let mut summary = Summary::default();
    let mut tables = BTreeMap::<&str, Vec<(&str, Encoding)>>::new();
    for &(table, column, encoding) in FIELDS {
        tables.entry(table).or_default().push((column, encoding));
    }
    macro_rules! transaction {
        ($tx:ident, $schema:expr, $postgres:literal) => {{
            for (table, fields) in tables {
                let schema: BTreeMap<_, _> = sqlx::query_as::<_, (String, String)>($schema)
                    .bind(table)
                    .fetch_all(&mut *$tx)
                    .await?
                    .into_iter()
                    .collect();
                if !schema.contains_key("id") {
                    continue;
                }
                if $postgres && !dry_run {
                    // All identifiers in these statements come from FIELDS.
                    sqlx::query(sqlx::AssertSqlSafe(format!(
                        "LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE"
                    )))
                    .execute(&mut *$tx)
                    .await?;
                }
                for (column, encoding) in fields {
                    let Some(column_type) = schema.get(column) else {
                        continue;
                    };
                    let value_expression = match ($postgres, column_type.as_str()) {
                        (true, "json") => "CAST($1 AS JSON)",
                        (true, "jsonb") => "CAST($1 AS JSONB)",
                        _ => "$1",
                    };
                    let select = format!(
                        "SELECT CAST(id AS TEXT), CAST({column} AS TEXT) FROM {table}
                         WHERE {column} IS NOT NULL
                           AND (CAST($1 AS TEXT) IS NULL OR CAST(id AS TEXT)>$1)
                         ORDER BY CAST(id AS TEXT) LIMIT 128",
                    );
                    let update = format!(
                        "UPDATE {table} SET {column}={value_expression} WHERE CAST(id AS TEXT)=$2",
                    );
                    let mut after: Option<String> = None;
                    loop {
                        let rows = sqlx::query_as::<_, (String, String)>(sqlx::AssertSqlSafe(
                            select.as_str(),
                        ))
                        .bind(after.as_deref())
                        .fetch_all(&mut *$tx)
                        .await?;
                        if rows.is_empty() {
                            break;
                        }
                        for (id, value) in rows {
                            summary.rows += 1;
                            let before = summary.errors;
                            let pending = rotate_cell(keys, encoding, value, &mut summary).await;
                            if summary.errors != before {
                                eprintln!("Could not read an encrypted value in {table}.{column}");
                            }
                            if let Some(value) = pending
                                && !dry_run
                            {
                                sqlx::query(sqlx::AssertSqlSafe(update.as_str()))
                                    .bind(value)
                                    .bind(&id)
                                    .execute(&mut *$tx)
                                    .await?;
                            }
                            after = Some(id);
                        }
                    }
                }
            }
            if dry_run || summary.errors != 0 {
                $tx.rollback().await?;
            } else {
                $tx.commit().await?;
            }
        }};
    }
    match database {
        Database::Sqlite(pool) => {
            let mut tx = if dry_run {
                pool.begin().await?
            } else {
                pool.begin_with("BEGIN IMMEDIATE").await?
            };
            transaction!(tx, "SELECT name,type FROM pragma_table_info($1)", false);
        }
        Database::Postgres(pool) => {
            let mut tx = if dry_run {
                pool.begin_with("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    .await?
            } else {
                pool.begin().await?
            };
            transaction!(
                tx,
                "SELECT attname,format_type(atttypid,atttypmod) FROM pg_attribute
                 WHERE attrelid=to_regclass($1) AND attnum>0 AND NOT attisdropped",
                true
            );
        }
    }
    Ok(summary)
}

async fn rotate_cell(
    keys: &RotationKeys,
    encoding: Encoding,
    value: String,
    summary: &mut Summary,
) -> Option<String> {
    match encoding {
        Encoding::Envelope => return outcome(keys.envelope(&value).await, summary),
        Encoding::Aes => return outcome(keys.aes(&value), summary),
        Encoding::AesScalar => {
            return match serde_json::from_str::<Value>(&value) {
                Ok(Value::String(value)) => outcome(keys.aes(&value), summary)
                    .map(|rotated| Value::String(rotated).to_string()),
                Ok(_) => outcome(Ok(None), summary),
                Err(_) => outcome(keys.aes(&value), summary),
            };
        }
        _ => {}
    }
    let Ok(mut value) = serde_json::from_str::<Value>(&value) else {
        summary.errors += 1;
        return None;
    };
    let mut targets = Vec::new();
    collect_targets(&mut value, encoding, false, &mut targets);
    let before = summary.migrated;
    for target in targets {
        let result = if matches!(encoding, Encoding::OAuth) {
            keys.envelope(target).await
        } else {
            keys.aes(target)
        };
        if let Some(rotated) = outcome(result, summary) {
            *target = rotated;
        }
    }
    (summary.migrated != before).then(|| value.to_string())
}

fn outcome(result: Result<Option<String>, ()>, summary: &mut Summary) -> Option<String> {
    match result {
        Ok(Some(value)) => {
            summary.migrated += 1;
            Some(value)
        }
        Ok(None) => {
            summary.skipped += 1;
            None
        }
        Err(()) => {
            summary.errors += 1;
            None
        }
    }
}

fn collect_targets<'a>(
    value: &'a mut Value,
    encoding: Encoding,
    protected: bool,
    targets: &mut Vec<&'a mut String>,
) {
    match value {
        Value::Object(fields) => {
            let singleton = fields.len() == 1;
            for (key, value) in fields {
                let encrypted_field = match encoding {
                    Encoding::OAuth => matches!(
                        key.to_ascii_lowercase().as_str(),
                        "client_secret"
                            | "password"
                            | "refresh_token"
                            | "access_token"
                            | "id_token"
                            | "token"
                            | "secret"
                            | "private_key"
                    ),
                    Encoding::QueryParameters => true,
                    Encoding::SigV4 => {
                        matches!(key.as_str(), "secret_access_key" | "session_token")
                    }
                    Encoding::Sentinel(sentinel) => singleton && key == sentinel,
                    _ => false,
                };
                if let Value::String(encoded) = value {
                    if encrypted_field {
                        targets.push(encoded);
                    }
                } else if matches!(encoding, Encoding::OAuth | Encoding::Sentinel(_)) {
                    collect_targets(value, encoding, encrypted_field, targets);
                }
            }
        }
        Value::Array(items) if matches!(encoding, Encoding::OAuth | Encoding::Sentinel(_)) => {
            for item in items {
                collect_targets(item, encoding, protected, targets);
            }
        }
        Value::String(value) if protected => targets.push(value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn rotates_tool_signing_credentials_and_nested_oauth_secret_arrays() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE TABLE tools (id TEXT PRIMARY KEY, sigv4_config TEXT);
             CREATE TABLE gateways (id TEXT PRIMARY KEY, oauth_config TEXT);",
        )
        .execute(&pool)
        .await
        .unwrap();
        let kdf = SecretKdf {
            time_cost: 1,
            memory_cost: 1024,
            parallelism: 1,
        };
        let mut keys = RotationKeys::new("fixture previous key", "fixture replacement key", kdf);
        keys.old_envelope.kdf = kdf;
        let signing_key = json!({"secret_access_key":"fixture signing value"});
        let session_token = json!({"session_token":"fixture session value"});
        let sigv4 = json!({
            "access_key_id":"fixture-id",
            "secret_access_key":keys.old_aes.seal(&signing_key).unwrap(),
            "session_token":keys.old_aes.seal(&session_token).unwrap(),
            "region":"us-east-1",
        });
        let oauth_value = keys
            .old_envelope
            .seal(Zeroizing::new("fixture oauth value".into()))
            .await
            .unwrap();
        let oauth = json!({"client_secret":[[oauth_value]],"metadata":[oauth_value]});
        sqlx::query("INSERT INTO tools VALUES ('tool', $1)")
            .bind(sigv4.to_string())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO gateways VALUES ('gateway', $1)")
            .bind(oauth.to_string())
            .execute(&pool)
            .await
            .unwrap();

        let database = Database::Sqlite(pool.clone());
        let summary = rotate(&database, &keys, false).await.unwrap();
        assert_eq!((summary.migrated, summary.errors), (3, 0));
        let rotated_sigv4: sqlx::types::Json<Value> =
            sqlx::query_scalar("SELECT sigv4_config FROM tools")
                .fetch_one(&pool)
                .await
                .unwrap();
        for (field, expected) in [
            ("secret_access_key", signing_key),
            ("session_token", session_token),
        ] {
            let value = rotated_sigv4[field].as_str().unwrap();
            assert_eq!(keys.new_aes.open::<Value>(value).unwrap(), expected);
            assert!(keys.old_aes.open::<Value>(value).is_err());
        }
        assert_eq!(rotated_sigv4["access_key_id"], sigv4["access_key_id"]);
        let rotated_oauth: sqlx::types::Json<Value> =
            sqlx::query_scalar("SELECT oauth_config FROM gateways")
                .fetch_one(&pool)
                .await
                .unwrap();
        let value = rotated_oauth["client_secret"][0][0].as_str().unwrap();
        assert_eq!(
            keys.new_envelope
                .open(value.to_owned())
                .await
                .unwrap()
                .as_str(),
            "fixture oauth value"
        );
        assert_eq!(rotated_oauth["metadata"], oauth["metadata"]);

        let retry = rotate(&database, &keys, false).await.unwrap();
        assert_eq!((retry.migrated, retry.skipped, retry.errors), (0, 3, 0));
    }

    #[test]
    fn rejects_the_pinned_known_weak_long_key() {
        assert!(!strong_secret("MY-TEST-KEY-BUT-NOW-LONGER-THAN-32-BYTES"));
    }

    #[tokio::test]
    async fn rejects_an_unwrapped_legacy_fernet_token() {
        let keys = RotationKeys::new("fixture old key", "fixture new key", SecretKdf::default());
        let mut bytes = [0; 57];
        bytes[0] = 0x80;
        let token = BASE64_URL_SAFE_NO_PAD.encode(bytes);
        assert!(keys.envelope(&token).await.is_err());
    }
}
