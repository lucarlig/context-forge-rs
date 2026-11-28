// SPDX-License-Identifier: Apache-2.0

use std::{io::ErrorKind, time::Instant};

use tokio::{io::AsyncReadExt, sync::Mutex};

use super::*;

const DEFAULT_FILE: &str = "mcp-catalog.yml";
const MAX_CATALOG_BYTES: u64 = 1_048_576;

pub(super) struct Registry {
    file: String,
    ttl: Duration,
    cache: Mutex<Option<(Instant, Vec<Entry>)>>,
}

#[derive(Deserialize)]
struct Document {
    #[serde(default)]
    catalog_servers: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
    name: String,
    description: String,
    auth_type: String,
}

impl Registry {
    pub(super) fn new(file: String, ttl: Duration) -> Self {
        Self {
            file,
            ttl,
            cache: Mutex::new(None),
        }
    }

    pub(super) async fn search(&self, q: &str, limit: usize) -> Vec<Value> {
        let mut cache = self.cache.lock().await;
        if cache
            .as_ref()
            .is_none_or(|(loaded, _)| loaded.elapsed() >= self.ttl)
        {
            match self.read().await {
                Ok(entries) => *cache = Some((Instant::now(), entries)),
                Err(error) => {
                    tracing::warn!(%error, "catalog search file could not be read");
                    return Vec::new();
                }
            }
        }
        cache
            .as_ref()
            .expect("loaded registry")
            .1
            .iter()
            .filter(|entry| {
                entry.auth_type == "Open"
                    && (entry.name.to_lowercase().contains(q)
                        || entry.description.to_lowercase().contains(q))
            })
            .take(limit)
            .map(|entry| json!({"id":entry.id,"name":entry.name,"description":entry.description}))
            .collect()
    }

    async fn read(&self) -> Result<Vec<Entry>, Box<dyn std::error::Error + Send + Sync>> {
        let input = match tokio::fs::File::open(&self.file).await {
            Ok(file) => {
                if !file.metadata().await?.is_file() {
                    return Err("catalog path is not a regular file".into());
                }
                let mut bytes = Vec::new();
                file.take(MAX_CATALOG_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .await?;
                if bytes.len() as u64 > MAX_CATALOG_BYTES {
                    return Err("catalog file exceeds its size limit".into());
                }
                String::from_utf8(bytes)?
            }
            Err(error) if error.kind() == ErrorKind::NotFound && self.file == DEFAULT_FILE => {
                include_str!("../mcp-catalog.yml").to_owned()
            }
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let document =
            tokio::task::spawn_blocking(move || serde_saphyr::from_str::<Document>(&input))
                .await?
                .map_err(|_| "catalog YAML is invalid")?;
        Ok(document.catalog_servers)
    }
}
