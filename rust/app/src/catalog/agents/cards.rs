// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) struct NewAgentCard<'a> {
    pub(crate) kind: &'static str,
    pub(crate) document: &'a Value,
    pub(crate) detected_version: &'static str,
    pub(crate) source_url: &'a str,
    pub(crate) etag: Option<&'a str>,
    pub(crate) max_age: Option<i32>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct StoredAgentCard {
    version: i32,
    kind: String,
    card: DbJson<Value>,
    detected_version: String,
    source_url: String,
    etag: Option<String>,
    max_age: Option<i32>,
    fetched_at: String,
}

impl StoredAgentCard {
    pub(crate) fn wire(self) -> Value {
        let time = self.fetched_at.replacen(' ', "T", 1);
        let stamp = time
            .strip_suffix("+00:00")
            .or_else(|| time.strip_suffix("+00"))
            .map_or(time.clone(), |stamp| format!("{stamp}Z"));
        json!({
            "version":self.version, "kind":self.kind, "card":self.card.0,
            "detectedVersion":self.detected_version, "sourceUrl":self.source_url,
            "etag":self.etag, "maxAge":self.max_age, "fetchedAt":stamp,
        })
    }
}

macro_rules! insert_cards {
    ($tx:ident, $agent:expr, $cards:expr) => {{
        for (index, card) in $cards.iter().enumerate() {
            sqlx::query("INSERT INTO a2a_agent_cards
                (id,a2a_agent_id,version,kind,card,detected_version,source_url,etag,max_age,fetched_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,CURRENT_TIMESTAMP)")
                .bind(uuid::Uuid::new_v4().simple().to_string())
                .bind($agent)
                .bind((index + 1) as i32)
                .bind(card.kind)
                .bind(DbJson(card.document))
                .bind(card.detected_version)
                .bind(card.source_url)
                .bind(card.etag.filter(|etag| etag.chars().count() <= 255))
                .bind(card.max_age)
                .execute(&mut *$tx)
                .await?;
        }
    }};
}

pub(super) use insert_cards;

const CURRENT_CARD: &str = "
    SELECT version,kind,card,detected_version,source_url,etag,max_age,
        CAST(fetched_at AS TEXT) AS fetched_at
    FROM a2a_agent_cards WHERE a2a_agent_id=$1 AND kind=$2
    ORDER BY version DESC LIMIT 1";

const SERVER_CARD_AGENTS: &str = concat!(
    projection!(),
    "
    WHERE r.enabled AND EXISTS (SELECT 1 FROM server_a2a_association a
        WHERE a.server_id=$1 AND a.a2a_agent_id=r.id) ORDER BY r.id"
);

impl Database {
    pub(crate) async fn stored_agent_card(
        &self,
        agent: &str,
        kind: &str,
    ) -> Result<Option<StoredAgentCard>, sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(CURRENT_CARD)
                    .bind(agent)
                    .bind(kind)
                    .fetch_optional(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as(CURRENT_CARD)
                    .bind(agent)
                    .bind(kind)
                    .fetch_optional(pool)
                    .await
            }
        }
    }

    pub(crate) async fn server_card_agents(
        &self,
        server: &str,
        scope: CatalogScope<'_>,
    ) -> Result<Vec<AgentRecord>, sqlx::Error> {
        let agents: Vec<AgentRecord> = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as(SERVER_CARD_AGENTS)
                    .bind(server)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as(SERVER_CARD_AGENTS)
                    .bind(server)
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok(agents
            .into_iter()
            .filter(|agent| agent.visible(scope))
            .collect())
    }
}
