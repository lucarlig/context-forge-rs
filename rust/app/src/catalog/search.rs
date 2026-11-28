// SPDX-License-Identifier: Apache-2.0

use super::{Database, Value, json, managed_visibility};

#[derive(Clone, Copy)]
pub(crate) enum SearchKind {
    Servers,
    Gateways,
    Tools,
    Resources,
    Prompts,
    Agents,
}

impl SearchKind {
    fn table(self) -> &'static str {
        match self {
            Self::Servers => "servers",
            Self::Gateways => "gateways",
            Self::Tools => "tools",
            Self::Resources => "resources",
            Self::Prompts => "prompts",
            Self::Agents => "a2a_agents",
        }
    }

    pub(crate) fn permission(self) -> &'static str {
        match self {
            Self::Servers => "servers.read",
            Self::Gateways => "gateways.read",
            Self::Tools => "tools.read",
            Self::Resources => "resources.read",
            Self::Prompts => "prompts.read",
            Self::Agents => "a2a.read",
        }
    }

    fn rank_columns(self) -> &'static [&'static str] {
        match self {
            Self::Servers | Self::Resources => &["name"],
            Self::Gateways => &["name", "url"],
            Self::Agents => &["name", "endpoint_url"],
            Self::Tools => &["original_name", "custom_name", "display_name"],
            Self::Prompts => &["original_name", "display_name"],
        }
    }

    fn projection(self) -> &'static str {
        match self {
            Self::Tools => {
                "r.id,r.original_name AS name,CAST(NULL AS TEXT) AS description,
                r.display_name,r.custom_name,CAST(NULL AS TEXT) AS url"
            }
            Self::Prompts => {
                "r.id,r.original_name AS name,r.description,r.display_name,
                CAST(NULL AS TEXT) AS custom_name,CAST(NULL AS TEXT) AS url"
            }
            Self::Gateways => {
                "r.id,r.name,r.description,CAST(NULL AS TEXT) AS display_name,
                CAST(NULL AS TEXT) AS custom_name,r.url"
            }
            Self::Agents => {
                "r.id,r.name,r.description,CAST(NULL AS TEXT) AS display_name,
                CAST(NULL AS TEXT) AS custom_name,r.endpoint_url AS url"
            }
            Self::Servers | Self::Resources => {
                "r.id,r.name,r.description,CAST(NULL AS TEXT) AS display_name,
                CAST(NULL AS TEXT) AS custom_name,CAST(NULL AS TEXT) AS url"
            }
        }
    }

    fn uses_gateway(self) -> bool {
        matches!(self, Self::Tools | Self::Resources | Self::Prompts)
    }
}

#[derive(sqlx::FromRow)]
struct Row {
    id: String,
    name: String,
    description: Option<String>,
    display_name: Option<String>,
    custom_name: Option<String>,
    url: Option<String>,
}

impl Row {
    fn item(self, kind: SearchKind) -> Value {
        match kind {
            SearchKind::Tools => json!({"id":self.id,"name":self.name,
                "display_name":self.display_name,"custom_name":self.custom_name}),
            SearchKind::Prompts => json!({"id":self.id,"name":self.name,"original_name":self.name,
                "display_name":self.display_name,"description":self.description}),
            SearchKind::Gateways => json!({"id":self.id,"name":self.name,"url":self.url,
                "description":self.description}),
            SearchKind::Agents => json!({"id":self.id,"name":self.name,"endpoint_url":self.url,
                "description":self.description}),
            SearchKind::Servers | SearchKind::Resources => json!({"id":self.id,"name":self.name,
                "description":self.description}),
        }
    }
}

pub(crate) struct SearchFilters<'a> {
    pub(crate) email: &'a str,
    pub(crate) team_ids: &'a [String],
    pub(crate) unrestricted: bool,
    pub(crate) team: Option<&'a str>,
    pub(crate) text: &'a str,
    pub(crate) tags: &'a [Vec<String>],
    pub(crate) gateways: &'a [String],
    pub(crate) local: bool,
    pub(crate) include_inactive: bool,
    pub(crate) limit: i64,
}

impl Database {
    pub(crate) async fn search_catalog(
        &self,
        kind: SearchKind,
        filter: &SearchFilters<'_>,
    ) -> Result<Vec<Value>, sqlx::Error> {
        let text = escape_like(filter.text);
        let teams = json!(filter.team_ids).to_string();
        let tags = json!(filter.tags).to_string();
        let gateways = if kind.uses_gateway() {
            filter.gateways
        } else {
            &[]
        };
        let gateways = json!(gateways).to_string();
        let local = kind.uses_gateway() && filter.local;
        macro_rules! load {
            ($pool:expr, $pg:expr) => {{
                let sql = search_sql(kind, $pg);
                // SearchKind and the backend select the SQL fragments. Search values are bound below.
                sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql))
                    .bind(filter.include_inactive)
                    .bind(filter.team)
                    .bind(filter.unrestricted || !filter.team_ids.is_empty())
                    .bind(filter.email)
                    .bind(&teams)
                    .bind(&text)
                    .bind(&tags)
                    .bind(&gateways)
                    .bind(local)
                    .bind(filter.limit)
                    .bind(filter.unrestricted)
                    .fetch_all($pool)
                    .await?
            }};
        }
        let rows = match self {
            Self::Sqlite(pool) => load!(pool, false),
            Self::Postgres(pool) => load!(pool, true),
        };
        Ok(rows.into_iter().map(|row| row.item(kind)).collect())
    }
}

fn search_sql(kind: SearchKind, postgres: bool) -> String {
    let (team_index, gateway_index, groups, terms, stored_tags, tag_id) = if postgres {
        (
            "SELECT json_array_elements_text(CAST($5 AS JSON))",
            "SELECT json_array_elements_text(CAST($8 AS JSON))",
            "json_array_elements(CAST($7 AS JSON)) AS matched_group(value)",
            "json_array_elements_text(matched_group.value) AS term(value)",
            "json_array_elements(CASE WHEN json_typeof(CAST(r.tags AS JSON)) = 'array'
                THEN CAST(r.tags AS JSON) ELSE '[]'::JSON END) AS tag(value)",
            "CASE WHEN json_typeof(tag.value) = 'object' THEN tag.value ->> 'id'
                WHEN json_typeof(tag.value) = 'string' THEN tag.value #>> '{}' END",
        )
    } else {
        (
            "SELECT value FROM json_each($5)",
            "SELECT value FROM json_each($8)",
            "json_each($7) AS matched_group",
            "json_each(matched_group.value) AS term",
            "json_each(CASE WHEN json_valid(r.tags) THEN r.tags ELSE '[]' END) AS tag",
            "CASE WHEN tag.type = 'object' THEN json_extract(tag.value, '$.id')
                WHEN tag.type = 'text' THEN tag.value END",
        )
    };
    let projection = kind.projection();
    let table = kind.table();
    let gateway_id = if kind.uses_gateway() {
        "r.gateway_id"
    } else {
        "CAST(NULL AS TEXT)"
    };
    let visibility = managed_visibility!(
        "r",
        "FALSE",
        "($3 AND ($11 OR r.team_id IN (SELECT id FROM visible_teams)))",
        "$4",
        "visible_teams"
    );
    let rank = kind.rank_columns();
    let name = rank[0];
    let mut columns = vec!["id", "description"];
    columns.extend_from_slice(rank);
    match kind {
        SearchKind::Tools => columns.push("url"),
        SearchKind::Resources => columns.push("uri"),
        _ => {}
    }
    let contains = columns
        .iter()
        .map(|column| format!("LOWER(r.{column}) LIKE '%' || $6 || '%' ESCAPE '\\'"))
        .collect::<Vec<_>>()
        .join(" OR ");
    let starts = rank
        .iter()
        .map(|column| format!("LOWER(r.{column}) LIKE $6 || '%' ESCAPE '\\'"))
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "WITH visible_teams(id) AS ({team_index}), requested_gateways(id) AS ({gateway_index})
        SELECT {projection} FROM {table} r
        WHERE ($1 OR r.enabled) AND (CAST($2 AS TEXT) IS NULL OR r.team_id = $2)
          AND {visibility}
          AND ((NOT $9 AND NOT EXISTS (SELECT 1 FROM requested_gateways))
              OR ($9 AND {gateway_id} IS NULL)
              OR {gateway_id} IN (SELECT id FROM requested_gateways))
          AND ($6 = '' OR {contains})
          AND (CAST($7 AS TEXT) = '[]' OR EXISTS (SELECT 1 FROM {groups}
              WHERE NOT EXISTS (SELECT 1 FROM {terms}
                  WHERE NOT EXISTS (SELECT 1 FROM {stored_tags} WHERE {tag_id} = term.value))))
        ORDER BY CASE WHEN $6 = '' OR {starts} THEN 0 ELSE 1 END, LOWER(r.{name}), r.id LIMIT $10"
    )
}

pub(crate) fn escape_like(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub(crate) fn parse_tag_groups(expression: &str) -> Vec<Vec<String>> {
    expression
        .split(',')
        .filter_map(|group| {
            let terms = group
                .split('+')
                .map(str::trim)
                .filter(|term| !term.is_empty())
                .take(10)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            (!terms.is_empty()).then_some(terms)
        })
        .take(20)
        .collect()
}
