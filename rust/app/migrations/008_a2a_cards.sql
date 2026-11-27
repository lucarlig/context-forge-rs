CREATE TABLE IF NOT EXISTS a2a_agent_cards (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    a2a_agent_id VARCHAR(36) NOT NULL REFERENCES a2a_agents(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    kind VARCHAR(20) NOT NULL DEFAULT 'public',
    card JSON NOT NULL,
    detected_version VARCHAR(20) NOT NULL,
    source_url VARCHAR(2048) NOT NULL,
    etag VARCHAR(255),
    max_age INTEGER,
    fetched_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (a2a_agent_id, version)
);
