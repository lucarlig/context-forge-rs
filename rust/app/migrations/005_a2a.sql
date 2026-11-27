CREATE TABLE IF NOT EXISTS a2a_agents (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL,
    description TEXT,
    endpoint_url VARCHAR(767) NOT NULL,
    agent_type VARCHAR(50) NOT NULL DEFAULT 'generic',
    protocol_binding VARCHAR(20),
    protocol_version VARCHAR(10) NOT NULL DEFAULT '1.0',
    capabilities JSON NOT NULL DEFAULT '{}',
    skills JSON,
    config JSON NOT NULL DEFAULT '{}',
    auth_type VARCHAR(20),
    auth_value TEXT,
    auth_query_params JSON,
    oauth_config JSON,
    passthrough_headers JSON,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    reachable BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_interaction TIMESTAMP WITH TIME ZONE,
    tags JSON NOT NULL DEFAULT '[]',
    created_by VARCHAR(255),
    created_from_ip VARCHAR(45),
    created_via VARCHAR(100),
    created_user_agent TEXT,
    modified_by VARCHAR(255),
    modified_from_ip VARCHAR(45),
    modified_via VARCHAR(100),
    modified_user_agent TEXT,
    import_batch_id VARCHAR(36),
    federation_source VARCHAR(255),
    version INTEGER NOT NULL DEFAULT 1,
    team_id VARCHAR(36) REFERENCES email_teams(id) ON DELETE SET NULL,
    owner_email VARCHAR(255),
    visibility VARCHAR(20) NOT NULL DEFAULT 'public',
    tool_id VARCHAR(36) REFERENCES tools(id) ON DELETE SET NULL,
    tenant VARCHAR(255),
    icon_url VARCHAR(767),
    uaid VARCHAR(2048),
    uaid_registry VARCHAR(255),
    uaid_proto VARCHAR(20),
    uaid_native_id VARCHAR(767)
);

CREATE INDEX IF NOT EXISTS idx_native_a2a_tool ON a2a_agents (tool_id);
CREATE INDEX IF NOT EXISTS idx_native_a2a_name ON a2a_agents (name);
CREATE INDEX IF NOT EXISTS idx_native_a2a_slug ON a2a_agents (visibility, slug, team_id, owner_email);
CREATE TABLE IF NOT EXISTS server_a2a_association (
    server_id VARCHAR(36) NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    a2a_agent_id VARCHAR(36) NOT NULL REFERENCES a2a_agents(id) ON DELETE CASCADE,
    PRIMARY KEY (server_id, a2a_agent_id)
);
