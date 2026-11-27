CREATE TABLE IF NOT EXISTS a2a_push_notification_configs (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    a2a_agent_id VARCHAR(36) NOT NULL REFERENCES a2a_agents(id) ON DELETE CASCADE,
    task_id VARCHAR(255) NOT NULL,
    webhook_url VARCHAR(2048) NOT NULL,
    auth_token TEXT,
    events JSON,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (a2a_agent_id, task_id, webhook_url)
);
