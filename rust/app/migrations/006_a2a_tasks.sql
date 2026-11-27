CREATE TABLE IF NOT EXISTS a2a_tasks (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    a2a_agent_id VARCHAR(36) NOT NULL REFERENCES a2a_agents(id) ON DELETE CASCADE,
    task_id VARCHAR(255) NOT NULL,
    context_id VARCHAR(255),
    state VARCHAR(50) NOT NULL DEFAULT 'submitted',
    payload JSON,
    latest_message JSON,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (a2a_agent_id, task_id)
);

CREATE INDEX IF NOT EXISTS ix_native_a2a_tasks_page
    ON a2a_tasks (a2a_agent_id, updated_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS ix_native_a2a_tasks_state_page
    ON a2a_tasks (a2a_agent_id, state, updated_at DESC, id DESC);

CREATE TABLE IF NOT EXISTS a2a_task_events (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    a2a_agent_id VARCHAR(36) REFERENCES a2a_agents(id) ON DELETE CASCADE,
    task_id VARCHAR(255) NOT NULL,
    event_id VARCHAR(36) NOT NULL,
    sequence BIGINT NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    payload JSON,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_native_a2a_task_event_sequence
    ON a2a_task_events (a2a_agent_id, task_id, sequence);
