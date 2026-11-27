CREATE TABLE IF NOT EXISTS a2a_agent_metrics (
    id BIGSERIAL PRIMARY KEY,
    a2a_agent_id VARCHAR(36) NOT NULL REFERENCES a2a_agents(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_time DOUBLE PRECISION NOT NULL,
    is_success BOOLEAN NOT NULL,
    error_message TEXT,
    interaction_type VARCHAR(50) NOT NULL DEFAULT 'invoke'
);

CREATE INDEX IF NOT EXISTS ix_native_a2a_metrics_agent_time
    ON a2a_agent_metrics (a2a_agent_id, timestamp);

CREATE TABLE IF NOT EXISTS a2a_agent_metrics_hourly (
    id BIGSERIAL PRIMARY KEY,
    a2a_agent_id VARCHAR(36) REFERENCES a2a_agents(id) ON DELETE SET NULL,
    agent_name VARCHAR(255) NOT NULL,
    hour_start TIMESTAMP WITH TIME ZONE NOT NULL,
    interaction_type VARCHAR(50) NOT NULL DEFAULT 'invoke',
    total_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    min_response_time DOUBLE PRECISION,
    max_response_time DOUBLE PRECISION,
    avg_response_time DOUBLE PRECISION,
    p50_response_time DOUBLE PRECISION,
    p95_response_time DOUBLE PRECISION,
    p99_response_time DOUBLE PRECISION,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (a2a_agent_id, hour_start, interaction_type)
);
