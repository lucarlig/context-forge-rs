-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE IF NOT EXISTS tool_metrics (
    id BIGSERIAL PRIMARY KEY,
    tool_id VARCHAR(36) NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_time DOUBLE PRECISION NOT NULL,
    is_success BOOLEAN NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS ix_native_tool_metrics_id_time ON tool_metrics (tool_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_native_tool_metrics_time ON tool_metrics (timestamp);

CREATE TABLE IF NOT EXISTS tool_metrics_hourly (
    id BIGSERIAL PRIMARY KEY,
    tool_id VARCHAR(36) REFERENCES tools(id) ON DELETE SET NULL,
    tool_name VARCHAR(255) NOT NULL,
    hour_start TIMESTAMP WITH TIME ZONE NOT NULL,
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
    UNIQUE (tool_id, hour_start)
);

CREATE INDEX IF NOT EXISTS ix_native_tool_metrics_hourly_time ON tool_metrics_hourly (hour_start);

CREATE TABLE IF NOT EXISTS resource_metrics (
    id BIGSERIAL PRIMARY KEY,
    resource_id VARCHAR(36) NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_time DOUBLE PRECISION NOT NULL,
    is_success BOOLEAN NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS ix_native_resource_metrics_id_time ON resource_metrics (resource_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_native_resource_metrics_time ON resource_metrics (timestamp);

CREATE TABLE IF NOT EXISTS resource_metrics_hourly (
    id BIGSERIAL PRIMARY KEY,
    resource_id VARCHAR(36) REFERENCES resources(id) ON DELETE SET NULL,
    resource_name VARCHAR(255) NOT NULL,
    hour_start TIMESTAMP WITH TIME ZONE NOT NULL,
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
    UNIQUE (resource_id, hour_start)
);

CREATE INDEX IF NOT EXISTS ix_native_resource_metrics_hourly_time ON resource_metrics_hourly (hour_start);

CREATE TABLE IF NOT EXISTS prompt_metrics (
    id BIGSERIAL PRIMARY KEY,
    prompt_id VARCHAR(36) NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_time DOUBLE PRECISION NOT NULL,
    is_success BOOLEAN NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS ix_native_prompt_metrics_id_time ON prompt_metrics (prompt_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_native_prompt_metrics_time ON prompt_metrics (timestamp);

CREATE TABLE IF NOT EXISTS prompt_metrics_hourly (
    id BIGSERIAL PRIMARY KEY,
    prompt_id VARCHAR(36) REFERENCES prompts(id) ON DELETE SET NULL,
    prompt_name VARCHAR(255) NOT NULL,
    hour_start TIMESTAMP WITH TIME ZONE NOT NULL,
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
    UNIQUE (prompt_id, hour_start)
);

CREATE INDEX IF NOT EXISTS ix_native_prompt_metrics_hourly_time ON prompt_metrics_hourly (hour_start);

CREATE TABLE IF NOT EXISTS server_metrics (
    id BIGSERIAL PRIMARY KEY,
    server_id VARCHAR(36) NOT NULL REFERENCES servers(id),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    response_time DOUBLE PRECISION NOT NULL,
    is_success BOOLEAN NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS ix_native_server_metrics_id_time ON server_metrics (server_id, timestamp);
CREATE INDEX IF NOT EXISTS ix_native_server_metrics_time ON server_metrics (timestamp);

CREATE TABLE IF NOT EXISTS server_metrics_hourly (
    id BIGSERIAL PRIMARY KEY,
    server_id VARCHAR(36) REFERENCES servers(id) ON DELETE SET NULL,
    server_name VARCHAR(255) NOT NULL,
    hour_start TIMESTAMP WITH TIME ZONE NOT NULL,
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
    UNIQUE (server_id, hour_start)
);

CREATE INDEX IF NOT EXISTS ix_native_server_metrics_hourly_time ON server_metrics_hourly (hour_start);
