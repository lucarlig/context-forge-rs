-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE IF NOT EXISTS observability_traces (
    trace_id VARCHAR(36) PRIMARY KEY NOT NULL,
    name VARCHAR(255) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_ms DOUBLE PRECISION,
    status VARCHAR(20) NOT NULL DEFAULT 'unset',
    status_message TEXT,
    http_method VARCHAR(10),
    http_url VARCHAR(767),
    http_status_code INTEGER,
    user_email VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    attributes JSON,
    resource_attributes JSON,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_observability_traces_start_time ON observability_traces (start_time);
CREATE INDEX IF NOT EXISTS idx_observability_traces_user_email ON observability_traces (user_email);
CREATE INDEX IF NOT EXISTS idx_observability_traces_status ON observability_traces (status);
CREATE INDEX IF NOT EXISTS idx_observability_traces_http_status_code ON observability_traces (http_status_code);

CREATE TABLE IF NOT EXISTS observability_spans (
    span_id VARCHAR(36) PRIMARY KEY NOT NULL,
    trace_id VARCHAR(36) NOT NULL REFERENCES observability_traces(trace_id) ON DELETE CASCADE,
    parent_span_id VARCHAR(36) REFERENCES observability_spans(span_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    kind VARCHAR(20) NOT NULL DEFAULT 'internal',
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE,
    duration_ms DOUBLE PRECISION,
    status VARCHAR(20) NOT NULL DEFAULT 'unset',
    status_message TEXT,
    attributes JSON,
    resource_name VARCHAR(255),
    resource_type VARCHAR(50),
    resource_id VARCHAR(36),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_observability_spans_trace_id ON observability_spans (trace_id);
CREATE INDEX IF NOT EXISTS idx_observability_spans_start_time ON observability_spans (start_time);
CREATE INDEX IF NOT EXISTS idx_observability_spans_parent_span_id ON observability_spans (parent_span_id);
CREATE INDEX IF NOT EXISTS idx_observability_spans_resource_name ON observability_spans (resource_name);

CREATE TABLE IF NOT EXISTS observability_events (
    id BIGSERIAL PRIMARY KEY,
    span_id VARCHAR(36) NOT NULL REFERENCES observability_spans(span_id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attributes JSON,
    severity VARCHAR(20),
    message TEXT,
    exception_type VARCHAR(255),
    exception_message TEXT,
    exception_stacktrace TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_observability_events_span_id ON observability_events (span_id);

CREATE TABLE IF NOT EXISTS observability_metrics (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    metric_type VARCHAR(20) NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    unit VARCHAR(20),
    attributes JSON,
    resource_type VARCHAR(50),
    resource_id VARCHAR(36),
    trace_id VARCHAR(36) REFERENCES observability_traces(trace_id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_observability_metrics_name_timestamp ON observability_metrics (name, timestamp);
CREATE INDEX IF NOT EXISTS idx_observability_metrics_trace_id ON observability_metrics (trace_id);
