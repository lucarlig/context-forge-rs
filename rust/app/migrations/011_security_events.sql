CREATE TABLE IF NOT EXISTS structured_log_entries (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    correlation_id VARCHAR(64),
    request_id VARCHAR(64),
    level VARCHAR(20) NOT NULL,
    component VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    logger VARCHAR(255),
    user_id VARCHAR(255),
    user_email VARCHAR(255),
    client_ip VARCHAR(45),
    user_agent TEXT,
    request_path VARCHAR(500),
    request_method VARCHAR(10),
    duration_ms DOUBLE PRECISION,
    operation_type VARCHAR(100),
    is_security_event BOOLEAN NOT NULL DEFAULT FALSE,
    security_severity VARCHAR(20),
    threat_indicators JSON,
    context JSON,
    error_details JSON,
    performance_metrics JSON,
    hostname VARCHAR(255) NOT NULL,
    process_id INTEGER NOT NULL,
    thread_id INTEGER,
    version VARCHAR(50) NOT NULL,
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    trace_id VARCHAR(32),
    span_id VARCHAR(16)
);

CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    detected_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    correlation_id VARCHAR(64),
    log_entry_id VARCHAR(36) REFERENCES structured_log_entries(id),
    event_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    category VARCHAR(50) NOT NULL,
    user_id VARCHAR(255),
    user_email VARCHAR(255),
    client_ip VARCHAR(45) NOT NULL,
    user_agent TEXT,
    description TEXT NOT NULL,
    action_taken VARCHAR(100),
    threat_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    threat_indicators JSON NOT NULL DEFAULT '{}',
    failed_attempts_count INTEGER NOT NULL DEFAULT 0,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by VARCHAR(255),
    resolution_notes TEXT,
    alert_sent BOOLEAN NOT NULL DEFAULT FALSE,
    alert_sent_at TIMESTAMP WITH TIME ZONE,
    alert_recipients JSON,
    context JSON
);

CREATE INDEX IF NOT EXISTS idx_security_type_time ON security_events (event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_security_severity_time ON security_events (severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_security_user_time ON security_events (user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_security_ip_time ON security_events (client_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_security_unresolved ON security_events (resolved, severity, timestamp);
