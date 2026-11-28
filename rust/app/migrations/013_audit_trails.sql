-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE IF NOT EXISTS audit_trails (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    correlation_id VARCHAR(64),
    request_id VARCHAR(64),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    resource_name VARCHAR(500),
    user_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    team_id VARCHAR(36),
    client_ip VARCHAR(45),
    user_agent TEXT,
    request_path VARCHAR(500),
    request_method VARCHAR(10),
    old_values JSON,
    new_values JSON,
    changes JSON,
    data_classification VARCHAR(50),
    requires_review BOOLEAN NOT NULL DEFAULT FALSE,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    context JSON,
    auth_method VARCHAR(50),
    acting_as VARCHAR(255),
    delegation_chain JSON
);

CREATE INDEX IF NOT EXISTS ix_audit_trails_timestamp ON audit_trails (timestamp);
CREATE INDEX IF NOT EXISTS ix_audit_trails_correlation_id ON audit_trails (correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_action_time ON audit_trails (action, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_resource_time ON audit_trails (resource_type, resource_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user_time ON audit_trails (user_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_classification ON audit_trails (data_classification, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_review ON audit_trails (requires_review, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_team_time ON audit_trails (team_id, timestamp);
