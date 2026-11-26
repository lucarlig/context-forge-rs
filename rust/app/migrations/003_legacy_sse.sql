-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE IF NOT EXISTS context_forge_sse_sessions (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    owner_email VARCHAR(255),
    server_id VARCHAR(36),
    expires_at BIGINT NOT NULL,
    next_sequence BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_context_forge_sse_sessions_expiry
    ON context_forge_sse_sessions (expires_at);

CREATE TABLE IF NOT EXISTS context_forge_sse_messages (
    session_id VARCHAR(36) NOT NULL REFERENCES context_forge_sse_sessions(id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL,
    payload TEXT NOT NULL,
    bytes BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (session_id, sequence)
);
