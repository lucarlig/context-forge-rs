-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE IF NOT EXISTS email_users (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    full_name VARCHAR(255),
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    admin_origin VARCHAR(20),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    auth_provider VARCHAR(50) NOT NULL DEFAULT 'local',
    password_hash_type VARCHAR(20) NOT NULL DEFAULT 'argon2id',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
    password_changed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS email_teams (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_by VARCHAR(255) NOT NULL REFERENCES email_users(email),
    is_personal BOOLEAN NOT NULL DEFAULT FALSE,
    visibility VARCHAR(20) NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private')),
    max_members INTEGER,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS email_team_members (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    team_id VARCHAR(36) NOT NULL REFERENCES email_teams(id) ON DELETE CASCADE,
    user_email VARCHAR(255) NOT NULL REFERENCES email_users(email),
    role VARCHAR(50) NOT NULL DEFAULT 'member',
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    invited_by VARCHAR(255) REFERENCES email_users(email),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    grant_source VARCHAR(50),
    UNIQUE (team_id, user_email)
);

CREATE INDEX IF NOT EXISTS idx_email_team_members_user_team_active
    ON email_team_members (user_email, team_id, is_active);

CREATE TABLE IF NOT EXISTS roles (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('global', 'team', 'personal')),
    permissions JSON NOT NULL DEFAULT '[]',
    inherits_from VARCHAR(36) REFERENCES roles(id),
    created_by VARCHAR(255) NOT NULL REFERENCES email_users(email),
    is_system_role BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_roles_name_scope_active
    ON roles (name, scope) WHERE is_active = TRUE;

CREATE TABLE IF NOT EXISTS user_roles (
    id VARCHAR(36) PRIMARY KEY NOT NULL,
    user_email VARCHAR(255) NOT NULL REFERENCES email_users(email),
    role_id VARCHAR(36) NOT NULL REFERENCES roles(id),
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('global', 'team', 'personal')),
    scope_id VARCHAR(36),
    granted_by VARCHAR(255) NOT NULL REFERENCES email_users(email),
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    grant_source VARCHAR(50)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_scope_active
    ON user_roles (user_email, scope, is_active);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_roles_email_role_scope_null_active
    ON user_roles (user_email, role_id, scope) WHERE scope_id IS NULL AND is_active = TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_roles_email_role_scope_id_active
    ON user_roles (user_email, role_id, scope, scope_id) WHERE scope_id IS NOT NULL AND is_active = TRUE;

CREATE TABLE IF NOT EXISTS token_revocations (
    jti VARCHAR(36) PRIMARY KEY NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_by VARCHAR(255) NOT NULL REFERENCES email_users(email),
    reason VARCHAR(255),
    token_expiry TIMESTAMP WITH TIME ZONE,
    last_activity TIMESTAMP WITH TIME ZONE
);
