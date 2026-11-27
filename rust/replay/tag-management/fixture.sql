INSERT INTO email_users (id, email, is_admin, created_at, updated_at)
VALUES ('tag-admin', 'admin@example.com', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (email) DO NOTHING;

INSERT INTO roles (id, name, scope, permissions, created_by, is_system_role, is_active, created_at, updated_at)
VALUES ('tag-reader', 'Fixture tag reader', 'global', '["tags.read"]', 'admin@example.com',
        FALSE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO user_roles (id, user_email, role_id, scope, granted_by, granted_at, is_active)
VALUES ('tag-reader-grant', 'admin@example.com', 'tag-reader', 'global', 'admin@example.com',
        CURRENT_TIMESTAMP, TRUE);

INSERT INTO email_teams (id, name, slug, created_by, is_personal, visibility, is_active, created_at, updated_at)
VALUES ('tag-team', 'Tag fixture team', 'tag-team', 'admin@example.com', FALSE, 'private',
        TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO gateways (
    id, name, slug, url, description, capabilities, tags, created_at, updated_at, enabled,
    reachable, transport, owner_email, team_id, visibility, gateway_mode, status, version, registration_attempts
) VALUES
    ('tag-gateway-01', 'public-fixture', 'public-fixture', 'https://example.invalid/public',
     'Fixture upstream', '{}', '[{"id":"common","label":"Common"},"CaseSensitive"]', CURRENT_TIMESTAMP,
     CURRENT_TIMESTAMP, TRUE, TRUE, 'STREAMABLEHTTP', 'admin@example.com', 'tag-team', 'public', 'cache', 'active', 1, 0),
    ('tag-gateway-02', 'private-fixture', 'private-fixture', 'https://example.invalid/private',
     NULL, '{}', '["common","owned-only"]', CURRENT_TIMESTAMP,
     CURRENT_TIMESTAMP, FALSE, TRUE, 'STREAMABLEHTTP', 'admin@example.com', NULL, 'private', 'cache', 'active', 1, 0),
    ('tag-gateway-03', 'other-private', 'other-private', 'https://example.invalid/other',
     NULL, '{}', '["hidden"]', CURRENT_TIMESTAMP,
     CURRENT_TIMESTAMP, TRUE, TRUE, 'STREAMABLEHTTP', 'other@example.invalid', NULL, 'private', 'cache', 'active', 1, 0);

INSERT INTO tools (
    id, name, original_name, custom_name, custom_name_slug, description, input_schema, tags,
    created_at, updated_at, enabled, reachable, jsonpath_filter, integration_type, request_type,
    gateway_id, owner_email, visibility
) VALUES (
    'tag-tool', 'public-fixture-echo', 'echo', 'echo', 'echo', 'Fixture tool', '{"type":"object"}',
    '["common","tools-only"]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE, TRUE, '', 'MCP',
    'STREAMABLEHTTP', 'tag-gateway-01', 'admin@example.com', 'public'
);

INSERT INTO resources (id, uri, name, description, created_at, updated_at, enabled, tags, owner_email, visibility)
VALUES ('tag-resource', 'fixture://tags/resource', 'Fixture resource', NULL, CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP, TRUE, '[{"id":"common","label":"Shared"}]', 'admin@example.com', 'public');

INSERT INTO prompts (
    id, name, original_name, custom_name, custom_name_slug, description, argument_schema,
    created_at, updated_at, enabled, tags, owner_email, team_id, visibility
) VALUES (
    'tag-prompt', 'fixture-prompt', 'fixture-prompt', 'fixture-prompt', 'fixture-prompt', 'Fixture prompt',
    '{"type":"object","properties":{}}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE,
    '["common","team-only"]', 'admin@example.com', 'tag-team', 'team'
);

INSERT INTO servers (id, name, description, created_at, updated_at, enabled, tags, owner_email, visibility)
VALUES ('tag-server', 'Fixture virtual server', NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE,
        '["common","servers-only"]', 'admin@example.com', 'public');
