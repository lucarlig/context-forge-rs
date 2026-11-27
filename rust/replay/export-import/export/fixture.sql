-- SPDX-License-Identifier: Apache-2.0

INSERT INTO email_users (id, email, is_admin, is_active, created_at, updated_at)
VALUES ('export-admin', 'admin@example.com', TRUE, TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00')
ON CONFLICT (email) DO NOTHING;

INSERT INTO email_users (id, email, is_admin, is_active, created_at, updated_at) VALUES
    ('export-user', 'exporter@example.com', FALSE, TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00'),
    ('export-viewer', 'viewer@example.com', FALSE, TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00');

INSERT INTO roles (id, name, scope, permissions, created_by, is_system_role, is_active, created_at, updated_at)
VALUES ('export-role', 'export-fixture', 'global', '["admin.export"]', 'admin@example.com', FALSE, TRUE,
        '2025-01-01 00:00:00', '2025-01-01 00:00:00');

INSERT INTO user_roles (id, user_email, role_id, scope, granted_by, granted_at, is_active)
VALUES ('export-grant', 'exporter@example.com', 'export-role', 'global', 'admin@example.com', '2025-01-01 00:00:00', TRUE);

INSERT INTO email_teams (id, name, slug, created_by, is_personal, visibility, is_active, created_at, updated_at) VALUES
    ('export-team', 'Export fixture team', 'export-team', 'admin@example.com', FALSE, 'private', TRUE,
     '2025-01-01 00:00:00', '2025-01-01 00:00:00'),
    ('other-team', 'Other fixture team', 'other-team', 'admin@example.com', FALSE, 'private', TRUE,
     '2025-01-01 00:00:00', '2025-01-01 00:00:00');

INSERT INTO email_team_members (id, team_id, user_email, role, joined_at, is_active)
VALUES ('export-membership', 'export-team', 'exporter@example.com', 'member', '2025-01-01 00:00:00', TRUE);

INSERT INTO gateways (id, name, slug, url, created_at, updated_at, last_seen, owner_email, team_id, visibility,
                      description, transport, capabilities, enabled, reachable, tags, version, status,
                      registration_attempts, gateway_mode, signing_algorithm, auth_type)
VALUES ('export-gateway', 'Export gateway', 'export-gateway', 'https://gateway.example.invalid/mcp',
        '2025-01-01 00:00:00', '2025-01-01 00:00:00', '2025-01-01 00:00:00', 'exporter@example.com',
        'export-team', 'team', 'Fixture gateway', 'STREAMABLEHTTP', '{"tools":{}}', TRUE, TRUE,
        '[{"id":"fixture","label":"Fixture"}]', 1, 'active', 0, 'cache', 'ed25519', NULL);

INSERT INTO tools (id, name, original_name, custom_name, custom_name_slug, display_name, url, integration_type,
                   request_type, input_schema, created_at, updated_at, enabled, jsonpath_filter, description,
                   original_description, tags, visibility, team_id, owner_email, auth_type, gateway_id, headers)
VALUES ('export-tool', 'public-tool', 'Original Tool', 'Public Tool', 'public-tool', 'Public tool display',
        'https://tools.example.invalid/echo', 'REST', 'POST', '{"type":"object","properties":{}}',
        '2025-01-03 00:00:00', '2025-01-04 00:00:00', TRUE, '', 'Public fixture tool', 'Original description',
        '[{"id":"fixture","label":"Fixture"}]', 'public', 'export-team', 'exporter@example.com', NULL, NULL,
        '{"X-Fixture":{"_mcpgateway_encrypted_header_value_v1":"DMUL1DHcEwPg-MDRXSEMB34Zci5obcPz0dxGa4727y2qwQZFlD6__SczhsuhlRf517G8Un9U4gjUiCiXM5no"}}'),
       ('export-inactive', 'inactive-tool', 'Inactive Tool', 'Inactive Tool', 'inactive-tool', 'Inactive Tool',
        'https://tools.example.invalid/inactive', 'REST', 'POST', '{"type":"object"}',
        '2025-01-02 00:00:00', '2025-01-02 00:00:00', FALSE, '', NULL, NULL, '[]', 'public', 'export-team',
        'exporter@example.com', NULL, NULL, NULL),
       ('export-federated', 'export-gateway-federated-tool', 'Federated Tool', 'Federated Tool', 'federated-tool', NULL,
        'https://gateway.example.invalid/mcp', 'MCP', 'STREAMABLEHTTP', '{"type":"object"}',
        '2025-01-01 00:00:00', '2025-01-01 00:00:00', TRUE, '', NULL, NULL, '[]', 'team', 'export-team',
        'exporter@example.com', NULL, 'export-gateway', NULL);

-- Synthetic values encrypted with the replay's dedicated fixture key.
UPDATE tools
SET auth_type = 'bearer',
    auth_value = '1JQAhjRhB6kVTcP9j4B5k0XF4hcnXvHoxWPBgr-0jm62sRcxz8s0wD1xlUwUU7nreGCmzypARWhRpwLI0D5rYMkuJlnkzmM5GeJ2hrcAcOE1j4Ic'
WHERE id = 'export-tool';

UPDATE gateways
SET auth_type = 'bearer',
    auth_value = '"ZGWD-SCJ_9q-YugpIt3iuvs5Quz9YZogEz0LuMH-8BLR4dvBhfGnNAh-zzzXvGaKTxRrH2JV4rxUPmVf7puw8ntL_w6jSJgsKf4cmjHRu-Wtm4xX4Wxx"'
WHERE id = 'export-gateway';

INSERT INTO resources (id, uri, name, original_name, custom_name_slug, description, mime_type, tags, enabled,
                       created_at, updated_at, gateway_id, team_id, owner_email, visibility)
VALUES ('export-resource', 'fixture://docs/readme', 'export-gateway-guides', 'Original guides', 'guides',
        'Fixture resource', 'text/plain', '[{"id":"fixture","label":"Fixture"}]', TRUE,
        '2025-01-02 00:00:00', '2025-01-04 00:00:00', 'export-gateway', 'export-team', 'exporter@example.com', 'team');

INSERT INTO prompts (id, name, original_name, custom_name, custom_name_slug, display_name, template, description,
                     argument_schema, tags, enabled, created_at, updated_at, team_id, owner_email, visibility)
VALUES ('export-prompt', 'private-prompt', 'Original Prompt', 'Private Prompt', 'private-prompt', 'Displayed prompt',
        'Hello {{ name }}', 'Fixture prompt',
        '{"type":"object","properties":{"name":{"type":"string","description":"A name"}},"required":["name"]}',
        '[{"id":"fixture","label":"Fixture"}]', TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00',
        'export-team', 'exporter@example.com', 'private'),
       ('hidden-prompt', 'hidden-prompt', 'Hidden Prompt', 'Hidden Prompt', 'hidden-prompt', NULL, 'Private template',
        NULL, NULL, '[]', TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00', 'other-team', 'admin@example.com', 'team');

INSERT INTO servers (id, name, description, instructions, enabled, tags, visibility, created_at, updated_at)
VALUES ('export-server', 'Fixture server', 'Public virtual server', 'Fixture instructions', TRUE,
        '[{"id":"fixture","label":"Fixture"}]', 'public', '2025-01-01 00:00:00', '2025-01-01 00:00:00');

INSERT INTO server_tool_association (server_id, tool_id)
VALUES ('export-server', 'export-tool'), ('export-server', 'export-inactive');
