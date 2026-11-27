INSERT INTO tools (
    id, original_name, custom_name, custom_name_slug, name, input_schema,
    created_at, updated_at, enabled, reachable, jsonpath_filter, integration_type,
    request_type, gateway_id, team_id, owner_email, visibility
) VALUES (
    'fixture-tool', 'echo', 'echo', 'echo', 'public-fixture-echo', '{"type":"object"}',
    '2025-01-01 00:00:00', '2025-01-01 00:00:00', TRUE, TRUE, '', 'MCP',
    'STREAMABLEHTTP', 'public-fixture', 'gateway-fixture-team', 'admin@example.com', 'public'
);

INSERT INTO servers (id, name, created_at, updated_at, enabled, team_id, owner_email, visibility)
VALUES (
    'fixture-virtual', 'Fixture virtual server', '2025-01-01 00:00:00', '2025-01-01 00:00:00',
    TRUE, 'gateway-fixture-team', 'admin@example.com', 'public'
);

INSERT INTO server_tool_association (server_id, tool_id)
VALUES ('fixture-virtual', 'fixture-tool');
