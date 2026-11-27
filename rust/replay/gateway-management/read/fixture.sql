INSERT INTO email_users (id, email, is_admin, created_at, updated_at)
VALUES ('fixture-admin', 'admin@example.com', TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00')
ON CONFLICT (email) DO NOTHING;

INSERT INTO email_teams (id, name, slug, created_by, is_personal, visibility, is_active, created_at, updated_at)
VALUES ('gateway-fixture-team', 'Gateway fixture team', 'gateway-fixture-team',
        'admin@example.com', FALSE, 'private', TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00');

INSERT INTO gateways (
    id, name, slug, url, created_at, updated_at, last_seen, owner_email,
    team_id, visibility, description, transport, capabilities, enabled, reachable,
    tags, version, auth_type, oauth_config, status, registration_attempts, gateway_mode,
    signing_algorithm
) VALUES
    ('public-fixture', 'public-fixture', 'public-fixture', 'https://example.invalid/public-fixture',
     '2025-01-01 00:00:00', '2025-01-01 00:00:00', '2025-01-01 00:00:00', 'admin@example.com',
     'gateway-fixture-team', 'public', 'Public API fixture', 'STREAMABLEHTTP', '{}', TRUE, TRUE,
     '["Fixture"]', 1, 'oauth', '{"client_id":"public-fixture","client_secret":"synthetic-mask-only","token_url":"https://example.invalid/oauth/token","grant_type":"client_credentials"}',
     'active', 0, 'cache', 'ed25519'),
    ('private-fixture', 'private-fixture', 'private-fixture', 'https://example.invalid/private-fixture',
     '2025-01-02 00:00:00', '2025-01-02 00:00:00', '2025-01-02 00:00:00', 'admin@example.com',
     'gateway-fixture-team', 'private', 'Public API fixture', 'STREAMABLEHTTP', '{}', TRUE, TRUE,
     '["Fixture"]', 1, 'oauth', '{"client_id":"private-fixture","client_secret":"synthetic-mask-only","token_url":"https://example.invalid/oauth/token","grant_type":"client_credentials"}',
     'active', 0, 'cache', 'ed25519');
