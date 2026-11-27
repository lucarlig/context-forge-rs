INSERT INTO email_users (id, email, is_admin, created_at, updated_at)
VALUES ('prompt-admin', 'admin@example.com', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (email) DO NOTHING;

INSERT INTO roles (id, name, scope, permissions, created_by, is_system_role, is_active, created_at, updated_at)
VALUES ('prompt-reader', 'Fixture prompt reader', 'global', '["prompts.read"]', 'admin@example.com',
        FALSE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO user_roles (id, user_email, role_id, scope, granted_by, granted_at, is_active)
VALUES ('prompt-reader-grant', 'admin@example.com', 'prompt-reader', 'global',
        'admin@example.com', CURRENT_TIMESTAMP, TRUE);


INSERT INTO prompts (
    id, name, original_name, custom_name, custom_name_slug, display_name, description, template,
    argument_schema, tags, enabled, created_at, updated_at, version, owner_email, visibility, created_by, created_via
) VALUES
    ('prompt-fixture', 'welcome', 'Welcome', 'Welcome', 'welcome', 'Greeting', 'Fixture prompt',
     'Hello {{ who }}!', '{"type":"object","properties":{"who":{"type":"string","description":"Name"}},"required":["who"]}',
     '[{"id":"friendly","label":"Friendly"}]', TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00', 1, 'admin@example.com',
     'public', 'admin@example.com', 'api'),
    ('prompt-disabled', 'disabled', 'Disabled', 'Disabled', 'disabled', NULL, NULL,
     'Disabled prompt', '{"type":"object","properties":{},"required":[]}', '[]', FALSE,
     '2024-12-31 00:00:00', '2024-12-31 00:00:00', 1, 'admin@example.com', 'public', 'admin@example.com', 'api'),
    ('prompt-private', 'private', 'Private', 'Private', 'private', NULL, 'Scope fixture',
     'Private prompt', '{"type":"object","properties":{},"required":[]}', '[]', TRUE,
     '2024-12-30 00:00:00', '2024-12-30 00:00:00', 1, 'admin@example.com', 'private', 'admin@example.com', 'api');
