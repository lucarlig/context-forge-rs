INSERT INTO email_users (id, email, is_admin, created_at, updated_at)
VALUES ('resource-admin', 'admin@example.com', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (email) DO NOTHING;

INSERT INTO roles (id, name, scope, permissions, created_by, is_system_role, is_active, created_at, updated_at)
VALUES ('resource-reader', 'Fixture resource reader', 'global', '["resources.read"]', 'admin@example.com',
        FALSE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO user_roles (id, user_email, role_id, scope, granted_by, granted_at, is_active)
VALUES ('resource-reader-grant', 'admin@example.com', 'resource-reader', 'global',
        'admin@example.com', CURRENT_TIMESTAMP, TRUE);

INSERT INTO resources (
    id, uri, uri_template, name, original_name, custom_name_slug, description, title, mime_type, size,
    text_content, tags, enabled, created_at, updated_at, version, owner_email, visibility, created_by, created_via
) VALUES
    ('resource-fixture', 'file:///fixture/catalog/welcome', NULL, 'Welcome note', 'Welcome note',
     'welcome-note', 'Fixture resource', 'Fixture title', 'text/plain', 12, 'Fixture text', '["Notes"]',
     TRUE, '2025-01-01 00:00:00', '2025-01-01 00:00:00', 1, 'admin@example.com',
     'public', 'admin@example.com', 'api'),
    ('resource-template', 'file:///fixture/catalog/{name}', 'file:///fixture/catalog/{name}',
     'Templated', 'Templated', 'templated', NULL, NULL, 'text/plain', 12, 'Fixture text', '[]',
     TRUE, '2025-01-02 00:00:00', '2025-01-02 00:00:00', 1, 'admin@example.com',
     'public', 'admin@example.com', 'api'),
    ('resource-disabled', 'file:///fixture/catalog/disabled', NULL, 'Disabled', 'Disabled',
     'disabled', NULL, NULL, 'text/plain', 12, 'Fixture text', '[]', FALSE,
     '2025-01-03 00:00:00', '2025-01-03 00:00:00', 1, 'admin@example.com', 'public', 'admin@example.com', 'api'),
    ('resource-private', 'file:///fixture/catalog/private', NULL, 'Private', 'Private',
     'private', NULL, NULL, 'text/plain', 12, 'Fixture text', '["private-tag"]',
     TRUE, '2025-01-04 00:00:00', '2025-01-04 00:00:00', 1, 'admin@example.com',
     'private', 'admin@example.com', 'api');
