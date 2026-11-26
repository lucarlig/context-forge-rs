INSERT INTO gateways (id, name, slug, url, transport, visibility)
VALUES ('fixture', 'fixture', 'fixture', 'http://127.0.0.1:46037/mcp', 'STREAMABLEHTTP', 'public');

INSERT INTO resources (id, uri, uri_template, name, description, mime_type, gateway_id) VALUES
    ('resource', 'fixture://notes/welcome', NULL, 'fixture-welcome', 'Fixture resource', 'text/plain', 'fixture'),
    ('template', 'fixture://notes/{name}', 'fixture://notes/{name}', 'fixture-note', NULL, 'text/plain', 'fixture');

INSERT INTO prompts (id, name, original_name, custom_name, custom_name_slug, description, argument_schema, gateway_id)
VALUES ('prompt', 'fixture-welcome', 'welcome', 'welcome', 'welcome', 'Fixture prompt',
        '{"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}', 'fixture');
