INSERT INTO resources (id, uri, uri_template, name) VALUES
    ('001-text', 'fixture://local/text', 'fixture://local/{name}', 'Text'),
    ('002-blob', 'fixture://local/blob', NULL, 'Blob');
INSERT INTO prompts (id, name, original_name, custom_name, custom_name_slug, argument_schema)
VALUES ('001-local', 'local', 'local', 'local', 'local',
    '{"properties":{"who":{"name":"who","type":"string","enum":["World","Waffle","Else"]}}}');
