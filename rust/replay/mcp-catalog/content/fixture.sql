INSERT INTO resources (id, uri, name, mime_type, text_content, binary_content) VALUES
    ('text', 'fixture://local/text', 'Text', 'text/plain', 'Local text', NULL),
    ('blob', 'fixture://local/blob', 'Blob', 'application/octet-stream', NULL, x'0001ff');

INSERT INTO prompts (id, name, original_name, custom_name, custom_name_slug, template, argument_schema)
VALUES ('local', 'local', 'local', 'local', 'local', '# User:
Hello {{ who }}
# Assistant:
Greetings', '{"properties":{"who":{"type":"string"}},"required":["who"]}');
