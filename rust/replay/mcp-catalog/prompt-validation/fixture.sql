INSERT INTO prompts (id, name, original_name, custom_name, custom_name_slug, template, argument_schema) VALUES
    ('local', 'local', 'local', 'local', 'local',
     '# User:
Hello {{ who }}
# Assistant:
Greetings',
     '{"type":"object","properties":{"who":{"type":"string","enum":["World"],"maxLength":5}},"required":["who"],"additionalProperties":false}'),
    ('schema-less', 'schema-less', 'schema-less', 'schema-less', 'schema-less',
     'Hello {{ who }}', NULL),
    ('escape', 'escape', 'escape', 'escape', 'escape',
     'Start
  {% if who %}
  Hello {{ who }}
  {% endif %}
End', '{"type":"object"}');
