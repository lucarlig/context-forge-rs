INSERT INTO email_users (id, email, is_admin, created_at, updated_at)
VALUES ('tool-admin', 'admin@example.com', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (email) DO NOTHING;

INSERT INTO roles (id, name, scope, permissions, created_by, is_system_role, is_active, created_at, updated_at)
VALUES ('tool-reader', 'Fixture tool reader', 'global', '["tools.read","tools.preview"]', 'admin@example.com',
        FALSE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO user_roles (id, user_email, role_id, scope, granted_by, granted_at, is_active)
VALUES ('tool-reader-grant', 'admin@example.com', 'tool-reader', 'global',
        'admin@example.com', CURRENT_TIMESTAMP, TRUE);


INSERT INTO email_users (id,email,is_admin,is_active,created_at,updated_at)
VALUES ('tool-viewer','viewer@example.com',FALSE,TRUE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);

INSERT INTO user_roles (id,user_email,role_id,scope,granted_by,granted_at,is_active)
VALUES ('tool-viewer-grant','viewer@example.com','tool-reader','global','admin@example.com',CURRENT_TIMESTAMP,TRUE);

INSERT INTO tools (
    id,name,original_name,custom_name,custom_name_slug,display_name,description,original_description,
    url,headers,input_schema,jsonpath_filter,request_type,integration_type,enabled,reachable,tags,created_at,updated_at,
    owner_email,visibility,created_by,created_via
) VALUES (
    'tool-fixture','hello','Hello','Hello','hello','Fixture tool','Return a greeting','Return a greeting',
    'http://127.0.0.1:30997/items','{"X-Fixture-Header":"fixture-visible-only-to-owner"}',
    '{"type":"object","properties":{"who":{"type":"string"}},"required":["who"]}','', 'POST','REST',TRUE,TRUE,
    '[{"id":"example","label":"Example"}]','2025-01-01 00:00:00','2025-01-01 00:00:00','admin@example.com','public','admin@example.com','api'
), (
    'tool-disabled','disabled','Disabled','Disabled','disabled',NULL,NULL,NULL,
    NULL,NULL,'{"type":"object","properties":{}}','', 'POST','REST',FALSE,FALSE,'[]',
    '2024-12-31 00:00:00','2024-12-31 00:00:00','admin@example.com','public','admin@example.com','api'
), (
    'tool-private','private','Private','Private','private',NULL,NULL,NULL,
    NULL,NULL,'{"type":"object","properties":{}}','', 'POST','REST',TRUE,TRUE,'[]',
    '2024-12-30 00:00:00','2024-12-30 00:00:00','admin@example.com','private','admin@example.com','api'
);

INSERT INTO servers(id,name,visibility,enabled,created_at,updated_at,tags)
VALUES ('fixture-server','Tools fixture','public',TRUE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'[]'),
       ('empty-server','Empty tools fixture','public',TRUE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'[]');

INSERT INTO server_tool_association (server_id,tool_id) VALUES ('fixture-server','tool-fixture');
