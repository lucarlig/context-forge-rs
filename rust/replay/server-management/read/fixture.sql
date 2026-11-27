INSERT INTO email_users (id, email, is_admin, created_at, updated_at)
VALUES ('server-admin', 'admin@example.com', TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (email) DO NOTHING;

INSERT INTO roles (id, name, scope, permissions, created_by, is_system_role, is_active, created_at, updated_at)
VALUES ('server-reader', 'Fixture server reader', 'global', '["servers.read"]', 'admin@example.com',
        FALSE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO user_roles (id, user_email, role_id, scope, granted_by, granted_at, is_active)
VALUES ('server-reader-grant', 'admin@example.com', 'server-reader', 'global',
        'admin@example.com', CURRENT_TIMESTAMP, TRUE);


INSERT INTO email_users (id,email,is_admin,is_active,created_at,updated_at)
VALUES ('server-viewer','viewer@example.com',FALSE,TRUE,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP);

INSERT INTO user_roles (id,user_email,role_id,scope,granted_by,granted_at,is_active)
VALUES ('server-viewer-grant','viewer@example.com','server-reader','global','admin@example.com',CURRENT_TIMESTAMP,TRUE);

INSERT INTO tools (id,name,original_name,custom_name,custom_name_slug,input_schema,jsonpath_filter,
                   integration_type,request_type,created_at,updated_at,enabled,visibility)
VALUES ('srv-tool','server-fixture-tool','Tool','Tool','tool','{"type":"object"}','','REST','POST',
        '2025-01-01 00:00:00','2025-01-01 00:00:00',TRUE,'public');
INSERT INTO resources (id,uri,name,original_name,custom_name_slug,text_content,size,tags,created_at,updated_at,enabled,visibility)
VALUES ('srv-resource','fixture://server/resource','Resource','Resource','resource','Fixture',7,'[]',
        '2025-01-01 00:00:00','2025-01-01 00:00:00',TRUE,'public');
INSERT INTO prompts (id,name,original_name,custom_name,custom_name_slug,template,argument_schema,tags,created_at,updated_at,enabled,visibility)
VALUES ('srv-prompt','server-fixture-prompt','Prompt','Prompt','prompt','Fixture prompt','{"type":"object","properties":{}}','[]',
        '2025-01-01 00:00:00','2025-01-01 00:00:00',TRUE,'public');

INSERT INTO servers (id,name,description,created_at,updated_at,enabled,visibility,owner_email,tags,instructions,
                     oauth_enabled,oauth_config,oauth_config_approved,oauth_config_generation)
VALUES
    ('385d718b52854aa39de43497ce61ce27','Public fixture','Fixture metadata',
     '2025-01-03 00:00:00','2025-01-03 00:00:00',TRUE,'public','admin@example.com','[{"id":"demo","label":"Demo"}]',
     'Use this fixture.',TRUE,'{"authorization_server":"https://auth.fixture.test/tenant","scopes_supported":["fixture.read"],"client_secret":"synthetic-secret"}',
     TRUE,'fixture-approval'),
    ('38751e559c704fc088a4cc68e4113a93','Disabled fixture',NULL,
     '2025-01-02 00:00:00','2025-01-02 00:00:00',FALSE,'public','admin@example.com','[]',
     NULL,FALSE,NULL,FALSE,NULL),
    ('44fd5fb719b040e6b72940cf61732485','Private fixture',NULL,
     '2025-01-01 00:00:00','2025-01-01 00:00:00',TRUE,'private','admin@example.com','[]',
     NULL,TRUE,'{"authorization_server":"https://auth.fixture.test/tenant"}',TRUE,'private-approval');

INSERT INTO server_tool_association (server_id,tool_id)
VALUES ('385d718b52854aa39de43497ce61ce27','srv-tool');
INSERT INTO server_resource_association (server_id,resource_id)
VALUES ('385d718b52854aa39de43497ce61ce27','srv-resource');
INSERT INTO server_prompt_association (server_id,prompt_id)
VALUES ('385d718b52854aa39de43497ce61ce27','srv-prompt');
INSERT INTO server_interfaces(id,server_id,protocol,binding,version,tenant,enabled,config,created_at,updated_at)
VALUES ('srv-interface','385d718b52854aa39de43497ce61ce27','a2a','https://a2a.fixture.test/agent','1.0','demo',
        TRUE,'{"fixture":true}','2025-01-01 00:00:00','2025-01-01 00:00:00');
