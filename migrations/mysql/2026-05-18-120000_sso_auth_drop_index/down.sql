ALTER TABLE sso_auth MODIFY COLUMN code_response VARCHAR(768);
CREATE INDEX code_response_index ON sso_auth(code_response);
