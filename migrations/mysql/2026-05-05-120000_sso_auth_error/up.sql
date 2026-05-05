DELETE FROM sso_auth;
ALTER TABLE sso_auth ADD COLUMN code_response_error TEXT;
ALTER TABLE sso_auth MODIFY COLUMN code_response VARCHAR(768);
CREATE INDEX code_response_index ON sso_auth(code_response);
