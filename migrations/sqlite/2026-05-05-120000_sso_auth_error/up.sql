ALTER TABLE sso_auth ADD COLUMN code_response_error TEXT;
CREATE INDEX code_response_index ON sso_auth(code_response);
