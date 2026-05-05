ALTER TABLE sso_auth ADD COLUMN IF NOT EXISTS code_response_error TEXT;
CREATE INDEX IF NOT EXISTS code_response_index ON sso_auth(code_response);
