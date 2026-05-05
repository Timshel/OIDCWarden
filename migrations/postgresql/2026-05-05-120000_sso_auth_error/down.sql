ALTER TABLE sso_auth DROP COLUMN IF EXISTS code_response_error;
DROP INDEX IF EXISTS code_response_index;
