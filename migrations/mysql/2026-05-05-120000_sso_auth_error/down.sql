ALTER TABLE sso_auth DROP COLUMN code_response_error;
DROP INDEX code_response_index;
ALTER TABLE sso_auth MODIFY COLUMN code_response TEXT;
