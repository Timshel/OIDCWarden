SELECT if (
    EXISTS(
        SELECT DISTINCT index_name FROM information_schema.statistics
            WHERE table_schema = DATABASE()
                AND table_name = 'sso_auth'
                AND index_name = 'code_response_index'
    )
    ,'DROP INDEX code_response_index ON sso_auth'
    ,'SELECT "info: index does not exist."'
) INTO @drop_stmt;
PREPARE drop_stmt FROM @drop_stmt;
EXECUTE drop_stmt;
DEALLOCATE PREPARE drop_stmt;

ALTER TABLE sso_auth MODIFY COLUMN code_response TEXT;
