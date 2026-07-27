//! Least-privilege PostgreSQL role boundary for the serving relay.

use sqlx::{AssertSqlSafe, PgPool};

use crate::{DbError, Result};

/// Validate the deliberately narrow PostgreSQL identifier accepted for the
/// runtime role. The bootstrap never interpolates an unvalidated identifier.
pub fn validate_role_name(role: &str) -> Result<()> {
    let valid = !role.is_empty()
        && role.len() <= 63
        && role.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        });
    if valid {
        Ok(())
    } else {
        Err(DbError::InvalidData(
            "runtime database role must be a PostgreSQL identifier".into(),
        ))
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// Create or reconcile the login role and grant only the serving privileges.
///
/// The password is passed through a bound `set_config` value so it never
/// appears in SQL text or duration-based PostgreSQL statement logs.
pub async fn provision_runtime_role(pool: &PgPool, role: &str, password: &str) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "runtime database password must contain at least 32 characters".into(),
        ));
    }

    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);

    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.runtime_role_password', $1, true)")
        .bind(password)
        .execute(&mut *transaction)
        .await?;

    let role_ddl = format!(
        "DO $snowman$\n\
         BEGIN\n\
           IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{role}') THEN\n\
             CREATE ROLE {role_identifier} LOGIN;\n\
           END IF;\n\
           ALTER ROLE {role_identifier}\n\
             WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;\n\
           EXECUTE format('ALTER ROLE %I PASSWORD %L', '{role}',\n\
             current_setting('snowman.runtime_role_password'));\n\
         END\n\
         $snowman$;"
    );
    sqlx::raw_sql(AssertSqlSafe(role_ddl))
        .execute(&mut *transaction)
        .await?;

    let grants = format!(
        "REVOKE ALL ON DATABASE {database_identifier} FROM {role_identifier};\n\
         REVOKE CREATE ON SCHEMA public FROM PUBLIC;\n\
         REVOKE ALL ON SCHEMA public FROM {role_identifier};\n\
         GRANT CONNECT ON DATABASE {database_identifier} TO {role_identifier};\n\
         GRANT USAGE ON SCHEMA public TO {role_identifier};\n\
         GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_agent_jobs FROM {role_identifier};\n\
         GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role_identifier};\n\
         ALTER DEFAULT PRIVILEGES IN SCHEMA public\n\
           GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role_identifier};\n\
         ALTER DEFAULT PRIVILEGES IN SCHEMA public\n\
           GRANT USAGE, SELECT ON SEQUENCES TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Fail closed unless the connected serving identity has its required DML
/// capabilities and lacks database/schema creation authority.
pub async fn verify_runtime_role(pool: &PgPool, expected_role: &str) -> Result<()> {
    validate_role_name(expected_role)?;
    let actual_role: String = sqlx::query_scalar("SELECT current_user")
        .fetch_one(pool)
        .await?;
    if actual_role != expected_role {
        return Err(DbError::InvalidData(format!(
            "runtime database identity mismatch: expected {expected_role}, received {actual_role}"
        )));
    }

    let least_privilege: bool = sqlx::query_scalar(
        "SELECT has_database_privilege(current_user, current_database(), 'CONNECT')\n\
           AND NOT has_database_privilege(current_user, current_database(), 'CREATE')\n\
           AND has_schema_privilege(current_user, 'public', 'USAGE')\n\
           AND NOT has_schema_privilege(current_user, 'public', 'CREATE')",
    )
    .fetch_one(pool)
    .await?;
    if !least_privilege {
        return Err(DbError::InvalidData(
            "runtime database identity violates the no-DDL privilege boundary".into(),
        ));
    }

    for table in [
        "communities",
        "users",
        "events",
        "channels",
        "workflows",
        "workflow_runs",
        "audit_log",
        "snowman_work_requests",
        "snowman_work_tasks",
    ] {
        let ready: bool = sqlx::query_scalar(
            "SELECT to_regclass($1) IS NOT NULL\n\
               AND COALESCE(has_table_privilege(current_user, to_regclass($1), 'SELECT'), false)\n\
               AND COALESCE(has_table_privilege(current_user, to_regclass($1), 'INSERT'), false)\n\
               AND COALESCE(has_table_privilege(current_user, to_regclass($1), 'UPDATE'), false)\n\
               AND COALESCE(has_table_privilege(current_user, to_regclass($1), 'DELETE'), false)",
        )
        .bind(format!("public.{table}"))
        .fetch_one(pool)
        .await?;
        if !ready {
            return Err(DbError::InvalidData(format!(
                "runtime database identity lacks required DML on {table}"
            )));
        }
    }
    let agent_job_authority_denied: bool = sqlx::query_scalar(
        "SELECT to_regclass('public.snowman_agent_jobs') IS NOT NULL \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','DELETE')",
    )
    .fetch_one(pool)
    .await?;
    if !agent_job_authority_denied {
        return Err(DbError::InvalidData(
            "serving relay database identity must not access one-shot agent jobs".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_name_is_strictly_bounded() {
        for valid in ["snowman_runtime", "SnowmanRuntime2", "_relay"] {
            assert!(validate_role_name(valid).is_ok(), "{valid}");
        }
        for invalid in ["", "2relay", "relay-role", "relay;drop role x"] {
            assert!(validate_role_name(invalid).is_err(), "{invalid}");
        }
        assert!(validate_role_name(&"r".repeat(64)).is_err());
    }

    #[test]
    fn relay_role_explicitly_excludes_agent_job_authority() {
        let source = include_str!("runtime_security.rs");
        assert!(source.contains("REVOKE ALL ON TABLE snowman_agent_jobs"));
        assert!(
            source.contains("serving relay database identity must not access one-shot agent jobs")
        );
    }
}
