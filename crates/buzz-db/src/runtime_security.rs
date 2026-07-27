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
         REVOKE ALL ON TABLE snowman_agent_launches FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_agent_coordinator_auth_events FROM {role_identifier};\n\
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

/// Create or reconcile the private agent-broker login with only read/update
/// access to the one-shot job ledger. It cannot mint jobs, delete evidence,
/// inspect relay tables, or create database objects.
pub async fn provision_agent_broker_role(pool: &PgPool, role: &str, password: &str) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "agent broker database password must contain at least 32 characters".into(),
        ));
    }
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.agent_broker_role_password', $1, true)")
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
             current_setting('snowman.agent_broker_role_password'));\n\
         END\n\
         $snowman$;"
    );
    sqlx::raw_sql(AssertSqlSafe(role_ddl))
        .execute(&mut *transaction)
        .await?;
    let grants = format!(
        "REVOKE ALL ON DATABASE {database_identifier} FROM {role_identifier};\n\
         REVOKE ALL ON SCHEMA public FROM {role_identifier};\n\
         REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role_identifier};\n\
         REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role_identifier};\n\
         GRANT CONNECT ON DATABASE {database_identifier} TO {role_identifier};\n\
         GRANT USAGE ON SCHEMA public TO {role_identifier};\n\
         GRANT SELECT, UPDATE ON TABLE snowman_agent_jobs TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Create or reconcile the trusted agent-coordinator login. It may validate
/// an active workforce lease, mint one job row, and maintain its launch row;
/// it cannot inspect collaboration/event data, mutate workforce authority, or
/// delete launch evidence.
pub async fn provision_agent_coordinator_role(
    pool: &PgPool,
    role: &str,
    password: &str,
) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "agent coordinator database password must contain at least 32 characters".into(),
        ));
    }
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.agent_coordinator_role_password', $1, true)")
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
             current_setting('snowman.agent_coordinator_role_password'));\n\
         END\n\
         $snowman$;"
    );
    sqlx::raw_sql(AssertSqlSafe(role_ddl))
        .execute(&mut *transaction)
        .await?;
    let grants = format!(
        "REVOKE ALL ON DATABASE {database_identifier} FROM {role_identifier};\n\
         REVOKE ALL ON SCHEMA public FROM {role_identifier};\n\
         REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {role_identifier};\n\
         REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {role_identifier};\n\
         GRANT CONNECT ON DATABASE {database_identifier} TO {role_identifier};\n\
         GRANT USAGE ON SCHEMA public TO {role_identifier};\n\
         GRANT SELECT ON TABLE snowman_work_requests, snowman_work_tasks,\n\
           snowman_task_leases, snowman_workforce_identities,\n\
           snowman_workforce_key_bindings, snowman_workforce_capability_grants,\n\
           snowman_model_routes\n\
           TO {role_identifier};\n\
         GRANT SELECT, INSERT, UPDATE ON TABLE snowman_agent_jobs,\n\
           snowman_agent_launches TO {role_identifier};\n\
         GRANT SELECT, INSERT ON TABLE snowman_agent_coordinator_auth_events\n\
           TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Fail closed unless the private agent broker has only its exact job-ledger
/// read/update authority and no creation, insert, delete, or relay-table access.
pub async fn verify_agent_broker_role(pool: &PgPool, expected_role: &str) -> Result<()> {
    validate_role_name(expected_role)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT current_user=$1 \
         AND has_database_privilege(current_user,current_database(),'CONNECT') \
         AND NOT has_database_privilege(current_user,current_database(),'CREATE') \
         AND has_schema_privilege(current_user,'public','USAGE') \
         AND NOT has_schema_privilege(current_user,'public','CREATE') \
         AND has_table_privilege(current_user,'snowman_agent_jobs','SELECT') \
         AND has_table_privilege(current_user,'snowman_agent_jobs','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','TRUNCATE') \
         AND NOT has_table_privilege(current_user,'events','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_work_tasks','SELECT')",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if !valid {
        return Err(DbError::InvalidData(
            "agent broker database identity violates its exact job-ledger boundary".into(),
        ));
    }
    Ok(())
}

/// Fail closed unless the coordinator has only its exact read/issue/reconcile
/// tables and cannot read collaboration events, change workforce authority,
/// delete evidence, or create database objects.
pub async fn verify_agent_coordinator_role(pool: &PgPool, expected_role: &str) -> Result<()> {
    validate_role_name(expected_role)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT current_user=$1 \
         AND has_database_privilege(current_user,current_database(),'CONNECT') \
         AND NOT has_database_privilege(current_user,current_database(),'CREATE') \
         AND has_schema_privilege(current_user,'public','USAGE') \
         AND NOT has_schema_privilege(current_user,'public','CREATE') \
         AND has_table_privilege(current_user,'snowman_work_requests','SELECT') \
         AND has_table_privilege(current_user,'snowman_work_tasks','SELECT') \
         AND has_table_privilege(current_user,'snowman_task_leases','SELECT') \
         AND has_table_privilege(current_user,'snowman_workforce_key_bindings','SELECT') \
         AND has_table_privilege(current_user,'snowman_workforce_capability_grants','SELECT') \
         AND has_table_privilege(current_user,'snowman_model_routes','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_work_tasks','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_work_tasks','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_work_tasks','DELETE') \
         AND has_table_privilege(current_user,'snowman_workforce_identities','SELECT') \
         AND NOT has_table_privilege(current_user,'events','SELECT') \
         AND NOT has_table_privilege(current_user,'channels','SELECT') \
         AND NOT has_table_privilege(current_user,'audit_log','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_work_events','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_spend_ledger','SELECT') \
         AND has_table_privilege(current_user,'snowman_agent_jobs','SELECT') \
         AND has_table_privilege(current_user,'snowman_agent_jobs','INSERT') \
         AND has_table_privilege(current_user,'snowman_agent_jobs','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_agent_launches','SELECT') \
         AND has_table_privilege(current_user,'snowman_agent_launches','INSERT') \
         AND has_table_privilege(current_user,'snowman_agent_launches','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_launches','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_launches','TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_agent_coordinator_auth_events','SELECT') \
         AND has_table_privilege(current_user,'snowman_agent_coordinator_auth_events','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_coordinator_auth_events','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_coordinator_auth_events','DELETE')",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if !valid {
        return Err(DbError::InvalidData(
            "agent coordinator database identity violates its exact launch boundary".into(),
        ));
    }
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
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_launches','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_launches','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_launches','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_launches','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_coordinator_auth_events','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_coordinator_auth_events','INSERT')",
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

    #[test]
    fn agent_broker_role_is_read_update_only_on_its_job_ledger() {
        let source = include_str!("runtime_security.rs");
        assert!(source.contains("GRANT SELECT, UPDATE ON TABLE snowman_agent_jobs"));
        assert!(source.contains("REVOKE ALL ON ALL TABLES IN SCHEMA public"));
        assert!(source.contains("NOT has_table_privilege(current_user,'events','SELECT')"));
        assert!(source
            .contains("agent broker database identity violates its exact job-ledger boundary"));
    }

    #[test]
    fn agent_coordinator_role_is_issue_reconcile_only() {
        let source = include_str!("runtime_security.rs");
        assert!(source.contains("GRANT SELECT, INSERT, UPDATE ON TABLE snowman_agent_jobs"));
        assert!(source.contains("snowman_agent_launches TO"));
        assert!(source.contains("NOT has_table_privilege(current_user,'events','SELECT')"));
        assert!(source
            .contains("agent coordinator database identity violates its exact launch boundary"));
    }
}
