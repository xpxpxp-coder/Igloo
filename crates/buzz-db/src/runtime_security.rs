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
         REVOKE ALL ON TABLE snowman_agent_model_generations FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_meeting_mailboxes FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_meeting_intake_receipts FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_meetings FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_meeting_commands FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_meeting_sessions FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_meeting_participant_consents FROM {role_identifier};\n\
         REVOKE ALL ON TABLE snowman_meeting_tool_intents FROM {role_identifier};\n\
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
         GRANT SELECT, INSERT, UPDATE ON TABLE snowman_orchestration_destination_receipts\n\
           TO {role_identifier};\n\
         GRANT SELECT ON TABLE snowman_orchestration_dispatches,\n\
           snowman_orchestration_control_outbox TO {role_identifier};\n\
         GRANT SELECT, INSERT ON TABLE snowman_agent_coordinator_auth_events\n\
           TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Create or reconcile the private model-gateway login. It can inspect only
/// the exact workforce/job authority rows, reserve/finalize model generations,
/// and append spend receipts. It cannot mutate job, lease, request, task, or
/// collaboration authority and it cannot delete accounting evidence.
pub async fn provision_model_gateway_role(pool: &PgPool, role: &str, password: &str) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "model gateway database password must contain at least 32 characters".into(),
        ));
    }
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.model_gateway_role_password', $1, true)")
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
             current_setting('snowman.model_gateway_role_password'));\n\
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
         GRANT SELECT ON TABLE snowman_work_requests,snowman_work_tasks,\n\
           snowman_task_leases,snowman_agent_jobs TO {role_identifier};\n\
         GRANT SELECT,INSERT,UPDATE ON TABLE snowman_agent_model_generations\n\
           TO {role_identifier};\n\
         GRANT SELECT,INSERT ON TABLE snowman_spend_ledger TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Create or reconcile the audit-checkpoint login. It can read only tenant IDs
/// and the audit chain, freeze checkpoint requests, and append publication
/// receipts. It cannot read collaboration content or mutate/delete evidence.
pub async fn provision_audit_checkpoint_role(
    pool: &PgPool,
    role: &str,
    password: &str,
) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "audit checkpoint database password must contain at least 32 characters".into(),
        ));
    }
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.audit_checkpoint_role_password', $1, true)")
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
             current_setting('snowman.audit_checkpoint_role_password'));\n\
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
         GRANT SELECT ON TABLE communities,audit_log TO {role_identifier};\n\
         GRANT SELECT,INSERT ON TABLE snowman_audit_checkpoint_requests,\n\
           snowman_audit_checkpoint_publications TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Fail closed unless the checkpoint runtime has its exact append-only audit boundary.
pub async fn verify_audit_checkpoint_role(pool: &PgPool, expected_role: &str) -> Result<()> {
    validate_role_name(expected_role)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT current_user=$1 \
         AND has_database_privilege(current_user,current_database(),'CONNECT') \
         AND NOT has_database_privilege(current_user,current_database(),'CREATE') \
         AND has_schema_privilege(current_user,'public','USAGE') \
         AND NOT has_schema_privilege(current_user,'public','CREATE') \
         AND has_table_privilege(current_user,'communities','SELECT') \
         AND has_table_privilege(current_user,'audit_log','SELECT') \
         AND NOT has_table_privilege(current_user,'audit_log','INSERT') \
         AND NOT has_table_privilege(current_user,'audit_log','UPDATE') \
         AND NOT has_table_privilege(current_user,'audit_log','DELETE') \
         AND has_table_privilege(current_user,'snowman_audit_checkpoint_requests','SELECT') \
         AND has_table_privilege(current_user,'snowman_audit_checkpoint_requests','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_audit_checkpoint_requests','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_audit_checkpoint_requests','DELETE') \
         AND has_table_privilege(current_user,'snowman_audit_checkpoint_publications','SELECT') \
         AND has_table_privilege(current_user,'snowman_audit_checkpoint_publications','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_audit_checkpoint_publications','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_audit_checkpoint_publications','DELETE') \
         AND NOT has_table_privilege(current_user,'events','SELECT') \
         AND NOT has_table_privilege(current_user,'channels','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_work_requests','SELECT')",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if !valid {
        return Err(DbError::InvalidData(
            "audit checkpoint database identity violates its exact append-only boundary".into(),
        ));
    }
    Ok(())
}

/// Create or reconcile the private meeting-control login. It can maintain only
/// the governed meeting ledgers and inspect workforce identity existence. It
/// cannot read collaboration events, raw evidence, agent jobs, model authority,
/// or audit content, and meeting commands remain append-only.
pub async fn provision_meeting_control_role(
    pool: &PgPool,
    role: &str,
    password: &str,
) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "meeting control database password must contain at least 32 characters".into(),
        ));
    }
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.meeting_control_role_password', $1, true)")
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
             current_setting('snowman.meeting_control_role_password'));\n\
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
         GRANT SELECT ON TABLE snowman_workforce_identities TO {role_identifier};\n\
         GRANT SELECT ON TABLE snowman_workforce_key_bindings,\n\
           snowman_workforce_capability_grants,snowman_meeting_command_callers,\n\
           snowman_meeting_command_receivers\n\
           TO {role_identifier};\n\
         GRANT SELECT,INSERT,UPDATE ON TABLE snowman_meeting_mailboxes,\n\
           snowman_meeting_intake_receipts,snowman_meetings,\n\
           snowman_meeting_sessions,snowman_meeting_participant_consents,\n\
           snowman_meeting_tool_intents TO {role_identifier};\n\
         GRANT SELECT,INSERT ON TABLE snowman_meeting_commands,\n\
           snowman_meeting_command_auth_events,snowman_meeting_command_receipts\n\
           TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Create or reconcile the private meeting-media login. It may read only the
/// admitted meeting/consent authority needed to fence a live session, maintain
/// its digest-only media ledgers, and append bounded tool intents. It cannot
/// read collaboration content, evidence bodies, agent/model authority, or
/// delete/rewrite immutable receipts.
pub async fn provision_meeting_media_role(pool: &PgPool, role: &str, password: &str) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "meeting media database password must contain at least 32 characters".into(),
        ));
    }
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.meeting_media_role_password', $1, true)")
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
             current_setting('snowman.meeting_media_role_password'));\n\
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
         GRANT SELECT ON TABLE snowman_workforce_identities,\n\
           snowman_meeting_mailboxes,snowman_meetings,snowman_meeting_sessions,\n\
           snowman_meeting_participant_consents,snowman_meeting_media_routes,\n\
           snowman_meeting_media_callers,snowman_meeting_media_callback_bindings\n\
           TO {role_identifier};\n\
         GRANT SELECT,INSERT,UPDATE ON TABLE snowman_meeting_media_sessions,\n\
           snowman_meeting_media_provider_sessions TO {role_identifier};\n\
         GRANT SELECT,INSERT ON TABLE snowman_meeting_media_commands,\n\
           snowman_meeting_media_webhook_receipts,\n\
           snowman_meeting_media_usage_receipts,\n\
           snowman_meeting_media_turn_receipts,\n\
           snowman_meeting_tool_intents TO {role_identifier};"
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
         AND has_table_privilege(current_user,'snowman_orchestration_destination_receipts','SELECT') \
         AND has_table_privilege(current_user,'snowman_orchestration_destination_receipts','INSERT') \
         AND has_table_privilege(current_user,'snowman_orchestration_destination_receipts','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_destination_receipts','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_destination_receipts','TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_orchestration_dispatches','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_dispatches','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_dispatches','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_dispatches','DELETE') \
         AND has_table_privilege(current_user,'snowman_orchestration_control_outbox','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_control_outbox','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_control_outbox','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_control_outbox','DELETE') \
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

/// Fail closed unless the model gateway has exactly its read-authority,
/// generation-reservation, and append-only spend permissions.
pub async fn verify_model_gateway_role(pool: &PgPool, expected_role: &str) -> Result<()> {
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
         AND has_table_privilege(current_user,'snowman_agent_jobs','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','DELETE') \
         AND has_table_privilege(current_user,'snowman_agent_model_generations','SELECT') \
         AND has_table_privilege(current_user,'snowman_agent_model_generations','INSERT') \
         AND has_table_privilege(current_user,'snowman_agent_model_generations','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_spend_ledger','SELECT') \
         AND has_table_privilege(current_user,'snowman_spend_ledger','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_spend_ledger','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_spend_ledger','DELETE') \
         AND NOT has_table_privilege(current_user,'events','SELECT') \
         AND NOT has_table_privilege(current_user,'channels','SELECT') \
         AND NOT has_table_privilege(current_user,'audit_log','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_work_events','SELECT')",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if !valid {
        return Err(DbError::InvalidData(
            "model gateway database identity violates its exact authority boundary".into(),
        ));
    }
    Ok(())
}

/// Fail closed unless the meeting controller has only its dedicated ledgers,
/// read-only workforce identity lookup, and append-only command authority.
pub async fn verify_meeting_control_role(pool: &PgPool, expected_role: &str) -> Result<()> {
    validate_role_name(expected_role)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT current_user=$1 \
         AND has_database_privilege(current_user,current_database(),'CONNECT') \
         AND NOT has_database_privilege(current_user,current_database(),'CREATE') \
         AND has_schema_privilege(current_user,'public','USAGE') \
         AND NOT has_schema_privilege(current_user,'public','CREATE') \
         AND has_table_privilege(current_user,'snowman_workforce_identities','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_workforce_identities','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_workforce_key_bindings','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_workforce_key_bindings','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_workforce_capability_grants','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_workforce_capability_grants','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_command_callers','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_command_callers','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_command_receivers','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_command_receivers','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_mailboxes','SELECT') \
         AND has_table_privilege(current_user,'snowman_meeting_mailboxes','INSERT') \
         AND has_table_privilege(current_user,'snowman_meeting_mailboxes','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_mailboxes','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_intake_receipts','SELECT') \
         AND has_table_privilege(current_user,'snowman_meeting_intake_receipts','INSERT') \
         AND has_table_privilege(current_user,'snowman_meeting_intake_receipts','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_intake_receipts','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meetings','SELECT') \
         AND has_table_privilege(current_user,'snowman_meetings','INSERT') \
         AND has_table_privilege(current_user,'snowman_meetings','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meetings','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_commands','SELECT') \
         AND has_table_privilege(current_user,'snowman_meeting_commands','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_commands','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_command_auth_events','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_command_auth_events','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_command_receipts','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_command_receipts','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_sessions','SELECT') \
         AND has_table_privilege(current_user,'snowman_meeting_sessions','INSERT') \
         AND has_table_privilege(current_user,'snowman_meeting_sessions','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_sessions','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_participant_consents','SELECT') \
         AND has_table_privilege(current_user,'snowman_meeting_participant_consents','INSERT') \
         AND has_table_privilege(current_user,'snowman_meeting_participant_consents','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_participant_consents','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_tool_intents','SELECT') \
         AND has_table_privilege(current_user,'snowman_meeting_tool_intents','INSERT') \
         AND has_table_privilege(current_user,'snowman_meeting_tool_intents','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_tool_intents','DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'events','SELECT') \
         AND NOT has_table_privilege(current_user,'channels','SELECT') \
         AND NOT has_table_privilege(current_user,'audit_log','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','SELECT')",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if !valid {
        return Err(DbError::InvalidData(
            "meeting control database identity violates its exact meeting boundary".into(),
        ));
    }
    Ok(())
}

/// Fail closed unless the meeting-media runtime has only its admitted-state
/// reads, digest-ledger writes, and append-only intent authority.
pub async fn verify_meeting_media_role(pool: &PgPool, expected_role: &str) -> Result<()> {
    validate_role_name(expected_role)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT current_user=$1 \
         AND has_database_privilege(current_user,current_database(),'CONNECT') \
         AND NOT has_database_privilege(current_user,current_database(),'CREATE') \
         AND has_schema_privilege(current_user,'public','USAGE') \
         AND NOT has_schema_privilege(current_user,'public','CREATE') \
         AND has_table_privilege(current_user,'snowman_meetings','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meetings','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_sessions','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_sessions','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_participant_consents','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_participant_consents','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_routes','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_routes','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_callers','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_callers','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_callback_bindings','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_callback_bindings','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_sessions','SELECT,INSERT,UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_sessions','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_provider_sessions','SELECT,INSERT,UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_provider_sessions','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_commands','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_commands','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_usage_receipts','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_usage_receipts','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_turn_receipts','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_turn_receipts','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_media_webhook_receipts','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_media_webhook_receipts','UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_meeting_tool_intents','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_tool_intents','UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'events','SELECT') \
         AND NOT has_table_privilege(current_user,'channels','SELECT') \
         AND NOT has_table_privilege(current_user,'audit_log','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','SELECT')",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if !valid {
        return Err(DbError::InvalidData(
            "meeting media database identity violates its exact live-media boundary".into(),
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
         AND NOT has_table_privilege(current_user,'snowman_agent_coordinator_auth_events','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_agent_model_generations','DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_mailboxes','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_intake_receipts','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'snowman_meetings','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_commands','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_sessions','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_participant_consents','SELECT,INSERT,UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'snowman_meeting_tool_intents','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')",
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

/// Create or reconcile the private orchestration-service login. It may mutate
/// only the metadata-only orchestration lifecycle, append auth/receipt
/// evidence, and inspect exact workforce identity/capability bindings. It has
/// no collaboration, agent-job, provider, media, audit, or Analyst data access.
pub async fn provision_orchestration_role(pool: &PgPool, role: &str, password: &str) -> Result<()> {
    validate_role_name(role)?;
    if password.len() < 32 {
        return Err(DbError::InvalidData(
            "orchestration database password must contain at least 32 characters".into(),
        ));
    }
    let database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(pool)
        .await?;
    let role_identifier = quote_identifier(role);
    let database_identifier = quote_identifier(&database);
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT set_config('snowman.orchestration_role_password', $1, true)")
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
             current_setting('snowman.orchestration_role_password'));\n\
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
         GRANT SELECT ON TABLE snowman_workforce_identities,\n\
           snowman_workforce_key_bindings,snowman_workforce_capability_grants\n\
           TO {role_identifier};\n\
         GRANT SELECT,INSERT ON TABLE snowman_orchestration_auth_events,\n\
           snowman_orchestration_commands,snowman_orchestration_delivery_attempts,\n\
           snowman_orchestration_terminal_receipts,snowman_orchestration_dead_letters,\n\
           snowman_orchestration_progress_digests,\n\
           snowman_orchestration_control_delivery_receipts\n\
           TO {role_identifier};\n\
         GRANT SELECT,INSERT,UPDATE ON TABLE snowman_orchestration_plans,\n\
           snowman_orchestration_schedule_policies,\n\
           snowman_orchestration_plan_automatic_capabilities,\n\
           snowman_orchestration_personas,snowman_orchestration_persona_capabilities,\n\
           snowman_orchestration_tasks,snowman_orchestration_task_context_refs,\n\
           snowman_orchestration_task_dependencies,\n\
           snowman_orchestration_task_required_capabilities,\n\
           snowman_orchestration_task_artifact_contracts,\n\
           snowman_orchestration_recurrences,snowman_orchestration_dispatches,\n\
           snowman_orchestration_dispatch_receipts,\n\
           snowman_orchestration_reminder_receipts,\n\
           snowman_orchestration_occurrences,snowman_orchestration_control_outbox\n\
           TO {role_identifier};\n\
         GRANT SELECT ON TABLE snowman_orchestration_callers TO {role_identifier};"
    );
    sqlx::raw_sql(AssertSqlSafe(grants))
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

/// Fail closed unless the orchestration service runs with only its exact
/// metadata-control privileges and cannot reach user content or execution
/// authority owned by other Snowman services.
pub async fn verify_orchestration_role(pool: &PgPool, expected_role: &str) -> Result<()> {
    validate_role_name(expected_role)?;
    let valid: bool = sqlx::query_scalar(
        "SELECT current_user=$1 \
         AND has_database_privilege(current_user,current_database(),'CONNECT') \
         AND NOT has_database_privilege(current_user,current_database(),'CREATE') \
         AND has_schema_privilege(current_user,'public','USAGE') \
         AND NOT has_schema_privilege(current_user,'public','CREATE') \
         AND has_table_privilege(current_user,'snowman_orchestration_callers','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_callers','INSERT,UPDATE,DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_orchestration_plans','SELECT,INSERT,UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_plans','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_orchestration_control_outbox','SELECT,INSERT,UPDATE') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_control_outbox','DELETE,TRUNCATE') \
         AND has_table_privilege(current_user,'snowman_orchestration_control_delivery_receipts','SELECT,INSERT') \
         AND NOT has_table_privilege(current_user,'snowman_orchestration_control_delivery_receipts','UPDATE,DELETE,TRUNCATE') \
         AND NOT has_table_privilege(current_user,'events','SELECT') \
         AND NOT has_table_privilege(current_user,'channels','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','SELECT') \
         AND NOT has_table_privilege(current_user,'snowman_agent_jobs','INSERT,UPDATE,DELETE') \
         AND NOT has_table_privilege(current_user,'snowman_meetings','SELECT') \
         AND NOT has_table_privilege(current_user,'audit_log','SELECT')",
    )
    .bind(expected_role)
    .fetch_one(pool)
    .await?;
    if !valid {
        return Err(DbError::InvalidData(
            "orchestration database identity violates its exact metadata-control boundary".into(),
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

    #[test]
    fn model_gateway_role_is_reservation_and_append_only() {
        let source = include_str!("runtime_security.rs");
        assert!(
            source.contains("GRANT SELECT,INSERT,UPDATE ON TABLE snowman_agent_model_generations")
        );
        assert!(source.contains("GRANT SELECT,INSERT ON TABLE snowman_spend_ledger TO"));
        assert!(
            source.contains("NOT has_table_privilege(current_user,'snowman_agent_jobs','UPDATE')")
        );
        assert!(source
            .contains("NOT has_table_privilege(current_user,'snowman_spend_ledger','UPDATE')"));
        assert!(source
            .contains("model gateway database identity violates its exact authority boundary"));
    }

    #[test]
    fn meeting_control_role_is_isolated_and_commands_are_append_only() {
        let source = include_str!("runtime_security.rs");
        assert!(source.contains("GRANT SELECT,INSERT,UPDATE ON TABLE snowman_meeting_mailboxes"));
        assert!(source.contains("GRANT SELECT,INSERT ON TABLE snowman_meeting_commands,"));
        assert!(
            source.contains("snowman_meeting_command_auth_events,snowman_meeting_command_receipts")
        );
        assert!(
            source.contains("snowman_workforce_capability_grants,snowman_meeting_command_callers,")
        );
        assert!(source.contains(
            "NOT has_table_privilege(current_user,'snowman_meeting_commands','UPDATE,DELETE,TRUNCATE')"
        ));
        assert!(
            source.contains("NOT has_table_privilege(current_user,'snowman_agent_jobs','SELECT')")
        );
        assert!(source
            .contains("meeting control database identity violates its exact meeting boundary"));
    }

    #[test]
    fn orchestration_role_is_metadata_only_and_receipts_are_append_only() {
        let source = include_str!("runtime_security.rs");
        assert!(source.contains("pub async fn verify_orchestration_role"));
        assert!(source
            .contains("snowman_orchestration_control_delivery_receipts','UPDATE,DELETE,TRUNCATE'"));
        assert!(source.contains("NOT has_table_privilege(current_user,'events','SELECT')"));
        assert!(source.contains(
            "orchestration database identity violates its exact metadata-control boundary"
        ));
    }
}
