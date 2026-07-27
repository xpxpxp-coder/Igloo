#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Private, purpose-bound broker for one-shot Snowman agent jobs.
//!
//! The service has no Nostr, public collaboration, Analyst dataset, arbitrary
//! connector, or model-provider route. A single opaque credential can read one
//! immutable job snapshot and submit only idempotent lifecycle receipts for its
//! exact generation.

use std::{net::SocketAddr, str::FromStr, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use snowman_agent_contract::{
    BrokerAck, Classification, JobSnapshot, ResultReceipt, RuntimeOutcome, StartedReceipt,
    BROKER_ACK_SCHEMA, JOB_RESULT_SCHEMA, JOB_SNAPSHOT_SCHEMA, JOB_STARTED_SCHEMA,
};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;
use uuid::Uuid;
use zeroize::Zeroize;

const MAX_SNAPSHOT_BYTES: usize = 768 * 1024;
const MAX_STARTED_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_RESULT_RECEIPT_BYTES: usize = 1_062_000;
const MAX_OUTPUT_BYTES: usize = 1_000_000;
const MAX_CLOCK_SKEW_SECONDS: i64 = 30;

/// Process configuration for the private broker task.
pub struct Config {
    bind_addr: SocketAddr,
    database_url: String,
    database_role: String,
    max_connections: u32,
}

/// Configuration failures contain no credential or connection content.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A required production control is absent or invalid.
    #[error("Snowman agent broker configuration is invalid: {0}")]
    Invalid(&'static str),
    /// The database connection or role check failed.
    #[error("Snowman agent broker database initialization failed")]
    Database,
}

impl Config {
    /// Load the exact production service boundary from the environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = std::env::var("SNOWMAN_AGENT_BROKER_BIND_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| ConfigError::Invalid("bind address is invalid"))?;
        let database_url = std::env::var("SNOWMAN_AGENT_BROKER_DATABASE_URL")
            .map_err(|_| ConfigError::Invalid("database URL is required"))?;
        let database_role = std::env::var("SNOWMAN_AGENT_BROKER_DATABASE_ROLE")
            .map_err(|_| ConfigError::Invalid("database role is required"))?;
        let max_connections = std::env::var("SNOWMAN_AGENT_BROKER_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "8".into())
            .parse::<u32>()
            .map_err(|_| ConfigError::Invalid("connection limit is invalid"))?;
        if !(1..=16).contains(&max_connections)
            || !valid_role(&database_role)
            || !valid_database_url(&database_url)
            || std::env::var("SNOWMAN_AGENT_BROKER_NETWORK_POLICY").as_deref()
                != Ok("private-snowman-only")
        {
            return Err(ConfigError::Invalid(
                "database or private-network control is invalid",
            ));
        }
        Ok(Self {
            bind_addr,
            database_url,
            database_role,
            max_connections,
        })
    }
}

/// Shared broker state.
#[derive(Clone)]
pub struct AppState {
    pool: PgPool,
    bind_addr: SocketAddr,
}

impl AppState {
    /// Connect using a dedicated no-DDL broker identity and verify its exact
    /// read/update-only database authority before serving traffic.
    pub async fn new(config: Config) -> Result<Self, ConfigError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&config.database_url)
            .await
            .map_err(|_| ConfigError::Database)?;
        buzz_db::runtime_security::verify_agent_broker_role(&pool, &config.database_role)
            .await
            .map_err(|_| ConfigError::Database)?;
        Ok(Self {
            pool,
            bind_addr: config.bind_addr,
        })
    }

    /// Construct state around an existing pool for controlled integration tests.
    pub fn from_pool(pool: PgPool, bind_addr: SocketAddr) -> Self {
        Self { pool, bind_addr }
    }

    /// Address on which the private task listens behind its internal load balancer.
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

/// Build the narrow private broker router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/_liveness", get(liveness))
        .route("/_readiness", get(readiness))
        .route(
            "/v1/tenants/{tenant_id}/jobs/{job_id}/snapshot",
            get(get_snapshot),
        )
        .route(
            "/v1/tenants/{tenant_id}/jobs/{job_id}/started",
            post(post_started),
        )
        .route(
            "/v1/tenants/{tenant_id}/jobs/{job_id}/result",
            post(post_result),
        )
        .layer(RequestBodyLimitLayer::new(MAX_RESULT_RECEIPT_BYTES))
        .with_state(state)
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn readiness(State(state): State<AppState>) -> StatusCode {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(1) => StatusCode::NO_CONTENT,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

async fn get_snapshot(
    State(state): State<AppState>,
    Path((tenant_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let token = bearer_token(&headers)?;
    let job = fetch_job(&state.pool, tenant_id, job_id).await?;
    authenticate(&job, token, Operation::Snapshot)?;
    let digest = hex::encode(&job.snapshot_sha256);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-snowman-content-sha256", digest)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(job.snapshot_body))
        .map_err(|_| ApiError::Internal)
}

async fn post_started(
    State(state): State<AppState>,
    Path((tenant_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<BrokerAck>, ApiError> {
    if body.is_empty() || body.len() > MAX_STARTED_RECEIPT_BYTES {
        return Err(ApiError::Invalid);
    }
    let token = bearer_token(&headers)?;
    let receipt: StartedReceipt = serde_json::from_slice(&body).map_err(|_| ApiError::Invalid)?;
    require_idempotency(&headers, job_id, receipt.generation, "started")?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let job = fetch_job_locked(&mut tx, tenant_id, job_id).await?;
    authenticate(&job, token, Operation::Started)?;
    validate_started(&job, &receipt)?;
    if let Some(existing) = &job.started_receipt_sha256 {
        if !digest_equal(existing, &digest) {
            return Err(ApiError::Conflict);
        }
    } else {
        let updated = sqlx::query(
            "UPDATE snowman_agent_jobs SET status='started', started_at=$3, \
             started_receipt_body=$4, started_receipt_sha256=$5, updated_at=NOW() \
             WHERE community_id=$1 AND job_id=$2 AND status='issued'",
        )
        .bind(tenant_id)
        .bind(job_id)
        .bind(receipt.started_at)
        .bind(body.as_ref())
        .bind(digest.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::Conflict);
        }
    }
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(ack())
}

async fn post_result(
    State(state): State<AppState>,
    Path((tenant_id, job_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<BrokerAck>, ApiError> {
    if body.is_empty() || body.len() > MAX_RESULT_RECEIPT_BYTES {
        return Err(ApiError::Invalid);
    }
    let token = bearer_token(&headers)?;
    let receipt: ResultReceipt = serde_json::from_slice(&body).map_err(|_| ApiError::Invalid)?;
    require_idempotency(&headers, job_id, receipt.generation, "result")?;
    let digest: [u8; 32] = Sha256::digest(&body).into();
    let mut tx = state.pool.begin().await.map_err(|_| ApiError::Internal)?;
    let job = fetch_job_locked(&mut tx, tenant_id, job_id).await?;
    authenticate(&job, token, Operation::Result)?;
    validate_result(&job, &receipt)?;
    if let Some(existing) = &job.result_receipt_sha256 {
        if !digest_equal(existing, &digest) {
            return Err(ApiError::Conflict);
        }
    } else {
        let status = match receipt.outcome {
            RuntimeOutcome::Succeeded { .. } => "succeeded",
            RuntimeOutcome::Failed { .. } => "failed",
        };
        let updated = sqlx::query(
            "UPDATE snowman_agent_jobs SET status=$3, completed_at=$4, \
             result_receipt_body=$5, result_receipt_sha256=$6, updated_at=NOW() \
             WHERE community_id=$1 AND job_id=$2 AND status IN ('issued','started')",
        )
        .bind(tenant_id)
        .bind(job_id)
        .bind(status)
        .bind(receipt.completed_at)
        .bind(body.as_ref())
        .bind(digest.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| ApiError::Internal)?;
        if updated.rows_affected() != 1 {
            return Err(ApiError::Conflict);
        }
    }
    tx.commit().await.map_err(|_| ApiError::Internal)?;
    Ok(ack())
}

fn ack() -> Json<BrokerAck> {
    Json(BrokerAck {
        schema_version: BROKER_ACK_SCHEMA.into(),
        accepted: true,
    })
}

#[derive(Clone, Copy)]
enum Operation {
    Snapshot,
    Started,
    Result,
}

struct JobRow {
    job_id: Uuid,
    generation: i64,
    runtime_id: String,
    model_id: String,
    snapshot_body: Vec<u8>,
    snapshot_sha256: Vec<u8>,
    job_token_sha256: Vec<u8>,
    status: String,
    issued_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    deadline_at: DateTime<Utc>,
    token_revoked_at: Option<DateTime<Utc>>,
    started_receipt_sha256: Option<Vec<u8>>,
    result_receipt_sha256: Option<Vec<u8>>,
    max_input_tokens: i64,
    max_output_tokens: i64,
}

const SELECT_JOB: &str = "SELECT job_id,generation,runtime_id,model_id,snapshot_body,\
 snapshot_sha256,job_token_sha256,status,issued_at,started_at,deadline_at,token_revoked_at,\
 started_receipt_sha256,result_receipt_sha256,max_input_tokens,max_output_tokens \
 FROM snowman_agent_jobs WHERE community_id=$1 AND job_id=$2";
const SELECT_JOB_FOR_UPDATE: &str = "SELECT job_id,generation,runtime_id,model_id,snapshot_body,\
 snapshot_sha256,job_token_sha256,status,issued_at,started_at,deadline_at,token_revoked_at,\
 started_receipt_sha256,result_receipt_sha256,max_input_tokens,max_output_tokens \
 FROM snowman_agent_jobs WHERE community_id=$1 AND job_id=$2 FOR UPDATE";

async fn fetch_job(pool: &PgPool, tenant_id: Uuid, job_id: Uuid) -> Result<JobRow, ApiError> {
    let row = sqlx::query(SELECT_JOB)
        .bind(tenant_id)
        .bind(job_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;
    row_to_job(&row)
}

async fn fetch_job_locked(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    job_id: Uuid,
) -> Result<JobRow, ApiError> {
    let row = sqlx::query(SELECT_JOB_FOR_UPDATE)
        .bind(tenant_id)
        .bind(job_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ApiError::Internal)?
        .ok_or(ApiError::Unauthorized)?;
    row_to_job(&row)
}

fn row_to_job(row: &sqlx::postgres::PgRow) -> Result<JobRow, ApiError> {
    Ok(JobRow {
        job_id: row.try_get("job_id").map_err(|_| ApiError::Internal)?,
        generation: row.try_get("generation").map_err(|_| ApiError::Internal)?,
        runtime_id: row.try_get("runtime_id").map_err(|_| ApiError::Internal)?,
        model_id: row.try_get("model_id").map_err(|_| ApiError::Internal)?,
        snapshot_body: row
            .try_get("snapshot_body")
            .map_err(|_| ApiError::Internal)?,
        snapshot_sha256: row
            .try_get("snapshot_sha256")
            .map_err(|_| ApiError::Internal)?,
        job_token_sha256: row
            .try_get("job_token_sha256")
            .map_err(|_| ApiError::Internal)?,
        status: row.try_get("status").map_err(|_| ApiError::Internal)?,
        issued_at: row.try_get("issued_at").map_err(|_| ApiError::Internal)?,
        started_at: row.try_get("started_at").map_err(|_| ApiError::Internal)?,
        deadline_at: row.try_get("deadline_at").map_err(|_| ApiError::Internal)?,
        token_revoked_at: row
            .try_get("token_revoked_at")
            .map_err(|_| ApiError::Internal)?,
        started_receipt_sha256: row
            .try_get("started_receipt_sha256")
            .map_err(|_| ApiError::Internal)?,
        result_receipt_sha256: row
            .try_get("result_receipt_sha256")
            .map_err(|_| ApiError::Internal)?,
        max_input_tokens: row
            .try_get("max_input_tokens")
            .map_err(|_| ApiError::Internal)?,
        max_output_tokens: row
            .try_get("max_output_tokens")
            .map_err(|_| ApiError::Internal)?,
    })
}

fn authenticate(job: &JobRow, token: &str, operation: Operation) -> Result<(), ApiError> {
    let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !digest_equal(&job.job_token_sha256, &digest)
        || job.token_revoked_at.is_some()
        || Utc::now() > job.deadline_at + chrono::Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
    {
        return Err(ApiError::Unauthorized);
    }
    let status_allowed = match operation {
        Operation::Snapshot => matches!(job.status.as_str(), "issued" | "started"),
        Operation::Started => matches!(job.status.as_str(), "issued" | "started"),
        Operation::Result => matches!(job.status.as_str(), "started" | "succeeded" | "failed"),
    };
    if !status_allowed {
        return Err(ApiError::Conflict);
    }
    Ok(())
}

fn validate_started(job: &JobRow, receipt: &StartedReceipt) -> Result<(), ApiError> {
    if receipt.schema_version != JOB_STARTED_SCHEMA
        || receipt.job_id != job.job_id
        || i64::from(receipt.generation) != job.generation
        || receipt.runtime_id != job.runtime_id
        || receipt.model_id != job.model_id
        || !snapshot_digest_matches(job, &receipt.snapshot_sha256)
        || !receipt_time_valid(job, receipt.started_at)
    {
        return Err(ApiError::Invalid);
    }
    Ok(())
}

fn validate_result(job: &JobRow, receipt: &ResultReceipt) -> Result<(), ApiError> {
    if receipt.schema_version != JOB_RESULT_SCHEMA
        || receipt.job_id != job.job_id
        || i64::from(receipt.generation) != job.generation
        || receipt.runtime_id != job.runtime_id
        || receipt.model_id != job.model_id
        || !snapshot_digest_matches(job, &receipt.snapshot_sha256)
        || !receipt_time_valid(job, receipt.completed_at)
        || !job.started_at.is_some_and(|started_at| {
            receipt.completed_at >= started_at - chrono::Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
        })
    {
        return Err(ApiError::Invalid);
    }
    match &receipt.outcome {
        RuntimeOutcome::Succeeded {
            stop_reason,
            output,
            input_tokens,
            output_tokens,
            ..
        } => {
            if !matches!(
                stop_reason.as_str(),
                "end_turn" | "max_tokens" | "max_turn_requests"
            ) || output.trim().is_empty()
                || output.len() > MAX_OUTPUT_BYTES
                || input_tokens.is_some_and(|value| value > job.max_input_tokens as u64)
                || output_tokens.is_some_and(|value| value > job.max_output_tokens as u64)
            {
                return Err(ApiError::Invalid);
            }
        }
        RuntimeOutcome::Failed { failure_code } => {
            if failure_code.len() < 3
                || failure_code.len() > 64
                || !failure_code
                    .chars()
                    .all(|value| value.is_ascii_lowercase() || value == '_')
            {
                return Err(ApiError::Invalid);
            }
        }
    }
    Ok(())
}

fn receipt_time_valid(job: &JobRow, time: DateTime<Utc>) -> bool {
    time >= job.issued_at - chrono::Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
        && time <= Utc::now() + chrono::Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
        && time <= job.deadline_at + chrono::Duration::seconds(MAX_CLOCK_SKEW_SECONDS)
}

fn snapshot_digest_matches(job: &JobRow, claimed: &str) -> bool {
    hex::decode(claimed)
        .ok()
        .is_some_and(|value| digest_equal(&job.snapshot_sha256, &value))
}

fn digest_equal(stored: &[u8], candidate: &[u8]) -> bool {
    stored.len() == 32 && candidate.len() == 32 && bool::from(stored.ct_eq(candidate))
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| {
            (32..=2048).contains(&value.len())
                && value.chars().all(|character| character.is_ascii_graphic())
        })
        .ok_or(ApiError::Unauthorized)?;
    Ok(value)
}

fn require_idempotency(
    headers: &HeaderMap,
    job_id: Uuid,
    generation: u32,
    operation: &str,
) -> Result<(), ApiError> {
    let expected = format!("{job_id}:{generation}:{operation}");
    let actual = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Invalid)?;
    if actual != expected {
        return Err(ApiError::Invalid);
    }
    Ok(())
}

/// Input to the trusted coordinator-side issuance function.
pub struct IssueJob {
    /// Exact minimized snapshot that the runtime will receive.
    pub snapshot: JobSnapshot,
    /// Opaque random one-job credential delivered only as a task override.
    pub job_token: String,
}

/// Outcome of idempotent job issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssueOutcome {
    /// Exact job identifier.
    pub job_id: Uuid,
    /// True only when this call created the durable job record.
    pub inserted: bool,
}

/// Validate and idempotently persist a purpose-bound job from a currently
/// active workforce lease. This function is for the trusted coordinator, not
/// the untrusted executor or broker HTTP surface.
pub async fn issue_job(pool: &PgPool, issue: IssueJob) -> Result<IssueOutcome, IssueError> {
    let mut transaction = pool.begin().await.map_err(|_| IssueError::Database)?;
    let outcome = issue_job_in_transaction(&mut transaction, issue).await?;
    transaction
        .commit()
        .await
        .map_err(|_| IssueError::Database)?;
    Ok(outcome)
}

/// Validate and idempotently persist a purpose-bound job inside the caller's
/// transaction. The coordinator uses this entry point so job issuance and its
/// crash-recovery launch record commit atomically.
pub async fn issue_job_in_transaction(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    mut issue: IssueJob,
) -> Result<IssueOutcome, IssueError> {
    validate_snapshot_for_issue(&issue.snapshot, &issue.job_token)?;
    let community_id =
        Uuid::parse_str(&issue.snapshot.tenant_id).map_err(|_| IssueError::Invalid)?;
    let snapshot_body = serde_json::to_vec(&issue.snapshot).map_err(|_| IssueError::Invalid)?;
    if snapshot_body.len() > MAX_SNAPSHOT_BYTES {
        return Err(IssueError::Invalid);
    }
    let snapshot_sha256: [u8; 32] = Sha256::digest(&snapshot_body).into();
    let token_sha256: [u8; 32] = Sha256::digest(issue.job_token.as_bytes()).into();
    issue.job_token.zeroize();
    let classification = classification_label(issue.snapshot.classification);
    let generation = i64::from(issue.snapshot.generation);
    let inserted = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO snowman_agent_jobs
          (community_id,job_id,request_id,task_id,generation,service_identity_id,
           runtime_id,model_id,classification,capability_grants,max_input_tokens,
           max_output_tokens,max_cost_microusd,snapshot_body,snapshot_sha256,
           job_token_sha256,status,issued_at,deadline_at,purge_after)
        SELECT t.community_id,$2,t.request_id,t.task_id,l.generation,t.service_identity_id,
               $6,t.model_id,r.classification,$7,$8,$9,$10,$11,$12,$13,
               'issued',NOW(),$14,$14 + INTERVAL '7 days'
        FROM snowman_work_tasks t
        JOIN snowman_work_requests r
          ON r.community_id=t.community_id AND r.request_id=t.request_id
        JOIN snowman_task_leases l
          ON l.community_id=t.community_id AND l.task_id=t.task_id
        JOIN snowman_workforce_identities i
          ON i.community_id=t.community_id AND i.identity_id=t.service_identity_id
        JOIN snowman_model_routes m
          ON m.community_id=t.community_id AND m.model_id=t.model_id
        WHERE t.community_id=$1 AND t.task_id=$3 AND t.request_id=$4
          AND l.generation=$5 AND l.worker_identity_id=t.service_identity_id
          AND l.expires_at >= $14 AND t.status IN ('leased','running')
          AND r.status IN ('running','reviewing')
          AND i.identity_type='service' AND i.status='active'
          AND (i.expires_at IS NULL OR i.expires_at >= $14)
          AND i.revoked_at IS NULL
          AND t.model_id=$15 AND t.specialist_role=$16 AND r.classification=$17
          AND m.status='active' AND $16=ANY(m.suited_roles)
          AND $17=ANY(m.allowed_classifications)
          AND m.max_context_tokens >= $8 + $9
          AND t.required_capabilities @> $7 AND t.required_capabilities <@ $7
          AND NOT EXISTS (
            SELECT 1 FROM unnest($7::TEXT[]) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_capability_grants g
              WHERE g.community_id=t.community_id
                AND g.identity_id=t.service_identity_id
                AND g.capability=required.capability
                AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at >= $14)
            )
          )
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_capability_grants g
            WHERE g.community_id=t.community_id
              AND g.identity_id=t.service_identity_id
              AND g.capability='workforce.tasks.execute'
              AND g.revoked_at IS NULL
              AND (g.expires_at IS NULL OR g.expires_at >= $14)
          )
          AND $8 <= r.max_input_tokens AND $8 >= t.expected_input_tokens
          AND $9 <= t.max_output_tokens AND $10 <= t.max_cost_microusd
          AND (t.deadline_at IS NULL OR t.deadline_at >= $14)
          AND (r.deadline_at IS NULL OR r.deadline_at >= $14)
        ON CONFLICT DO NOTHING
        RETURNING job_id
        "#,
    )
    .bind(community_id)
    .bind(issue.snapshot.job_id)
    .bind(issue.snapshot.task_id)
    .bind(issue.snapshot.request_id)
    .bind(generation)
    .bind(&issue.snapshot.runtime_id)
    .bind(&issue.snapshot.capability_grants)
    .bind(issue.snapshot.max_input_tokens as i64)
    .bind(issue.snapshot.max_output_tokens as i64)
    .bind(issue.snapshot.max_cost_microusd as i64)
    .bind(&snapshot_body)
    .bind(snapshot_sha256.as_slice())
    .bind(token_sha256.as_slice())
    .bind(issue.snapshot.deadline_at)
    .bind(&issue.snapshot.model_id)
    .bind(&issue.snapshot.specialist_role)
    .bind(classification)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IssueError::Database)?;
    if inserted.is_some() {
        return Ok(IssueOutcome {
            job_id: issue.snapshot.job_id,
            inserted: true,
        });
    }
    let existing = sqlx::query(
        "SELECT job_id,snapshot_sha256,job_token_sha256 FROM snowman_agent_jobs \
         WHERE community_id=$1 AND task_id=$2 AND generation=$3",
    )
    .bind(community_id)
    .bind(issue.snapshot.task_id)
    .bind(generation)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|_| IssueError::Database)?
    .ok_or(IssueError::Conflict)?;
    let existing_job: Uuid = existing
        .try_get("job_id")
        .map_err(|_| IssueError::Database)?;
    let existing_snapshot: Vec<u8> = existing
        .try_get("snapshot_sha256")
        .map_err(|_| IssueError::Database)?;
    let existing_token: Vec<u8> = existing
        .try_get("job_token_sha256")
        .map_err(|_| IssueError::Database)?;
    if existing_job != issue.snapshot.job_id
        || !digest_equal(&existing_snapshot, &snapshot_sha256)
        || !digest_equal(&existing_token, &token_sha256)
    {
        return Err(IssueError::Conflict);
    }
    Ok(IssueOutcome {
        job_id: existing_job,
        inserted: false,
    })
}

/// Coordinator-side issuance failure with no prompt, token, or database detail.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// The snapshot or token violates the governed contract.
    #[error("agent job issuance input is invalid")]
    Invalid,
    /// A different job already owns this fenced task generation.
    #[error("agent job issuance conflicts with the active task generation")]
    Conflict,
    /// The durable issuance operation failed.
    #[error("agent job issuance database operation failed")]
    Database,
}

fn validate_snapshot_for_issue(snapshot: &JobSnapshot, token: &str) -> Result<(), IssueError> {
    let community = Uuid::parse_str(&snapshot.tenant_id).map_err(|_| IssueError::Invalid)?;
    let now = Utc::now();
    if snapshot.schema_version != JOB_SNAPSHOT_SCHEMA
        || snapshot.job_id.is_nil()
        || snapshot.request_id.is_nil()
        || snapshot.task_id.is_nil()
        || snapshot.generation == 0
        || snapshot.workspace_id != community
        || !valid_runtime_id(&snapshot.runtime_id)
        || snapshot.model_id.is_empty()
        || snapshot.model_id.len() > 256
        || snapshot.model_id.contains("://")
        || snapshot.specialist_role.is_empty()
        || snapshot.specialist_role.len() > 64
        || !snapshot.data_policy.pii_prohibited
        || !valid_sha256(&snapshot.data_policy.minimization_evidence_sha256)
        || snapshot.system_prompt.is_empty()
        || snapshot.system_prompt.len() > 64 * 1024
        || snapshot.prompt.is_empty()
        || snapshot.prompt.len() > 512 * 1024
        || snapshot.capability_grants.len() > 64
        || snapshot.max_input_tokens == 0
        || snapshot.max_input_tokens > 10_000_000
        || snapshot.max_output_tokens == 0
        || snapshot.max_output_tokens > 1_000_000
        || snapshot.max_cost_microusd > 1_000_000_000
        || snapshot.deadline_at <= now + chrono::Duration::seconds(30)
        || snapshot.deadline_at > now + chrono::Duration::hours(4)
        || !(32..=2048).contains(&token.len())
        || !token.chars().all(|value| value.is_ascii_graphic())
        || snapshot
            .capability_grants
            .iter()
            .any(|value| !valid_capability(value))
    {
        return Err(IssueError::Invalid);
    }
    let mut capabilities = snapshot.capability_grants.clone();
    capabilities.sort();
    capabilities.dedup();
    if capabilities != snapshot.capability_grants {
        return Err(IssueError::Invalid);
    }
    Ok(())
}

fn classification_label(value: Classification) -> &'static str {
    match value {
        Classification::Internal => "internal",
        Classification::Confidential => "confidential",
        Classification::Restricted => "restricted",
    }
}

fn valid_runtime_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn valid_capability(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 120
        && value.split('.').count() >= 2
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment.len() <= 40
                && segment.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
                })
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_role(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.chars().enumerate().all(|(index, value)| {
            value == '_' || value.is_ascii_alphabetic() || (index > 0 && value.is_ascii_digit())
        })
}

fn valid_database_url(value: &str) -> bool {
    if sqlx::postgres::PgConnectOptions::from_str(value).is_err() {
        return false;
    }
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    let ssl_modes = url
        .query_pairs()
        .filter_map(|(name, value)| (name == "sslmode").then_some(value.into_owned()))
        .collect::<Vec<_>>();
    matches!(url.scheme(), "postgres" | "postgresql")
        && url
            .host_str()
            .is_some_and(|host| host.ends_with(".rds.amazonaws.com"))
        && !url.username().is_empty()
        && url.password().is_some_and(|password| password.len() >= 32)
        && url.port().is_none_or(|port| port == 5432)
        && ssl_modes.len() == 1
        && matches!(
            ssl_modes[0].as_str(),
            "require" | "verify-ca" | "verify-full"
        )
}

#[derive(Debug)]
enum ApiError {
    Invalid,
    Unauthorized,
    Conflict,
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Invalid => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication_failed"),
            Self::Conflict => (StatusCode::CONFLICT, "job_state_conflict"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };
        (status, Json(json!({ "error": code }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> JobRow {
        let token = "t".repeat(64);
        JobRow {
            job_id: Uuid::new_v4(),
            generation: 3,
            runtime_id: "snowman-acp".into(),
            model_id: "snowman-research-v1".into(),
            snapshot_body: vec![1],
            snapshot_sha256: vec![2; 32],
            job_token_sha256: Sha256::digest(token).to_vec(),
            status: "started".into(),
            issued_at: Utc::now() - chrono::Duration::seconds(5),
            started_at: Some(Utc::now() - chrono::Duration::seconds(4)),
            deadline_at: Utc::now() + chrono::Duration::minutes(5),
            token_revoked_at: None,
            started_receipt_sha256: None,
            result_receipt_sha256: None,
            max_input_tokens: 100,
            max_output_tokens: 50,
        }
    }

    #[test]
    fn token_is_exact_and_terminal_routes_are_operation_scoped() {
        let mut value = job();
        assert!(authenticate(&value, &"t".repeat(64), Operation::Snapshot).is_ok());
        assert!(authenticate(&value, &"x".repeat(64), Operation::Snapshot).is_err());
        value.status = "issued".into();
        assert!(authenticate(&value, &"t".repeat(64), Operation::Result).is_err());
        value.status = "succeeded".into();
        assert!(authenticate(&value, &"t".repeat(64), Operation::Snapshot).is_err());
        assert!(authenticate(&value, &"t".repeat(64), Operation::Result).is_ok());
        value.token_revoked_at = Some(Utc::now());
        assert!(authenticate(&value, &"t".repeat(64), Operation::Result).is_err());
    }

    #[test]
    fn result_receipt_binds_every_coordinate_and_budget() {
        let value = job();
        let mut receipt = ResultReceipt {
            schema_version: JOB_RESULT_SCHEMA.into(),
            job_id: value.job_id,
            generation: value.generation as u32,
            snapshot_sha256: hex::encode(&value.snapshot_sha256),
            runtime_id: value.runtime_id.clone(),
            model_id: value.model_id.clone(),
            completed_at: Utc::now(),
            outcome: RuntimeOutcome::Succeeded {
                stop_reason: "end_turn".into(),
                output: "bounded work product".into(),
                output_truncated: false,
                input_tokens: Some(90),
                output_tokens: Some(40),
            },
        };
        assert!(validate_result(&value, &receipt).is_ok());
        receipt.model_id = "other".into();
        assert!(validate_result(&value, &receipt).is_err());
        receipt.model_id = value.model_id.clone();
        if let RuntimeOutcome::Succeeded { output_tokens, .. } = &mut receipt.outcome {
            *output_tokens = Some(51);
        }
        assert!(validate_result(&value, &receipt).is_err());
    }

    #[test]
    fn issuance_rejects_non_uuid_tenant_duplicate_capabilities_and_provider_model() {
        let community = Uuid::new_v4();
        let mut snapshot = JobSnapshot {
            schema_version: JOB_SNAPSHOT_SCHEMA.into(),
            job_id: Uuid::new_v4(),
            tenant_id: community.to_string(),
            workspace_id: community,
            request_id: Uuid::new_v4(),
            task_id: Uuid::new_v4(),
            generation: 1,
            runtime_id: "snowman-acp".into(),
            model_id: "snowman-research-v1".into(),
            specialist_role: "research_evidence".into(),
            classification: Classification::Confidential,
            data_policy: snowman_agent_contract::AgentDataPolicy {
                pii_prohibited: true,
                minimization_evidence_sha256: "ab".repeat(32),
            },
            system_prompt: "Snowman policy".into(),
            prompt: "Minimized request".into(),
            capability_grants: vec!["artifact.draft".into()],
            max_input_tokens: 100,
            max_output_tokens: 50,
            max_cost_microusd: 1_000,
            deadline_at: Utc::now() + chrono::Duration::minutes(5),
        };
        assert!(validate_snapshot_for_issue(&snapshot, &"t".repeat(64)).is_ok());
        snapshot.capability_grants.push("artifact.draft".into());
        assert!(validate_snapshot_for_issue(&snapshot, &"t".repeat(64)).is_err());
        snapshot.capability_grants.pop();
        snapshot.model_id = "https://provider.example/model".into();
        assert!(validate_snapshot_for_issue(&snapshot, &"t".repeat(64)).is_err());
        snapshot.model_id = "snowman-research-v1".into();
        snapshot.tenant_id = "aptive".into();
        assert!(validate_snapshot_for_issue(&snapshot, &"t".repeat(64)).is_err());
        snapshot.tenant_id = community.to_string();
        snapshot.data_policy.pii_prohibited = false;
        assert!(validate_snapshot_for_issue(&snapshot, &"t".repeat(64)).is_err());
    }

    #[test]
    fn role_names_are_strict() {
        assert!(valid_role("snowman_agent_broker"));
        for invalid in ["", "2broker", "broker-role", "broker;drop role"] {
            assert!(!valid_role(invalid));
        }
    }

    #[test]
    fn database_urls_require_rds_tls_and_a_bounded_credential() {
        let password = "p".repeat(32);
        assert!(valid_database_url(&format!(
            "postgresql://broker:{password}@snowman.cluster.us-west-2.rds.amazonaws.com:5432/snowman?sslmode=require"
        )));
        for invalid in [
            format!("postgresql://broker:{password}@database.attacker.test/snowman?sslmode=require"),
            format!("postgresql://broker:{password}@snowman.cluster.us-west-2.rds.amazonaws.com/snowman?sslmode=disable"),
            "postgresql://broker:short@snowman.cluster.us-west-2.rds.amazonaws.com/snowman?sslmode=require".to_owned(),
        ] {
            assert!(!valid_database_url(&invalid));
        }
    }
}
