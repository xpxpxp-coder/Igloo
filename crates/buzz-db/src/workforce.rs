//! Durable, tenant-scoped queue primitives for the Snowman AI Workforce.
//!
//! The queue stores coordination state and immutable context references. Raw
//! client datasets remain in Analyst 360. Claims use PostgreSQL row locking and
//! fenced, digest-bound leases so a stale worker cannot complete a task after a
//! replacement worker has acquired it.

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction};
use url::Url;
use uuid::Uuid;

use buzz_core::CommunityId;

use crate::{DbError, Result};

/// One specialist task created with a work request.
#[derive(Debug, Clone)]
pub struct NewWorkTask {
    /// Stable task identifier supplied by the orchestrator.
    pub task_id: Uuid,
    /// Optional parent task for delegation lineage.
    pub parent_task_id: Option<Uuid>,
    /// Named specialist role, such as `research_evidence`.
    pub specialist_role: String,
    /// Unique tenant-bound service identity for this assignment.
    pub service_identity_id: Uuid,
    /// Optional Nostr public key bound to the service identity.
    pub assigned_agent_pubkey: Option<Vec<u8>>,
    /// Deny-by-default capabilities required by the task.
    pub required_capabilities: Vec<String>,
    /// Snowman gateway URL; the database rejects non-Snowman routes.
    pub model_gateway_route: String,
    /// Model selected for this specialist task.
    pub model_id: String,
    /// Digest of the exact capability/model/context/action snapshot to approve.
    pub execution_snapshot_sha256: [u8; 32],
    /// Machine-readable artifact quality and output contract.
    pub expected_artifact_contract: Value,
    /// Optional immutable context packet reference.
    pub context_packet_id: Option<Uuid>,
    /// `low`, `moderate`, `high`, or `prohibited`.
    pub risk_tier: String,
    /// Whether the action can be safely undone.
    pub reversible: bool,
    /// Whether execution must stop for a human decision.
    pub approval_required: bool,
    /// Queue priority from 0 through 100.
    pub priority: i16,
    /// Earliest time a worker may claim the task.
    pub available_at: DateTime<Utc>,
    /// Optional task deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Maximum execution attempts before dead-lettering.
    pub max_attempts: i32,
}

/// One durable, idempotent user work request and its initial task graph.
#[derive(Debug, Clone)]
pub struct NewWorkRequest {
    /// Stable request identifier supplied by the command center.
    pub request_id: Uuid,
    /// Raw idempotency key; only its SHA-256 digest is persisted.
    pub idempotency_key: String,
    /// Authenticated Snowman human or service subject.
    pub requester_identity: String,
    /// Digest of the complete canonical intake contract used for exact replay.
    pub request_contract_sha256: [u8; 32],
    /// User objective. Client records must not be embedded here.
    pub objective: String,
    /// `internal`, `confidential`, or `restricted`.
    pub classification: String,
    /// Optional overall deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Hard cost ceiling in millionths of a US dollar.
    pub max_cost_microusd: i64,
    /// Hard aggregate input-token ceiling.
    pub max_input_tokens: i64,
    /// Hard aggregate output-token ceiling.
    pub max_output_tokens: i64,
    /// Initial specialist task graph.
    pub tasks: Vec<NewWorkTask>,
}

/// A task plus its current fenced lease.
#[derive(Debug, Clone)]
pub struct LeasedWorkTask {
    /// Tenant/community scope.
    pub community_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Task identifier.
    pub task_id: Uuid,
    /// Specialist role.
    pub specialist_role: String,
    /// Tenant-bound service identity.
    pub service_identity_id: Uuid,
    /// Required capability set.
    pub required_capabilities: Vec<String>,
    /// Snowman model gateway route.
    pub model_gateway_route: String,
    /// Selected model identifier.
    pub model_id: String,
    /// Digest binding any approval to this exact execution snapshot.
    pub execution_snapshot_sha256: [u8; 32],
    /// Expected work-product contract.
    pub expected_artifact_contract: Value,
    /// Optional immutable context packet reference.
    pub context_packet_id: Option<Uuid>,
    /// Risk tier.
    pub risk_tier: String,
    /// Whether the action is reversible.
    pub reversible: bool,
    /// Whether a human approval is required.
    pub approval_required: bool,
    /// Monotonic lease fencing generation.
    pub lease_generation: i64,
    /// Lease expiry.
    pub lease_expires_at: DateTime<Utc>,
}

/// Spend usage associated with one model call or bounded operation.
#[derive(Debug, Clone)]
pub struct SpendEntry {
    /// Unique ledger entry identifier.
    pub ledger_entry_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Task identifier.
    pub task_id: Uuid,
    /// Model charged for the operation.
    pub model_id: String,
    /// Provider-reported input tokens.
    pub input_tokens: i64,
    /// Provider-reported output tokens.
    pub output_tokens: i64,
    /// Cost in millionths of a US dollar.
    pub cost_microusd: i64,
    /// Digest of the gateway/provider receipt, never the raw credential.
    pub provider_receipt_sha256: [u8; 32],
    /// Receipt time.
    pub recorded_at: DateTime<Utc>,
}

/// A human decision bound to one exact task execution snapshot.
#[derive(Debug, Clone)]
pub struct WorkApproval {
    /// Unique approval record identifier.
    pub approval_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Task identifier.
    pub task_id: Uuid,
    /// Digest copied from the task's immutable execution snapshot.
    pub task_snapshot_sha256: [u8; 32],
    /// `approved`, `denied`, or `revoked`.
    pub decision: String,
    /// Authenticated Snowman workforce identity making the decision.
    pub approver_identity: String,
    /// Digest of rationale retained by the governed evidence authority.
    pub rationale_sha256: [u8; 32],
    /// Decision time.
    pub decided_at: DateTime<Utc>,
    /// Hard expiry after which approval cannot authorize a claim.
    pub expires_at: DateTime<Utc>,
}

/// One immutable workforce lifecycle event. Payloads are bounded metadata and
/// artifact references, never credentials or raw client datasets.
#[derive(Debug, Clone)]
pub struct NewWorkEvent {
    /// Stable event ID supplied by the producer for idempotent correlation.
    pub event_id: Uuid,
    /// Work request identifier.
    pub request_id: Uuid,
    /// Optional specialist task identifier.
    pub task_id: Option<Uuid>,
    /// Namespaced lifecycle type such as `task.claimed`.
    pub event_type: String,
    /// Authenticated workforce or service identity.
    pub actor_identity: String,
    /// Bounded, secret-free metadata and immutable references.
    pub payload: Value,
    /// Producer-observed event time.
    pub occurred_at: DateTime<Utc>,
}

/// Hash-chain coordinates returned after an event is durably appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendedWorkEvent {
    /// Monotonic request-local sequence number.
    pub sequence: i64,
    /// Previous hash, absent only for the first event.
    pub previous_event_sha256: Option<[u8; 32]>,
    /// Digest of the domain-separated canonical event fields.
    pub event_sha256: [u8; 32],
}

/// Result of idempotently accepting a Snowman work request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnqueuedWorkRequest {
    /// Stable request ID, including when the idempotency key already existed.
    pub request_id: Uuid,
    /// True only when this call inserted the request and its initial task graph.
    pub inserted: bool,
}

/// Governed request status returned to authorized command-center callers.
#[derive(Debug, Clone, Serialize)]
pub struct WorkRequestStatus {
    /// Stable request ID.
    pub request_id: Uuid,
    /// Digest of the objective retained for evidence correlation.
    pub objective_sha256: String,
    /// Digest of the complete canonical intake contract.
    pub request_contract_sha256: String,
    /// Data classification applied to this request.
    pub classification: String,
    /// Aggregate lifecycle status.
    pub status: String,
    /// Optional user deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Hard request budget in millionths of a US dollar.
    pub max_cost_microusd: i64,
    /// Spend recorded so far.
    pub used_cost_microusd: i64,
    /// Hard input-token ceiling.
    pub max_input_tokens: i64,
    /// Input tokens recorded so far.
    pub used_input_tokens: i64,
    /// Hard output-token ceiling.
    pub max_output_tokens: i64,
    /// Output tokens recorded so far.
    pub used_output_tokens: i64,
    /// Current specialist task state.
    pub tasks: Vec<WorkTaskStatus>,
    /// Bounded lifecycle evidence, ordered by request-local sequence.
    pub events: Vec<WorkEventStatus>,
    /// Total event count. The response carries at most the newest 200 events.
    pub event_count: i64,
    /// Request creation time.
    pub created_at: DateTime<Utc>,
    /// Last aggregate status change.
    pub updated_at: DateTime<Utc>,
}

/// One specialist task in an authorized status response.
#[derive(Debug, Clone, Serialize)]
pub struct WorkTaskStatus {
    /// Stable task ID.
    pub task_id: Uuid,
    /// Delegation parent, when present.
    pub parent_task_id: Option<Uuid>,
    /// Named specialist role.
    pub specialist_role: String,
    /// Selected model, invoked only through the Snowman model gateway.
    pub model_id: String,
    /// Deny-by-default task capability set.
    pub required_capabilities: Vec<String>,
    /// Machine-readable expected work product.
    pub expected_artifact_contract: Value,
    /// Immutable Analyst 360 or Snowman context packet reference.
    pub context_packet_id: Option<Uuid>,
    /// Risk classification.
    pub risk_tier: String,
    /// Whether work can be undone safely.
    pub reversible: bool,
    /// Whether execution is stopped at a human gate.
    pub approval_required: bool,
    /// Current task lifecycle status.
    pub status: String,
    /// Execution attempts consumed.
    pub attempt_count: i32,
    /// Maximum execution attempts.
    pub max_attempts: i32,
    /// Optional task deadline.
    pub deadline_at: Option<DateTime<Utc>>,
    /// Immutable execution snapshot digest.
    pub execution_snapshot_sha256: String,
}

/// One hash-chained lifecycle event safe for the command-center response.
#[derive(Debug, Clone, Serialize)]
pub struct WorkEventStatus {
    /// Stable event ID.
    pub event_id: Uuid,
    /// Optional task ID.
    pub task_id: Option<Uuid>,
    /// Monotonic request-local sequence.
    pub sequence: i64,
    /// Namespaced lifecycle event type.
    pub event_type: String,
    /// Stable Snowman workforce actor identifier.
    pub actor_identity: String,
    /// Bounded metadata and immutable artifact references.
    pub payload: Value,
    /// Previous event digest, absent for the genesis event.
    pub previous_event_sha256: Option<String>,
    /// This event's evidence digest.
    pub event_sha256: String,
    /// Producer-observed event time.
    pub occurred_at: DateTime<Utc>,
}

/// Insert a work request and its initial task graph exactly once.
///
/// Reusing an idempotency key with the same objective returns the original
/// request ID. Reusing it with different content fails closed.
pub async fn enqueue_work_request(
    pool: &PgPool,
    community_id: CommunityId,
    request: &NewWorkRequest,
) -> Result<EnqueuedWorkRequest> {
    validate_new_request(request)?;
    let community_id = *community_id.as_uuid();
    let idempotency_digest = sha256(request.idempotency_key.as_bytes());
    let objective_digest = sha256(request.objective.as_bytes());
    let mut tx = pool.begin().await?;
    let inserted = sqlx::query(
        r#"
        INSERT INTO snowman_work_requests
          (community_id, request_id, idempotency_key_sha256, requester_identity,
           objective, objective_sha256, request_contract_sha256, classification,
           status, deadline_at, max_cost_microusd, max_input_tokens, max_output_tokens)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'requested',$9,$10,$11,$12)
        ON CONFLICT (community_id, idempotency_key_sha256) DO NOTHING
        RETURNING request_id
        "#,
    )
    .bind(community_id)
    .bind(request.request_id)
    .bind(idempotency_digest.as_slice())
    .bind(&request.requester_identity)
    .bind(&request.objective)
    .bind(objective_digest.as_slice())
    .bind(request.request_contract_sha256.as_slice())
    .bind(&request.classification)
    .bind(request.deadline_at)
    .bind(request.max_cost_microusd)
    .bind(request.max_input_tokens)
    .bind(request.max_output_tokens)
    .fetch_optional(&mut *tx)
    .await?;

    if inserted.is_none() {
        let existing = sqlx::query(
            "SELECT request_id, objective_sha256, request_contract_sha256, requester_identity, classification, deadline_at, \
                    max_cost_microusd, max_input_tokens, max_output_tokens \
             FROM snowman_work_requests \
             WHERE community_id=$1 AND idempotency_key_sha256=$2",
        )
        .bind(community_id)
        .bind(idempotency_digest.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        let existing_digest: Vec<u8> = existing.try_get("objective_sha256")?;
        let exact_replay = existing_digest.as_slice() == objective_digest.as_slice()
            && existing
                .try_get::<Vec<u8>, _>("request_contract_sha256")?
                .as_slice()
                == request.request_contract_sha256.as_slice()
            && existing.try_get::<String, _>("requester_identity")? == request.requester_identity
            && existing.try_get::<String, _>("classification")? == request.classification
            && existing.try_get::<Option<DateTime<Utc>>, _>("deadline_at")? == request.deadline_at
            && existing.try_get::<i64, _>("max_cost_microusd")? == request.max_cost_microusd
            && existing.try_get::<i64, _>("max_input_tokens")? == request.max_input_tokens
            && existing.try_get::<i64, _>("max_output_tokens")? == request.max_output_tokens;
        if !exact_replay {
            return Err(DbError::AccessDenied(
                "Snowman workforce idempotency key was reused for a different request".into(),
            ));
        }
        let existing_id: Uuid = existing.try_get("request_id")?;
        tx.commit().await?;
        return Ok(EnqueuedWorkRequest {
            request_id: existing_id,
            inserted: false,
        });
    }

    for task in &request.tasks {
        insert_task(&mut tx, community_id, request.request_id, task).await?;
    }
    let accepted_at = Utc::now();
    let accepted_event = NewWorkEvent {
        event_id: request.request_id,
        request_id: request.request_id,
        task_id: None,
        event_type: "request.accepted".to_string(),
        actor_identity: request.requester_identity.clone(),
        payload: serde_json::json!({
            "schema_version": "snowman.work.event.v1",
            "classification": request.classification,
            "objective_sha256": hex::encode(objective_digest),
            "request_contract_sha256": hex::encode(request.request_contract_sha256),
            "initial_task_count": request.tasks.len(),
        }),
        occurred_at: accepted_at,
    };
    validate_work_event(&accepted_event)?;
    let accepted_digest = work_event_digest(community_id, 0, None, &accepted_event)?;
    sqlx::query(
        r#"
        INSERT INTO snowman_work_events
          (community_id, event_id, request_id, task_id, sequence, event_type,
           actor_identity, payload, previous_event_sha256, event_sha256, occurred_at)
        VALUES ($1,$2,$3,NULL,0,$4,$5,$6,NULL,$7,$8)
        "#,
    )
    .bind(community_id)
    .bind(accepted_event.event_id)
    .bind(accepted_event.request_id)
    .bind(&accepted_event.event_type)
    .bind(&accepted_event.actor_identity)
    .bind(&accepted_event.payload)
    .bind(accepted_digest.as_slice())
    .bind(accepted_event.occurred_at)
    .execute(&mut *tx)
    .await?;
    refresh_request_status(&mut tx, community_id, request.request_id).await?;
    tx.commit().await?;
    Ok(EnqueuedWorkRequest {
        request_id: request.request_id,
        inserted: true,
    })
}

/// Read one request from the writer with strict tenant scoping.
///
/// Raw objective text and requester identifiers are deliberately omitted. The
/// command center receives only current state, budgets, bounded event metadata,
/// and immutable evidence coordinates.
pub async fn get_work_request_status(
    pool: &PgPool,
    community_id: CommunityId,
    request_id: Uuid,
) -> Result<Option<WorkRequestStatus>> {
    let community_id = *community_id.as_uuid();
    let request = sqlx::query(
        r#"
        SELECT r.request_id, r.objective_sha256, r.request_contract_sha256,
               r.classification, r.status,
               r.deadline_at, r.max_cost_microusd, r.max_input_tokens,
               r.max_output_tokens, r.created_at, r.updated_at,
               COALESCE(SUM(s.cost_microusd), 0)::bigint AS used_cost_microusd,
               COALESCE(SUM(s.input_tokens), 0)::bigint AS used_input_tokens,
               COALESCE(SUM(s.output_tokens), 0)::bigint AS used_output_tokens
        FROM snowman_work_requests r
        LEFT JOIN snowman_spend_ledger s
          ON s.community_id=r.community_id AND s.request_id=r.request_id
        WHERE r.community_id=$1 AND r.request_id=$2
        GROUP BY r.community_id, r.request_id
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_optional(pool)
    .await?;
    let Some(request) = request else {
        return Ok(None);
    };

    let task_rows = sqlx::query(
        r#"
        SELECT task_id, parent_task_id, specialist_role, model_id,
               required_capabilities, expected_artifact_contract,
               context_packet_id, risk_tier, reversible, approval_required,
               status, attempt_count, max_attempts, deadline_at,
               execution_snapshot_sha256
        FROM snowman_work_tasks
        WHERE community_id=$1 AND request_id=$2
        ORDER BY created_at, task_id
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_all(pool)
    .await?;
    let tasks = task_rows
        .into_iter()
        .map(|row| -> Result<WorkTaskStatus> {
            Ok(WorkTaskStatus {
                task_id: row.try_get("task_id")?,
                parent_task_id: row.try_get("parent_task_id")?,
                specialist_role: row.try_get("specialist_role")?,
                model_id: row.try_get("model_id")?,
                required_capabilities: row.try_get("required_capabilities")?,
                expected_artifact_contract: row.try_get("expected_artifact_contract")?,
                context_packet_id: row.try_get("context_packet_id")?,
                risk_tier: row.try_get("risk_tier")?,
                reversible: row.try_get("reversible")?,
                approval_required: row.try_get("approval_required")?,
                status: row.try_get("status")?,
                attempt_count: row.try_get("attempt_count")?,
                max_attempts: row.try_get("max_attempts")?,
                deadline_at: row.try_get("deadline_at")?,
                execution_snapshot_sha256: hex::encode(
                    row.try_get::<Vec<u8>, _>("execution_snapshot_sha256")?,
                ),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let event_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)::bigint FROM snowman_work_events WHERE community_id=$1 AND request_id=$2",
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_one(pool)
    .await?;
    let mut event_rows = sqlx::query(
        r#"
        SELECT event_id, task_id, sequence, event_type, actor_identity, payload,
               previous_event_sha256, event_sha256, occurred_at
        FROM snowman_work_events
        WHERE community_id=$1 AND request_id=$2
        ORDER BY sequence DESC
        LIMIT 200
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_all(pool)
    .await?;
    event_rows.reverse();
    let events = event_rows
        .into_iter()
        .map(|row| -> Result<WorkEventStatus> {
            Ok(WorkEventStatus {
                event_id: row.try_get("event_id")?,
                task_id: row.try_get("task_id")?,
                sequence: row.try_get("sequence")?,
                event_type: row.try_get("event_type")?,
                actor_identity: row.try_get("actor_identity")?,
                payload: row.try_get("payload")?,
                previous_event_sha256: row
                    .try_get::<Option<Vec<u8>>, _>("previous_event_sha256")?
                    .map(hex::encode),
                event_sha256: hex::encode(row.try_get::<Vec<u8>, _>("event_sha256")?),
                occurred_at: row.try_get("occurred_at")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Some(WorkRequestStatus {
        request_id: request.try_get("request_id")?,
        objective_sha256: hex::encode(request.try_get::<Vec<u8>, _>("objective_sha256")?),
        request_contract_sha256: hex::encode(
            request.try_get::<Vec<u8>, _>("request_contract_sha256")?,
        ),
        classification: request.try_get("classification")?,
        status: request.try_get("status")?,
        deadline_at: request.try_get("deadline_at")?,
        max_cost_microusd: request.try_get("max_cost_microusd")?,
        used_cost_microusd: request.try_get("used_cost_microusd")?,
        max_input_tokens: request.try_get("max_input_tokens")?,
        used_input_tokens: request.try_get("used_input_tokens")?,
        max_output_tokens: request.try_get("max_output_tokens")?,
        used_output_tokens: request.try_get("used_output_tokens")?,
        tasks,
        events,
        event_count,
        created_at: request.try_get("created_at")?,
        updated_at: request.try_get("updated_at")?,
    }))
}

/// Claim the next due task using `FOR UPDATE SKIP LOCKED` and a fenced lease.
pub async fn claim_next_work_task(
    pool: &PgPool,
    community_id: CommunityId,
    worker_identity_id: Uuid,
    lease_token_sha256: [u8; 32],
    lease_duration: Duration,
) -> Result<Option<LeasedWorkTask>> {
    if lease_duration <= Duration::zero() {
        return Err(DbError::InvalidData(
            "a positive lease duration is required".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let candidate = sqlx::query(
        r#"
        SELECT * FROM snowman_work_tasks
        WHERE community_id=$1 AND service_identity_id=$2
          AND status='queued' AND available_at <= NOW()
          AND (deadline_at IS NULL OR deadline_at > NOW())
          AND EXISTS (
            SELECT 1 FROM snowman_workforce_identities i
            WHERE i.community_id=snowman_work_tasks.community_id
              AND i.identity_id=snowman_work_tasks.service_identity_id
              AND i.identity_type='service' AND i.role='agent' AND i.status='active'
              AND i.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > NOW())
          )
          AND NOT EXISTS (
            SELECT 1 FROM unnest(required_capabilities) required(capability)
            WHERE NOT EXISTS (
              SELECT 1 FROM snowman_workforce_capability_grants g
              WHERE g.community_id=snowman_work_tasks.community_id
                AND g.identity_id=snowman_work_tasks.service_identity_id
                AND g.capability=required.capability AND g.revoked_at IS NULL
                AND (g.expires_at IS NULL OR g.expires_at > NOW())
            )
          )
          AND (
            NOT approval_required OR (
              SELECT a.decision = 'approved'
                     AND a.task_snapshot_sha256 = snowman_work_tasks.execution_snapshot_sha256
                     AND a.expires_at > NOW()
              FROM snowman_work_approvals a
              WHERE a.community_id=snowman_work_tasks.community_id
                AND a.request_id=snowman_work_tasks.request_id
                AND a.task_id=snowman_work_tasks.task_id
              ORDER BY a.decided_at DESC, a.approval_id DESC
              LIMIT 1
            ) IS TRUE
          )
        ORDER BY priority DESC, created_at ASC
        FOR UPDATE SKIP LOCKED
        LIMIT 1
        "#,
    )
    .bind(community_id)
    .bind(worker_identity_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(task) = candidate else {
        tx.commit().await?;
        return Ok(None);
    };
    let task_id: Uuid = task.try_get("task_id")?;
    let expires_at = Utc::now() + lease_duration;
    let lease = sqlx::query(
        r#"
        INSERT INTO snowman_task_leases
          (community_id, task_id, worker_identity_id, generation,
           lease_token_sha256, leased_at, heartbeat_at, expires_at)
        VALUES ($1,$2,$3,1,$4,NOW(),NOW(),$5)
        ON CONFLICT (community_id, task_id) DO UPDATE SET
          worker_identity_id=EXCLUDED.worker_identity_id,
          generation=snowman_task_leases.generation + 1,
          lease_token_sha256=EXCLUDED.lease_token_sha256,
          leased_at=NOW(), heartbeat_at=NOW(), expires_at=EXCLUDED.expires_at
        RETURNING generation, expires_at
        "#,
    )
    .bind(community_id)
    .bind(task_id)
    .bind(worker_identity_id)
    .bind(lease_token_sha256.as_slice())
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE snowman_work_tasks SET status='leased', attempt_count=attempt_count+1, updated_at=NOW() WHERE community_id=$1 AND task_id=$2",
    )
    .bind(community_id)
    .bind(task_id)
    .execute(&mut *tx)
    .await?;
    refresh_request_status(
        &mut tx,
        community_id,
        task.try_get::<Uuid, _>("request_id")?,
    )
    .await?;
    tx.commit().await?;

    Ok(Some(LeasedWorkTask {
        community_id,
        request_id: task.try_get("request_id")?,
        task_id,
        specialist_role: task.try_get("specialist_role")?,
        service_identity_id: task.try_get("service_identity_id")?,
        required_capabilities: task.try_get("required_capabilities")?,
        model_gateway_route: task.try_get("model_gateway_route")?,
        model_id: task.try_get("model_id")?,
        execution_snapshot_sha256: vec_to_sha256(task.try_get("execution_snapshot_sha256")?)?,
        expected_artifact_contract: task.try_get("expected_artifact_contract")?,
        context_packet_id: task.try_get("context_packet_id")?,
        risk_tier: task.try_get("risk_tier")?,
        reversible: task.try_get("reversible")?,
        approval_required: task.try_get("approval_required")?,
        lease_generation: lease.try_get("generation")?,
        lease_expires_at: lease.try_get("expires_at")?,
    }))
}

/// Extend a live lease only when every fencing attribute still matches.
pub async fn heartbeat_work_task(
    pool: &PgPool,
    community_id: CommunityId,
    task_id: Uuid,
    worker_identity_id: Uuid,
    generation: i64,
    lease_token_sha256: [u8; 32],
    lease_duration: Duration,
) -> Result<bool> {
    if lease_duration <= Duration::zero() {
        return Err(DbError::InvalidData(
            "lease duration must be positive".into(),
        ));
    }
    let result = sqlx::query(
        r#"
        UPDATE snowman_task_leases SET heartbeat_at=NOW(), expires_at=$6
        WHERE community_id=$1 AND task_id=$2 AND worker_identity_id=$3
          AND generation=$4 AND lease_token_sha256=$5 AND expires_at > NOW()
        "#,
    )
    .bind(community_id.as_uuid())
    .bind(task_id)
    .bind(worker_identity_id)
    .bind(generation)
    .bind(lease_token_sha256.as_slice())
    .bind(Utc::now() + lease_duration)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Finish a task only under its current live fenced lease.
pub async fn finish_work_task(
    pool: &PgPool,
    community_id: CommunityId,
    task_id: Uuid,
    worker_identity_id: Uuid,
    generation: i64,
    lease_token_sha256: [u8; 32],
    succeeded: bool,
) -> Result<bool> {
    let community_id = community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let result = sqlx::query(
        r#"
        UPDATE snowman_work_tasks t
        SET status=$6, updated_at=NOW()
        WHERE t.community_id=$1 AND t.task_id=$2 AND t.status IN ('leased','running','reviewing')
          AND EXISTS (
            SELECT 1 FROM snowman_task_leases l
            WHERE l.community_id=$1 AND l.task_id=$2 AND l.worker_identity_id=$3
              AND l.generation=$4 AND l.lease_token_sha256=$5
              AND l.expires_at > NOW()
          )
        "#,
    )
    .bind(community_id)
    .bind(task_id)
    .bind(worker_identity_id)
    .bind(generation)
    .bind(lease_token_sha256.as_slice())
    .bind(if succeeded { "succeeded" } else { "failed" })
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() == 1 {
        sqlx::query("DELETE FROM snowman_task_leases WHERE community_id=$1 AND task_id=$2")
            .bind(community_id)
            .bind(task_id)
            .execute(&mut *tx)
            .await?;
        let request_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT request_id FROM snowman_work_tasks WHERE community_id=$1 AND task_id=$2",
        )
        .bind(community_id)
        .bind(task_id)
        .fetch_one(&mut *tx)
        .await?;
        refresh_request_status(&mut tx, *community_id, request_id).await?;
    }
    tx.commit().await?;
    Ok(result.rows_affected() == 1)
}

/// Requeue expired work or dead-letter tasks that exhausted their attempt cap.
pub async fn recover_expired_work_tasks(pool: &PgPool, community_id: CommunityId) -> Result<u64> {
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let recovered = sqlx::query(
        r#"
        UPDATE snowman_work_tasks t SET
          status=CASE WHEN t.attempt_count >= t.max_attempts THEN 'dead_lettered' ELSE 'queued' END,
          available_at=CASE
            WHEN t.attempt_count >= t.max_attempts THEN t.available_at
            ELSE NOW() + make_interval(
              secs => LEAST(300, (5 * power(2, LEAST(t.attempt_count, 6)))::integer)
            )
          END,
          updated_at=NOW()
        FROM snowman_task_leases l
        WHERE t.community_id=$1 AND l.community_id=t.community_id AND l.task_id=t.task_id
          AND l.expires_at <= NOW() AND t.status IN ('leased','running','reviewing')
        RETURNING t.request_id
        "#,
    )
    .bind(community_id)
    .fetch_all(&mut *tx)
    .await?;
    let mut request_ids = std::collections::HashSet::new();
    for row in &recovered {
        request_ids.insert(row.try_get::<Uuid, _>("request_id")?);
    }
    sqlx::query("DELETE FROM snowman_task_leases WHERE community_id=$1 AND expires_at <= NOW()")
        .bind(community_id)
        .execute(&mut *tx)
        .await?;
    for request_id in request_ids {
        refresh_request_status(&mut tx, community_id, request_id).await?;
    }
    tx.commit().await?;
    Ok(recovered.len() as u64)
}

/// Append one request-local event under a PostgreSQL advisory lock so parallel
/// workers cannot fork the sequence or hash chain. Exact event-ID replays return
/// the original coordinates; conflicting reuse fails closed.
pub async fn append_work_event(
    pool: &PgPool,
    community_id: CommunityId,
    event: &NewWorkEvent,
) -> Result<AppendedWorkEvent> {
    validate_work_event(event)?;
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text, 0))")
        .bind(community_id)
        .bind(event.request_id)
        .execute(&mut *tx)
        .await?;

    if let Some(existing) = sqlx::query(
        "SELECT request_id, sequence, event_type, actor_identity, payload, occurred_at, \
                previous_event_sha256, event_sha256, task_id \
         FROM snowman_work_events WHERE community_id=$1 AND event_id=$2",
    )
    .bind(community_id)
    .bind(event.event_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        let previous = optional_vec_to_sha256(existing.try_get("previous_event_sha256")?)?;
        let digest = vec_to_sha256(existing.try_get("event_sha256")?)?;
        let exact_replay = existing.try_get::<Uuid, _>("request_id")? == event.request_id
            && existing.try_get::<String, _>("event_type")? == event.event_type
            && existing.try_get::<String, _>("actor_identity")? == event.actor_identity
            && existing.try_get::<Value, _>("payload")? == event.payload
            && existing.try_get::<DateTime<Utc>, _>("occurred_at")? == event.occurred_at
            && existing.try_get::<Option<Uuid>, _>("task_id")? == event.task_id;
        if !exact_replay {
            return Err(DbError::AccessDenied(
                "work event ID was reused with different evidence".into(),
            ));
        }
        let result = AppendedWorkEvent {
            sequence: existing.try_get("sequence")?,
            previous_event_sha256: previous,
            event_sha256: digest,
        };
        tx.commit().await?;
        return Ok(result);
    }

    let previous = sqlx::query(
        "SELECT sequence, event_sha256 FROM snowman_work_events \
         WHERE community_id=$1 AND request_id=$2 ORDER BY sequence DESC LIMIT 1",
    )
    .bind(community_id)
    .bind(event.request_id)
    .fetch_optional(&mut *tx)
    .await?;
    let sequence = previous
        .as_ref()
        .map(|row| row.try_get::<i64, _>("sequence"))
        .transpose()?
        .map_or(0, |value| value + 1);
    let previous_digest = previous
        .map(|row| vec_to_sha256(row.try_get("event_sha256")?))
        .transpose()?;
    let event_digest = work_event_digest(community_id, sequence, previous_digest, event)?;

    sqlx::query(
        r#"
        INSERT INTO snowman_work_events
          (community_id, event_id, request_id, task_id, sequence, event_type,
           actor_identity, payload, previous_event_sha256, event_sha256, occurred_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        "#,
    )
    .bind(community_id)
    .bind(event.event_id)
    .bind(event.request_id)
    .bind(event.task_id)
    .bind(sequence)
    .bind(&event.event_type)
    .bind(&event.actor_identity)
    .bind(&event.payload)
    .bind(previous_digest.map(|value| value.to_vec()))
    .bind(event_digest.as_slice())
    .bind(event.occurred_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(AppendedWorkEvent {
        sequence,
        previous_event_sha256: previous_digest,
        event_sha256: event_digest,
    })
}

/// Record spend atomically after enforcing the request's hard cost/token caps.
pub async fn record_work_spend(
    pool: &PgPool,
    community_id: CommunityId,
    entry: &SpendEntry,
) -> Result<()> {
    if entry.input_tokens < 0 || entry.output_tokens < 0 || entry.cost_microusd < 0 {
        return Err(DbError::InvalidData(
            "spend values must be non-negative".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text || ':' || $2::text, 0))")
        .bind(community_id)
        .bind(entry.ledger_entry_id)
        .execute(&mut *tx)
        .await?;
    let existing = sqlx::query(
        "SELECT request_id, task_id, model_id, input_tokens, output_tokens, \
                cost_microusd, provider_receipt_sha256, recorded_at \
         FROM snowman_spend_ledger WHERE community_id=$1 AND ledger_entry_id=$2",
    )
    .bind(community_id)
    .bind(entry.ledger_entry_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let exact_replay = existing.try_get::<Uuid, _>("request_id")? == entry.request_id
            && existing.try_get::<Uuid, _>("task_id")? == entry.task_id
            && existing.try_get::<String, _>("model_id")? == entry.model_id
            && existing.try_get::<i64, _>("input_tokens")? == entry.input_tokens
            && existing.try_get::<i64, _>("output_tokens")? == entry.output_tokens
            && existing.try_get::<i64, _>("cost_microusd")? == entry.cost_microusd
            && existing
                .try_get::<Vec<u8>, _>("provider_receipt_sha256")?
                .as_slice()
                == entry.provider_receipt_sha256.as_slice()
            && existing.try_get::<DateTime<Utc>, _>("recorded_at")? == entry.recorded_at;
        if exact_replay {
            tx.commit().await?;
            return Ok(());
        }
        return Err(DbError::AccessDenied(
            "spend ledger entry ID was reused with different evidence".into(),
        ));
    }
    let budget = sqlx::query(
        r#"
        SELECT max_cost_microusd, max_input_tokens, max_output_tokens
        FROM snowman_work_requests
        WHERE community_id=$1 AND request_id=$2
        FOR UPDATE
        "#,
    )
    .bind(community_id)
    .bind(entry.request_id)
    .fetch_one(&mut *tx)
    .await?;
    let used = sqlx::query(
        r#"
        SELECT COALESCE(SUM(cost_microusd),0)::bigint AS cost,
               COALESCE(SUM(input_tokens),0)::bigint AS input,
               COALESCE(SUM(output_tokens),0)::bigint AS output
        FROM snowman_spend_ledger WHERE community_id=$1 AND request_id=$2
        "#,
    )
    .bind(community_id)
    .bind(entry.request_id)
    .fetch_one(&mut *tx)
    .await?;
    let would_exceed = used.try_get::<i64, _>("cost")? + entry.cost_microusd
        > budget.try_get::<i64, _>("max_cost_microusd")?
        || used.try_get::<i64, _>("input")? + entry.input_tokens
            > budget.try_get::<i64, _>("max_input_tokens")?
        || used.try_get::<i64, _>("output")? + entry.output_tokens
            > budget.try_get::<i64, _>("max_output_tokens")?;
    if would_exceed {
        return Err(DbError::AccessDenied(
            "Snowman workforce request budget would be exceeded".into(),
        ));
    }
    sqlx::query(
        r#"
        INSERT INTO snowman_spend_ledger
          (community_id, ledger_entry_id, request_id, task_id, model_id,
           input_tokens, output_tokens, cost_microusd,
           provider_receipt_sha256, recorded_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(community_id)
    .bind(entry.ledger_entry_id)
    .bind(entry.request_id)
    .bind(entry.task_id)
    .bind(&entry.model_id)
    .bind(entry.input_tokens)
    .bind(entry.output_tokens)
    .bind(entry.cost_microusd)
    .bind(entry.provider_receipt_sha256.as_slice())
    .bind(entry.recorded_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Persist a human decision and atomically advance or stop the gated task.
pub async fn record_work_approval(
    pool: &PgPool,
    community_id: CommunityId,
    approval: &WorkApproval,
) -> Result<()> {
    if !matches!(
        approval.decision.as_str(),
        "approved" | "denied" | "revoked"
    ) || approval.approver_identity.trim().is_empty()
        || approval.expires_at <= approval.decided_at
    {
        return Err(DbError::InvalidData(
            "approval requires a valid decision, approver, and future expiry".into(),
        ));
    }
    let community_id = *community_id.as_uuid();
    let mut tx = pool.begin().await?;
    let task = sqlx::query(
        "SELECT execution_snapshot_sha256, approval_required FROM snowman_work_tasks \
         WHERE community_id=$1 AND request_id=$2 AND task_id=$3 FOR UPDATE",
    )
    .bind(community_id)
    .bind(approval.request_id)
    .bind(approval.task_id)
    .fetch_one(&mut *tx)
    .await?;
    let current_snapshot: Vec<u8> = task.try_get("execution_snapshot_sha256")?;
    if current_snapshot.as_slice() != approval.task_snapshot_sha256.as_slice()
        || !task.try_get::<bool, _>("approval_required")?
    {
        return Err(DbError::AccessDenied(
            "approval does not match the current gated task snapshot".into(),
        ));
    }
    sqlx::query(
        r#"
        INSERT INTO snowman_work_approvals
          (community_id, request_id, task_id, approval_id, task_snapshot_sha256,
           decision, approver_identity, rationale_sha256, decided_at, expires_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        "#,
    )
    .bind(community_id)
    .bind(approval.request_id)
    .bind(approval.task_id)
    .bind(approval.approval_id)
    .bind(approval.task_snapshot_sha256.as_slice())
    .bind(&approval.decision)
    .bind(approval.approver_identity.trim())
    .bind(approval.rationale_sha256.as_slice())
    .bind(approval.decided_at)
    .bind(approval.expires_at)
    .execute(&mut *tx)
    .await?;
    let next_status = match approval.decision.as_str() {
        "approved" => "queued",
        "denied" => "failed",
        _ => "awaiting_approval",
    };
    sqlx::query(
        "UPDATE snowman_work_tasks SET status=$4, updated_at=NOW() \
         WHERE community_id=$1 AND request_id=$2 AND task_id=$3 \
           AND status IN ('awaiting_approval','queued')",
    )
    .bind(community_id)
    .bind(approval.request_id)
    .bind(approval.task_id)
    .bind(next_status)
    .execute(&mut *tx)
    .await?;
    refresh_request_status(&mut tx, community_id, approval.request_id).await?;
    tx.commit().await?;
    Ok(())
}

async fn refresh_request_status(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
    request_id: Uuid,
) -> Result<()> {
    let counts = sqlx::query(
        r#"
        SELECT COUNT(*)::bigint AS total,
          COUNT(*) FILTER (WHERE status IN ('succeeded','failed','cancelled','expired','dead_lettered'))::bigint AS terminal,
          COUNT(*) FILTER (WHERE status IN ('failed','expired','dead_lettered'))::bigint AS failed,
          COUNT(*) FILTER (WHERE status='cancelled')::bigint AS cancelled,
          COUNT(*) FILTER (WHERE status='awaiting_approval')::bigint AS awaiting,
          COUNT(*) FILTER (WHERE status IN ('leased','running','reviewing'))::bigint AS active
        FROM snowman_work_tasks WHERE community_id=$1 AND request_id=$2
        "#,
    )
    .bind(community_id)
    .bind(request_id)
    .fetch_one(&mut **tx)
    .await?;
    let total: i64 = counts.try_get("total")?;
    let terminal: i64 = counts.try_get("terminal")?;
    let failed: i64 = counts.try_get("failed")?;
    let cancelled: i64 = counts.try_get("cancelled")?;
    let awaiting: i64 = counts.try_get("awaiting")?;
    let active: i64 = counts.try_get("active")?;
    let next = if total > 0 && terminal == total {
        if failed > 0 {
            "failed"
        } else if cancelled > 0 {
            "cancelled"
        } else {
            "completed"
        }
    } else if active > 0 {
        "running"
    } else if awaiting > 0 {
        "awaiting_approval"
    } else {
        "planned"
    };
    sqlx::query(
        "UPDATE snowman_work_requests SET status=$3, updated_at=NOW() \
         WHERE community_id=$1 AND request_id=$2 AND status <> 'cancelled'",
    )
    .bind(community_id)
    .bind(request_id)
    .bind(next)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn insert_task(
    tx: &mut Transaction<'_, Postgres>,
    community_id: Uuid,
    request_id: Uuid,
    task: &NewWorkTask,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO snowman_work_tasks
          (community_id, task_id, request_id, parent_task_id, specialist_role,
           service_identity_id, assigned_agent_pubkey, required_capabilities,
           model_gateway_route, model_id, execution_snapshot_sha256, expected_artifact_contract,
           context_packet_id, risk_tier, reversible, approval_required, status,
           priority, available_at, deadline_at, max_attempts)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
        "#,
    )
    .bind(community_id)
    .bind(task.task_id)
    .bind(request_id)
    .bind(task.parent_task_id)
    .bind(&task.specialist_role)
    .bind(task.service_identity_id)
    .bind(&task.assigned_agent_pubkey)
    .bind(&task.required_capabilities)
    .bind(&task.model_gateway_route)
    .bind(&task.model_id)
    .bind(task.execution_snapshot_sha256.as_slice())
    .bind(&task.expected_artifact_contract)
    .bind(task.context_packet_id)
    .bind(&task.risk_tier)
    .bind(task.reversible)
    .bind(task.approval_required)
    .bind(if task.approval_required {
        "awaiting_approval"
    } else {
        "queued"
    })
    .bind(task.priority)
    .bind(task.available_at)
    .bind(task.deadline_at)
    .bind(task.max_attempts)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn validate_new_request(request: &NewWorkRequest) -> Result<()> {
    if request.idempotency_key.trim().is_empty()
        || request.requester_identity.trim().is_empty()
        || request.objective.trim().is_empty()
        || request.tasks.is_empty()
        || request.request_contract_sha256 == [0; 32]
    {
        return Err(DbError::InvalidData(
            "idempotency key, requester, objective, and at least one task are required".into(),
        ));
    }
    if request.max_cost_microusd < 0
        || request.max_input_tokens < 0
        || request.max_output_tokens < 0
    {
        return Err(DbError::InvalidData(
            "work request budgets must be non-negative".into(),
        ));
    }
    let mut task_ids = std::collections::HashSet::new();
    for task in &request.tasks {
        if !task_ids.insert(task.task_id) {
            return Err(DbError::InvalidData(
                "duplicate task ID in work graph".into(),
            ));
        }
        validate_model_gateway_route(&task.model_gateway_route)?;
        if task.risk_tier == "prohibited" || (!task.reversible && !task.approval_required) {
            return Err(DbError::AccessDenied(
                "prohibited or irreversible work requires a different human-gated plan".into(),
            ));
        }
    }
    Ok(())
}

fn validate_model_gateway_route(route: &str) -> Result<()> {
    let parsed = Url::parse(route).map_err(|_| {
        DbError::AccessDenied("model route must be a valid Snowman-controlled HTTPS URL".into())
    })?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let snowman_host = host == "snowmanai.org" || host.ends_with(".snowmanai.org");
    if parsed.scheme() != "https"
        || !snowman_host
        || parsed.port_or_known_default() != Some(443)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(DbError::AccessDenied(
            "model route must use a credential-free Snowman-controlled HTTPS gateway on port 443"
                .into(),
        ));
    }
    Ok(())
}

fn validate_work_event(event: &NewWorkEvent) -> Result<()> {
    let event_type = event.event_type.trim();
    if event_type.is_empty()
        || event_type != event.event_type
        || event_type.len() > 128
        || !event_type.contains('.')
        || !event_type.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
        || event.actor_identity.trim().is_empty()
        || event.actor_identity.trim() != event.actor_identity
        || event.actor_identity.len() > 256
    {
        return Err(DbError::InvalidData(
            "work event requires a namespaced type and bounded actor identity".into(),
        ));
    }
    let payload = serde_json::to_vec(&event.payload)
        .map_err(|error| DbError::InvalidData(format!("invalid work event payload: {error}")))?;
    if payload.len() > 65_536 {
        return Err(DbError::InvalidData(
            "work event payload exceeds the 64 KiB metadata limit".into(),
        ));
    }
    if value_contains_secret_key(&event.payload) {
        return Err(DbError::AccessDenied(
            "work event payload contains a credential-like field".into(),
        ));
    }
    Ok(())
}

fn value_contains_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "authorization"
                    | "credential"
                    | "credentials"
                    | "password"
                    | "private_key"
                    | "secret"
                    | "token"
            ) || value_contains_secret_key(value)
        }),
        Value::Array(values) => values.iter().any(value_contains_secret_key),
        _ => false,
    }
}

fn work_event_digest(
    community_id: Uuid,
    sequence: i64,
    previous_event_sha256: Option<[u8; 32]>,
    event: &NewWorkEvent,
) -> Result<[u8; 32]> {
    let payload = serde_json::to_vec(&event.payload)
        .map_err(|error| DbError::InvalidData(format!("invalid work event payload: {error}")))?;
    let sequence_bytes = sequence.to_be_bytes();
    let occurred_at = event
        .occurred_at
        .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let task_id_bytes = event.task_id.map(|value| *value.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(b"snowman.work.event.v1\0");
    update_digest_field(&mut hasher, community_id.as_bytes());
    update_digest_field(&mut hasher, event.request_id.as_bytes());
    update_digest_field(
        &mut hasher,
        task_id_bytes.as_ref().map_or(&[], |value| value.as_slice()),
    );
    update_digest_field(&mut hasher, &sequence_bytes);
    update_digest_field(
        &mut hasher,
        previous_event_sha256
            .as_ref()
            .map_or(&[], |value| value.as_slice()),
    );
    update_digest_field(&mut hasher, event.event_id.as_bytes());
    update_digest_field(&mut hasher, event.event_type.as_bytes());
    update_digest_field(&mut hasher, event.actor_identity.as_bytes());
    update_digest_field(&mut hasher, occurred_at.as_bytes());
    update_digest_field(&mut hasher, &payload);
    Ok(hasher.finalize().into())
}

fn update_digest_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn vec_to_sha256(value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| DbError::InvalidData("expected a 32-byte SHA-256 digest".into()))
}

fn optional_vec_to_sha256(value: Option<Vec<u8>>) -> Result<Option<[u8; 32]>> {
    value.map(vec_to_sha256).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> NewWorkRequest {
        let request_id = Uuid::new_v4();
        NewWorkRequest {
            request_id,
            idempotency_key: "user-request-1".into(),
            requester_identity: "google:founder@snowmanai.org".into(),
            request_contract_sha256: sha256(b"complete-request-contract-v1"),
            objective: "Prepare an evidence-backed client-ready brief.".into(),
            classification: "confidential".into(),
            deadline_at: None,
            max_cost_microusd: 5_000_000,
            max_input_tokens: 500_000,
            max_output_tokens: 100_000,
            tasks: vec![NewWorkTask {
                task_id: Uuid::new_v4(),
                parent_task_id: None,
                specialist_role: "research_evidence".into(),
                service_identity_id: Uuid::new_v4(),
                assigned_agent_pubkey: None,
                required_capabilities: vec!["context.read".into()],
                model_gateway_route: "https://models.snowmanai.org/anthropic".into(),
                model_id: "snowman-research-model".into(),
                execution_snapshot_sha256: sha256(b"safe-task-v1"),
                expected_artifact_contract: serde_json::json!({"type": "brief"}),
                context_packet_id: None,
                risk_tier: "low".into(),
                reversible: true,
                approval_required: false,
                priority: 50,
                available_at: Utc::now(),
                deadline_at: None,
                max_attempts: 3,
            }],
        }
    }

    fn event() -> NewWorkEvent {
        NewWorkEvent {
            event_id: Uuid::from_u128(1),
            request_id: Uuid::from_u128(2),
            task_id: Some(Uuid::from_u128(3)),
            event_type: "task.claimed".into(),
            actor_identity: "snowman-service:research-worker".into(),
            payload: serde_json::json!({
                "artifact_ref": "sha256:abc",
                "lease_generation": 1
            }),
            occurred_at: DateTime::parse_from_rfc3339("2026-07-26T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }
    }

    #[test]
    fn validates_safe_snowman_work_graph() {
        validate_new_request(&request()).expect("safe request");
    }

    #[test]
    fn rejects_direct_model_provider_and_irreversible_autonomy() {
        let mut direct = request();
        direct.tasks[0].model_gateway_route = "https://api.openai.com/v1".into();
        assert!(matches!(
            validate_new_request(&direct),
            Err(DbError::AccessDenied(_))
        ));

        let mut unsafe_request = request();
        unsafe_request.tasks[0].reversible = false;
        unsafe_request.tasks[0].approval_required = false;
        assert!(matches!(
            validate_new_request(&unsafe_request),
            Err(DbError::AccessDenied(_))
        ));
    }

    #[test]
    fn rejects_snowman_lookalike_model_route() {
        let mut invalid = request();
        invalid.tasks[0].model_gateway_route =
            "https://evil.example/.snowmanai.org/anthropic".into();
        assert!(matches!(
            validate_new_request(&invalid),
            Err(DbError::AccessDenied(_))
        ));
    }

    #[test]
    fn rejects_duplicate_task_ids() {
        let mut invalid = request();
        invalid.tasks.push(invalid.tasks[0].clone());
        assert!(matches!(
            validate_new_request(&invalid),
            Err(DbError::InvalidData(_))
        ));
    }

    #[test]
    fn work_event_digest_is_deterministic_and_chain_bound() {
        let event = event();
        let community = Uuid::from_u128(4);
        let first = work_event_digest(community, 0, None, &event).unwrap();
        assert_eq!(
            first,
            work_event_digest(community, 0, None, &event).unwrap()
        );
        assert_ne!(
            first,
            work_event_digest(community, 1, Some(first), &event).unwrap()
        );
    }

    #[test]
    fn work_event_rejects_nested_credentials() {
        let mut invalid = event();
        invalid.payload = serde_json::json!({"details": {"authorization": "Bearer nope"}});
        assert!(matches!(
            validate_work_event(&invalid),
            Err(DbError::AccessDenied(_))
        ));
    }
}
