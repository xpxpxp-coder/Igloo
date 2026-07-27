//! Adversarial PostgreSQL proof for Snowman's governed authority ledgers.
//!
//! These tests are ignored by default because they require PostgreSQL. Every
//! test creates a unique schema and pins `search_path` on every pooled
//! connection, so the suite is parallel-safe and never resets `public`.
//!
//! Run:
//! `BUZZ_TEST_DATABASE_URL=postgres://... cargo test -p buzz-db --test snowman_authority_postgres -- --include-ignored`

use std::sync::Arc;

use sqlx::{postgres::PgPoolOptions, AssertSqlSafe, PgPool, Row};
use tokio::sync::Barrier;
use uuid::Uuid;

const TEST_DB_URL: &str = "postgres://buzz:buzz_dev@localhost:5432/buzz";
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

struct Sandbox {
    pool: PgPool,
    schema: String,
    database_url: String,
}

impl Sandbox {
    async fn through(version: i64, connections: u32) -> Self {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| TEST_DB_URL.to_owned());
        let schema = format!("snowman_authority_{}", Uuid::new_v4().simple());
        let bootstrap = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await
            .expect("connect to PostgreSQL proof database");
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&bootstrap)
            .await
            .expect("create isolated proof schema");
        bootstrap.close().await;

        let set_path = format!("SET search_path TO {schema}");
        let pool = PgPoolOptions::new()
            .max_connections(connections)
            .after_connect(move |connection, _| {
                let set_path = set_path.clone();
                Box::pin(async move {
                    sqlx::query(AssertSqlSafe(set_path))
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .expect("connect to isolated proof schema");
        MIGRATOR
            .run_to(version, &pool)
            .await
            .unwrap_or_else(|error| panic!("apply migrations through {version}: {error}"));
        Self {
            pool,
            schema,
            database_url,
        }
    }

    async fn latest(connections: u32) -> Self {
        let latest = MIGRATOR
            .iter()
            .map(|migration| migration.version)
            .max()
            .expect("migrations exist");
        Self::through(latest, connections).await
    }

    async fn finish(self) {
        self.pool.close().await;
        let bootstrap = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.database_url)
            .await
            .expect("reconnect for proof teardown");
        sqlx::query(AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&bootstrap)
        .await
        .expect("drop isolated proof schema");
        bootstrap.close().await;
    }
}

fn digest(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

async fn community(pool: &PgPool, id: Uuid, label: &str) {
    sqlx::query("INSERT INTO communities (id,host,signing_key) VALUES ($1,$2,$3)")
        .bind(id)
        .bind(format!("{label}-{}.snowman.test", id.simple()))
        .bind(digest(1))
        .execute(pool)
        .await
        .expect("insert community");
}

async fn service_identity(pool: &PgPool, tenant_id: Uuid, identity_id: Uuid, marker: u8) {
    sqlx::query(
        "INSERT INTO snowman_workforce_identities \
         (community_id,identity_id,identity_type,provider,provider_subject_sha256,display_name,role,status) \
         VALUES ($1,$2,'service','snowman_service',$3,'Postgres proof identity','agent','active')",
    )
    .bind(tenant_id)
    .bind(identity_id)
    .bind(digest(marker))
    .execute(pool)
    .await
    .expect("insert service identity");
}

struct WorkforceSeed {
    request_id: Uuid,
    task_id: Uuid,
    identity_id: Uuid,
    job_id: Uuid,
}

async fn workforce(pool: &PgPool, tenant_id: Uuid, ids: &WorkforceSeed, marker: u8) {
    service_identity(pool, tenant_id, ids.identity_id, marker).await;
    sqlx::query(
        "INSERT INTO snowman_work_requests \
         (community_id,request_id,idempotency_key_sha256,requester_identity,objective,objective_sha256,\
          classification,status,deadline_at,max_cost_microusd,max_input_tokens,max_output_tokens) \
         VALUES ($1,$2,$3,'proof','bounded proof',$4,'confidential','running',NOW()+INTERVAL '1 hour',100,100,100)",
    )
    .bind(tenant_id)
    .bind(ids.request_id)
    .bind(digest(marker.wrapping_add(1)))
    .bind(digest(marker.wrapping_add(2)))
    .execute(pool)
    .await
    .expect("insert work request");
    sqlx::query(
        "INSERT INTO snowman_work_tasks \
         (community_id,task_id,request_id,specialist_role,service_identity_id,required_capabilities,\
          model_gateway_route,model_id,execution_snapshot_sha256,risk_tier,reversible,approval_required,\
          status,deadline_at,max_cost_microusd,expected_input_tokens,max_output_tokens) \
         VALUES ($1,$2,$3,'governed_analyst',$4,ARRAY['artifact.create'],\
          'https://models.snowmanai.org/','snowman-proof',$5,'low',TRUE,FALSE,'running',\
          NOW()+INTERVAL '50 minutes',100,100,100)",
    )
    .bind(tenant_id)
    .bind(ids.task_id)
    .bind(ids.request_id)
    .bind(ids.identity_id)
    .bind(digest(marker.wrapping_add(3)))
    .execute(pool)
    .await
    .expect("insert work task");
    sqlx::query(
        "INSERT INTO snowman_task_leases \
         (community_id,task_id,worker_identity_id,generation,lease_token_sha256,leased_at,heartbeat_at,expires_at) \
         VALUES ($1,$2,$3,1,$4,NOW(),NOW(),NOW()+INTERVAL '30 minutes')",
    )
    .bind(tenant_id)
    .bind(ids.task_id)
    .bind(ids.identity_id)
    .bind(digest(marker.wrapping_add(4)))
    .execute(pool)
    .await
    .expect("insert task lease");
    sqlx::query(
        "INSERT INTO snowman_agent_jobs \
         (community_id,job_id,request_id,task_id,generation,service_identity_id,runtime_id,model_id,\
          classification,capability_grants,max_input_tokens,max_output_tokens,max_cost_microusd,\
          snapshot_body,snapshot_sha256,job_token_sha256,status,issued_at,deadline_at,purge_after) \
         VALUES ($1,$2,$3,$4,1,$5,'proof-runtime','snowman-proof','confidential',\
          ARRAY['artifact.create'],100,100,100,$6,$7,$8,'started',NOW(),\
          NOW()+INTERVAL '20 minutes',NOW()+INTERVAL '1 day')",
    )
    .bind(tenant_id)
    .bind(ids.job_id)
    .bind(ids.request_id)
    .bind(ids.task_id)
    .bind(ids.identity_id)
    .bind(vec![marker; 16])
    .bind(digest(marker.wrapping_add(5)))
    .bind(digest(marker.wrapping_add(6)))
    .execute(pool)
    .await
    .expect("insert agent job");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATE SCHEMA"]
async fn fresh_install_and_populated_0048_upgrade_reach_exact_latest_schema() {
    let fresh = Sandbox::latest(2).await;
    let latest = MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .max()
        .expect("latest migration");
    assert_eq!(
        latest, 55,
        "update the proof when the authority chain advances"
    );
    let applied: i64 =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(&fresh.pool)
            .await
            .expect("read fresh migration version");
    assert_eq!(applied, latest);
    for table in [
        "snowman_agent_tool_actions",
        "snowman_meeting_command_receipts",
        "snowman_orchestration_terminal_receipts",
        "snowman_audit_checkpoint_publications",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&fresh.pool)
            .await
            .expect("inspect fresh schema");
        assert!(exists, "fresh install omitted {table}");
    }
    fresh.finish().await;

    let upgrade = Sandbox::through(48, 2).await;
    let tenant_id = Uuid::new_v4();
    community(&upgrade.pool, tenant_id, "upgrade").await;
    MIGRATOR
        .run(&upgrade.pool)
        .await
        .expect("upgrade populated 0048 database through latest");
    let preserved: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM communities WHERE id=$1)")
            .bind(tenant_id)
            .fetch_one(&upgrade.pool)
            .await
            .expect("verify upgrade row");
    assert!(preserved);
    let applied: i64 =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(&upgrade.pool)
            .await
            .expect("read upgraded migration version");
    assert_eq!(applied, latest);
    upgrade.finish().await;
}

#[derive(Debug, PartialEq, Eq)]
enum Reservation {
    Reserved,
    Replay,
    Conflict,
    BudgetDenied,
}

async fn reserve_model(
    pool: &PgPool,
    tenant_id: Uuid,
    ids: &WorkforceSeed,
    generation_id: Uuid,
    request_digest: Vec<u8>,
    cost: i64,
) -> Reservation {
    let mut tx = pool.begin().await.expect("begin reservation");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .expect("set serializable");
    sqlx::query(
        "SELECT request_id FROM snowman_work_requests WHERE community_id=$1 AND request_id=$2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(ids.request_id)
    .fetch_one(&mut *tx)
    .await
    .expect("lock request authority");
    if let Some(row) = sqlx::query(
        "SELECT request_sha256 FROM snowman_agent_model_generations \
         WHERE community_id=$1 AND generation_id=$2",
    )
    .bind(tenant_id)
    .bind(generation_id)
    .fetch_optional(&mut *tx)
    .await
    .expect("read replay fence")
    {
        let prior: Vec<u8> = row.get("request_sha256");
        tx.commit().await.expect("commit reconciliation");
        return if prior == request_digest {
            Reservation::Replay
        } else {
            Reservation::Conflict
        };
    }
    let within: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT SUM(cost_microusd) FROM snowman_spend_ledger \
          WHERE community_id=$1 AND request_id=$2),0) + \
          COALESCE((SELECT SUM(accounted_cost_microusd) FROM snowman_agent_model_generations \
          WHERE community_id=$1 AND request_id=$2 AND status IN ('reserved','indeterminate')),0) + $3 \
          <= (SELECT max_cost_microusd FROM snowman_work_requests \
              WHERE community_id=$1 AND request_id=$2)",
    )
    .bind(tenant_id)
    .bind(ids.request_id)
    .bind(cost)
    .fetch_one(&mut *tx)
    .await
    .expect("check aggregate model budget");
    if !within {
        tx.rollback().await.expect("rollback budget denial");
        return Reservation::BudgetDenied;
    }
    sqlx::query(
        "INSERT INTO snowman_agent_model_generations \
         (community_id,generation_id,job_id,request_id,task_id,lease_generation,request_sha256,\
          model_id,capability,requested_input_tokens,requested_output_tokens,requested_cost_microusd,\
          accounted_input_tokens,accounted_output_tokens,accounted_cost_microusd,status) \
         VALUES ($1,$2,$3,$4,$5,1,$6,'snowman-proof','artifact.create',10,10,$7,10,10,$7,'reserved')",
    )
    .bind(tenant_id)
    .bind(generation_id)
    .bind(ids.job_id)
    .bind(ids.request_id)
    .bind(ids.task_id)
    .bind(request_digest)
    .bind(cost)
    .execute(&mut *tx)
    .await
    .expect("insert model reservation");
    tx.commit().await.expect("commit model reservation");
    Reservation::Reserved
}

async fn insert_tool_receipt(
    pool: &PgPool,
    tenant_id: Uuid,
    job_id: Uuid,
    task_id: Uuid,
    action_id: Uuid,
    receipt_id: Uuid,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO snowman_agent_tool_receipts \
         (community_id,receipt_id,workspace_id,job_id,task_id,generation,action_id,sequence,status,\
          action_sha256,redaction_evidence_sha256,receipt_sha256,signing_key_arn,\
          signature_algorithm,signature,signature_sha256,external_checkpoint_sha256,occurred_at) \
         VALUES ($1,$2,$3,$4,$5,1,$6,0,'authorized',$7,$8,$9,\
          'arn:aws:kms:us-west-2:123456789012:key/proof','ECDSA_SHA_256',$10,$11,$12,NOW())",
    )
    .bind(tenant_id)
    .bind(receipt_id)
    .bind(Uuid::new_v4())
    .bind(job_id)
    .bind(task_id)
    .bind(action_id)
    .bind(digest(54))
    .bind(digest(55))
    .bind(digest(receipt_id.as_bytes()[0]))
    .bind(vec![1_u8; 64])
    .bind(digest(56))
    .bind(digest(57))
    .execute(pool)
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATE SCHEMA"]
async fn model_budget_serializes_duplicate_races_and_tool_receipts_are_exactly_once() {
    let sandbox = Sandbox::latest(8).await;
    let tenant_id = Uuid::new_v4();
    community(&sandbox.pool, tenant_id, "budget").await;
    let ids = Arc::new(WorkforceSeed {
        request_id: Uuid::new_v4(),
        task_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
    });
    workforce(&sandbox.pool, tenant_id, &ids, 20).await;

    let barrier = Arc::new(Barrier::new(2));
    let first = {
        let pool = sandbox.pool.clone();
        let ids = Arc::clone(&ids);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            reserve_model(&pool, tenant_id, &ids, Uuid::new_v4(), digest(31), 80).await
        })
    };
    let second = {
        let pool = sandbox.pool.clone();
        let ids = Arc::clone(&ids);
        let barrier = Arc::clone(&barrier);
        tokio::spawn(async move {
            barrier.wait().await;
            reserve_model(&pool, tenant_id, &ids, Uuid::new_v4(), digest(32), 80).await
        })
    };
    let outcomes = [
        first.await.expect("first race"),
        second.await.expect("second race"),
    ];
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == Reservation::Reserved)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| **value == Reservation::BudgetDenied)
            .count(),
        1
    );

    let replay_id = Uuid::new_v4();
    assert_eq!(
        reserve_model(&sandbox.pool, tenant_id, &ids, replay_id, digest(41), 10).await,
        Reservation::Reserved
    );
    assert_eq!(
        reserve_model(&sandbox.pool, tenant_id, &ids, replay_id, digest(41), 10).await,
        Reservation::Replay
    );
    assert_eq!(
        reserve_model(&sandbox.pool, tenant_id, &ids, replay_id, digest(42), 10).await,
        Reservation::Conflict
    );

    let action_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO snowman_agent_tool_actions \
         (community_id,action_id,workspace_id,request_id,job_id,task_id,agent_identity_id,\
          service_identity_id,requested_by_identity_id,generation,lease_generation,lease_fence_sha256,\
          capability_id,tool_id,registry_sha256,classification,minimization_evidence_sha256,\
          input_sha256,action_sha256,impact,status,deadline_at,authorized_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$7,1,1,$8,'artifact.create','proof-tool',$9,\
          'confidential',$10,$11,$12,'low','authorized',NOW()+INTERVAL '10 minutes',NOW())",
    )
    .bind(tenant_id)
    .bind(action_id)
    .bind(Uuid::new_v4())
    .bind(ids.request_id)
    .bind(ids.job_id)
    .bind(ids.task_id)
    .bind(ids.identity_id)
    .bind(digest(50))
    .bind(digest(51))
    .bind(digest(52))
    .bind(digest(53))
    .bind(digest(54))
    .execute(&sandbox.pool)
    .await
    .expect("insert authorized tool action");
    let (left, right) = tokio::join!(
        insert_tool_receipt(
            &sandbox.pool,
            tenant_id,
            ids.job_id,
            ids.task_id,
            action_id,
            Uuid::new_v4()
        ),
        insert_tool_receipt(
            &sandbox.pool,
            tenant_id,
            ids.job_id,
            ids.task_id,
            action_id,
            Uuid::new_v4()
        )
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    sandbox.finish().await;
}

async fn insert_minimal_meeting(
    pool: &PgPool,
    tenant_id: Uuid,
    workspace_id: Uuid,
    meeting_id: Uuid,
    mailbox_id: Uuid,
    agent_id: Uuid,
    marker: u8,
) {
    service_identity(pool, tenant_id, mailbox_id, marker).await;
    service_identity(pool, tenant_id, agent_id, marker.wrapping_add(1)).await;
    sqlx::query(
        "INSERT INTO snowman_meeting_mailboxes \
         (community_id,mailbox_identity_id,workspace_id,provider,provider_subject_sha256,\
          mailbox_binding_sha256,status) VALUES ($1,$2,$3,'google_workspace',$4,$5,'disabled')",
    )
    .bind(tenant_id)
    .bind(mailbox_id)
    .bind(workspace_id)
    .bind(digest(marker.wrapping_add(2)))
    .bind(digest(marker.wrapping_add(3)))
    .execute(pool)
    .await
    .expect("insert meeting mailbox");
    sqlx::query(
        "INSERT INTO snowman_meetings \
         (community_id,meeting_id,workspace_id,mailbox_identity_id,meeting_agent_identity_id,\
          parent_thread_sha256,data_class,provider_event_id_sha256,provider_revision,organizer_approved,\
          conference_kind,conference_entrypoint_sha256,sealed_coordinate_ref,conference_approval_sha256,\
          starts_at,ends_at,join_not_before,join_not_after,voice_route,speech_output_route,\
          external_processing_allowed,processor_policy_sha256,consent_policy_sha256,disclosure_required,\
          transcription_consent_required,external_processing_consent_required,transcript_retention,\
          max_cost_microusd,max_duration_seconds,source_analyst_artifact_id,source_content_sha256,\
          admission_evidence_sha256,schedule_revision,status,activation_enabled) \
         VALUES ($1,$2,$3,$4,$5,$6,'confidential',$7,2,TRUE,'snowman_huddle',$8,\
          'snowman-coordinate:proof',$9,NOW()+INTERVAL '1 hour',NOW()+INTERVAL '2 hours',\
          NOW()+INTERVAL '50 minutes',NOW()+INTERVAL '70 minutes','snowman_aws','voice_route',\
          FALSE,$10,$11,TRUE,TRUE,FALSE,'analyst_evidence',1000,3600,$12,$13,$14,1,'scheduled',TRUE)",
    )
    .bind(tenant_id)
    .bind(meeting_id)
    .bind(workspace_id)
    .bind(mailbox_id)
    .bind(agent_id)
    .bind(digest(marker.wrapping_add(4)))
    .bind(digest(marker.wrapping_add(5)))
    .bind(digest(marker.wrapping_add(6)))
    .bind(digest(marker.wrapping_add(7)))
    .bind(digest(marker.wrapping_add(8)))
    .bind(digest(marker.wrapping_add(9)))
    .bind(Uuid::new_v4())
    .bind(digest(marker.wrapping_add(10)))
    .bind(digest(marker.wrapping_add(11)))
    .execute(pool)
    .await
    .expect("insert meeting");
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATE SCHEMA"]
async fn tenant_composite_keys_and_meeting_cancel_revision_fence_cross_tenant_uuid_collisions() {
    let sandbox = Sandbox::latest(4).await;
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    community(&sandbox.pool, tenant_a, "tenant-a").await;
    community(&sandbox.pool, tenant_b, "tenant-b").await;
    let shared_meeting = Uuid::new_v4();
    let shared_mailbox = Uuid::new_v4();
    let workspace = Uuid::new_v4();
    insert_minimal_meeting(
        &sandbox.pool,
        tenant_b,
        workspace,
        shared_meeting,
        shared_mailbox,
        Uuid::new_v4(),
        70,
    )
    .await;

    service_identity(&sandbox.pool, tenant_a, Uuid::new_v4(), 90).await;
    let cross_tenant = sqlx::query(
        "INSERT INTO snowman_meeting_command_callers \
         (community_id,workspace_id,mailbox_identity_id,service_identity_id,service_principal,\
          policy_generation,status,authority_evidence_sha256) \
         VALUES ($1,$2,$3,$4,'snowman:proof',1,'active',$5)",
    )
    .bind(tenant_a)
    .bind(workspace)
    .bind(shared_mailbox)
    .bind(Uuid::new_v4())
    .bind(digest(91))
    .execute(&sandbox.pool)
    .await;
    assert!(
        cross_tenant.is_err(),
        "tenant A must not bind tenant B mailbox UUID"
    );

    let cancelled = sqlx::query(
        "UPDATE snowman_meetings SET provider_revision=2,schedule_revision=schedule_revision+1,\
         session_generation=session_generation+1,status='cancelled',activation_enabled=FALSE,updated_at=NOW() \
         WHERE community_id=$1 AND meeting_id=$2 AND provider_revision<=2 AND status<>'cancelled'",
    )
    .bind(tenant_b)
    .bind(shared_meeting)
    .execute(&sandbox.pool)
    .await
    .expect("cancel exact meeting revision");
    assert_eq!(cancelled.rows_affected(), 1);
    let stale_reschedule = sqlx::query(
        "UPDATE snowman_meetings SET provider_revision=3,schedule_revision=schedule_revision+1 \
         WHERE community_id=$1 AND meeting_id=$2 AND provider_revision<3 AND status<>'cancelled'",
    )
    .bind(tenant_b)
    .bind(shared_meeting)
    .execute(&sandbox.pool)
    .await
    .expect("attempt stale post-cancel reschedule");
    assert_eq!(stale_reschedule.rows_affected(), 0);
    let wrong_tenant_cancel = sqlx::query(
        "UPDATE snowman_meetings SET status='cancelled' WHERE community_id=$1 AND meeting_id=$2",
    )
    .bind(tenant_a)
    .bind(shared_meeting)
    .execute(&sandbox.pool)
    .await
    .expect("attempt wrong-tenant cancellation");
    assert_eq!(wrong_tenant_cancel.rows_affected(), 0);
    sandbox.finish().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL with CREATE SCHEMA"]
async fn orchestration_fk_ordering_cancellation_and_receipt_fences_are_immediate() {
    let sandbox = Sandbox::latest(4).await;
    let tenant_id = Uuid::new_v4();
    community(&sandbox.pool, tenant_id, "orchestration").await;
    let first = WorkforceSeed {
        request_id: Uuid::new_v4(),
        task_id: Uuid::new_v4(),
        identity_id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
    };
    workforce(&sandbox.pool, tenant_id, &first, 100).await;
    let second_task = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO snowman_work_tasks \
         (community_id,task_id,request_id,specialist_role,service_identity_id,required_capabilities,\
          model_gateway_route,model_id,execution_snapshot_sha256,risk_tier,reversible,approval_required,\
          status,deadline_at,max_cost_microusd) \
         SELECT community_id,$1,request_id,specialist_role,service_identity_id,required_capabilities,\
          model_gateway_route,model_id,$2,risk_tier,reversible,approval_required,status,deadline_at,40 \
         FROM snowman_work_tasks WHERE community_id=$3 AND task_id=$4",
    )
    .bind(second_task)
    .bind(digest(111))
    .bind(tenant_id)
    .bind(first.task_id)
    .execute(&sandbox.pool)
    .await
    .expect("insert dependent workforce task");
    sqlx::query(
        "INSERT INTO snowman_model_routes \
         (community_id,model_id,gateway_url,suited_roles,allowed_classifications,quality_score,\
          latency_score,max_cost_microusd_per_million_tokens,max_context_tokens,\
          evaluation_evidence_sha256,status,evaluated_at) \
         VALUES ($1,'snowman-proof','https://models.snowmanai.org/',ARRAY['governed_analyst'],\
          ARRAY['confidential'],900,900,1000,10000,$2,'active',NOW())",
    )
    .bind(tenant_id)
    .bind(digest(112))
    .execute(&sandbox.pool)
    .await
    .expect("insert model route");
    let plan_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO snowman_orchestration_plans \
         (community_id,workspace_id,plan_id,request_id,work_kind,generation,objective_sha256,\
          classification,plan_sha256,max_cost_microusd,automatic_execution_enabled,\
          minimum_confidence_basis_points,minimum_value_basis_points,maximum_risk_basis_points,\
          max_automatic_task_cost_microusd,deadline_at,state,activated_at) \
         VALUES ($1,$2,$3,$4,'user_request',1,$5,'confidential',$6,100,TRUE,8000,8000,1000,50,\
          NOW()+INTERVAL '40 minutes','active',NOW())",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(plan_id)
    .bind(first.request_id)
    .bind(digest(113))
    .bind(digest(114))
    .execute(&sandbox.pool)
    .await
    .expect("create active plan");
    let persona_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO snowman_orchestration_personas \
         (community_id,plan_id,persona_id,persona_version_sha256,service_identity_id,specialist_role,\
          model_id,model_route_revision,maximum_classification,max_cost_microusd,enabled,model_route_reference) \
         VALUES ($1,$2,$3,$4,$5,'governed_analyst','snowman-proof',1,'confidential',100,TRUE,$6)",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .bind(persona_id)
    .bind(digest(115))
    .bind(first.identity_id)
    .bind(format!("snowman:model-route:{}:revision:1", Uuid::new_v4()))
    .execute(&sandbox.pool)
    .await
    .expect("insert orchestration persona");
    for task_id in [first.task_id, second_task] {
        sqlx::query(
            "INSERT INTO snowman_orchestration_tasks \
             (community_id,plan_id,plan_generation,request_id,task_id,persona_id,usefulness_sha256,\
              confidence_basis_points,value_basis_points,risk_basis_points,reversible,approval_required,\
              automatic_execution_candidate,max_cost_microusd,deadline_at) \
             VALUES ($1,$2,1,$3,$4,$5,$6,9000,9000,100,TRUE,FALSE,TRUE,40,NOW()+INTERVAL '30 minutes')",
        )
        .bind(tenant_id)
        .bind(plan_id)
        .bind(first.request_id)
        .bind(task_id)
        .bind(persona_id)
        .bind(digest(116))
        .execute(&sandbox.pool)
        .await
        .expect("insert orchestration task before dependency");
    }
    sqlx::query(
        "INSERT INTO snowman_orchestration_task_dependencies \
         (community_id,plan_id,plan_generation,task_id,depends_on_task_id) VALUES ($1,$2,1,$3,$4)",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .bind(second_task)
    .bind(first.task_id)
    .execute(&sandbox.pool)
    .await
    .expect("dependency FK accepts only after both tasks exist");
    let foreign_dependency = sqlx::query(
        "INSERT INTO snowman_orchestration_task_dependencies \
         (community_id,plan_id,plan_generation,task_id,depends_on_task_id) VALUES ($1,$2,1,$3,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(plan_id)
    .bind(second_task)
    .bind(first.task_id)
    .execute(&sandbox.pool)
    .await;
    assert!(foreign_dependency.is_err());

    let occurrence_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO snowman_orchestration_occurrences \
         (community_id,workspace_id,plan_id,plan_generation,occurrence_id,scheduled_at,status) \
         VALUES ($1,$2,$3,1,$4,NOW(),'materialized')",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(plan_id)
    .bind(occurrence_id)
    .execute(&sandbox.pool)
    .await
    .expect("materialize occurrence");
    let dispatch_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO snowman_orchestration_dispatches \
         (community_id,workspace_id,dispatch_id,plan_id,plan_generation,task_id,occurrence_id,\
          lease_generation,execution_snapshot_sha256,coordinator_job_reference,model_route_reference,\
          analyst_context_references,required_capabilities,reserved_cost_microusd,status,\
          lease_owner_identity_id,lease_expires_at) \
         VALUES ($1,$2,$3,$4,1,$5,$6,1,$7,$8,$9,ARRAY[$10],ARRAY['artifact.create'],40,\
          'leased',$11,NOW()+INTERVAL '10 minutes')",
    )
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(dispatch_id)
    .bind(plan_id)
    .bind(first.task_id)
    .bind(occurrence_id)
    .bind(digest(120))
    .bind(format!("snowman:agent-job:{}:generation:1", first.job_id))
    .bind(format!("snowman:model-route:{}:revision:1", Uuid::new_v4()))
    .bind(format!("analyst360:sha256:{}", hex::encode(digest(121))))
    .bind(first.identity_id)
    .execute(&sandbox.pool)
    .await
    .expect("insert leased dispatch");

    let mut cancel = sandbox.pool.begin().await.expect("begin cancellation");
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *cancel)
        .await
        .expect("set serializable cancellation");
    sqlx::query(
        "UPDATE snowman_orchestration_plans SET state='cancelled',automatic_execution_enabled=FALSE,\
         cancelled_at=NOW(),updated_at=NOW() WHERE community_id=$1 AND plan_id=$2 AND generation=1",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .execute(&mut *cancel)
    .await
    .expect("cancel plan");
    sqlx::query(
        "UPDATE snowman_orchestration_dispatches SET status='cancelled',\
         cancellation_generation=cancellation_generation+1,lease_owner_identity_id=NULL,lease_expires_at=NULL,updated_at=NOW() \
         WHERE community_id=$1 AND plan_id=$2 AND plan_generation=1 \
           AND status IN ('pending','leased','failed','submitted')",
    )
    .bind(tenant_id)
    .bind(plan_id)
    .execute(&mut *cancel)
    .await
    .expect("fence dispatches");
    cancel.commit().await.expect("commit cancellation fence");

    let stale_submit = sqlx::query(
        "UPDATE snowman_orchestration_dispatches SET status='submitted',submitted_at=NOW() \
         WHERE community_id=$1 AND dispatch_id=$2 AND status='leased' \
           AND lease_generation=1 AND cancellation_generation=0",
    )
    .bind(tenant_id)
    .bind(dispatch_id)
    .execute(&sandbox.pool)
    .await
    .expect("attempt stale delivery");
    assert_eq!(stale_submit.rows_affected(), 0);
    let stale_receipt = sqlx::query(
        "INSERT INTO snowman_orchestration_terminal_receipts \
         (community_id,workspace_id,dispatch_id,occurrence_id,plan_id,plan_generation,task_id,\
          lease_generation,cancellation_generation,execution_snapshot_sha256,outcome,\
          handoff_manifest_reference,handoff_manifest_sha256,artifact_references,evidence_references,\
          execution_receipt_references,actual_cost_microusd,receipt_sha256,completed_at) \
         SELECT community_id,workspace_id,dispatch_id,occurrence_id,plan_id,plan_generation,task_id,\
          lease_generation,0,execution_snapshot_sha256,'succeeded',$3,$4,ARRAY[$5],ARRAY[$6],ARRAY[$7],10,$8,NOW() \
         FROM snowman_orchestration_dispatches WHERE community_id=$1 AND dispatch_id=$2 \
           AND cancellation_generation=0 AND status='submitted'",
    )
    .bind(tenant_id)
    .bind(dispatch_id)
    .bind(format!("analyst360:sha256:{}", hex::encode(digest(122))))
    .bind(digest(122))
    .bind(format!("analyst360:sha256:{}", hex::encode(digest(123))))
    .bind(format!("analyst360:sha256:{}", hex::encode(digest(124))))
    .bind(format!("snowman:agent-job:{}:generation:1", first.job_id))
    .bind(digest(125))
    .execute(&sandbox.pool)
    .await
    .expect("attempt stale terminal receipt");
    assert_eq!(stale_receipt.rows_affected(), 0);
    sandbox.finish().await;
}

#[tokio::test]
#[ignore = "requires PostgreSQL role administration and CREATE SCHEMA"]
async fn checkpoint_tables_are_trigger_and_role_enforced_append_only() {
    let sandbox = Sandbox::latest(2).await;
    let tenant_id = Uuid::new_v4();
    community(&sandbox.pool, tenant_id, "audit").await;
    sqlx::query(
        "INSERT INTO snowman_audit_checkpoint_requests \
         (community_id,sequence,chain_root_sha256,signed_at,build_sha256,database_schema_sha256,signing_key_arn) \
         VALUES ($1,1,$2,'2026-07-27T12:00:00.000000Z',$3,$4,\
          'arn:aws:kms:us-west-2:123456789012:key/proof')",
    )
    .bind(tenant_id)
    .bind(digest(130))
    .bind(digest(131))
    .bind(digest(132))
    .execute(&sandbox.pool)
    .await
    .expect("insert checkpoint request");
    sqlx::query(
        "INSERT INTO snowman_audit_checkpoint_publications \
         (community_id,sequence,checkpoint_sha256,object_key,object_version_id,kms_key_arn,signed_at) \
         VALUES ($1,1,$2,$3,'proof-version','arn:aws:kms:us-west-2:123456789012:key/proof',\
          '2026-07-27T12:00:00.000000Z')",
    )
    .bind(tenant_id)
    .bind(digest(133))
    .bind(format!(
        "checkpoints/{tenant_id}/{:020}-{}.json",
        1,
        hex::encode(digest(133))
    ))
    .execute(&sandbox.pool)
    .await
    .expect("insert checkpoint publication");
    assert!(sqlx::query(
        "UPDATE snowman_audit_checkpoint_requests SET requested_at=NOW() \
         WHERE community_id=$1 AND sequence=1",
    )
    .bind(tenant_id)
    .execute(&sandbox.pool)
    .await
    .is_err());
    assert!(sqlx::query(
        "DELETE FROM snowman_audit_checkpoint_publications WHERE community_id=$1 AND sequence=1",
    )
    .bind(tenant_id)
    .execute(&sandbox.pool)
    .await
    .is_err());

    let role = format!("snowman_proof_{}", Uuid::new_v4().simple());
    let role_sql = format!(
        "CREATE ROLE {role} NOLOGIN NOINHERIT; \
         GRANT USAGE ON SCHEMA {schema} TO {role}; \
         GRANT SELECT,INSERT ON TABLE {schema}.snowman_audit_checkpoint_requests,\
          {schema}.snowman_audit_checkpoint_publications TO {role}",
        schema = sandbox.schema
    );
    sqlx::raw_sql(AssertSqlSafe(role_sql))
        .execute(&sandbox.pool)
        .await
        .expect("create exact checkpoint proof role");
    let mut role_tx = sandbox.pool.begin().await.expect("begin role probe");
    sqlx::query(AssertSqlSafe(format!("SET LOCAL ROLE {role}")))
        .execute(&mut *role_tx)
        .await
        .expect("assume checkpoint proof role");
    let can_read: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM snowman_audit_checkpoint_requests WHERE community_id=$1",
    )
    .bind(tenant_id)
    .fetch_one(&mut *role_tx)
    .await
    .expect("checkpoint role reads exact ledger");
    assert_eq!(can_read, 1);
    let update_denied = sqlx::query(
        "UPDATE snowman_audit_checkpoint_requests SET requested_at=NOW() \
         WHERE community_id=$1 AND sequence=1",
    )
    .bind(tenant_id)
    .execute(&mut *role_tx)
    .await
    .is_err();
    role_tx.rollback().await.expect("finish role probe");

    let mut event_probe = sandbox.pool.begin().await.expect("begin event probe");
    sqlx::query(AssertSqlSafe(format!("SET LOCAL ROLE {role}")))
        .execute(&mut *event_probe)
        .await
        .expect("assume role for event denial");
    let event_denied = sqlx::query("SELECT count(*) FROM events")
        .fetch_one(&mut *event_probe)
        .await
        .is_err();
    event_probe.rollback().await.expect("finish event probe");

    sqlx::raw_sql(AssertSqlSafe(format!("DROP ROLE {role}")))
        .execute(&sandbox.pool)
        .await
        .expect("drop checkpoint proof role");
    assert!(update_denied, "checkpoint role must not update evidence");
    assert!(
        event_denied,
        "checkpoint role must not read collaboration events"
    );
    sandbox.finish().await;
}
