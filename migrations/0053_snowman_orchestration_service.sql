-- Private, metadata-only transactional state for the Snowman orchestration
-- service and timezone-aware scheduler. Raw objectives, prompts, mail,
-- transcripts, client rows, provider endpoints, and credentials are excluded.

CREATE TABLE snowman_orchestration_callers (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    service_identity_id UUID NOT NULL,
    service_principal TEXT NOT NULL CHECK (
        service_principal ~ '^snowman:[a-z0-9][a-z0-9._-]{2,127}$'
    ),
    policy_generation BIGINT NOT NULL CHECK (policy_generation > 0),
    status TEXT NOT NULL DEFAULT 'disabled' CHECK (status IN ('disabled','active','revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, workspace_id, service_identity_id),
    UNIQUE (community_id, workspace_id, service_principal),
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id)
);

CREATE TABLE snowman_orchestration_auth_events (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    auth_event_id BYTEA NOT NULL CHECK (octet_length(auth_event_id) = 32),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    requester_pubkey BYTEA NOT NULL CHECK (octet_length(requester_pubkey) = 32),
    service_identity_id UUID NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, auth_event_id),
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (expires_at > observed_at)
);

CREATE TABLE snowman_orchestration_commands (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    command_id UUID NOT NULL,
    command_kind TEXT NOT NULL CHECK (
        command_kind IN ('create_plan','activate_plan','pause_plan','cancel_plan','supersede_plan')
    ),
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    command_sha256 BYTEA NOT NULL CHECK (octet_length(command_sha256) = 32),
    service_identity_id UUID NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('applied','duplicate')),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, command_id),
    FOREIGN KEY (community_id, plan_id, plan_generation)
        REFERENCES snowman_orchestration_plans(community_id, plan_id, generation),
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id)
);

CREATE TABLE snowman_orchestration_plan_automatic_capabilities (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    capability TEXT NOT NULL CHECK (
        length(capability) BETWEEN 3 AND 128 AND
        capability ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$' AND
        capability NOT LIKE '%.all' AND capability NOT LIKE '%*%' AND
        capability NOT IN ('shell.execute','network.unrestricted','filesystem.unrestricted')
    ),
    PRIMARY KEY (community_id, plan_id, capability),
    FOREIGN KEY (community_id, plan_id)
        REFERENCES snowman_orchestration_plans(community_id, plan_id) ON DELETE CASCADE
);

ALTER TABLE snowman_orchestration_personas
    ADD COLUMN model_route_reference TEXT CHECK (
        model_route_reference IS NULL OR
        model_route_reference ~ '^snowman:model-route:[0-9a-f-]{36}:revision:[1-9][0-9]*$'
    );

CREATE TABLE snowman_orchestration_task_dependencies (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    task_id UUID NOT NULL,
    depends_on_task_id UUID NOT NULL,
    PRIMARY KEY (community_id, plan_id, plan_generation, task_id, depends_on_task_id),
    FOREIGN KEY (community_id, plan_id, plan_generation, task_id)
        REFERENCES snowman_orchestration_tasks(community_id, plan_id, plan_generation, task_id)
        ON DELETE CASCADE,
    FOREIGN KEY (community_id, plan_id, plan_generation, depends_on_task_id)
        REFERENCES snowman_orchestration_tasks(community_id, plan_id, plan_generation, task_id)
        ON DELETE CASCADE,
    CHECK (task_id <> depends_on_task_id)
);

CREATE TABLE snowman_orchestration_recurrences (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    schedule_generation BIGINT NOT NULL CHECK (schedule_generation > 0),
    local_minute INTEGER NOT NULL CHECK (local_minute BETWEEN 0 AND 1439),
    weekdays SMALLINT[] NOT NULL CHECK (
        cardinality(weekdays) BETWEEN 1 AND 7 AND weekdays <@ ARRAY[1,2,3,4,5,6,7]::SMALLINT[]
    ),
    dst_gap_policy TEXT NOT NULL CHECK (dst_gap_policy IN ('skip','shift_forward')),
    dst_fold_policy TEXT NOT NULL CHECK (dst_fold_policy IN ('first','second')),
    catch_up_policy TEXT NOT NULL CHECK (catch_up_policy IN ('skip','one')),
    max_catch_up_seconds INTEGER NOT NULL CHECK (max_catch_up_seconds BETWEEN 0 AND 86400),
    next_fire_at TIMESTAMPTZ,
    last_fire_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    schedule_sha256 BYTEA NOT NULL CHECK (octet_length(schedule_sha256) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, plan_id),
    UNIQUE (community_id, plan_id, schedule_generation),
    FOREIGN KEY (community_id, plan_id)
        REFERENCES snowman_orchestration_plans(community_id, plan_id) ON DELETE CASCADE,
    CHECK (last_fire_at IS NULL OR next_fire_at IS NULL OR last_fire_at < next_fire_at)
);

CREATE INDEX idx_snowman_orchestration_recurrences_due
    ON snowman_orchestration_recurrences (next_fire_at, community_id, plan_id)
    WHERE enabled AND next_fire_at IS NOT NULL;

CREATE TABLE snowman_orchestration_dispatches (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    dispatch_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    task_id UUID NOT NULL,
    occurrence_id UUID NOT NULL,
    schedule_generation BIGINT,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    execution_snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(execution_snapshot_sha256) = 32),
    coordinator_job_reference TEXT NOT NULL CHECK (
        coordinator_job_reference ~ '^snowman:agent-job:[0-9a-f-]{36}:generation:[1-9][0-9]*$'
    ),
    model_route_reference TEXT NOT NULL CHECK (
        model_route_reference ~ '^snowman:model-route:[0-9a-f-]{36}:revision:[1-9][0-9]*$'
    ),
    analyst_context_references TEXT[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(analyst_context_references) BETWEEN 1 AND 128
    ),
    required_capabilities TEXT[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(required_capabilities) BETWEEN 1 AND 32
    ),
    reserved_cost_microusd BIGINT NOT NULL CHECK (reserved_cost_microusd >= 0),
    status TEXT NOT NULL CHECK (
        status IN ('pending','leased','submitted','succeeded','failed','cancelled','dead_letter')
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 20),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
    lease_owner_identity_id UUID,
    lease_expires_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cancellation_generation BIGINT NOT NULL DEFAULT 0 CHECK (cancellation_generation >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, dispatch_id),
    UNIQUE (community_id, plan_id, plan_generation, task_id, occurrence_id),
    FOREIGN KEY (community_id, plan_id, plan_generation, task_id)
        REFERENCES snowman_orchestration_tasks(community_id, plan_id, plan_generation, task_id)
        ON DELETE CASCADE,
    FOREIGN KEY (community_id, lease_owner_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK ((status = 'leased') = (lease_owner_identity_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK (lease_expires_at IS NULL OR lease_expires_at > created_at)
);

CREATE INDEX idx_snowman_orchestration_dispatches_claim
    ON snowman_orchestration_dispatches (next_attempt_at, community_id, dispatch_id)
    WHERE status IN ('pending','failed');

CREATE TABLE snowman_orchestration_dispatch_receipts (
    community_id UUID NOT NULL,
    dispatch_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    receipt_kind TEXT NOT NULL CHECK (
        receipt_kind IN ('coordinator','model','tool','analyst_handoff')
    ),
    immutable_reference TEXT NOT NULL,
    receipt_sha256 BYTEA NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    actual_cost_microusd BIGINT NOT NULL DEFAULT 0 CHECK (actual_cost_microusd >= 0),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, dispatch_id, lease_generation, receipt_kind, immutable_reference),
    FOREIGN KEY (community_id, dispatch_id)
        REFERENCES snowman_orchestration_dispatches(community_id, dispatch_id) ON DELETE CASCADE,
    CHECK (
        (receipt_kind = 'analyst_handoff' AND immutable_reference ~ '^analyst360:sha256:[0-9a-f]{64}$') OR
        (receipt_kind = 'coordinator' AND immutable_reference ~ '^snowman:agent-job:[0-9a-f-]{36}:generation:[1-9][0-9]*$') OR
        (receipt_kind = 'model' AND immutable_reference ~ '^snowman:model-generation:[0-9a-f-]{36}:generation:[1-9][0-9]*$') OR
        (receipt_kind = 'tool' AND immutable_reference ~ '^snowman:tool-action:[0-9a-f-]{36}:generation:[1-9][0-9]*$')
    )
);

CREATE TABLE snowman_orchestration_dead_letters (
    community_id UUID NOT NULL,
    dead_letter_id UUID NOT NULL,
    dispatch_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL,
    task_id UUID NOT NULL,
    failure_class TEXT NOT NULL CHECK (
        failure_class IN ('authority_lost','budget_exhausted','deadline_expired','delivery_failed','receipt_conflict')
    ),
    failure_sha256 BYTEA NOT NULL CHECK (octet_length(failure_sha256) = 32),
    operator_action TEXT NOT NULL DEFAULT 'review' CHECK (operator_action IN ('review','cancel','retry')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, dead_letter_id),
    UNIQUE (community_id, dispatch_id),
    FOREIGN KEY (community_id, dispatch_id)
        REFERENCES snowman_orchestration_dispatches(community_id, dispatch_id) ON DELETE CASCADE
);

CREATE TABLE snowman_orchestration_reminder_receipts (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL,
    reminder_offset_seconds INTEGER NOT NULL CHECK (reminder_offset_seconds BETWEEN 60 AND 2592000),
    occurrence_id UUID NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    delivered_at TIMESTAMPTZ,
    delivery_receipt_sha256 BYTEA CHECK (
        delivery_receipt_sha256 IS NULL OR octet_length(delivery_receipt_sha256) = 32
    ),
    status TEXT NOT NULL CHECK (status IN ('pending','delivered','cancelled','expired')),
    PRIMARY KEY (community_id, plan_id, plan_generation, reminder_offset_seconds),
    FOREIGN KEY (community_id, plan_id, plan_generation)
        REFERENCES snowman_orchestration_plans(community_id, plan_id, generation) ON DELETE CASCADE
);
