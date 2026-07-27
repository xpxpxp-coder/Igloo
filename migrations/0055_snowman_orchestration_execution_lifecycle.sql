-- Occurrence-scoped execution lifecycle for Snowman specialist orchestration.
-- This remains metadata-only: immutable Analyst references and SHA-256 digests
-- are allowed; raw prompts, mail, transcripts, client rows, provider endpoints,
-- credentials, and arbitrary tool input are not represented.

CREATE TABLE snowman_orchestration_task_required_capabilities (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    task_id UUID NOT NULL,
    capability TEXT NOT NULL CHECK (
        length(capability) BETWEEN 3 AND 128 AND
        capability ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$' AND
        capability NOT LIKE '%.all' AND capability NOT LIKE '%*%' AND
        capability NOT IN ('shell.execute','network.unrestricted','filesystem.unrestricted')
    ),
    PRIMARY KEY (community_id, plan_id, plan_generation, task_id, capability),
    FOREIGN KEY (community_id, plan_id, plan_generation, task_id)
        REFERENCES snowman_orchestration_tasks(community_id, plan_id, plan_generation, task_id)
        ON DELETE CASCADE
);

CREATE TABLE snowman_orchestration_task_artifact_contracts (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    task_id UUID NOT NULL,
    artifact_type TEXT NOT NULL CHECK (
        length(artifact_type) BETWEEN 1 AND 128 AND
        artifact_type ~ '^[a-z0-9][a-z0-9._-]*$'
    ),
    PRIMARY KEY (community_id, plan_id, plan_generation, task_id, artifact_type),
    FOREIGN KEY (community_id, plan_id, plan_generation, task_id)
        REFERENCES snowman_orchestration_tasks(community_id, plan_id, plan_generation, task_id)
        ON DELETE CASCADE
);

CREATE TABLE snowman_orchestration_occurrences (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    occurrence_id UUID NOT NULL,
    schedule_generation BIGINT,
    scheduled_at TIMESTAMPTZ NOT NULL,
    catch_up BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL CHECK (
        status IN ('materialized','skipped','completed','failed','cancelled')
    ),
    progress_sha256 BYTEA CHECK (progress_sha256 IS NULL OR octet_length(progress_sha256) = 32),
    accounted_cost_microusd BIGINT NOT NULL DEFAULT 0 CHECK (accounted_cost_microusd >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, occurrence_id),
    UNIQUE (community_id, plan_id, plan_generation, schedule_generation, scheduled_at),
    FOREIGN KEY (community_id, plan_id, plan_generation)
        REFERENCES snowman_orchestration_plans(community_id, plan_id, generation)
        ON DELETE CASCADE
);

CREATE INDEX idx_snowman_orchestration_occurrences_plan
    ON snowman_orchestration_occurrences (
        community_id, workspace_id, plan_id, plan_generation, scheduled_at
    );

ALTER TABLE snowman_orchestration_reminder_receipts
    DROP CONSTRAINT snowman_orchestration_reminder_receipts_pkey,
    ADD PRIMARY KEY (
        community_id, plan_id, plan_generation, occurrence_id, reminder_offset_seconds
    ),
    ADD FOREIGN KEY (community_id, occurrence_id)
        REFERENCES snowman_orchestration_occurrences(community_id, occurrence_id)
        ON DELETE CASCADE;

ALTER TABLE snowman_orchestration_dispatches
    ADD COLUMN submitted_at TIMESTAMPTZ,
    ADD COLUMN terminal_at TIMESTAMPTZ,
    ADD COLUMN terminal_outcome TEXT CHECK (
        terminal_outcome IS NULL OR terminal_outcome IN ('succeeded','blocked','failed','cancelled')
    ),
    ADD COLUMN last_failure_sha256 BYTEA CHECK (
        last_failure_sha256 IS NULL OR octet_length(last_failure_sha256) = 32
    );

ALTER TABLE snowman_orchestration_dispatches
    ADD FOREIGN KEY (community_id, occurrence_id)
        REFERENCES snowman_orchestration_occurrences(community_id, occurrence_id)
        ON DELETE CASCADE,
    ADD CHECK ((terminal_at IS NULL) = (terminal_outcome IS NULL));

CREATE TABLE snowman_orchestration_delivery_attempts (
    community_id UUID NOT NULL,
    dispatch_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    cancellation_generation BIGINT NOT NULL CHECK (cancellation_generation >= 0),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('submitted','retryable_failure','dead_letter')),
    coordinator_receipt_reference TEXT CHECK (
        coordinator_receipt_reference IS NULL OR
        coordinator_receipt_reference ~ '^snowman:agent-job:[0-9a-f-]{36}:generation:[1-9][0-9]*$'
    ),
    response_sha256 BYTEA CHECK (response_sha256 IS NULL OR octet_length(response_sha256) = 32),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, dispatch_id, lease_generation),
    FOREIGN KEY (community_id, dispatch_id)
        REFERENCES snowman_orchestration_dispatches(community_id, dispatch_id) ON DELETE CASCADE,
    CHECK (
        (outcome = 'submitted') =
        (coordinator_receipt_reference IS NOT NULL AND response_sha256 IS NOT NULL)
    )
);

CREATE TABLE snowman_orchestration_terminal_receipts (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    dispatch_id UUID NOT NULL,
    occurrence_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    task_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    cancellation_generation BIGINT NOT NULL CHECK (cancellation_generation >= 0),
    execution_snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(execution_snapshot_sha256) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','blocked','failed','cancelled')),
    handoff_manifest_reference TEXT NOT NULL CHECK (
        handoff_manifest_reference ~ '^analyst360:sha256:[0-9a-f]{64}$'
    ),
    handoff_manifest_sha256 BYTEA NOT NULL CHECK (octet_length(handoff_manifest_sha256) = 32),
    artifact_references TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(artifact_references) <= 128),
    evidence_references TEXT[] NOT NULL DEFAULT '{}' CHECK (cardinality(evidence_references) <= 128),
    execution_receipt_references TEXT[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(execution_receipt_references) BETWEEN 1 AND 128
    ),
    actual_cost_microusd BIGINT NOT NULL CHECK (actual_cost_microusd >= 0),
    receipt_sha256 BYTEA NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    completed_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, dispatch_id),
    UNIQUE (community_id, occurrence_id, task_id),
    FOREIGN KEY (community_id, dispatch_id)
        REFERENCES snowman_orchestration_dispatches(community_id, dispatch_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, occurrence_id)
        REFERENCES snowman_orchestration_occurrences(community_id, occurrence_id) ON DELETE CASCADE,
    CHECK (
        outcome <> 'succeeded' OR
        (cardinality(artifact_references) > 0 AND cardinality(evidence_references) > 0)
    ),
    CHECK (completed_at <= accepted_at + INTERVAL '5 minutes')
);

CREATE TABLE snowman_orchestration_progress_digests (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    occurrence_id UUID NOT NULL,
    progress_sha256 BYTEA NOT NULL CHECK (octet_length(progress_sha256) = 32),
    completed_task_ids UUID[] NOT NULL DEFAULT '{}',
    next_ready_task_ids UUID[] NOT NULL DEFAULT '{}',
    accounted_cost_microusd BIGINT NOT NULL CHECK (accounted_cost_microusd >= 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, occurrence_id, revision),
    FOREIGN KEY (community_id, occurrence_id)
        REFERENCES snowman_orchestration_occurrences(community_id, occurrence_id) ON DELETE CASCADE
);

CREATE TABLE snowman_orchestration_control_outbox (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    outbox_id UUID NOT NULL,
    command_kind TEXT NOT NULL CHECK (command_kind IN ('cancel_dispatch','deliver_reminder')),
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    dispatch_id UUID,
    occurrence_id UUID NOT NULL,
    command_sha256 BYTEA NOT NULL CHECK (octet_length(command_sha256) = 32),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (
        status IN ('pending','leased','delivered','dead_letter','cancelled')
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 20),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_owner_identity_id UUID,
    lease_expires_at TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, outbox_id),
    UNIQUE NULLS NOT DISTINCT (
        community_id, command_kind, plan_id, plan_generation, dispatch_id, occurrence_id
    ),
    FOREIGN KEY (community_id, plan_id, plan_generation)
        REFERENCES snowman_orchestration_plans(community_id, plan_id, generation)
        ON DELETE CASCADE,
    FOREIGN KEY (community_id, dispatch_id)
        REFERENCES snowman_orchestration_dispatches(community_id, dispatch_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, occurrence_id)
        REFERENCES snowman_orchestration_occurrences(community_id, occurrence_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, lease_owner_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK ((status = 'leased') = (lease_owner_identity_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((command_kind = 'cancel_dispatch') = (dispatch_id IS NOT NULL))
);

CREATE INDEX idx_snowman_orchestration_control_outbox_claim
    ON snowman_orchestration_control_outbox (next_attempt_at, community_id, outbox_id)
    WHERE status IN ('pending','leased');
