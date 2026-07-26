-- Human-authorized recurring work is represented as a durable, tenant-bound
-- schedule. A separately scoped trigger service may claim only schedules bound
-- to its identity and convert each occurrence into the governed proactive-task
-- path. No raw client data or free-form instruction body is stored here.

CREATE TABLE snowman_work_schedules (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    schedule_id UUID NOT NULL,
    request_id UUID NOT NULL,
    created_by_identity_id UUID NOT NULL,
    trigger_identity_id UUID NOT NULL,
    executor_identity_id UUID NOT NULL,
    specialist_role TEXT NOT NULL CHECK (length(specialist_role) BETWEEN 1 AND 128),
    capability TEXT NOT NULL CHECK (
        length(capability) BETWEEN 3 AND 128
        AND capability ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$'
        AND capability NOT IN ('admin.all', 'aws.all', 'filesystem.all', 'network.all', 'tool.all')
    ),
    instruction_reference TEXT NOT NULL CHECK (
        instruction_reference ~ '^(analyst360|snowman):sha256:[0-9a-f]{64}$'
    ),
    context_references TEXT[] NOT NULL DEFAULT '{}',
    requested_model_id TEXT CHECK (
        requested_model_id IS NULL OR length(requested_model_id) BETWEEN 1 AND 128
    ),
    expected_input_tokens BIGINT NOT NULL CHECK (expected_input_tokens BETWEEN 1 AND 20000000),
    max_output_tokens BIGINT NOT NULL CHECK (max_output_tokens BETWEEN 1 AND 5000000),
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd BETWEEN 0 AND 500000000),
    expected_artifact_type TEXT NOT NULL CHECK (length(expected_artifact_type) BETWEEN 1 AND 128),
    risk_tier TEXT NOT NULL CHECK (risk_tier IN ('low', 'moderate', 'high')),
    reversible BOOLEAN NOT NULL,
    confidence_basis_points INTEGER NOT NULL CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    usefulness_sha256 BYTEA NOT NULL CHECK (octet_length(usefulness_sha256) = 32),
    cadence_seconds INTEGER NOT NULL CHECK (cadence_seconds BETWEEN 900 AND 2592000),
    next_run_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    max_occurrences INTEGER NOT NULL CHECK (max_occurrences BETWEEN 1 AND 366),
    occurrence_count INTEGER NOT NULL DEFAULT 0 CHECK (occurrence_count BETWEEN 0 AND max_occurrences),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
    schedule_sha256 BYTEA NOT NULL CHECK (octet_length(schedule_sha256) = 32),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','completed','cancelled')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, schedule_id),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, created_by_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    FOREIGN KEY (community_id, trigger_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    FOREIGN KEY (community_id, executor_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (ends_at > next_run_at),
    CHECK (created_at <= next_run_at),
    CHECK (cardinality(context_references) <= 64),
    CHECK (reversible OR risk_tier <> 'low')
);

CREATE INDEX idx_snowman_work_schedules_due
    ON snowman_work_schedules (community_id, trigger_identity_id, next_run_at, schedule_id)
    WHERE status = 'active';

CREATE TABLE snowman_work_schedule_occurrences (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    occurrence_id UUID NOT NULL,
    schedule_id UUID NOT NULL,
    request_id UUID NOT NULL,
    action_id UUID NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL,
    scheduled_for TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    source_event_sha256 BYTEA NOT NULL CHECK (octet_length(source_event_sha256) = 32),
    claim_generation BIGINT NOT NULL DEFAULT 1 CHECK (claim_generation > 0),
    claim_expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'claimed' CHECK (status IN ('claimed','submitted','expired')),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, occurrence_id),
    UNIQUE (community_id, action_id),
    UNIQUE (community_id, schedule_id, due_at),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, schedule_id)
        REFERENCES snowman_work_schedules(community_id, schedule_id) ON DELETE CASCADE,
    CHECK (proposed_at <= scheduled_for),
    CHECK (expires_at > scheduled_for),
    CHECK (claim_expires_at > proposed_at)
);

CREATE INDEX idx_snowman_work_schedule_occurrences_claim
    ON snowman_work_schedule_occurrences (community_id, status, claim_expires_at, occurrence_id)
    WHERE status = 'claimed';
