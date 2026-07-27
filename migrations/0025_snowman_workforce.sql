-- Durable, tenant-scoped control-plane state for the Snowman AI Workforce.
-- Client datasets and raw Aptive rows remain in Analyst 360; context here is
-- content-addressed metadata and immutable authority references only.

CREATE TABLE snowman_work_requests (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    idempotency_key_sha256 BYTEA NOT NULL CHECK (octet_length(idempotency_key_sha256) = 32),
    requester_identity TEXT NOT NULL CHECK (length(requester_identity) BETWEEN 1 AND 256),
    objective TEXT NOT NULL CHECK (length(objective) BETWEEN 1 AND 8000),
    objective_sha256 BYTEA NOT NULL CHECK (octet_length(objective_sha256) = 32),
    classification TEXT NOT NULL CHECK (classification IN ('internal', 'confidential', 'restricted')),
    status TEXT NOT NULL CHECK (status IN (
        'requested', 'planned', 'running', 'awaiting_approval', 'reviewing',
        'completed', 'failed', 'cancelled', 'expired'
    )),
    deadline_at TIMESTAMPTZ,
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd >= 0),
    max_input_tokens BIGINT NOT NULL CHECK (max_input_tokens >= 0),
    max_output_tokens BIGINT NOT NULL CHECK (max_output_tokens >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, request_id),
    UNIQUE (community_id, idempotency_key_sha256)
);

CREATE INDEX idx_snowman_work_requests_status
    ON snowman_work_requests (community_id, status, deadline_at, created_at);

CREATE TABLE snowman_context_packets (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    context_packet_id UUID NOT NULL,
    request_id UUID NOT NULL,
    schema_version TEXT NOT NULL CHECK (schema_version = 'snowman.workforce.context.v1'),
    classification TEXT NOT NULL CHECK (classification IN ('internal', 'confidential', 'restricted')),
    authority TEXT NOT NULL CHECK (authority IN ('analyst360', 'snowman-command-center')),
    artifact_id TEXT NOT NULL CHECK (length(artifact_id) BETWEEN 1 AND 512),
    artifact_version TEXT NOT NULL CHECK (length(artifact_version) BETWEEN 1 AND 256),
    content_sha256 BYTEA NOT NULL CHECK (octet_length(content_sha256) = 32),
    size_bytes BIGINT NOT NULL CHECK (size_bytes BETWEEN 0 AND 1048576),
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, context_packet_id),
    UNIQUE (community_id, request_id, context_packet_id),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE
);

CREATE INDEX idx_snowman_context_packets_request
    ON snowman_context_packets (community_id, request_id, created_at);

CREATE TABLE snowman_work_tasks (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    task_id UUID NOT NULL,
    request_id UUID NOT NULL,
    parent_task_id UUID,
    specialist_role TEXT NOT NULL CHECK (length(specialist_role) BETWEEN 1 AND 128),
    service_identity_id UUID NOT NULL,
    assigned_agent_pubkey BYTEA CHECK (
        assigned_agent_pubkey IS NULL OR octet_length(assigned_agent_pubkey) = 32
    ),
    required_capabilities TEXT[] NOT NULL DEFAULT '{}',
    model_gateway_route TEXT NOT NULL CHECK (
        model_gateway_route ~ '^https://([a-z0-9-]+\.)*snowmanai\.org(:443)?(/|$)'
    ),
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 256),
    execution_snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(execution_snapshot_sha256) = 32),
    expected_artifact_contract JSONB NOT NULL DEFAULT '{}'::jsonb,
    context_packet_id UUID,
    risk_tier TEXT NOT NULL CHECK (risk_tier IN ('low', 'moderate', 'high', 'prohibited')),
    reversible BOOLEAN NOT NULL,
    approval_required BOOLEAN NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'queued', 'leased', 'running', 'awaiting_approval', 'reviewing',
        'succeeded', 'failed', 'cancelled', 'expired', 'dead_lettered'
    )),
    priority SMALLINT NOT NULL DEFAULT 50 CHECK (priority BETWEEN 0 AND 100),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deadline_at TIMESTAMPTZ,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, task_id),
    UNIQUE (community_id, request_id, task_id),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, parent_task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id),
    FOREIGN KEY (community_id, request_id, context_packet_id)
        REFERENCES snowman_context_packets(community_id, request_id, context_packet_id)
);

CREATE INDEX idx_snowman_work_tasks_claim
    ON snowman_work_tasks (community_id, status, available_at, priority DESC, created_at)
    WHERE status = 'queued';

CREATE INDEX idx_snowman_work_tasks_request
    ON snowman_work_tasks (community_id, request_id, status, created_at);

CREATE TABLE snowman_work_approvals (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    approval_id UUID NOT NULL,
    task_snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(task_snapshot_sha256) = 32),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'denied', 'revoked')),
    approver_identity TEXT NOT NULL CHECK (length(approver_identity) BETWEEN 1 AND 256),
    rationale_sha256 BYTEA NOT NULL CHECK (octet_length(rationale_sha256) = 32),
    decided_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, approval_id),
    UNIQUE (community_id, request_id, task_id, approval_id),
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    CHECK (expires_at > decided_at)
);

CREATE INDEX idx_snowman_work_approvals_active
    ON snowman_work_approvals (community_id, request_id, task_id, expires_at DESC)
    WHERE decision = 'approved';

CREATE TABLE snowman_task_leases (
    community_id UUID NOT NULL,
    task_id UUID NOT NULL,
    worker_identity_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    lease_token_sha256 BYTEA NOT NULL CHECK (octet_length(lease_token_sha256) = 32),
    leased_at TIMESTAMPTZ NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, task_id),
    FOREIGN KEY (community_id, task_id)
        REFERENCES snowman_work_tasks(community_id, task_id) ON DELETE CASCADE,
    CHECK (heartbeat_at >= leased_at),
    CHECK (expires_at > heartbeat_at)
);

CREATE INDEX idx_snowman_task_leases_expiry
    ON snowman_task_leases (community_id, expires_at);

CREATE TABLE snowman_work_events (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 128),
    actor_identity TEXT NOT NULL CHECK (length(actor_identity) BETWEEN 1 AND 256),
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_event_sha256 BYTEA CHECK (
        previous_event_sha256 IS NULL OR octet_length(previous_event_sha256) = 32
    ),
    event_sha256 BYTEA NOT NULL CHECK (octet_length(event_sha256) = 32),
    occurred_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, event_id),
    UNIQUE (community_id, request_id, sequence),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id)
);

CREATE INDEX idx_snowman_work_events_request
    ON snowman_work_events (community_id, request_id, sequence);

CREATE TABLE snowman_spend_ledger (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    ledger_entry_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 256),
    input_tokens BIGINT NOT NULL CHECK (input_tokens >= 0),
    output_tokens BIGINT NOT NULL CHECK (output_tokens >= 0),
    cost_microusd BIGINT NOT NULL CHECK (cost_microusd >= 0),
    provider_receipt_sha256 BYTEA NOT NULL CHECK (octet_length(provider_receipt_sha256) = 32),
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, ledger_entry_id),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE
);

CREATE INDEX idx_snowman_spend_ledger_request
    ON snowman_spend_ledger (community_id, request_id, recorded_at);
