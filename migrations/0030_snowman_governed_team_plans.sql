-- Durable model catalog and governed specialist-plan expansion. Planner output
-- cannot directly select external endpoints or bypass tenant service identities.

ALTER TABLE snowman_work_requests
    ADD COLUMN client_ready_delivery BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE snowman_work_tasks
    ADD COLUMN max_cost_microusd BIGINT NOT NULL DEFAULT 0 CHECK (max_cost_microusd >= 0),
    ADD COLUMN expected_input_tokens BIGINT NOT NULL DEFAULT 0 CHECK (expected_input_tokens >= 0),
    ADD COLUMN max_output_tokens BIGINT NOT NULL DEFAULT 0 CHECK (max_output_tokens >= 0);

CREATE TABLE snowman_model_routes (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 256),
    gateway_url TEXT NOT NULL CHECK (
        length(gateway_url) BETWEEN 1 AND 2048 AND
        gateway_url = lower(gateway_url) AND
        gateway_url ~ '^https://([a-z0-9-]+\.)*snowmanai\.org(:443)?(/|$)' AND
        gateway_url !~ '[?#@]'
    ),
    suited_roles TEXT[] NOT NULL CHECK (
        cardinality(suited_roles) BETWEEN 1 AND 16 AND
        suited_roles <@ ARRAY[
            'lead','client_delivery','research_evidence','governed_analyst',
            'quality_risk_reviewer','deadline_operations'
        ]::TEXT[]
    ),
    allowed_classifications TEXT[] NOT NULL CHECK (
        cardinality(allowed_classifications) BETWEEN 1 AND 3 AND
        allowed_classifications <@ ARRAY['internal','confidential','restricted']::TEXT[]
    ),
    quality_score INTEGER NOT NULL CHECK (quality_score BETWEEN 0 AND 1000),
    latency_score INTEGER NOT NULL CHECK (latency_score BETWEEN 0 AND 1000),
    max_cost_microusd_per_million_tokens BIGINT NOT NULL CHECK (
        max_cost_microusd_per_million_tokens >= 0
    ),
    max_context_tokens BIGINT NOT NULL CHECK (max_context_tokens BETWEEN 1 AND 10000000),
    evaluation_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(evaluation_evidence_sha256) = 32
    ),
    status TEXT NOT NULL CHECK (status IN ('active','suspended','retired')),
    evaluated_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, model_id)
);

CREATE INDEX idx_snowman_model_routes_active
    ON snowman_model_routes (community_id, status, model_id)
    WHERE status = 'active';

CREATE TABLE snowman_team_plans (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    request_id UUID NOT NULL,
    lead_task_id UUID NOT NULL,
    plan_sha256 BYTEA NOT NULL CHECK (octet_length(plan_sha256) = 32),
    committed_by_identity_id UUID NOT NULL,
    committed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, plan_id),
    UNIQUE (community_id, request_id),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, lead_task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id),
    FOREIGN KEY (community_id, committed_by_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id)
);

CREATE TABLE snowman_work_task_dependencies (
    community_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    depends_on_task_id UUID NOT NULL,
    PRIMARY KEY (community_id, task_id, depends_on_task_id),
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, depends_on_task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    CHECK (task_id <> depends_on_task_id)
);

CREATE INDEX idx_snowman_work_task_dependencies_ready
    ON snowman_work_task_dependencies (community_id, task_id, depends_on_task_id);

CREATE TABLE snowman_work_task_context_refs (
    community_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    context_reference TEXT NOT NULL CHECK (
        context_reference ~ '^(analyst360|snowman):sha256:[0-9a-f]{64}$'
    ),
    PRIMARY KEY (community_id, task_id, context_reference),
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE
);
