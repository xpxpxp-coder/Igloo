-- Purpose-bound one-shot agent jobs. The snapshot is a minimized Snowman
-- coordination projection, never a raw Analyst dataset or provider payload.

CREATE TABLE snowman_agent_jobs (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    job_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    service_identity_id UUID NOT NULL,
    runtime_id TEXT NOT NULL CHECK (
        length(runtime_id) BETWEEN 1 AND 64 AND
        runtime_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 256),
    classification TEXT NOT NULL CHECK (
        classification IN ('internal','confidential','restricted')
    ),
    capability_grants TEXT[] NOT NULL CHECK (cardinality(capability_grants) <= 64),
    max_input_tokens BIGINT NOT NULL CHECK (max_input_tokens BETWEEN 1 AND 10000000),
    max_output_tokens BIGINT NOT NULL CHECK (max_output_tokens BETWEEN 1 AND 1000000),
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd BETWEEN 0 AND 1000000000),
    snapshot_body BYTEA NOT NULL CHECK (
        octet_length(snapshot_body) BETWEEN 1 AND 786432
    ),
    snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(snapshot_sha256) = 32),
    job_token_sha256 BYTEA NOT NULL CHECK (octet_length(job_token_sha256) = 32),
    status TEXT NOT NULL CHECK (status IN (
        'issued','started','succeeded','failed','cancelled','expired'
    )),
    issued_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    deadline_at TIMESTAMPTZ NOT NULL,
    token_revoked_at TIMESTAMPTZ,
    started_receipt_body BYTEA CHECK (
        started_receipt_body IS NULL OR octet_length(started_receipt_body) BETWEEN 1 AND 65536
    ),
    started_receipt_sha256 BYTEA CHECK (
        started_receipt_sha256 IS NULL OR octet_length(started_receipt_sha256) = 32
    ),
    result_receipt_body BYTEA CHECK (
        result_receipt_body IS NULL OR octet_length(result_receipt_body) BETWEEN 1 AND 1114112
    ),
    result_receipt_sha256 BYTEA CHECK (
        result_receipt_sha256 IS NULL OR octet_length(result_receipt_sha256) = 32
    ),
    purge_after TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, job_id),
    UNIQUE (community_id, task_id, generation),
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (deadline_at > issued_at),
    CHECK (purge_after > deadline_at),
    CHECK ((started_at IS NULL) = (started_receipt_sha256 IS NULL)),
    CHECK ((started_receipt_body IS NULL) = (started_receipt_sha256 IS NULL)),
    CHECK ((completed_at IS NULL) = (result_receipt_sha256 IS NULL)),
    CHECK ((result_receipt_body IS NULL) = (result_receipt_sha256 IS NULL))
);

CREATE INDEX idx_snowman_agent_jobs_active
    ON snowman_agent_jobs (community_id, status, deadline_at)
    WHERE status IN ('issued','started');

CREATE INDEX idx_snowman_agent_jobs_purge
    ON snowman_agent_jobs (purge_after, community_id, job_id);
