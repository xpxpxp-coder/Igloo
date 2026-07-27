-- Durable, tenant-scoped reservations for agent model invocations. A
-- reservation is committed before provider dispatch and retained at its
-- worst-case limits whenever the provider outcome is uncertain. This makes a
-- crash or lost response consume authority instead of permitting an
-- unaccounted duplicate invocation.

CREATE TABLE snowman_agent_model_generations (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    generation_id UUID NOT NULL,
    job_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 256),
    capability TEXT NOT NULL CHECK (length(capability) BETWEEN 1 AND 128),
    requested_input_tokens BIGINT NOT NULL CHECK (
        requested_input_tokens BETWEEN 1 AND 10000000
    ),
    requested_output_tokens BIGINT NOT NULL CHECK (
        requested_output_tokens BETWEEN 1 AND 1000000
    ),
    requested_cost_microusd BIGINT NOT NULL CHECK (
        requested_cost_microusd BETWEEN 0 AND 1000000000
    ),
    accounted_input_tokens BIGINT NOT NULL CHECK (accounted_input_tokens >= 0),
    accounted_output_tokens BIGINT NOT NULL CHECK (accounted_output_tokens >= 0),
    accounted_cost_microusd BIGINT NOT NULL CHECK (accounted_cost_microusd >= 0),
    status TEXT NOT NULL CHECK (status IN (
        'reserved','succeeded','accounted_rejected','indeterminate','aborted'
    )),
    provider_receipt_sha256 BYTEA CHECK (
        provider_receipt_sha256 IS NULL OR octet_length(provider_receipt_sha256) = 32
    ),
    response_sha256 BYTEA CHECK (
        response_sha256 IS NULL OR octet_length(response_sha256) = 32
    ),
    reserved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    invocation_started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, generation_id),
    UNIQUE (community_id, job_id, generation_id),
    FOREIGN KEY (community_id, job_id)
        REFERENCES snowman_agent_jobs(community_id, job_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    CHECK (
        status <> 'reserved' OR (
            invocation_started_at IS NULL AND completed_at IS NULL AND
            provider_receipt_sha256 IS NULL AND response_sha256 IS NULL AND
            accounted_input_tokens = requested_input_tokens AND
            accounted_output_tokens = requested_output_tokens AND
            accounted_cost_microusd = requested_cost_microusd
        )
    ),
    CHECK (
        status <> 'indeterminate' OR (
            invocation_started_at IS NOT NULL AND
            provider_receipt_sha256 IS NULL AND response_sha256 IS NULL AND
            accounted_input_tokens = requested_input_tokens AND
            accounted_output_tokens = requested_output_tokens AND
            accounted_cost_microusd = requested_cost_microusd
        )
    ),
    CHECK (
        status <> 'aborted' OR (
            completed_at IS NOT NULL AND provider_receipt_sha256 IS NULL AND
            response_sha256 IS NULL AND accounted_input_tokens = 0 AND
            accounted_output_tokens = 0 AND accounted_cost_microusd = 0
        )
    ),
    CHECK (
        status NOT IN ('succeeded','accounted_rejected') OR (
            invocation_started_at IS NOT NULL AND completed_at IS NOT NULL AND
            provider_receipt_sha256 IS NOT NULL
        )
    ),
    CHECK (status <> 'succeeded' OR response_sha256 IS NOT NULL),
    CHECK (status <> 'accounted_rejected' OR response_sha256 IS NULL)
);

CREATE INDEX idx_snowman_agent_model_generations_job_budget
    ON snowman_agent_model_generations
       (community_id, job_id, status, reserved_at);

CREATE INDEX idx_snowman_agent_model_generations_request_reservations
    ON snowman_agent_model_generations
       (community_id, request_id, status, reserved_at)
    WHERE status IN ('reserved','indeterminate');
