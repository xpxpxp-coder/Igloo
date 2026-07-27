-- Crash-fenced launch state for the trusted Snowman agent coordinator.
-- No raw job/model credential, prompt, result, or client dataset is stored.

CREATE TABLE snowman_agent_launches (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    launch_id UUID NOT NULL,
    job_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    runtime_profile TEXT NOT NULL CHECK (
        length(runtime_profile) BETWEEN 3 AND 32 AND
        runtime_profile ~ '^[a-z][a-z0-9-]*$'
    ),
    ecs_cluster_arn TEXT NOT NULL CHECK (
        length(ecs_cluster_arn) BETWEEN 20 AND 2048 AND
        ecs_cluster_arn ~ '^arn:aws[a-z-]*:ecs:[a-z0-9-]+:[0-9]{12}:cluster/[A-Za-z0-9_-]+$'
    ),
    task_definition_arn TEXT NOT NULL CHECK (
        length(task_definition_arn) BETWEEN 20 AND 2048 AND
        task_definition_arn ~ '^arn:aws[a-z-]*:ecs:[a-z0-9-]+:[0-9]{12}:task-definition/[A-Za-z0-9_-]+:[1-9][0-9]*$'
    ),
    client_token_sha256 BYTEA NOT NULL CHECK (
        octet_length(client_token_sha256) = 32
    ),
    requester_pubkey BYTEA NOT NULL CHECK (octet_length(requester_pubkey) = 32),
    auth_event_id BYTEA NOT NULL CHECK (octet_length(auth_event_id) = 32),
    status TEXT NOT NULL CHECK (status IN (
        'pending','launching','running','stopping','stopped','launch_failed',
        'cancelled','expired','succeeded','failed'
    )),
    ecs_task_arn TEXT CHECK (
        ecs_task_arn IS NULL OR (
            length(ecs_task_arn) BETWEEN 20 AND 2048 AND
            ecs_task_arn ~ '^arn:aws[a-z-]*:ecs:[a-z0-9-]+:[0-9]{12}:task/[A-Za-z0-9_/-]+$'
        )
    ),
    launch_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (
        launch_attempt_count BETWEEN 0 AND 20
    ),
    claim_id UUID,
    claim_expires_at TIMESTAMPTZ,
    reconcile_after TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ,
    stop_requested_at TIMESTAMPTZ,
    stopped_at TIMESTAMPTZ,
    failure_code TEXT CHECK (
        failure_code IS NULL OR (
            length(failure_code) BETWEEN 3 AND 64 AND
            failure_code ~ '^[a-z][a-z0-9_]*$'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, launch_id),
    UNIQUE (community_id, job_id),
    UNIQUE (community_id, task_id, generation),
    UNIQUE (community_id, auth_event_id),
    FOREIGN KEY (community_id, job_id)
        REFERENCES snowman_agent_jobs(community_id, job_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    CHECK ((claim_id IS NULL) = (claim_expires_at IS NULL)),
    CHECK (claim_expires_at IS NULL OR claim_expires_at > updated_at),
    CHECK (stop_requested_at IS NULL OR stop_requested_at >= created_at),
    CHECK (stopped_at IS NULL OR stopped_at >= created_at)
);

CREATE INDEX idx_snowman_agent_launches_reconcile
    ON snowman_agent_launches (status, reconcile_after, community_id, launch_id)
    WHERE status IN ('pending','launching','running','stopping');

CREATE UNIQUE INDEX idx_snowman_agent_launches_ecs_task
    ON snowman_agent_launches (community_id, ecs_task_arn)
    WHERE ecs_task_arn IS NOT NULL;

CREATE TABLE snowman_agent_coordinator_auth_events (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    auth_event_id BYTEA NOT NULL CHECK (octet_length(auth_event_id) = 32),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    requester_pubkey BYTEA NOT NULL CHECK (octet_length(requester_pubkey) = 32),
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, auth_event_id),
    CHECK (expires_at > observed_at)
);

CREATE INDEX idx_snowman_agent_coordinator_auth_expiry
    ON snowman_agent_coordinator_auth_events (expires_at, community_id);
