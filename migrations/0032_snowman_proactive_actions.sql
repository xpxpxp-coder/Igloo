-- Durable policy decisions for the Snowman 24/7 workforce. This is a bounded
-- control-plane queue, not authority to execute arbitrary actions: consumers
-- still need the exact action capability and human approval where recorded.

CREATE TABLE snowman_proactive_actions (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    action_id UUID NOT NULL,
    request_id UUID NOT NULL,
    proposed_by_identity_id UUID NOT NULL,
    trigger_kind TEXT NOT NULL CHECK (trigger_kind IN (
        'user_objective', 'authorized_schedule', 'tenant_signal', 'policy_review'
    )),
    capability TEXT NOT NULL CHECK (
        length(capability) BETWEEN 3 AND 128
        AND capability ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$'
        AND capability NOT IN ('admin.all', 'aws.all', 'filesystem.all', 'network.all', 'tool.all')
    ),
    risk_tier TEXT NOT NULL CHECK (risk_tier IN ('low', 'moderate', 'high', 'prohibited')),
    reversible BOOLEAN NOT NULL,
    expected_cost_microusd BIGINT NOT NULL CHECK (expected_cost_microusd >= 0),
    confidence_basis_points INTEGER NOT NULL CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    usefulness_sha256 BYTEA NOT NULL CHECK (octet_length(usefulness_sha256) = 32),
    source_event_sha256 BYTEA NOT NULL CHECK (octet_length(source_event_sha256) = 32),
    policy_sha256 BYTEA NOT NULL CHECK (octet_length(policy_sha256) = 32),
    action_sha256 BYTEA NOT NULL CHECK (octet_length(action_sha256) = 32),
    decision TEXT NOT NULL CHECK (decision IN (
        'execute_automatically', 'await_human_approval', 'reject'
    )),
    status TEXT NOT NULL CHECK (status IN (
        'queued', 'awaiting_approval', 'rejected', 'leased', 'running',
        'succeeded', 'failed', 'cancelled', 'expired'
    )),
    scheduled_for TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, action_id),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, proposed_by_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (expires_at > scheduled_for),
    CHECK (created_at <= scheduled_for)
);

CREATE INDEX idx_snowman_proactive_actions_due
    ON snowman_proactive_actions (community_id, status, scheduled_for, action_id)
    WHERE status = 'queued';

CREATE INDEX idx_snowman_proactive_actions_request
    ON snowman_proactive_actions (community_id, request_id, created_at);
