-- Immutable, lease-fenced receipts for the existing orchestration control
-- outbox. Payload bodies, reminder text, provider responses, credentials, and
-- Analyst 360 content are intentionally not representable here.

CREATE TABLE snowman_orchestration_control_delivery_receipts (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    outbox_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    command_kind TEXT NOT NULL CHECK (command_kind IN ('cancel_dispatch','deliver_reminder')),
    command_sha256 BYTEA NOT NULL CHECK (octet_length(command_sha256) = 32),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('delivered','retryable_failure','dead_letter')),
    delivery_reference TEXT,
    response_sha256 BYTEA CHECK (response_sha256 IS NULL OR octet_length(response_sha256) = 32),
    failure_sha256 BYTEA CHECK (failure_sha256 IS NULL OR octet_length(failure_sha256) = 32),
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, outbox_id, lease_generation),
    FOREIGN KEY (community_id, outbox_id)
        REFERENCES snowman_orchestration_control_outbox(community_id, outbox_id)
        ON DELETE CASCADE,
    CHECK (
        (outcome = 'delivered') =
        (delivery_reference IS NOT NULL AND response_sha256 IS NOT NULL)
    ),
    CHECK ((outcome = 'delivered') = (failure_sha256 IS NULL)),
    CHECK (
        delivery_reference IS NULL OR
        delivery_reference ~ '^snowman:(agent-job|reminder-delivery):[0-9a-f-]{36}:generation:[1-9][0-9]*$'
    )
);

CREATE INDEX idx_snowman_orchestration_control_delivery_outcome
    ON snowman_orchestration_control_delivery_receipts (
        accepted_at, community_id, outcome, outbox_id
    );
