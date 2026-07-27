-- Durable coordinator-destination claim and receipt ledger. The table stores
-- only exact request/response digests and Snowman coordinates; prompts,
-- messages, provider payloads, credentials, and client content are excluded.

ALTER TABLE snowman_orchestration_dispatches
    ADD CONSTRAINT uq_snowman_orchestration_dispatch_scope
    UNIQUE (community_id, workspace_id, dispatch_id);

ALTER TABLE snowman_orchestration_control_outbox
    ADD CONSTRAINT uq_snowman_orchestration_control_scope
    UNIQUE (community_id, workspace_id, outbox_id);

CREATE TABLE snowman_orchestration_destination_receipts (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    destination_kind TEXT NOT NULL CHECK (destination_kind IN ('dispatch','cancel')),
    request_id UUID NOT NULL,
    dispatch_id UUID GENERATED ALWAYS AS (
        CASE WHEN destination_kind = 'dispatch' THEN request_id END
    ) STORED,
    outbox_id UUID GENERATED ALWAYS AS (
        CASE WHEN destination_kind = 'cancel' THEN request_id END
    ) STORED,
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    delivery_reference TEXT NOT NULL CHECK (
        delivery_reference ~ '^snowman:agent-job:[0-9a-f-]{36}:generation:[1-9][0-9]*$'
    ),
    status TEXT NOT NULL CHECK (status IN ('processing','completed')),
    response_sha256 BYTEA CHECK (response_sha256 IS NULL OR octet_length(response_sha256) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, request_id),
    FOREIGN KEY (community_id, workspace_id, dispatch_id)
        REFERENCES snowman_orchestration_dispatches(community_id, workspace_id, dispatch_id),
    FOREIGN KEY (community_id, workspace_id, outbox_id)
        REFERENCES snowman_orchestration_control_outbox(community_id, workspace_id, outbox_id),
    CHECK ((status = 'completed') = (response_sha256 IS NOT NULL AND completed_at IS NOT NULL)),
    CHECK (
        (destination_kind = 'dispatch' AND dispatch_id IS NOT NULL AND outbox_id IS NULL) OR
        (destination_kind = 'cancel' AND dispatch_id IS NULL AND outbox_id IS NOT NULL)
    )
);

CREATE INDEX idx_snowman_orchestration_destination_processing
    ON snowman_orchestration_destination_receipts (created_at, community_id, destination_kind)
    WHERE status = 'processing';
