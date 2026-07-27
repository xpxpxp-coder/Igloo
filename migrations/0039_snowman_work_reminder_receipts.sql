-- Idempotent, evidence-preserving delivery receipts for agent-authored reminders.
-- Reminder text and recipients are server-derived: workers cannot provide either.

CREATE TABLE snowman_work_reminder_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    delivery_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    worker_identity_id UUID NOT NULL,
    target_pubkeys BYTEA[] NOT NULL CHECK (cardinality(target_pubkeys) BETWEEN 1 AND 16),
    event_created_at TIMESTAMPTZ NOT NULL,
    nostr_event_id BYTEA CHECK (nostr_event_id IS NULL OR octet_length(nostr_event_id) = 32),
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, delivery_id),
    UNIQUE (community_id, task_id),
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, worker_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK ((nostr_event_id IS NULL) = (delivered_at IS NULL))
);

CREATE INDEX idx_snowman_work_reminder_receipts_pending
    ON snowman_work_reminder_receipts (community_id, created_at)
    WHERE delivered_at IS NULL;
