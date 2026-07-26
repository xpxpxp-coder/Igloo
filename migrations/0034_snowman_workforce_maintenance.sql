-- Idempotent scheduler receipts for Snowman's tenant-local workforce. The
-- result is bounded operational metadata; task/request mutations and their
-- request-local hash-chain events commit in the same database transaction.

CREATE TABLE snowman_workforce_maintenance_ticks (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    tick_id UUID NOT NULL,
    scheduler_identity_id UUID NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    result JSONB NOT NULL CHECK (
        jsonb_typeof(result) = 'object'
        AND result->>'observed_at' IS NOT NULL
    ),
    PRIMARY KEY (community_id, tick_id),
    FOREIGN KEY (community_id, scheduler_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (observed_at >= requested_at - INTERVAL '5 minutes')
);

CREATE INDEX idx_snowman_workforce_maintenance_observed
    ON snowman_workforce_maintenance_ticks (community_id, observed_at DESC);
