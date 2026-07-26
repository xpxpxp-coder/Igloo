-- Secret-free evidence that one exact governed workforce manifest was applied.
-- Private service keys remain solely in Snowman AWS Secrets Manager.

ALTER TABLE snowman_workforce_identities
    ADD COLUMN provisioning_authority TEXT CHECK (
        provisioning_authority IS NULL OR provisioning_authority='workforce_bootstrap'
    );

ALTER TABLE snowman_model_routes
    ADD COLUMN provisioning_authority TEXT CHECK (
        provisioning_authority IS NULL OR provisioning_authority='workforce_bootstrap'
    );

CREATE TABLE snowman_workforce_bootstrap_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    manifest_sha256 BYTEA NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    identity_count INTEGER NOT NULL CHECK (identity_count BETWEEN 1 AND 64),
    model_route_count INTEGER NOT NULL CHECK (model_route_count BETWEEN 1 AND 64),
    applied_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, manifest_sha256)
);

CREATE INDEX idx_snowman_workforce_bootstrap_receipts_latest
    ON snowman_workforce_bootstrap_receipts (community_id, applied_at DESC);
