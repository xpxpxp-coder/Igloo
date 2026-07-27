-- Network-attested credential bootstrap evidence for one-shot agent launches.
-- The launch coordinate is not a secret; no plaintext credential is durable.

ALTER TABLE snowman_agent_launches
    ADD COLUMN bootstrap_redeemed_at TIMESTAMPTZ,
    ADD COLUMN bootstrap_last_redeemed_at TIMESTAMPTZ,
    ADD COLUMN bootstrap_source_ip INET,
    ADD COLUMN bootstrap_redeem_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE snowman_agent_launches
    ADD CONSTRAINT snowman_agent_launches_bootstrap_count
    CHECK (bootstrap_redeem_count BETWEEN 0 AND 5),
    ADD CONSTRAINT snowman_agent_launches_bootstrap_evidence
    CHECK (
        (bootstrap_redeem_count = 0) = (bootstrap_redeemed_at IS NULL) AND
        (bootstrap_redeem_count = 0) = (bootstrap_last_redeemed_at IS NULL) AND
        (bootstrap_redeem_count = 0) = (bootstrap_source_ip IS NULL) AND
        (
            bootstrap_redeemed_at IS NULL OR
            bootstrap_last_redeemed_at >= bootstrap_redeemed_at
        ) AND
        (
            bootstrap_source_ip IS NULL OR
            family(bootstrap_source_ip) = 4
        )
    );

CREATE INDEX idx_snowman_agent_launches_bootstrap_authority
    ON snowman_agent_launches (community_id, launch_id, status)
    WHERE bootstrap_redeem_count < 5;
