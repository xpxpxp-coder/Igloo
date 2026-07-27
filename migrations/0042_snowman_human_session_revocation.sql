-- Identity-authority revocations are one-time, tenant-scoped, and auditable.
-- Session and device rows remain for forensic history; authorization is removed
-- by timestamps and broker-owned relay membership deletion.

CREATE TABLE snowman_workforce_revocation_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    assertion_id UUID NOT NULL,
    broker_id TEXT NOT NULL,
    identity_id UUID NOT NULL,
    session_id UUID,
    revocation_scope TEXT NOT NULL CHECK (
        revocation_scope IN ('session', 'all_sessions', 'identity')
    ),
    reason TEXT NOT NULL CHECK (
        reason IN ('user_logout', 'device_removed', 'global_logout',
                   'identity_inactive', 'assignment_changed', 'security_response')
    ),
    assertion_body_sha256 BYTEA NOT NULL CHECK (octet_length(assertion_body_sha256)=32),
    revoked_session_count INTEGER NOT NULL CHECK (revoked_session_count >= 0),
    revoked_device_count INTEGER NOT NULL CHECK (revoked_device_count >= 0),
    revoked_grant_count INTEGER NOT NULL CHECK (revoked_grant_count >= 0),
    revoked_member_count INTEGER NOT NULL CHECK (revoked_member_count >= 0),
    revoked_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, assertion_id),
    FOREIGN KEY (community_id, broker_id)
        REFERENCES snowman_workforce_identity_brokers(community_id, broker_id),
    FOREIGN KEY (community_id, identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    FOREIGN KEY (community_id, identity_id, session_id)
        REFERENCES snowman_workforce_sessions(community_id, identity_id, session_id),
    CHECK (
        (revocation_scope='session' AND session_id IS NOT NULL)
        OR (revocation_scope<>'session' AND session_id IS NULL)
    )
);

CREATE INDEX idx_snowman_workforce_revocation_receipts_identity
    ON snowman_workforce_revocation_receipts
       (community_id, identity_id, revoked_at DESC);
