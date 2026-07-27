-- A Snowman-owned identity authority may enroll a Google Workspace human
-- device only through a fresh, exact-body, asymmetric KMS assertion. The
-- relay still verifies the device's Nostr signature itself. Neither Google
-- tokens, email addresses, nor raw provider subjects cross this boundary.

ALTER TABLE snowman_workforce_identities
    DROP CONSTRAINT snowman_workforce_identities_provisioning_authority_check;

ALTER TABLE snowman_workforce_identities
    ADD CONSTRAINT snowman_workforce_identities_provisioning_authority_check CHECK (
        provisioning_authority IS NULL
        OR provisioning_authority IN ('workforce_bootstrap', 'identity_broker')
    );

CREATE TABLE snowman_workforce_identity_brokers (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    broker_id TEXT NOT NULL CHECK (
        broker_id ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$'
    ),
    provider TEXT NOT NULL CHECK (provider='google_workspace'),
    hosted_domain TEXT NOT NULL CHECK (
        hosted_domain = lower(hosted_domain)
        AND length(hosted_domain) BETWEEN 3 AND 253
        AND hosted_domain ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$'
    ),
    tenant_id TEXT NOT NULL CHECK (length(tenant_id) BETWEEN 1 AND 120),
    client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 120),
    project_id TEXT NOT NULL CHECK (length(project_id) BETWEEN 1 AND 120),
    assurance_level TEXT NOT NULL CHECK (assurance_level IN ('mfa', 'phishing_resistant')),
    assurance_evidence_sha256 BYTEA NOT NULL CHECK (octet_length(assurance_evidence_sha256)=32),
    assurance_evaluated_at TIMESTAMPTZ NOT NULL,
    signing_kms_key_arn TEXT NOT NULL CHECK (
        signing_kms_key_arn ~ '^arn:aws(-[a-z]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$'
    ),
    max_session_seconds INTEGER NOT NULL CHECK (max_session_seconds BETWEEN 60 AND 3600),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    provisioning_authority TEXT NOT NULL CHECK (provisioning_authority='workforce_bootstrap'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, broker_id),
    UNIQUE (community_id, signing_kms_key_arn),
    CHECK ((status='revoked') = (revoked_at IS NOT NULL))
);

CREATE TABLE snowman_workforce_enrollment_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    assertion_id UUID NOT NULL,
    broker_id TEXT NOT NULL,
    identity_id UUID NOT NULL,
    session_id UUID NOT NULL,
    provider_subject_sha256 BYTEA NOT NULL CHECK (octet_length(provider_subject_sha256)=32),
    device_pubkey BYTEA NOT NULL CHECK (octet_length(device_pubkey)=32),
    assertion_body_sha256 BYTEA NOT NULL CHECK (octet_length(assertion_body_sha256)=32),
    device_proof_event_id BYTEA NOT NULL CHECK (octet_length(device_proof_event_id)=32),
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    assurance_level TEXT NOT NULL CHECK (assurance_level IN ('mfa', 'phishing_resistant')),
    authenticated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, assertion_id),
    UNIQUE (community_id, session_id),
    FOREIGN KEY (community_id, broker_id)
        REFERENCES snowman_workforce_identity_brokers(community_id, broker_id),
    FOREIGN KEY (community_id, identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (expires_at > authenticated_at),
    CHECK (enrolled_at >= authenticated_at)
);

CREATE INDEX idx_snowman_workforce_enrollment_receipts_identity
    ON snowman_workforce_enrollment_receipts (community_id, identity_id, enrolled_at DESC);

ALTER TABLE snowman_workforce_bootstrap_receipts
    ADD COLUMN identity_broker_count INTEGER NOT NULL DEFAULT 0
    CHECK (identity_broker_count BETWEEN 0 AND 1);
