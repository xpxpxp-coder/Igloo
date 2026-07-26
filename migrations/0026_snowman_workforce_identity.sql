-- Snowman workforce identity binding above Nostr key possession.
-- The identity broker verifies Google Workspace or AWS IAM Identity Center
-- assertions before writing these tenant-scoped bindings. Relay authentication
-- then requires a live human session or an active, capability-bounded service
-- identity. Raw OIDC tokens and provider subject values are never persisted.

CREATE TABLE snowman_workforce_identities (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    identity_id UUID NOT NULL,
    identity_type TEXT NOT NULL CHECK (identity_type IN ('human', 'service')),
    provider TEXT NOT NULL CHECK (
        provider IN ('google_workspace', 'aws_identity_center', 'snowman_service')
    ),
    provider_subject_sha256 BYTEA NOT NULL CHECK (octet_length(provider_subject_sha256) = 32),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'member', 'guest', 'agent')),
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, identity_id),
    UNIQUE (community_id, provider, provider_subject_sha256),
    CHECK ((identity_type = 'service') = (provider = 'snowman_service')),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX idx_snowman_workforce_identities_status
    ON snowman_workforce_identities (community_id, status, identity_type, expires_at);

CREATE TABLE snowman_workforce_sessions (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    identity_id UUID NOT NULL,
    device_pubkey BYTEA NOT NULL CHECK (octet_length(device_pubkey) = 32),
    assurance_level TEXT NOT NULL CHECK (assurance_level IN ('single_factor', 'mfa', 'phishing_resistant')),
    authenticated_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT CHECK (revocation_reason IS NULL OR length(revocation_reason) BETWEEN 1 AND 512),
    PRIMARY KEY (community_id, session_id),
    UNIQUE (community_id, identity_id, session_id),
    FOREIGN KEY (community_id, identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id) ON DELETE CASCADE,
    CHECK (expires_at > authenticated_at),
    CHECK (last_seen_at >= authenticated_at),
    CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL))
);

CREATE INDEX idx_snowman_workforce_sessions_active
    ON snowman_workforce_sessions (community_id, identity_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE snowman_workforce_key_bindings (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    pubkey BYTEA NOT NULL CHECK (octet_length(pubkey) = 32),
    identity_id UUID NOT NULL,
    binding_type TEXT NOT NULL CHECK (binding_type IN ('human_device', 'service_runtime')),
    session_id UUID,
    bound_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, pubkey),
    FOREIGN KEY (community_id, identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, identity_id, session_id)
        REFERENCES snowman_workforce_sessions(community_id, identity_id, session_id) ON DELETE CASCADE,
    CHECK (
        (binding_type = 'human_device' AND session_id IS NOT NULL)
        OR (binding_type = 'service_runtime' AND session_id IS NULL)
    ),
    CHECK (expires_at IS NULL OR expires_at > bound_at)
);

CREATE INDEX idx_snowman_workforce_key_bindings_identity
    ON snowman_workforce_key_bindings (community_id, identity_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE snowman_workforce_capability_grants (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    grant_id UUID NOT NULL,
    identity_id UUID NOT NULL,
    capability TEXT NOT NULL CHECK (
        capability ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
        AND length(capability) BETWEEN 3 AND 128
    ),
    grant_source TEXT NOT NULL CHECK (grant_source IN ('role_policy', 'task_assignment', 'operator')),
    granted_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, grant_id),
    FOREIGN KEY (community_id, identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id) ON DELETE CASCADE,
    CHECK (expires_at IS NULL OR expires_at > granted_at)
);

CREATE INDEX idx_snowman_workforce_capability_grants_active
    ON snowman_workforce_capability_grants (community_id, identity_id, capability, expires_at)
    WHERE revoked_at IS NULL;

ALTER TABLE snowman_work_tasks
    ADD CONSTRAINT snowman_work_tasks_service_identity_fk
    FOREIGN KEY (community_id, service_identity_id)
    REFERENCES snowman_workforce_identities(community_id, identity_id);

ALTER TABLE snowman_task_leases
    ADD CONSTRAINT snowman_task_leases_worker_identity_fk
    FOREIGN KEY (community_id, worker_identity_id)
    REFERENCES snowman_workforce_identities(community_id, identity_id);
