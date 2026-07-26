-- Private, tenant-isolated Analyst 360 event ingress. KMS keys are asymmetric:
-- the relay can verify the Analyst request key and use the receipt key through
-- AWS KMS, but neither private key is exportable or stored in Postgres.

CREATE TABLE snowman_analyst_integrations (
    community_id UUID NOT NULL PRIMARY KEY REFERENCES communities(id),
    analyst_service_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    request_kms_key_arn TEXT NOT NULL,
    receipt_kms_key_arn TEXT NOT NULL,
    receiver_service_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (length(analyst_service_id) BETWEEN 3 AND 200),
    CHECK (length(tenant_id) BETWEEN 1 AND 200),
    CHECK (length(client_id) BETWEEN 1 AND 200),
    CHECK (length(project_id) BETWEEN 1 AND 200),
    CHECK (length(receiver_service_id) BETWEEN 3 AND 200),
    CHECK (request_kms_key_arn <> receipt_kms_key_arn)
);

CREATE UNIQUE INDEX idx_snowman_analyst_scope
    ON snowman_analyst_integrations (community_id, tenant_id, client_id, project_id);

CREATE TABLE snowman_analyst_request_nonces (
    community_id UUID NOT NULL,
    analyst_service_id TEXT NOT NULL,
    nonce TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation = 'events.ingest'),
    request_target_sha256 BYTEA NOT NULL CHECK (octet_length(request_target_sha256) = 32),
    body_sha256 BYTEA NOT NULL CHECK (octet_length(body_sha256) = 32),
    used_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, analyst_service_id, nonce),
    FOREIGN KEY (community_id) REFERENCES snowman_analyst_integrations(community_id),
    CHECK (length(nonce) BETWEEN 24 AND 200),
    CHECK (expires_at > used_at)
);

CREATE INDEX idx_snowman_analyst_nonce_expiry
    ON snowman_analyst_request_nonces (expires_at);

CREATE TABLE snowman_analyst_events (
    community_id UUID NOT NULL REFERENCES communities(id),
    event_id TEXT NOT NULL,
    command_id TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    project_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    status TEXT NOT NULL CHECK (
        status IN ('accepted', 'queued', 'running', 'awaiting_approval',
                   'succeeded', 'failed', 'cancelled', 'expired')
    ),
    payload JSONB NOT NULL,
    event_sha256 BYTEA NOT NULL CHECK (octet_length(event_sha256) = 32),
    payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
    received_from_service_id TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    receipt_id TEXT,
    receipt_sha256 BYTEA CHECK (receipt_sha256 IS NULL OR octet_length(receipt_sha256) = 32),
    receipt_signature BYTEA,
    receipt_signed_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, event_id),
    UNIQUE (community_id, command_id, sequence),
    CHECK (
        (receipt_id IS NULL AND receipt_sha256 IS NULL
         AND receipt_signature IS NULL AND receipt_signed_at IS NULL)
        OR
        (receipt_id IS NOT NULL AND receipt_sha256 IS NOT NULL
         AND receipt_signature IS NOT NULL AND receipt_signed_at IS NOT NULL)
    )
);

CREATE INDEX idx_snowman_analyst_events_command
    ON snowman_analyst_events (community_id, command_id, sequence);
