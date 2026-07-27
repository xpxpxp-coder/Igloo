-- Private Analyst-to-meeting-control command authentication and signed receipt
-- evidence. This boundary stores exact digests, service identities, and KMS
-- signatures only; it has no raw Gmail, Calendar, transcript, dial target, or
-- provider credential fields.

CREATE TABLE snowman_meeting_command_callers (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    mailbox_identity_id UUID NOT NULL,
    service_identity_id UUID NOT NULL,
    service_principal TEXT NOT NULL CHECK (
        length(service_principal) BETWEEN 3 AND 200 AND
        service_principal ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]+$'
    ),
    policy_generation BIGINT NOT NULL CHECK (policy_generation > 0),
    status TEXT NOT NULL DEFAULT 'disabled' CHECK (
        status IN ('disabled','active','revoked')
    ),
    authority_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(authority_evidence_sha256) = 32
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, workspace_id, mailbox_identity_id, service_identity_id),
    UNIQUE (community_id, workspace_id, mailbox_identity_id, service_principal),
    FOREIGN KEY (community_id, mailbox_identity_id)
        REFERENCES snowman_meeting_mailboxes(community_id, mailbox_identity_id),
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (mailbox_identity_id <> service_identity_id)
);

CREATE INDEX idx_snowman_meeting_command_callers_active
    ON snowman_meeting_command_callers (
        community_id, workspace_id, mailbox_identity_id, service_principal
    ) WHERE status = 'active';

CREATE TABLE snowman_meeting_command_receivers (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    receiver_identity_id UUID NOT NULL,
    receiver_key_id TEXT NOT NULL CHECK (
        length(receiver_key_id) BETWEEN 60 AND 256 AND
        receiver_key_id ~ '^arn:aws[^:]*:kms:[^:]+:[0-9]{12}:key/[A-Za-z0-9-]+$'
    ),
    authority_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(authority_evidence_sha256) = 32
    ),
    status TEXT NOT NULL DEFAULT 'disabled' CHECK (
        status IN ('disabled','active','revoked')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, receiver_identity_id),
    UNIQUE (community_id, receiver_key_id),
    FOREIGN KEY (community_id, receiver_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id)
);

CREATE TABLE snowman_meeting_command_auth_events (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    auth_event_id BYTEA NOT NULL CHECK (octet_length(auth_event_id) = 32),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    requester_pubkey BYTEA NOT NULL CHECK (octet_length(requester_pubkey) = 32),
    service_principal TEXT NOT NULL CHECK (
        length(service_principal) BETWEEN 3 AND 200 AND
        service_principal ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]+$'
    ),
    observed_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, auth_event_id),
    FOREIGN KEY (community_id, requester_pubkey)
        REFERENCES snowman_workforce_key_bindings(community_id, pubkey),
    CHECK (expires_at > observed_at AND expires_at <= observed_at + INTERVAL '2 minutes')
);

CREATE INDEX idx_snowman_meeting_command_auth_expiry
    ON snowman_meeting_command_auth_events (community_id, expires_at, auth_event_id);

CREATE TABLE snowman_meeting_command_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    receipt_id UUID NOT NULL,
    command_id UUID NOT NULL,
    auth_event_id BYTEA NOT NULL CHECK (octet_length(auth_event_id) = 32),
    receipt_payload_sha256 BYTEA NOT NULL CHECK (
        octet_length(receipt_payload_sha256) = 32
    ),
    receiver_key_id TEXT NOT NULL CHECK (
        length(receiver_key_id) BETWEEN 60 AND 256 AND
        receiver_key_id ~ '^arn:aws[^:]*:kms:[^:]+:[0-9]{12}:key/[A-Za-z0-9-]+$'
    ),
    receiver_signature BYTEA NOT NULL CHECK (
        octet_length(receiver_signature) BETWEEN 64 AND 1024
    ),
    issued_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, receipt_id),
    UNIQUE (community_id, auth_event_id),
    FOREIGN KEY (community_id, command_id)
        REFERENCES snowman_meeting_commands(community_id, command_id),
    FOREIGN KEY (community_id, auth_event_id)
        REFERENCES snowman_meeting_command_auth_events(community_id, auth_event_id)
);

CREATE INDEX idx_snowman_meeting_command_receipts_command
    ON snowman_meeting_command_receipts (community_id, command_id, issued_at);
