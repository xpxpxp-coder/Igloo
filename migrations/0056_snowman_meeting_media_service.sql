-- Authentication and durable runtime fencing for the private Snowman meeting
-- media service. Tokens are stored only as SHA-256 digests. Provider callback
-- verification remains bound to a Snowman policy proxy; no provider secret,
-- raw callback body, audio, transcript, dial target, URL, or SIP coordinate is
-- stored here.

CREATE TABLE snowman_meeting_media_callers (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    service_identity_id UUID NOT NULL,
    token_sha256 BYTEA NOT NULL CHECK (octet_length(token_sha256) = 32),
    scopes TEXT[] NOT NULL CHECK (
        cardinality(scopes) BETWEEN 1 AND 4 AND
        scopes <@ ARRAY[
            'meeting.media.join','meeting.media.stop',
            'meeting.media.usage','meeting.media.intent'
        ]::TEXT[]
    ),
    status TEXT NOT NULL DEFAULT 'disabled' CHECK (
        status IN ('disabled','active','revoked')
    ),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    authority_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(authority_evidence_sha256) = 32
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, service_identity_id),
    UNIQUE (community_id, token_sha256),
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (expires_at > created_at),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX idx_snowman_meeting_media_callers_live
    ON snowman_meeting_media_callers(
        community_id, status, expires_at, service_identity_id
    ) WHERE status = 'active';

CREATE TABLE snowman_meeting_media_callback_bindings (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    callback_binding_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK (
        provider IN ('twilio','open_ai_realtime')
    ),
    provider_binding_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_binding_sha256) = 32
    ),
    callback_origin_sha256 BYTEA NOT NULL CHECK (
        octet_length(callback_origin_sha256) = 32
    ),
    policy_proxy_binding_sha256 BYTEA NOT NULL CHECK (
        octet_length(policy_proxy_binding_sha256) = 32
    ),
    callback_authenticator TEXT NOT NULL CHECK (
        callback_authenticator IN ('twilio_request','openai_standard_webhook')
    ),
    websocket_upgrade_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'disabled' CHECK (
        status IN ('disabled','active','revoked')
    ),
    activated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, callback_binding_id),
    UNIQUE (community_id, provider, provider_binding_sha256),
    CHECK (status <> 'active' OR activated_at IS NOT NULL),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

-- Commands are authenticated before mutation. Keeping the caller identity and
-- authentication digest beside the command makes the durable result
-- independently attributable without retaining a bearer token.
ALTER TABLE snowman_meeting_media_sessions
    DROP CONSTRAINT snowman_meeting_media_sessions_status_check,
    ADD CONSTRAINT snowman_meeting_media_sessions_status_check CHECK (
        status IN (
            'joining','indeterminate','active','stopping','stopped','failed'
        )
    );

ALTER TABLE snowman_meeting_media_commands
    ADD COLUMN caller_service_identity_id UUID;

ALTER TABLE snowman_meeting_media_commands
    ADD COLUMN authentication_sha256 BYTEA CHECK (
        authentication_sha256 IS NULL OR octet_length(authentication_sha256) = 32
    );

ALTER TABLE snowman_meeting_media_commands
    ADD CONSTRAINT snowman_meeting_media_command_caller_fk
        FOREIGN KEY (community_id, caller_service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id);

ALTER TABLE snowman_meeting_media_commands
    ADD CONSTRAINT snowman_meeting_media_command_auth_pair CHECK (
        (caller_service_identity_id IS NULL) = (authentication_sha256 IS NULL)
    );
