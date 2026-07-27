-- Provider-neutral Snowman meeting media authority. These tables contain only
-- tenant-scoped identifiers, opaque seals, digests, bounded usage, and
-- Analyst-owned artifact references. They deliberately contain no phone
-- number, SIP URI, conference URL, email address, raw audio, transcript text,
-- provider credential, prompt, or tool instruction.

CREATE TABLE snowman_meeting_media_routes (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    mailbox_identity_id UUID NOT NULL,
    gateway_service_identity_id UUID NOT NULL,
    activation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    allow_snowman_huddle BOOLEAN NOT NULL DEFAULT FALSE,
    allow_snowman_aws BOOLEAN NOT NULL DEFAULT FALSE,
    allow_twilio BOOLEAN NOT NULL DEFAULT FALSE,
    allow_openai_realtime BOOLEAN NOT NULL DEFAULT FALSE,
    allow_eleven_labs BOOLEAN NOT NULL DEFAULT FALSE,
    provider_binding_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_binding_sha256) = 32
    ),
    policy_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(policy_evidence_sha256) = 32
    ),
    max_session_cost_microusd BIGINT NOT NULL CHECK (
        max_session_cost_microusd BETWEEN 1 AND 1000000000
    ),
    max_session_duration_seconds INTEGER NOT NULL CHECK (
        max_session_duration_seconds BETWEEN 1 AND 43200
    ),
    max_concurrent_sessions INTEGER NOT NULL CHECK (
        max_concurrent_sessions BETWEEN 1 AND 1000
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, workspace_id, mailbox_identity_id),
    FOREIGN KEY (community_id, mailbox_identity_id)
        REFERENCES snowman_meeting_mailboxes(community_id, mailbox_identity_id),
    FOREIGN KEY (community_id, gateway_service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (mailbox_identity_id <> gateway_service_identity_id),
    CHECK (
        activation_enabled OR NOT (
            allow_snowman_huddle OR allow_snowman_aws OR allow_twilio OR
            allow_openai_realtime OR allow_eleven_labs
        )
    )
);

CREATE TABLE snowman_meeting_media_sessions (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    media_session_id UUID NOT NULL,
    meeting_id UUID NOT NULL,
    meeting_session_id UUID NOT NULL,
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    workspace_id UUID NOT NULL,
    mailbox_identity_id UUID NOT NULL,
    meeting_agent_identity_id UUID NOT NULL,
    gateway_service_identity_id UUID NOT NULL,
    provider_revision BIGINT NOT NULL CHECK (provider_revision > 0),
    schedule_revision BIGINT NOT NULL CHECK (schedule_revision > 0),
    conference_kind TEXT NOT NULL CHECK (
        conference_kind IN ('snowman_huddle','google_meet','telephony')
    ),
    ingress_route TEXT NOT NULL CHECK (
        ingress_route IN ('snowman_huddle','twilio_telephony')
    ),
    conversation_route TEXT NOT NULL CHECK (
        conversation_route IN ('snowman_aws','open_ai_realtime')
    ),
    renderer_route TEXT NOT NULL CHECK (
        renderer_route IN ('conversation_native','snowman_aws','eleven_labs')
    ),
    status TEXT NOT NULL CHECK (
        status IN ('joining','active','stopping','stopped','failed')
    ),
    provider_session_set_sha256 BYTEA CHECK (
        provider_session_set_sha256 IS NULL OR
        octet_length(provider_session_set_sha256) = 32
    ),
    provider_binding_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_binding_sha256) = 32
    ),
    conference_approval_sha256 BYTEA NOT NULL CHECK (
        octet_length(conference_approval_sha256) = 32
    ),
    admission_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(admission_evidence_sha256) = 32
    ),
    consent_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(consent_evidence_sha256) = 32
    ),
    gateway_policy_sha256 BYTEA NOT NULL CHECK (
        octet_length(gateway_policy_sha256) = 32
    ),
    raw_audio_retention TEXT NOT NULL DEFAULT 'none' CHECK (
        raw_audio_retention = 'none'
    ),
    transcript_authority TEXT CHECK (
        transcript_authority IS NULL OR transcript_authority = 'analyst360'
    ),
    max_cost_microusd BIGINT NOT NULL CHECK (
        max_cost_microusd BETWEEN 1 AND 1000000000
    ),
    spent_microusd BIGINT NOT NULL DEFAULT 0 CHECK (
        spent_microusd BETWEEN 0 AND max_cost_microusd
    ),
    started_at TIMESTAMPTZ NOT NULL,
    deadline TIMESTAMPTZ NOT NULL,
    stopped_at TIMESTAMPTZ,
    last_receipt_sha256 BYTEA NOT NULL CHECK (
        octet_length(last_receipt_sha256) = 32
    ),
    failure_code TEXT CHECK (
        failure_code IS NULL OR (
            length(failure_code) BETWEEN 3 AND 64 AND
            failure_code ~ '^[a-z][a-z0-9_]*$'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, media_session_id),
    UNIQUE (community_id, meeting_session_id, meeting_id, session_generation),
    FOREIGN KEY (
        community_id, meeting_session_id, meeting_id, session_generation
    ) REFERENCES snowman_meeting_sessions(
        community_id, session_id, meeting_id, generation
    ) ON DELETE CASCADE,
    FOREIGN KEY (community_id, mailbox_identity_id)
        REFERENCES snowman_meeting_mailboxes(community_id, mailbox_identity_id),
    FOREIGN KEY (community_id, meeting_agent_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    FOREIGN KEY (community_id, gateway_service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (
        mailbox_identity_id <> meeting_agent_identity_id AND
        mailbox_identity_id <> gateway_service_identity_id
    ),
    CHECK (deadline > started_at AND deadline <= started_at + INTERVAL '12 hours'),
    CHECK (stopped_at IS NULL OR stopped_at >= started_at),
    CHECK (status <> 'active' OR provider_session_set_sha256 IS NOT NULL),
    CHECK (status NOT IN ('stopped','failed') OR stopped_at IS NOT NULL)
);

CREATE TABLE snowman_meeting_media_provider_sessions (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    media_session_id UUID NOT NULL,
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    provider TEXT NOT NULL CHECK (
        provider IN (
            'snowman_huddle','snowman_aws','twilio','open_ai_realtime'
        )
    ),
    provider_session_id_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_session_id_sha256) = 32
    ),
    handshake_sha256 BYTEA NOT NULL CHECK (octet_length(handshake_sha256) = 32),
    established_at TIMESTAMPTZ NOT NULL,
    stopped_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, media_session_id, provider),
    FOREIGN KEY (community_id, media_session_id)
        REFERENCES snowman_meeting_media_sessions(community_id, media_session_id)
        ON DELETE CASCADE,
    CHECK (stopped_at IS NULL OR stopped_at >= established_at)
);

CREATE INDEX idx_snowman_meeting_media_sessions_live
    ON snowman_meeting_media_sessions(
        community_id, status, deadline, media_session_id
    ) WHERE status IN ('joining','active','stopping');

CREATE TABLE snowman_meeting_media_commands (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    command_id UUID NOT NULL,
    media_session_id UUID NOT NULL,
    command_kind TEXT NOT NULL CHECK (command_kind IN ('join','stop')),
    command_sha256 BYTEA NOT NULL CHECK (octet_length(command_sha256) = 32),
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    issuer_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(issuer_evidence_sha256) = 32
    ),
    result_receipt_sha256 BYTEA NOT NULL CHECK (
        octet_length(result_receipt_sha256) = 32
    ),
    applied_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, command_id),
    FOREIGN KEY (community_id, media_session_id)
        REFERENCES snowman_meeting_media_sessions(community_id, media_session_id)
        ON DELETE CASCADE
);

CREATE TABLE snowman_meeting_media_webhook_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    provider TEXT NOT NULL CHECK (
        provider IN ('twilio','open_ai_realtime','eleven_labs')
    ),
    delivery_id_sha256 BYTEA NOT NULL CHECK (
        octet_length(delivery_id_sha256) = 32
    ),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    authentication_key_version_sha256 BYTEA NOT NULL CHECK (
        octet_length(authentication_key_version_sha256) = 32
    ),
    media_session_id UUID,
    session_generation BIGINT CHECK (
        session_generation IS NULL OR session_generation > 0
    ),
    received_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, provider, delivery_id_sha256),
    FOREIGN KEY (community_id, media_session_id)
        REFERENCES snowman_meeting_media_sessions(community_id, media_session_id)
        ON DELETE CASCADE,
    CHECK (
        (media_session_id IS NULL AND session_generation IS NULL) OR
        (media_session_id IS NOT NULL AND session_generation IS NOT NULL)
    )
);

CREATE TABLE snowman_meeting_media_usage_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    media_session_id UUID NOT NULL,
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    provider TEXT NOT NULL CHECK (
        provider IN (
            'snowman_huddle','snowman_aws','twilio',
            'open_ai_realtime','eleven_labs'
        )
    ),
    provider_receipt_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_receipt_sha256) = 32
    ),
    response_sha256 BYTEA NOT NULL CHECK (octet_length(response_sha256) = 32),
    cost_microusd BIGINT NOT NULL CHECK (
        cost_microusd BETWEEN 0 AND 1000000000
    ),
    input_units BIGINT NOT NULL CHECK (input_units >= 0),
    output_units BIGINT NOT NULL CHECK (output_units >= 0),
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, provider, provider_receipt_sha256),
    FOREIGN KEY (community_id, media_session_id)
        REFERENCES snowman_meeting_media_sessions(community_id, media_session_id)
        ON DELETE CASCADE
);

CREATE INDEX idx_snowman_meeting_media_usage_session
    ON snowman_meeting_media_usage_receipts(
        community_id, media_session_id, observed_at, provider_receipt_sha256
    );

CREATE TABLE snowman_meeting_media_turn_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    media_session_id UUID NOT NULL,
    turn_id UUID NOT NULL,
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    input_audio_sha256 BYTEA CHECK (
        input_audio_sha256 IS NULL OR octet_length(input_audio_sha256) = 32
    ),
    output_audio_sha256 BYTEA CHECK (
        output_audio_sha256 IS NULL OR octet_length(output_audio_sha256) = 32
    ),
    source_turn_sha256 BYTEA NOT NULL CHECK (
        octet_length(source_turn_sha256) = 32
    ),
    analyst_artifact_id UUID,
    analyst_artifact_sha256 BYTEA CHECK (
        analyst_artifact_sha256 IS NULL OR
        octet_length(analyst_artifact_sha256) = 32
    ),
    transcript_authority TEXT CHECK (
        transcript_authority IS NULL OR transcript_authority = 'analyst360'
    ),
    observed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, media_session_id, turn_id),
    FOREIGN KEY (community_id, media_session_id)
        REFERENCES snowman_meeting_media_sessions(community_id, media_session_id)
        ON DELETE CASCADE,
    CHECK (
        (analyst_artifact_id IS NULL AND analyst_artifact_sha256 IS NULL AND
         transcript_authority IS NULL) OR
        (analyst_artifact_id IS NOT NULL AND analyst_artifact_sha256 IS NOT NULL AND
         transcript_authority = 'analyst360')
    )
);
