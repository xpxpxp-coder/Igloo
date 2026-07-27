-- Governed meeting scheduling and execution authority. These tables store
-- tenant-scoped coordination, digests, and sealed references only. Raw mail,
-- calendar descriptions, attachments, audio, and transcripts remain under
-- Analyst 360 evidence/retention authority; phone numbers, SIP URIs,
-- conference URLs, provider credentials, and model prompts are never stored.

CREATE TABLE snowman_meeting_mailboxes (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    mailbox_identity_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    provider TEXT NOT NULL CHECK (provider = 'google_workspace'),
    provider_subject_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_subject_sha256) = 32
    ),
    mailbox_binding_sha256 BYTEA NOT NULL CHECK (
        octet_length(mailbox_binding_sha256) = 32
    ),
    gmail_history_id NUMERIC(20, 0) CHECK (
        gmail_history_id IS NULL OR gmail_history_id > 0
    ),
    gmail_watch_expires_at TIMESTAMPTZ,
    calendar_sync_token_sha256 BYTEA CHECK (
        calendar_sync_token_sha256 IS NULL OR
        octet_length(calendar_sync_token_sha256) = 32
    ),
    last_reconciled_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'disabled' CHECK (
        status IN ('disabled','active','revoked','reconciliation_required')
    ),
    dedicated_tenant_identity BOOLEAN NOT NULL DEFAULT TRUE CHECK (
        dedicated_tenant_identity
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, mailbox_identity_id),
    UNIQUE (community_id, workspace_id),
    UNIQUE (community_id, provider_subject_sha256),
    FOREIGN KEY (community_id, mailbox_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (
        status <> 'active' OR (
            gmail_history_id IS NOT NULL AND
            gmail_watch_expires_at IS NOT NULL AND
            last_reconciled_at IS NOT NULL
        )
    )
);

CREATE INDEX idx_snowman_meeting_mailboxes_watch_renewal
    ON snowman_meeting_mailboxes (
        community_id, status, gmail_watch_expires_at, mailbox_identity_id
    )
    WHERE status IN ('active','reconciliation_required');

CREATE TABLE snowman_meeting_intake_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    intake_receipt_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    mailbox_identity_id UUID NOT NULL,
    source_kind TEXT NOT NULL CHECK (
        source_kind IN ('gmail_history','calendar_event','calendar_cancellation')
    ),
    provider_resource_id_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_resource_id_sha256) = 32
    ),
    provider_revision BIGINT NOT NULL CHECK (provider_revision > 0),
    provider_revision_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_revision_sha256) = 32
    ),
    envelope_sha256 BYTEA NOT NULL CHECK (octet_length(envelope_sha256) = 32),
    sender_or_organizer_sha256 BYTEA NOT NULL CHECK (
        octet_length(sender_or_organizer_sha256) = 32
    ),
    analyst_artifact_id UUID NOT NULL,
    analyst_content_sha256 BYTEA NOT NULL CHECK (
        octet_length(analyst_content_sha256) = 32
    ),
    content_trust TEXT NOT NULL DEFAULT 'untrusted' CHECK (
        content_trust = 'untrusted'
    ),
    status TEXT NOT NULL CHECK (
        status IN ('observed','admitted','ignored','cancelled','rejected')
    ),
    observed_at TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, intake_receipt_id),
    UNIQUE (
        community_id, mailbox_identity_id, source_kind,
        provider_resource_id_sha256, provider_revision
    ),
    FOREIGN KEY (community_id, mailbox_identity_id)
        REFERENCES snowman_meeting_mailboxes(community_id, mailbox_identity_id)
        ON DELETE CASCADE,
    CHECK (processed_at IS NULL OR processed_at >= observed_at)
);

CREATE INDEX idx_snowman_meeting_intake_pending
    ON snowman_meeting_intake_receipts (
        community_id, status, observed_at, intake_receipt_id
    )
    WHERE status = 'observed';

CREATE TABLE snowman_meetings (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    meeting_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    mailbox_identity_id UUID NOT NULL,
    meeting_agent_identity_id UUID NOT NULL,
    parent_thread_sha256 BYTEA NOT NULL CHECK (
        octet_length(parent_thread_sha256) = 32
    ),
    data_class TEXT NOT NULL CHECK (
        data_class IN ('internal','confidential','restricted')
    ),
    provider_event_id_sha256 BYTEA NOT NULL CHECK (
        octet_length(provider_event_id_sha256) = 32
    ),
    provider_revision BIGINT NOT NULL CHECK (provider_revision > 0),
    organizer_approved BOOLEAN NOT NULL CHECK (organizer_approved),
    conference_kind TEXT NOT NULL CHECK (
        conference_kind IN ('snowman_huddle','google_meet','telephony')
    ),
    conference_entrypoint_sha256 BYTEA NOT NULL CHECK (
        octet_length(conference_entrypoint_sha256) = 32
    ),
    sealed_coordinate_ref TEXT NOT NULL CHECK (
        length(sealed_coordinate_ref) BETWEEN 16 AND 256 AND
        sealed_coordinate_ref ~ '^[A-Za-z0-9_.:-]+$' AND
        sealed_coordinate_ref !~ '^[0-9]+$' AND
        sealed_coordinate_ref !~* '^sip:' AND
        position('://' IN sealed_coordinate_ref) = 0
    ),
    conference_approval_sha256 BYTEA NOT NULL CHECK (
        octet_length(conference_approval_sha256) = 32
    ),
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    join_not_before TIMESTAMPTZ NOT NULL,
    join_not_after TIMESTAMPTZ NOT NULL,
    voice_route TEXT NOT NULL DEFAULT 'disabled' CHECK (
        voice_route IN ('disabled','snowman_aws','open_ai_realtime')
    ),
    speech_output_route TEXT NOT NULL CHECK (
        speech_output_route IN ('voice_route','snowman_aws','eleven_labs')
    ),
    external_processing_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    restricted_external_approval_sha256 BYTEA CHECK (
        restricted_external_approval_sha256 IS NULL OR
        octet_length(restricted_external_approval_sha256) = 32
    ),
    processor_policy_sha256 BYTEA NOT NULL CHECK (
        octet_length(processor_policy_sha256) = 32
    ),
    consent_policy_sha256 BYTEA NOT NULL CHECK (
        octet_length(consent_policy_sha256) = 32
    ),
    disclosure_required BOOLEAN NOT NULL CHECK (disclosure_required),
    transcription_consent_required BOOLEAN NOT NULL,
    recording_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    external_processing_consent_required BOOLEAN NOT NULL,
    raw_audio_retention TEXT NOT NULL DEFAULT 'none' CHECK (
        raw_audio_retention IN ('none','analyst_evidence')
    ),
    transcript_retention TEXT NOT NULL CHECK (
        transcript_retention IN ('none','analyst_evidence')
    ),
    max_cost_microusd BIGINT NOT NULL CHECK (
        max_cost_microusd BETWEEN 0 AND 1000000000
    ),
    max_duration_seconds INTEGER NOT NULL CHECK (
        max_duration_seconds BETWEEN 1 AND 43200
    ),
    source_analyst_artifact_id UUID NOT NULL,
    source_content_sha256 BYTEA NOT NULL CHECK (
        octet_length(source_content_sha256) = 32
    ),
    admission_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(admission_evidence_sha256) = 32
    ),
    schedule_revision BIGINT NOT NULL CHECK (schedule_revision > 0),
    session_generation BIGINT NOT NULL DEFAULT 0 CHECK (session_generation >= 0),
    status TEXT NOT NULL DEFAULT 'scheduled' CHECK (
        status IN ('scheduled','joining','active','cancelled','expired','completed')
    ),
    activation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, meeting_id),
    UNIQUE (community_id, mailbox_identity_id, provider_event_id_sha256),
    FOREIGN KEY (community_id, mailbox_identity_id)
        REFERENCES snowman_meeting_mailboxes(community_id, mailbox_identity_id),
    FOREIGN KEY (community_id, meeting_agent_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (mailbox_identity_id <> meeting_agent_identity_id),
    CHECK (ends_at > starts_at AND ends_at <= starts_at + INTERVAL '12 hours'),
    CHECK (
        join_not_before <= starts_at AND
        join_not_after >= starts_at AND
        join_not_after > join_not_before AND
        join_not_after <= join_not_before + INTERVAL '30 minutes'
    ),
    CHECK (recording_enabled OR raw_audio_retention = 'none'),
    CHECK (
        NOT (voice_route = 'open_ai_realtime' OR speech_output_route = 'eleven_labs')
        OR (
            external_processing_allowed AND
            external_processing_consent_required
        )
    ),
    CHECK (
        data_class <> 'restricted' OR
        NOT (voice_route = 'open_ai_realtime' OR speech_output_route = 'eleven_labs') OR
        restricted_external_approval_sha256 IS NOT NULL
    ),
    CHECK (NOT activation_enabled OR voice_route <> 'disabled'),
    CHECK (status NOT IN ('joining','active') OR activation_enabled)
);

CREATE INDEX idx_snowman_meetings_join_due
    ON snowman_meetings (
        community_id, status, join_not_before, join_not_after, meeting_id
    )
    WHERE status = 'scheduled' AND activation_enabled;

CREATE TABLE snowman_meeting_commands (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    command_id UUID NOT NULL,
    meeting_id UUID NOT NULL,
    command_kind TEXT NOT NULL CHECK (
        command_kind IN ('schedule','reschedule','cancel','expire','complete')
    ),
    command_sha256 BYTEA NOT NULL CHECK (octet_length(command_sha256) = 32),
    provider_revision BIGINT NOT NULL CHECK (provider_revision > 0),
    result_schedule_revision BIGINT NOT NULL CHECK (result_schedule_revision > 0),
    evidence_sha256 BYTEA NOT NULL CHECK (octet_length(evidence_sha256) = 32),
    applied_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, command_id),
    FOREIGN KEY (community_id, meeting_id)
        REFERENCES snowman_meetings(community_id, meeting_id) ON DELETE CASCADE
);

CREATE INDEX idx_snowman_meeting_commands_evidence
    ON snowman_meeting_commands (
        community_id, meeting_id, result_schedule_revision, applied_at
    );

CREATE TABLE snowman_meeting_sessions (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    meeting_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    meeting_agent_identity_id UUID NOT NULL,
    voice_route TEXT NOT NULL CHECK (
        voice_route IN ('snowman_aws','open_ai_realtime')
    ),
    status TEXT NOT NULL CHECK (
        status IN ('joining','awaiting_consent','active','stopping','stopped','failed')
    ),
    consent_complete BOOLEAN NOT NULL DEFAULT FALSE,
    source_policy_sha256 BYTEA NOT NULL CHECK (
        octet_length(source_policy_sha256) = 32
    ),
    provider_session_id_sha256 BYTEA CHECK (
        provider_session_id_sha256 IS NULL OR
        octet_length(provider_session_id_sha256) = 32
    ),
    started_at TIMESTAMPTZ NOT NULL,
    media_activated_at TIMESTAMPTZ,
    stopped_at TIMESTAMPTZ,
    spent_microusd BIGINT NOT NULL DEFAULT 0 CHECK (spent_microusd >= 0),
    failure_code TEXT CHECK (
        failure_code IS NULL OR (
            length(failure_code) BETWEEN 3 AND 64 AND
            failure_code ~ '^[a-z][a-z0-9_]*$'
        )
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, session_id),
    UNIQUE (community_id, meeting_id, generation),
    UNIQUE (community_id, session_id, meeting_id, generation),
    FOREIGN KEY (community_id, meeting_id)
        REFERENCES snowman_meetings(community_id, meeting_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, meeting_agent_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    CHECK (media_activated_at IS NULL OR consent_complete),
    CHECK (media_activated_at IS NULL OR media_activated_at >= started_at),
    CHECK (stopped_at IS NULL OR stopped_at >= started_at)
);

CREATE INDEX idx_snowman_meeting_sessions_active
    ON snowman_meeting_sessions (
        community_id, status, started_at, session_id
    )
    WHERE status IN ('joining','awaiting_consent','active','stopping');

CREATE TABLE snowman_meeting_participant_consents (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    participant_subject_sha256 BYTEA NOT NULL CHECK (
        octet_length(participant_subject_sha256) = 32
    ),
    disclosure_evidence_sha256 BYTEA CHECK (
        disclosure_evidence_sha256 IS NULL OR
        octet_length(disclosure_evidence_sha256) = 32
    ),
    transcription_consent_sha256 BYTEA CHECK (
        transcription_consent_sha256 IS NULL OR
        octet_length(transcription_consent_sha256) = 32
    ),
    recording_consent_sha256 BYTEA CHECK (
        recording_consent_sha256 IS NULL OR
        octet_length(recording_consent_sha256) = 32
    ),
    external_processing_consent_sha256 BYTEA CHECK (
        external_processing_consent_sha256 IS NULL OR
        octet_length(external_processing_consent_sha256) = 32
    ),
    present BOOLEAN NOT NULL DEFAULT TRUE,
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, session_id, participant_subject_sha256),
    FOREIGN KEY (community_id, session_id)
        REFERENCES snowman_meeting_sessions(community_id, session_id) ON DELETE CASCADE
);

CREATE TABLE snowman_meeting_tool_intents (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    intent_id UUID NOT NULL,
    meeting_id UUID NOT NULL,
    session_id UUID NOT NULL,
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    service_identity_id UUID NOT NULL,
    intent_kind TEXT NOT NULL CHECK (
        intent_kind IN (
            'propose_action_item','clarify_owner','record_decision',
            'request_specialist_work'
        )
    ),
    intent_body BYTEA NOT NULL CHECK (
        octet_length(intent_body) BETWEEN 1 AND 32768
    ),
    intent_sha256 BYTEA NOT NULL CHECK (octet_length(intent_sha256) = 32),
    source_turn_sha256 BYTEA NOT NULL CHECK (
        octet_length(source_turn_sha256) = 32
    ),
    input_trust TEXT NOT NULL DEFAULT 'untrusted' CHECK (input_trust = 'untrusted'),
    status TEXT NOT NULL DEFAULT 'proposed' CHECK (
        status IN ('proposed','accepted','rejected','dispatched','completed','cancelled')
    ),
    workforce_request_id UUID,
    observed_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, intent_id),
    UNIQUE (community_id, session_id, intent_sha256),
    FOREIGN KEY (community_id, meeting_id)
        REFERENCES snowman_meetings(community_id, meeting_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, session_id, meeting_id, session_generation)
        REFERENCES snowman_meeting_sessions(
            community_id, session_id, meeting_id, generation
        ) ON DELETE CASCADE,
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    FOREIGN KEY (community_id, workforce_request_id)
        REFERENCES snowman_work_requests(community_id, request_id),
    CHECK (decided_at IS NULL OR decided_at >= observed_at),
    CHECK (status <> 'dispatched' OR workforce_request_id IS NOT NULL),
    CHECK (
        workforce_request_id IS NULL OR
        status IN ('dispatched','completed','cancelled')
    )
);

CREATE INDEX idx_snowman_meeting_tool_intents_pending
    ON snowman_meeting_tool_intents (
        community_id, status, observed_at, intent_id
    )
    WHERE status = 'proposed';
