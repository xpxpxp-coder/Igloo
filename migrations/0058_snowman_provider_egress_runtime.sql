-- Tenant-scoped, content-free replay/cancellation/receipt authority for the
-- Snowman provider-egress runtime. Raw provider bodies, audio, transcripts,
-- prompts, headers, URLs, credentials, and provider responses are deliberately
-- not representable in these tables.

CREATE TABLE snowman_provider_egress_cancellations (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    session_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    principal_id TEXT NOT NULL CHECK (principal_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    reason_sha256 BYTEA NOT NULL CHECK (octet_length(reason_sha256) = 32),
    cancelled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, session_id, generation),
    FOREIGN KEY (community_id, session_id)
        REFERENCES snowman_meeting_media_sessions(community_id, media_session_id)
        ON DELETE RESTRICT
);

CREATE TABLE snowman_provider_egress_requests (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    request_id UUID NOT NULL,
    session_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256) = 32),
    provider TEXT NOT NULL CHECK (provider IN ('twilio','open_ai','eleven_labs')),
    purpose TEXT NOT NULL CHECK (purpose ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    classification TEXT NOT NULL CHECK (classification ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    budget_microusd BIGINT NOT NULL CHECK (budget_microusd > 0),
    policy_generation BIGINT NOT NULL CHECK (policy_generation > 0),
    destination_id TEXT NOT NULL CHECK (destination_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
    status TEXT NOT NULL CHECK (status IN (
        'claimed','succeeded','provider_rejected','cancelled','expired',
        'pre_dispatch_denied','indeterminate'
    )),
    response_sha256 BYTEA CHECK (response_sha256 IS NULL OR octet_length(response_sha256) = 32),
    response_bytes BIGINT NOT NULL DEFAULT 0 CHECK (response_bytes >= 0),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deadline TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (community_id, request_id),
    FOREIGN KEY (community_id, session_id)
        REFERENCES snowman_meeting_media_sessions(community_id, media_session_id)
        ON DELETE RESTRICT,
    CHECK (deadline > claimed_at),
    CHECK ((status = 'claimed') = (completed_at IS NULL)),
    CHECK ((status = 'succeeded') = (response_sha256 IS NOT NULL)),
    CHECK (status = 'succeeded' OR response_bytes = 0)
);

CREATE INDEX idx_snowman_provider_egress_session_fence
    ON snowman_provider_egress_requests (
        community_id, session_id, generation, claimed_at
    );

CREATE TABLE snowman_provider_egress_receipt_events (
    community_id UUID NOT NULL,
    request_id UUID NOT NULL,
    transition TEXT NOT NULL CHECK (transition IN ('dispatched','completed')),
    receipt_sha256 BYTEA NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    status TEXT NOT NULL CHECK (status IN (
        'succeeded','provider_rejected','cancelled','expired',
        'pre_dispatch_denied','indeterminate'
    )),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, request_id, transition),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_provider_egress_requests(community_id, request_id)
        ON DELETE RESTRICT
);

ALTER TABLE snowman_provider_egress_cancellations ENABLE ROW LEVEL SECURITY;
ALTER TABLE snowman_provider_egress_cancellations FORCE ROW LEVEL SECURITY;
ALTER TABLE snowman_provider_egress_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE snowman_provider_egress_requests FORCE ROW LEVEL SECURITY;
ALTER TABLE snowman_provider_egress_receipt_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE snowman_provider_egress_receipt_events FORCE ROW LEVEL SECURITY;

CREATE POLICY snowman_provider_egress_cancellations_tenant
    ON snowman_provider_egress_cancellations
    USING (community_id = NULLIF(current_setting('snowman.tenant_id', true), '')::UUID)
    WITH CHECK (community_id = NULLIF(current_setting('snowman.tenant_id', true), '')::UUID);
CREATE POLICY snowman_provider_egress_requests_tenant
    ON snowman_provider_egress_requests
    USING (community_id = NULLIF(current_setting('snowman.tenant_id', true), '')::UUID)
    WITH CHECK (community_id = NULLIF(current_setting('snowman.tenant_id', true), '')::UUID);
CREATE POLICY snowman_provider_egress_receipts_tenant
    ON snowman_provider_egress_receipt_events
    USING (community_id = NULLIF(current_setting('snowman.tenant_id', true), '')::UUID)
    WITH CHECK (community_id = NULLIF(current_setting('snowman.tenant_id', true), '')::UUID);
