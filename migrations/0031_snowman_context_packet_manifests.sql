-- Evidence-linked, bounded context manifests let replacement specialists resume
-- work without copying raw client datasets or unbounded transcripts into the
-- command center. The content itself remains behind an immutable Snowman or
-- Analyst 360 artifact coordinate.

CREATE TABLE snowman_context_packet_manifests (
    community_id UUID NOT NULL,
    context_packet_id UUID NOT NULL,
    request_id UUID NOT NULL,
    created_by_identity_id UUID NOT NULL,
    objective_sha256 BYTEA NOT NULL CHECK (octet_length(objective_sha256) = 32),
    content_reference TEXT NOT NULL CHECK (
        content_reference ~ '^(analyst360|snowman):sha256:[0-9a-f]{64}$'
    ),
    source_event_sha256 BYTEA NOT NULL CHECK (octet_length(source_event_sha256) = 32),
    manifest_sha256 BYTEA NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    artifact_references TEXT[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(artifact_references) <= 128
    ),
    evidence_references TEXT[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(evidence_references) <= 128
    ),
    decision_digests TEXT[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(decision_digests) <= 64
    ),
    open_question_digests TEXT[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(open_question_digests) <= 64
    ),
    next_actions JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (
        jsonb_typeof(next_actions) = 'array' AND jsonb_array_length(next_actions) <= 32
    ),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, context_packet_id),
    FOREIGN KEY (community_id, request_id, context_packet_id)
        REFERENCES snowman_context_packets(community_id, request_id, context_packet_id)
        ON DELETE CASCADE,
    FOREIGN KEY (community_id, created_by_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id)
);

CREATE INDEX idx_snowman_context_packet_manifests_request
    ON snowman_context_packet_manifests (community_id, request_id, created_at);
