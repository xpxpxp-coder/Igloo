-- Externally anchored audit checkpoints contain only exact tenant identifiers,
-- sequence/root/preceding-checkpoint/build/schema digests, KMS coordinates, and
-- immutable S3 version coordinates. They never contain audit detail, event
-- bodies, messages, prompts, transcripts, emails, meeting coordinates or PII.

CREATE TABLE snowman_audit_checkpoint_requests (
    community_id                 UUID NOT NULL REFERENCES communities(id),
    sequence                     BIGINT NOT NULL CHECK (sequence > 0),
    chain_root_sha256            BYTEA NOT NULL CHECK (octet_length(chain_root_sha256) = 32),
    previous_checkpoint_sha256   BYTEA CHECK (
        previous_checkpoint_sha256 IS NULL OR octet_length(previous_checkpoint_sha256) = 32
    ),
    signed_at                    TEXT NOT NULL CHECK (
        signed_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$'
    ),
    build_sha256                 BYTEA NOT NULL CHECK (octet_length(build_sha256) = 32),
    database_schema_sha256       BYTEA NOT NULL CHECK (octet_length(database_schema_sha256) = 32),
    signing_key_arn              TEXT NOT NULL CHECK (
        signing_key_arn ~ '^arn:aws(-us-gov)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$'
    ),
    requested_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, sequence),
    UNIQUE (community_id, sequence, chain_root_sha256),
    CHECK (
        (sequence = 1 AND previous_checkpoint_sha256 IS NULL)
        OR sequence > 1
    )
);

CREATE TABLE snowman_audit_checkpoint_publications (
    community_id                 UUID NOT NULL REFERENCES communities(id),
    sequence                     BIGINT NOT NULL CHECK (sequence > 0),
    checkpoint_sha256            BYTEA NOT NULL CHECK (octet_length(checkpoint_sha256) = 32),
    previous_checkpoint_sha256   BYTEA CHECK (
        previous_checkpoint_sha256 IS NULL OR octet_length(previous_checkpoint_sha256) = 32
    ),
    object_key                   TEXT NOT NULL CHECK (
        object_key ~ '^checkpoints/[0-9a-f-]{36}/[0-9]{20}-[0-9a-f]{64}\.json$'
    ),
    object_version_id            TEXT NOT NULL CHECK (
        length(object_version_id) BETWEEN 1 AND 1024
        AND object_version_id !~ '[[:cntrl:]]'
    ),
    kms_key_arn                  TEXT NOT NULL CHECK (
        kms_key_arn ~ '^arn:aws(-us-gov)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+$'
    ),
    signed_at                    TEXT NOT NULL CHECK (
        signed_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$'
    ),
    recorded_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, sequence, checkpoint_sha256),
    UNIQUE (community_id, object_key, object_version_id),
    FOREIGN KEY (community_id, sequence)
        REFERENCES snowman_audit_checkpoint_requests(community_id, sequence)
);

CREATE OR REPLACE FUNCTION snowman_reject_audit_checkpoint_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit checkpoint evidence is append-only';
END;
$$;

CREATE TRIGGER snowman_audit_checkpoint_requests_append_only
BEFORE UPDATE OR DELETE ON snowman_audit_checkpoint_requests
FOR EACH ROW EXECUTE FUNCTION snowman_reject_audit_checkpoint_mutation();

CREATE TRIGGER snowman_audit_checkpoint_publications_append_only
BEFORE UPDATE OR DELETE ON snowman_audit_checkpoint_publications
FOR EACH ROW EXECUTE FUNCTION snowman_reject_audit_checkpoint_mutation();

REVOKE ALL ON snowman_audit_checkpoint_requests FROM PUBLIC;
REVOKE ALL ON snowman_audit_checkpoint_publications FROM PUBLIC;
