-- Preserve the authority-local artifact contract across specialist handoffs.
-- Existing rows predate the explicit field and receive the bounded generic
-- type; every new publisher must supply the exact immutable artifact type.
ALTER TABLE snowman_context_packets
    ADD COLUMN artifact_type TEXT NOT NULL DEFAULT 'governed_work_product'
    CHECK (length(artifact_type) BETWEEN 1 AND 128);

ALTER TABLE snowman_context_packets
    ALTER COLUMN artifact_type DROP DEFAULT;
