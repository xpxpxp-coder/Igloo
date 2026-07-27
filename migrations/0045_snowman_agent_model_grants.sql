-- Domain-separated model credentials for one-shot agent jobs. Only the token
-- digest is durable; plaintext credentials and model content are never stored.

ALTER TABLE snowman_agent_jobs
    ADD COLUMN model_token_sha256 BYTEA;

ALTER TABLE snowman_agent_jobs
    ADD CONSTRAINT snowman_agent_jobs_model_token_digest
    CHECK (
        model_token_sha256 IS NULL OR octet_length(model_token_sha256) = 32
    );

CREATE INDEX idx_snowman_agent_jobs_model_authority
    ON snowman_agent_jobs (community_id, job_id, status, deadline_at)
    WHERE model_token_sha256 IS NOT NULL;
