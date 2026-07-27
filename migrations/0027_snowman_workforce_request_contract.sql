-- Bind idempotency and launch evidence to the entire governed request contract,
-- including immutable context references and client-ready review requirements.
-- Legacy rows predate that contract and use the objective digest as an explicit
-- compatibility marker; a new caller cannot silently reinterpret them.

ALTER TABLE snowman_work_requests
    ADD COLUMN request_contract_sha256 BYTEA;

UPDATE snowman_work_requests
SET request_contract_sha256 = objective_sha256
WHERE request_contract_sha256 IS NULL;

ALTER TABLE snowman_work_requests
    ALTER COLUMN request_contract_sha256 SET NOT NULL,
    ADD CONSTRAINT snowman_work_requests_contract_digest
      CHECK (octet_length(request_contract_sha256) = 32);
