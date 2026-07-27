-- A worker-generated claim ID makes lease acquisition idempotent. The relay can
-- deterministically reissue the same bearer lease token after a lost response
-- without creating a second claim or extending the lease implicitly.

ALTER TABLE snowman_task_leases ADD COLUMN claim_id UUID;

UPDATE snowman_task_leases SET claim_id = task_id WHERE claim_id IS NULL;

ALTER TABLE snowman_task_leases ALTER COLUMN claim_id SET NOT NULL;

CREATE UNIQUE INDEX idx_snowman_task_leases_worker_claim
    ON snowman_task_leases (community_id, worker_identity_id, claim_id);

-- Spend receipts are also actor-bound so an exact ledger replay cannot be
-- reattributed to a replacement worker after lease turnover.
ALTER TABLE snowman_spend_ledger ADD COLUMN worker_identity_id UUID;

UPDATE snowman_spend_ledger s
SET worker_identity_id = t.service_identity_id
FROM snowman_work_tasks t
WHERE t.community_id=s.community_id AND t.task_id=s.task_id
  AND s.worker_identity_id IS NULL;

ALTER TABLE snowman_spend_ledger
    ALTER COLUMN worker_identity_id SET NOT NULL,
    ADD CONSTRAINT snowman_spend_ledger_worker_identity_fk
      FOREIGN KEY (community_id, worker_identity_id)
      REFERENCES snowman_workforce_identities(community_id, identity_id);
