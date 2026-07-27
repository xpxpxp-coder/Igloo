-- Bind every non-rejected proactive decision to an ordinary governed work task.
-- The existing fenced lease, approval, spend, context, cancellation, recovery,
-- and evidence machinery remains the sole execution authority.

ALTER TABLE snowman_proactive_actions
    ADD COLUMN task_id UUID;

ALTER TABLE snowman_proactive_actions
    ADD CONSTRAINT snowman_proactive_actions_task_fk
    FOREIGN KEY (community_id, request_id, task_id)
    REFERENCES snowman_work_tasks(community_id, request_id, task_id)
    ON DELETE CASCADE;

ALTER TABLE snowman_proactive_actions
    DROP CONSTRAINT snowman_proactive_actions_status_check;

ALTER TABLE snowman_proactive_actions
    ADD CONSTRAINT snowman_proactive_actions_status_check CHECK (status IN (
        'queued', 'awaiting_approval', 'rejected', 'leased', 'running',
        'reviewing', 'succeeded', 'failed', 'cancelled', 'expired',
        'dead_lettered'
    ));

ALTER TABLE snowman_proactive_actions
    ADD CONSTRAINT snowman_proactive_actions_task_decision_check CHECK (
        (decision = 'reject' AND task_id IS NULL AND status = 'rejected')
        OR (decision <> 'reject' AND task_id IS NOT NULL AND status <> 'rejected')
    );

CREATE FUNCTION snowman_sync_proactive_task_status()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE snowman_proactive_actions
       SET status = NEW.status
     WHERE community_id = NEW.community_id
       AND task_id = NEW.task_id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_snowman_sync_proactive_task_status
AFTER UPDATE OF status ON snowman_work_tasks
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION snowman_sync_proactive_task_status();

CREATE INDEX idx_snowman_proactive_actions_task
    ON snowman_proactive_actions (community_id, request_id, task_id)
    WHERE task_id IS NOT NULL;
