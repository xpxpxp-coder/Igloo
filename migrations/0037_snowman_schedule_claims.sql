-- Bind retryable schedule claims to the exact trigger identity and close the
-- occurrence automatically when its proactive decision is committed.

ALTER TABLE snowman_work_schedule_occurrences
    ADD COLUMN trigger_identity_id UUID;

UPDATE snowman_work_schedule_occurrences o
SET trigger_identity_id = s.trigger_identity_id
FROM snowman_work_schedules s
WHERE s.community_id=o.community_id AND s.schedule_id=o.schedule_id;

ALTER TABLE snowman_work_schedule_occurrences
    ALTER COLUMN trigger_identity_id SET NOT NULL,
    ADD COLUMN claim_id UUID;

ALTER TABLE snowman_work_schedule_occurrences
    ADD CONSTRAINT snowman_schedule_occurrences_trigger_fk
    FOREIGN KEY (community_id, trigger_identity_id)
    REFERENCES snowman_workforce_identities(community_id, identity_id);

CREATE UNIQUE INDEX idx_snowman_schedule_occurrences_claim_id
    ON snowman_work_schedule_occurrences (community_id, trigger_identity_id, claim_id)
    WHERE claim_id IS NOT NULL;

CREATE FUNCTION snowman_submit_schedule_occurrence()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE snowman_work_schedule_occurrences
       SET status='submitted', updated_at=NEW.created_at
     WHERE community_id=NEW.community_id
       AND action_id=NEW.action_id
       AND status='claimed';
    IF NEW.status = 'rejected' THEN
        UPDATE snowman_work_schedules s
           SET status='paused', updated_at=NEW.created_at
         WHERE s.community_id=NEW.community_id
           AND s.status='active'
           AND EXISTS (
             SELECT 1 FROM snowman_work_schedule_occurrences o
             WHERE o.community_id=NEW.community_id
               AND o.schedule_id=s.schedule_id
               AND o.action_id=NEW.action_id
           );
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_snowman_submit_schedule_occurrence
AFTER INSERT ON snowman_proactive_actions
FOR EACH ROW
EXECUTE FUNCTION snowman_submit_schedule_occurrence();
