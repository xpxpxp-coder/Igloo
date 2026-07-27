-- Repeated automation must fail safe. A failed, expired, or dead-lettered
-- materialized occurrence pauses its parent schedule before request status is
-- refreshed, requiring a human to review before more work can be generated.

CREATE FUNCTION snowman_pause_schedule_on_occurrence_failure()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status IN ('failed','expired','dead_lettered') THEN
        UPDATE snowman_work_schedules s
           SET status='paused', updated_at=NOW()
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

CREATE TRIGGER trg_snowman_pause_schedule_on_occurrence_failure
AFTER UPDATE OF status ON snowman_proactive_actions
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status)
EXECUTE FUNCTION snowman_pause_schedule_on_occurrence_failure();
