-- Prevent endpoint-specific schedules from becoming company-wide after the
-- endpoint is deleted, and atomically claim due schedules before dispatch.

ALTER TABLE endpt.scheduled_jobs
    DROP CONSTRAINT IF EXISTS scheduled_jobs_endpoint_id_fkey;
ALTER TABLE endpt.scheduled_jobs
    ADD CONSTRAINT scheduled_jobs_endpoint_id_fkey
    FOREIGN KEY (endpoint_id) REFERENCES endpt.endpoints(id) ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION endpt.claim_due_scheduled_jobs(p_limit INTEGER DEFAULT 100)
RETURNS SETOF endpt.scheduled_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
BEGIN
    RETURN QUERY
    WITH due AS (
        SELECT s.id
          FROM endpt.scheduled_jobs s
         WHERE s.enabled = TRUE
           AND s.next_run_at <= now()
         ORDER BY s.next_run_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT LEAST(GREATEST(p_limit, 1), 500)
    )
    UPDATE endpt.scheduled_jobs s
       SET last_run_at = now(),
           next_run_at = now() + make_interval(
               secs => LEAST(GREATEST(s.interval_seconds, 3600), 31536000)
           )
      FROM due
     WHERE s.id = due.id
    RETURNING s.*;
END;
$$;

REVOKE ALL ON FUNCTION endpt.claim_due_scheduled_jobs(INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_due_scheduled_jobs(INTEGER) TO service_role;

NOTIFY pgrst, 'reload schema';
