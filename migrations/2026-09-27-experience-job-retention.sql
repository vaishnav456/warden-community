-- Expire device-experience deployments that were not collected within 72 hours.
ALTER TABLE endpt.jobs ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_jobs_pending_expiry
    ON endpt.jobs(expires_at)
    WHERE status IN ('pending', 'approved', 'running') AND expires_at IS NOT NULL;

CREATE OR REPLACE FUNCTION endpt.claim_jobs_for_endpoint(
    p_endpoint_id UUID,
    p_limit INTEGER DEFAULT 5,
    p_lease_seconds INTEGER DEFAULT 900
)
RETURNS SETOF endpt.jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
BEGIN
    UPDATE endpt.jobs j
       SET status = 'failed', completed_at = now(), exit_code = 408,
           lease_expires_at = NULL
     WHERE j.endpoint_id = p_endpoint_id
       AND j.expires_at IS NOT NULL AND j.expires_at <= now()
       AND (j.status IN ('pending', 'approved') OR
            (j.status = 'running' AND
             (j.lease_expires_at IS NULL OR j.lease_expires_at <= now())));

    RETURN QUERY
    WITH candidates AS (
        SELECT j.id
          FROM endpt.jobs j
         WHERE j.endpoint_id = p_endpoint_id
           AND (j.expires_at IS NULL OR j.expires_at > now())
           AND (
                j.status IN ('pending', 'approved')
                OR (j.status = 'running' AND
                    (j.lease_expires_at IS NULL OR j.lease_expires_at <= now()))
           )
         ORDER BY j.priority DESC, j.created_at ASC
         FOR UPDATE SKIP LOCKED
         LIMIT LEAST(GREATEST(p_limit, 1), 20)
    )
    UPDATE endpt.jobs j
       SET status = 'running',
           started_at = COALESCE(j.started_at, now()),
           delivered_at = now(),
           lease_expires_at = now() + make_interval(secs => LEAST(GREATEST(p_lease_seconds, 60), 3600)),
           delivery_attempts = j.delivery_attempts + 1
      FROM candidates c
     WHERE j.id = c.id
    RETURNING j.*;
END;
$$;

REVOKE ALL ON FUNCTION endpt.claim_jobs_for_endpoint(UUID, INTEGER, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_jobs_for_endpoint(UUID, INTEGER, INTEGER) TO service_role;
