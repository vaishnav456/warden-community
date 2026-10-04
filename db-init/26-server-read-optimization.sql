-- Apply before enabling aggregate dashboard reads. No device jobs are issued.
-- Index creation takes table write locks: schedule on populated deployments.
CREATE INDEX IF NOT EXISTS idx_jobs_dashboard_scope
    ON endpt.jobs (company_id, branch_id, status, created_at DESC)
    WHERE status IN ('pending', 'running', 'failed');
CREATE INDEX IF NOT EXISTS idx_alerts_dashboard_scope
    ON endpt.alerts (company_id, branch_id, snoozed_until, severity)
    WHERE is_resolved = false;
CREATE INDEX IF NOT EXISTS idx_escalations_dashboard_scope
    ON endpt.escalation_requests (company_id, branch_id, expires_at)
    WHERE status IN ('pending', 'pending_secondary');

CREATE OR REPLACE FUNCTION endpt.dashboard_counts(
    p_company_id uuid, p_branch_id uuid DEFAULT NULL,
    p_now timestamptz DEFAULT CURRENT_TIMESTAMP
) RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER
SET search_path = endpt, pg_temp AS $$
    SELECT jsonb_build_object(
        'pending_escalations', e.pending,
        'open_alerts', a.open, 'critical_alerts', a.critical,
        'failed_jobs', j.failed, 'pending_jobs', j.pending, 'running_jobs', j.running
    )
    FROM (
        SELECT count(*) AS pending FROM endpt.escalation_requests
        WHERE company_id = p_company_id
          AND (p_branch_id IS NULL OR branch_id = p_branch_id)
          AND status IN ('pending', 'pending_secondary') AND expires_at > p_now
    ) e
    CROSS JOIN (
        SELECT count(*) AS open, count(*) FILTER (WHERE severity = 'critical') AS critical
        FROM endpt.alerts WHERE company_id = p_company_id
          AND (p_branch_id IS NULL OR branch_id = p_branch_id)
          AND is_resolved = false AND (snoozed_until IS NULL OR snoozed_until <= p_now)
    ) a
    CROSS JOIN (
        SELECT count(*) FILTER (WHERE status = 'failed' AND created_at >= p_now - interval '24 hours') AS failed,
               count(*) FILTER (WHERE status = 'pending') AS pending,
               count(*) FILTER (WHERE status = 'running') AS running
        FROM endpt.jobs WHERE company_id = p_company_id
          AND (p_branch_id IS NULL OR branch_id = p_branch_id)
          AND status IN ('pending', 'running', 'failed')
    ) j;
$$;
REVOKE ALL ON FUNCTION endpt.dashboard_counts(uuid, uuid, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.dashboard_counts(uuid, uuid, timestamptz) TO service_role;
