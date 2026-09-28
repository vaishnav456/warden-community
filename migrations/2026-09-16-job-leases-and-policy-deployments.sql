-- Durable job delivery and transactional policy deployment batches.
-- Safe to apply repeatedly.

ALTER TABLE endpt.jobs
    ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS delivery_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE endpt.jobs
    ADD COLUMN IF NOT EXISTS result_processing_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS result_processed_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_jobs_lease_expiry
    ON endpt.jobs(endpoint_id, lease_expires_at)
    WHERE status = 'running';

CREATE TABLE IF NOT EXISTS endpt.policy_deployments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id       UUID NOT NULL REFERENCES endpt.branches(id) ON DELETE CASCADE,
    template_id     UUID REFERENCES endpt.policy_templates(id) ON DELETE SET NULL,
    template_name   TEXT NOT NULL,
    reason          TEXT,
    status          TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','cancelled')),
    targeted_count  INTEGER NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at    TIMESTAMPTZ
);

ALTER TABLE endpt.policy_deployments DROP CONSTRAINT IF EXISTS policy_deployments_status_check;
ALTER TABLE endpt.policy_deployments ADD CONSTRAINT policy_deployments_status_check
    CHECK (status IN ('active','paused','completed','cancelled'));

ALTER TABLE endpt.policy_deployments
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_deployments_idempotency
    ON endpt.policy_deployments(company_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_policy_deployments_company
    ON endpt.policy_deployments(company_id, created_at DESC);

CREATE TABLE IF NOT EXISTS endpt.policy_deployment_targets (
    deployment_id UUID NOT NULL REFERENCES endpt.policy_deployments(id) ON DELETE CASCADE,
    endpoint_id   UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    job_id        UUID NOT NULL UNIQUE REFERENCES endpt.jobs(id) ON DELETE CASCADE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_policy_deployment_targets_deployment
    ON endpt.policy_deployment_targets(deployment_id);

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
    RETURN QUERY
    WITH candidates AS (
        SELECT j.id
          FROM endpt.jobs j
         WHERE j.endpoint_id = p_endpoint_id
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

CREATE OR REPLACE FUNCTION endpt.claim_job_result_processing(p_job_id UUID)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
    UPDATE endpt.jobs SET result_processing_at=now()
     WHERE id=p_job_id AND status IN('completed','failed') AND result_processed_at IS NULL
       AND (result_processing_at IS NULL OR result_processing_at<now()-interval '60 seconds');
    RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION endpt.claim_job_result_processing(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_job_result_processing(UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.complete_job_result_processing(p_job_id UUID)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
    UPDATE endpt.jobs SET result_processed_at=now(),result_processing_at=NULL
     WHERE id=p_job_id AND result_processed_at IS NULL;
    RETURN FOUND;
END;
$$;
REVOKE ALL ON FUNCTION endpt.complete_job_result_processing(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.complete_job_result_processing(UUID) TO service_role;

DROP FUNCTION IF EXISTS endpt.create_policy_deployment(UUID, UUID, UUID, TEXT, TEXT, UUID, TEXT);
CREATE OR REPLACE FUNCTION endpt.create_policy_deployment(
    p_company_id UUID,
    p_branch_id UUID,
    p_template_id UUID,
    p_template_name TEXT,
    p_encrypted_payload TEXT,
    p_created_by UUID,
    p_reason TEXT DEFAULT NULL,
    p_idempotency_key TEXT DEFAULT NULL
)
RETURNS TABLE(deployment_id UUID, targeted INTEGER, queued INTEGER)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
DECLARE
    v_deployment_id UUID;
    v_endpoint RECORD;
    v_job_id UUID;
    v_targeted INTEGER := 0;
    v_queued INTEGER := 0;
BEGIN
    IF p_idempotency_key IS NOT NULL THEN
        PERFORM pg_advisory_xact_lock(hashtextextended(p_company_id::text || ':' || p_idempotency_key, 0));
        SELECT id, targeted_count INTO v_deployment_id, v_targeted
          FROM endpt.policy_deployments
         WHERE company_id = p_company_id AND idempotency_key = p_idempotency_key;
        IF FOUND THEN
            SELECT count(*) INTO v_queued FROM endpt.policy_deployment_targets
             WHERE deployment_id = v_deployment_id;
            RETURN QUERY SELECT v_deployment_id, v_targeted, v_queued;
            RETURN;
        END IF;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM endpt.branches
         WHERE id = p_branch_id AND company_id = p_company_id
    ) THEN
        RAISE EXCEPTION 'branch does not belong to company';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM endpt.policy_templates
         WHERE id = p_template_id AND company_id = p_company_id
    ) THEN
        RAISE EXCEPTION 'template does not belong to company';
    END IF;

    SELECT count(*) INTO v_targeted
      FROM endpt.endpoints
     WHERE company_id = p_company_id
       AND branch_id = p_branch_id
       AND is_active = TRUE;

    INSERT INTO endpt.policy_deployments (
        company_id, branch_id, template_id, template_name, reason,
        targeted_count, created_by, idempotency_key
    ) VALUES (
        p_company_id, p_branch_id, p_template_id, p_template_name, p_reason,
        v_targeted, p_created_by, p_idempotency_key
    ) RETURNING id INTO v_deployment_id;

    FOR v_endpoint IN
        SELECT id FROM endpt.endpoints
         WHERE company_id = p_company_id
           AND branch_id = p_branch_id
           AND is_active = TRUE
         ORDER BY hostname ASC
    LOOP
        INSERT INTO endpt.jobs (
            company_id, branch_id, endpoint_id, type, payload, status, created_by
        ) VALUES (
            p_company_id, p_branch_id, v_endpoint.id, 'PUSH_LOCAL_POLICY',
            p_encrypted_payload, 'pending', p_created_by
        ) RETURNING id INTO v_job_id;

        INSERT INTO endpt.policy_deployment_targets(deployment_id, endpoint_id, job_id)
        VALUES (v_deployment_id, v_endpoint.id, v_job_id);
        v_queued := v_queued + 1;
    END LOOP;

    RETURN QUERY SELECT v_deployment_id, v_targeted, v_queued;
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_policy_deployment(UUID, UUID, UUID, TEXT, TEXT, UUID, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_policy_deployment(UUID, UUID, UUID, TEXT, TEXT, UUID, TEXT, TEXT) TO service_role;

CREATE OR REPLACE FUNCTION endpt.cancel_policy_deployment(
    p_deployment_id UUID,
    p_company_id UUID
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
DECLARE
    v_cancelled INTEGER;
BEGIN
    UPDATE endpt.policy_deployments
       SET status = 'cancelled', cancelled_at = now()
     WHERE id = p_deployment_id AND company_id = p_company_id AND status = 'active';
    IF NOT FOUND THEN
        RETURN 0;
    END IF;

    UPDATE endpt.jobs j
       SET status = 'cancelled', completed_at = now(), lease_expires_at = NULL
      FROM endpt.policy_deployment_targets t
     WHERE t.deployment_id = p_deployment_id
       AND t.job_id = j.id
       AND j.status IN ('pending', 'approved');
    GET DIAGNOSTICS v_cancelled = ROW_COUNT;
    RETURN v_cancelled;
END;
$$;

REVOKE ALL ON FUNCTION endpt.cancel_policy_deployment(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.cancel_policy_deployment(UUID, UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.retry_policy_deployment(
    p_deployment_id UUID,
    p_company_id UUID
)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
DECLARE
    v_target RECORD;
    v_new_job_id UUID;
    v_retried INTEGER := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM endpt.policy_deployments
         WHERE id = p_deployment_id AND company_id = p_company_id
         FOR UPDATE
    ) THEN
        RETURN 0;
    END IF;

    FOR v_target IN
        SELECT t.endpoint_id, t.job_id, j.company_id, j.branch_id, j.type,
               j.payload, j.created_by
          FROM endpt.policy_deployment_targets t
          JOIN endpt.jobs j ON j.id = t.job_id
         WHERE t.deployment_id = p_deployment_id
           AND j.status IN ('failed','cancelled')
         FOR UPDATE OF t, j
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(v_target.company_id,v_target.branch_id,v_target.endpoint_id,v_target.type,
               v_target.payload,'pending',v_target.created_by)
        RETURNING id INTO v_new_job_id;
        UPDATE endpt.policy_deployment_targets
           SET job_id = v_new_job_id, created_at = now()
         WHERE deployment_id = p_deployment_id AND endpoint_id = v_target.endpoint_id;
        v_retried := v_retried + 1;
    END LOOP;

    IF v_retried > 0 THEN
        UPDATE endpt.policy_deployments
           SET status = 'active', cancelled_at = NULL
         WHERE id = p_deployment_id;
    END IF;
    RETURN v_retried;
END;
$$;

REVOKE ALL ON FUNCTION endpt.retry_policy_deployment(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.retry_policy_deployment(UUID, UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.maybe_pause_policy_deployment(p_job_id UUID)
RETURNS UUID LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE
    v_deployment_id UUID;
    v_targeted INTEGER;
    v_failed INTEGER;
BEGIN
    SELECT d.id,d.targeted_count INTO v_deployment_id,v_targeted
      FROM endpt.policy_deployment_targets t
      JOIN endpt.policy_deployments d ON d.id=t.deployment_id
     WHERE t.job_id=p_job_id AND d.status='active'
     FOR UPDATE OF d;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT count(*) INTO v_failed FROM endpt.policy_deployment_targets t
      JOIN endpt.jobs j ON j.id=t.job_id
     WHERE t.deployment_id=v_deployment_id AND j.status='failed';
    IF v_failed < 2 OR v_failed*100 < GREATEST(v_targeted,1)*20 THEN RETURN NULL; END IF;
    UPDATE endpt.policy_deployments SET status='paused' WHERE id=v_deployment_id;
    UPDATE endpt.jobs j SET status='cancelled',completed_at=now(),lease_expires_at=NULL
      FROM endpt.policy_deployment_targets t
     WHERE t.deployment_id=v_deployment_id AND t.job_id=j.id AND j.status IN('pending','approved');
    RETURN v_deployment_id;
END;
$$;
REVOKE ALL ON FUNCTION endpt.maybe_pause_policy_deployment(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.maybe_pause_policy_deployment(UUID) TO service_role;

CREATE OR REPLACE FUNCTION endpt.get_policy_deployment_summaries(
    p_company_id UUID, p_limit INTEGER DEFAULT 20
)
RETURNS TABLE(
    id UUID, company_id UUID, branch_id UUID, branch_name TEXT,
    template_name TEXT, status TEXT, targeted_count INTEGER,
    pending BIGINT, running BIGINT, completed BIGINT, failed BIGINT,
    cancelled BIGINT, created_at TIMESTAMPTZ
)
LANGUAGE sql SECURITY DEFINER SET search_path=endpt,public AS $$
    SELECT d.id,d.company_id,d.branch_id,b.name,d.template_name,d.status,d.targeted_count,
           count(*) FILTER(WHERE j.status IN('pending','approved')),
           count(*) FILTER(WHERE j.status='running'),
           count(*) FILTER(WHERE j.status='completed'),
           count(*) FILTER(WHERE j.status='failed'),
           count(*) FILTER(WHERE j.status='cancelled'),d.created_at
      FROM endpt.policy_deployments d
      JOIN endpt.branches b ON b.id=d.branch_id
      LEFT JOIN endpt.policy_deployment_targets t ON t.deployment_id=d.id
      LEFT JOIN endpt.jobs j ON j.id=t.job_id
     WHERE d.company_id=p_company_id
     GROUP BY d.id,b.name
     ORDER BY d.created_at DESC
     LIMIT LEAST(GREATEST(p_limit,1),100);
$$;
REVOKE ALL ON FUNCTION endpt.get_policy_deployment_summaries(UUID,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.get_policy_deployment_summaries(UUID,INTEGER) TO service_role;

CREATE OR REPLACE FUNCTION endpt.refresh_policy_deployment_status(p_job_id UUID)
RETURNS TEXT LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_deployment_id UUID; v_status TEXT; v_open INTEGER;
BEGIN
    SELECT d.id,d.status INTO v_deployment_id,v_status
      FROM endpt.policy_deployment_targets t JOIN endpt.policy_deployments d ON d.id=t.deployment_id
     WHERE t.job_id=p_job_id FOR UPDATE OF d;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT count(*) INTO v_open FROM endpt.policy_deployment_targets t JOIN endpt.jobs j ON j.id=t.job_id
     WHERE t.deployment_id=v_deployment_id AND j.status IN('pending','approved','running');
    IF v_open=0 AND v_status='active' THEN
        UPDATE endpt.policy_deployments SET status='completed' WHERE id=v_deployment_id;
        RETURN 'completed';
    END IF;
    RETURN v_status;
END;
$$;
REVOKE ALL ON FUNCTION endpt.refresh_policy_deployment_status(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.refresh_policy_deployment_status(UUID) TO service_role;

NOTIFY pgrst, 'reload schema';
