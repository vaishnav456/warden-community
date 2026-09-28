-- Durable security rate limits and tamper-evident audit chain.
CREATE TABLE IF NOT EXISTS endpt.security_rate_limits (
    bucket_key TEXT PRIMARY KEY,
    window_started TIMESTAMPTZ NOT NULL DEFAULT now(),
    request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS security_rate_limits_updated_idx
    ON endpt.security_rate_limits(updated_at);

CREATE OR REPLACE FUNCTION endpt.consume_rate_limit(
    p_bucket_key TEXT,
    p_max_requests INTEGER,
    p_window_seconds INTEGER DEFAULT 60
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, pg_temp
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    IF length(p_bucket_key) < 16 OR p_max_requests < 1 OR p_window_seconds < 1 THEN
        RETURN FALSE;
    END IF;

    INSERT INTO endpt.security_rate_limits AS limits
        (bucket_key, window_started, request_count, updated_at)
    VALUES (p_bucket_key, now(), 1, now())
    ON CONFLICT (bucket_key) DO UPDATE SET
        request_count = CASE
            WHEN limits.window_started <= now() - make_interval(secs => p_window_seconds)
                THEN 1
            ELSE limits.request_count + 1
        END,
        window_started = CASE
            WHEN limits.window_started <= now() - make_interval(secs => p_window_seconds)
                THEN now()
            ELSE limits.window_started
        END,
        updated_at = now()
    RETURNING request_count INTO v_count;

    RETURN v_count <= p_max_requests;
END;
$$;

ALTER TABLE endpt.audit_log
    ADD COLUMN IF NOT EXISTS prev_hash TEXT,
    ADD COLUMN IF NOT EXISTS row_hash TEXT;

DROP TRIGGER IF EXISTS audit_log_hash_before_insert ON endpt.audit_log;
DROP FUNCTION IF EXISTS endpt.set_audit_log_hash();

DO $$
DECLARE
    audit_row RECORD;
    previous_hash TEXT := NULL;
    calculated_hash TEXT;
BEGIN
    FOR audit_row IN
        SELECT id, company_id, branch_id, endpoint_id, actor_id, escalation_id,
               action, detail, created_at
        FROM endpt.audit_log
        ORDER BY created_at, id
    LOOP
        calculated_hash := encode(public.digest(convert_to(concat_ws('|',
            coalesce(previous_hash, ''),
            audit_row.id::text,
            coalesce(audit_row.company_id::text, ''),
            coalesce(audit_row.branch_id::text, ''),
            coalesce(audit_row.endpoint_id::text, ''),
            coalesce(audit_row.actor_id::text, ''),
            coalesce(audit_row.escalation_id::text, ''),
            audit_row.action,
            audit_row.detail::text,
            audit_row.created_at::text
        ), 'UTF8'), 'sha256'), 'hex');

        UPDATE endpt.audit_log
        SET prev_hash = previous_hash, row_hash = calculated_hash
        WHERE id = audit_row.id;
        previous_hash := calculated_hash;
    END LOOP;
END;
$$;

CREATE FUNCTION endpt.set_audit_log_hash()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, pg_temp
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('endpt.audit_log.hash_chain'));

    SELECT row_hash INTO NEW.prev_hash
    FROM endpt.audit_log
    ORDER BY created_at DESC, id DESC
    LIMIT 1;

    NEW.row_hash := encode(public.digest(convert_to(concat_ws('|',
        coalesce(NEW.prev_hash, ''),
        NEW.id::text,
        coalesce(NEW.company_id::text, ''),
        coalesce(NEW.branch_id::text, ''),
        coalesce(NEW.endpoint_id::text, ''),
        coalesce(NEW.actor_id::text, ''),
        coalesce(NEW.escalation_id::text, ''),
        NEW.action,
        NEW.detail::text,
        NEW.created_at::text
    ), 'UTF8'), 'sha256'), 'hex');
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_log_hash_before_insert
BEFORE INSERT ON endpt.audit_log
FOR EACH ROW EXECUTE FUNCTION endpt.set_audit_log_hash();

CREATE OR REPLACE FUNCTION endpt.verify_audit_chain()
RETURNS JSONB
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = endpt, pg_temp
AS $$
WITH ordered AS (
    SELECT audit_log.*,
           lag(row_hash) OVER (ORDER BY created_at, id) AS expected_prev
    FROM endpt.audit_log
),
checked AS (
    SELECT *,
        encode(public.digest(convert_to(concat_ws('|',
            coalesce(expected_prev, ''),
            id::text,
            coalesce(company_id::text, ''),
            coalesce(branch_id::text, ''),
            coalesce(endpoint_id::text, ''),
            coalesce(actor_id::text, ''),
            coalesce(escalation_id::text, ''),
            action,
            detail::text,
            created_at::text
        ), 'UTF8'), 'sha256'), 'hex') AS expected_hash
    FROM ordered
)
SELECT jsonb_build_object(
    'rows', count(*),
    'broken', count(*) FILTER (
        WHERE prev_hash IS DISTINCT FROM expected_prev
           OR row_hash IS DISTINCT FROM expected_hash
    ),
    'valid', count(*) FILTER (
        WHERE prev_hash IS DISTINCT FROM expected_prev
           OR row_hash IS DISTINCT FROM expected_hash
    ) = 0,
    'verified_at', now()
)
FROM checked;
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.security_rate_limits TO service_role;
REVOKE ALL ON FUNCTION endpt.consume_rate_limit(TEXT, INTEGER, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.consume_rate_limit(TEXT, INTEGER, INTEGER) TO service_role;
REVOKE ALL ON FUNCTION endpt.verify_audit_chain() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.verify_audit_chain() TO service_role;

-- Audit rows are append-only for the application identity. Referential actions
-- remain database-owned, while PostgREST cannot directly mutate or erase evidence.
REVOKE UPDATE, DELETE, TRUNCATE ON endpt.audit_log FROM service_role;

NOTIFY pgrst, 'reload schema';
