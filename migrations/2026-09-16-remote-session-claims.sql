-- Serialize remote-session creation per endpoint. Application-side
-- check-then-insert is not sufficient when two browser tabs click together.

CREATE UNIQUE INDEX IF NOT EXISTS idx_remote_sessions_one_active_endpoint
    ON endpt.remote_sessions(endpoint_id)
    WHERE status = 'active';

CREATE OR REPLACE FUNCTION endpt.create_or_get_remote_session(
    p_endpoint_id UUID,
    p_company_id UUID,
    p_admin_id UUID DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
DECLARE
    v_session endpt.remote_sessions%ROWTYPE;
    v_created BOOLEAN := FALSE;
BEGIN
    -- The endpoint row is the per-endpoint mutex and also enforces tenant
    -- ownership before any remote-session record can be returned.
    PERFORM 1 FROM endpt.endpoints
     WHERE id = p_endpoint_id AND company_id = p_company_id AND is_active = TRUE
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;

    SELECT * INTO v_session FROM endpt.remote_sessions
     WHERE endpoint_id = p_endpoint_id AND status = 'active'
     ORDER BY started_at DESC LIMIT 1;

    IF NOT FOUND THEN
        INSERT INTO endpt.remote_sessions(endpoint_id, admin_id, company_id)
        VALUES (p_endpoint_id, p_admin_id, p_company_id)
        RETURNING * INTO v_session;
        v_created := TRUE;
    END IF;

    RETURN to_jsonb(v_session) || jsonb_build_object('_created', v_created);
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_or_get_remote_session(UUID, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_or_get_remote_session(UUID, UUID, UUID) TO service_role;

NOTIFY pgrst, 'reload schema';
