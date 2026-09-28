-- Restore a claimed enrollment-token use when enrollment fails before an
-- endpoint is created. Safe to apply repeatedly.
CREATE OR REPLACE FUNCTION endpt.release_enrollment_token_use(p_token_id UUID)
RETURNS BOOLEAN AS $$
DECLARE
    v_use_count  INTEGER;
    v_max_uses   INTEGER;
    v_expires_at TIMESTAMPTZ;
BEGIN
    SELECT use_count, max_uses, expires_at
      INTO v_use_count, v_max_uses, v_expires_at
      FROM endpt.enrollment_tokens
     WHERE id = p_token_id
     FOR UPDATE;

    IF NOT FOUND OR v_use_count <= 0 THEN
        RETURN FALSE;
    END IF;

    UPDATE endpt.enrollment_tokens
       SET use_count = v_use_count - 1,
           is_active = v_expires_at > now()
                       AND (v_max_uses IS NULL OR v_use_count - 1 < v_max_uses)
     WHERE id = p_token_id;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

GRANT EXECUTE ON FUNCTION endpt.release_enrollment_token_use(UUID) TO service_role;

-- A support-link use is claimed before its session/job is created. Return
-- that use on a downstream failure so a transient database error does not
-- permanently consume a customer's limited-use link.
CREATE OR REPLACE FUNCTION endpt.release_remote_support_link_claim(p_link_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = endpt, public
AS $$
BEGIN
    UPDATE endpt.remote_support_links
       SET use_count = use_count - 1
     WHERE id = p_link_id
       AND use_count > 0;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION endpt.release_remote_support_link_claim(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.release_remote_support_link_claim(UUID) TO service_role;
NOTIFY pgrst, 'reload schema';
