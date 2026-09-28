-- Server-authoritative idle/absolute expiry, atomic refresh rotation, replay
-- response, and concurrent-session limiting.
ALTER TABLE endpt.refresh_tokens
    ADD COLUMN IF NOT EXISTS family_id UUID,
    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS absolute_expires_at TIMESTAMPTZ;

UPDATE endpt.refresh_tokens
   SET family_id = COALESCE(family_id, gen_random_uuid()),
       last_used_at = COALESCE(last_used_at, created_at),
       absolute_expires_at = COALESCE(absolute_expires_at, expires_at)
 WHERE family_id IS NULL OR last_used_at IS NULL OR absolute_expires_at IS NULL;

ALTER TABLE endpt.refresh_tokens
    ALTER COLUMN family_id SET DEFAULT gen_random_uuid(),
    ALTER COLUMN family_id SET NOT NULL,
    ALTER COLUMN last_used_at SET DEFAULT now(),
    ALTER COLUMN last_used_at SET NOT NULL,
    ALTER COLUMN absolute_expires_at SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON endpt.refresh_tokens(family_id);

CREATE OR REPLACE FUNCTION endpt.create_refresh_session(
    p_admin_id UUID, p_token_hash TEXT, p_ip_address TEXT,
    p_user_agent TEXT, p_expires_at TIMESTAMPTZ,
    p_absolute_expires_at TIMESTAMPTZ, p_max_sessions INTEGER
) RETURNS SETOF endpt.refresh_tokens
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, pg_temp AS $$
DECLARE created endpt.refresh_tokens%ROWTYPE;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtextextended(p_admin_id::text, 0));
    INSERT INTO endpt.refresh_tokens(
        admin_id, token_hash, ip_address, user_agent, expires_at,
        absolute_expires_at, family_id, last_used_at
    ) VALUES (
        p_admin_id, p_token_hash, p_ip_address, left(COALESCE(p_user_agent, ''), 500),
        p_expires_at, p_absolute_expires_at, gen_random_uuid(), now()
    ) RETURNING * INTO created;

    IF p_max_sessions > 0 THEN
        UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
         WHERE id IN (
             SELECT id FROM endpt.refresh_tokens
              WHERE admin_id = p_admin_id AND revoked = FALSE
                AND expires_at > now() AND absolute_expires_at > now()
              ORDER BY last_used_at DESC, created_at DESC
              OFFSET p_max_sessions
         );
    END IF;
    RETURN NEXT created;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.rotate_refresh_session(
    p_old_token_hash TEXT, p_new_token_hash TEXT,
    p_ip_address TEXT, p_user_agent TEXT,
    p_expires_at TIMESTAMPTZ, p_idle_minutes INTEGER
) RETURNS SETOF endpt.refresh_tokens
LANGUAGE plpgsql SECURITY DEFINER SET search_path = endpt, pg_temp AS $$
DECLARE old_token endpt.refresh_tokens%ROWTYPE;
DECLARE replacement endpt.refresh_tokens%ROWTYPE;
BEGIN
    SELECT * INTO old_token FROM endpt.refresh_tokens
     WHERE token_hash = p_old_token_hash FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;

    -- A reused token invalidates its entire rotation family. This includes a
    -- successor created by an earlier racing request.
    IF old_token.revoked THEN
        UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
         WHERE family_id = old_token.family_id AND revoked = FALSE;
        RETURN;
    END IF;

    IF old_token.expires_at <= now()
       OR old_token.absolute_expires_at <= now()
       OR old_token.last_used_at + make_interval(mins => p_idle_minutes) <= now() THEN
        UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
         WHERE family_id = old_token.family_id AND revoked = FALSE;
        RETURN;
    END IF;

    UPDATE endpt.refresh_tokens SET revoked = TRUE, revoked_at = now()
     WHERE id = old_token.id;
    INSERT INTO endpt.refresh_tokens(
        admin_id, token_hash, ip_address, user_agent, expires_at,
        absolute_expires_at, family_id, last_used_at
    ) VALUES (
        old_token.admin_id, p_new_token_hash, p_ip_address,
        left(COALESCE(p_user_agent, ''), 500),
        LEAST(p_expires_at, old_token.absolute_expires_at),
        old_token.absolute_expires_at, old_token.family_id, now()
    ) RETURNING * INTO replacement;
    RETURN NEXT replacement;
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_refresh_session(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION endpt.rotate_refresh_session(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_refresh_session(UUID, TEXT, TEXT, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, INTEGER) TO service_role;
GRANT EXECUTE ON FUNCTION endpt.rotate_refresh_session(TEXT, TEXT, TEXT, TEXT, TIMESTAMPTZ, INTEGER) TO service_role;
