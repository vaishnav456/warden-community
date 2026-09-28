BEGIN;

ALTER TABLE endpt.warden_identities
    ADD COLUMN IF NOT EXISTS login_email TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_warden_identities_company_login_email_ci
    ON endpt.warden_identities(company_id, lower(login_email))
    WHERE login_email IS NOT NULL;

DROP FUNCTION IF EXISTS endpt.create_warden_identity_with_setup_and_jobs(
    UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ
);

CREATE OR REPLACE FUNCTION endpt.create_warden_identity_with_setup_and_jobs(
    p_company_id UUID, p_username TEXT, p_login_email TEXT, p_display_name TEXT,
    p_placeholder_password_hash TEXT, p_is_admin BOOLEAN, p_created_by UUID,
    p_endpoint_ids JSONB, p_profile_photo TEXT, p_profile_photo_mime TEXT,
    p_encrypted_payload TEXT, p_setup_token_hash TEXT, p_setup_expires_at TIMESTAMPTZ
) RETURNS TABLE(identity_id UUID, queued INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_created RECORD; v_email TEXT;
BEGIN
    v_email := lower(NULLIF(btrim(p_login_email), ''));
    IF v_email IS NULL OR char_length(v_email) > 254
       OR v_email !~ '^[A-Za-z0-9.!#$%&''*+/=?^_\x60{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$' THEN
        RAISE EXCEPTION 'invalid login email';
    END IF;
    IF p_setup_token_hash IS NULL OR char_length(p_setup_token_hash) <> 64
       OR p_setup_expires_at <= now() THEN
        RAISE EXCEPTION 'invalid password setup token';
    END IF;
    SELECT * INTO v_created FROM endpt.create_warden_identity_and_jobs(
        p_company_id, p_username, p_display_name, p_placeholder_password_hash,
        p_is_admin, p_created_by, p_endpoint_ids, p_profile_photo,
        p_profile_photo_mime, p_encrypted_payload
    );
    UPDATE endpt.warden_identities SET
        login_email=v_email,
        password_setup_required=true,
        password_setup_token_hash=p_setup_token_hash,
        password_setup_expires_at=p_setup_expires_at,
        updated_at=now()
    WHERE id=v_created.identity_id;
    identity_id := v_created.identity_id;
    queued := v_created.queued;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_warden_identity_with_setup_and_jobs(
    UUID,TEXT,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_warden_identity_with_setup_and_jobs(
    UUID,TEXT,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ
) TO service_role;

COMMIT;
