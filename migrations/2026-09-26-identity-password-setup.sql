ALTER TABLE endpt.warden_identities
    ADD COLUMN IF NOT EXISTS password_setup_required BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS password_setup_token_hash TEXT,
    ADD COLUMN IF NOT EXISTS password_setup_expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_warden_identity_password_setup_token
    ON endpt.warden_identities(password_setup_token_hash)
    WHERE password_setup_token_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_warden_identity_password_setup_token_unique
    ON endpt.warden_identities(password_setup_token_hash)
    WHERE password_setup_token_hash IS NOT NULL;

CREATE OR REPLACE FUNCTION endpt.create_warden_identity_with_setup_and_jobs(
    p_company_id UUID, p_username TEXT, p_display_name TEXT,
    p_placeholder_password_hash TEXT, p_is_admin BOOLEAN, p_created_by UUID,
    p_endpoint_ids JSONB, p_profile_photo TEXT, p_profile_photo_mime TEXT,
    p_encrypted_payload TEXT, p_setup_token_hash TEXT, p_setup_expires_at TIMESTAMPTZ
) RETURNS TABLE(identity_id UUID, queued INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_created RECORD;
BEGIN
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

CREATE OR REPLACE FUNCTION endpt.complete_warden_identity_password_setup(
    p_token_hash TEXT, p_password_hash TEXT
) RETURNS TABLE(identity_id UUID, username TEXT)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
    IF p_token_hash IS NULL OR char_length(p_token_hash) <> 64
       OR p_password_hash IS NULL OR char_length(p_password_hash) < 20 THEN
        RAISE EXCEPTION 'invalid password setup completion';
    END IF;
    RETURN QUERY
    UPDATE endpt.warden_identities i SET
        password_hash=p_password_hash,
        password_version=i.password_version+1,
        password_changed_at=now(),
        password_setup_required=false,
        password_setup_token_hash=NULL,
        password_setup_expires_at=NULL,
        failed_attempts=0,
        locked_until=NULL,
        updated_at=now()
    WHERE i.password_setup_token_hash=p_token_hash
      AND i.password_setup_expires_at > now()
    RETURNING i.id, i.username;
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_warden_identity_with_setup_and_jobs(
    UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_warden_identity_with_setup_and_jobs(
    UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT,TEXT,TEXT,TEXT,TIMESTAMPTZ
) TO service_role;
REVOKE ALL ON FUNCTION endpt.complete_warden_identity_password_setup(TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.complete_warden_identity_password_setup(TEXT,TEXT) TO service_role;
