BEGIN;

ALTER TABLE endpt.warden_identities
    ADD COLUMN IF NOT EXISTS profile_photo TEXT,
    ADD COLUMN IF NOT EXISTS profile_photo_mime TEXT;

ALTER TABLE endpt.windows_users
    ADD COLUMN IF NOT EXISTS profile_photo TEXT,
    ADD COLUMN IF NOT EXISTS profile_photo_mime TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'warden_identities_profile_photo_mime_check'
          AND conrelid = 'endpt.warden_identities'::regclass
    ) THEN
        ALTER TABLE endpt.warden_identities
            ADD CONSTRAINT warden_identities_profile_photo_mime_check
            CHECK (profile_photo_mime IS NULL OR profile_photo_mime = 'image/png');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'windows_users_profile_photo_mime_check'
          AND conrelid = 'endpt.windows_users'::regclass
    ) THEN
        ALTER TABLE endpt.windows_users
            ADD CONSTRAINT windows_users_profile_photo_mime_check
            CHECK (profile_photo_mime IS NULL OR profile_photo_mime = 'image/png');
    END IF;
END $$;

DROP FUNCTION IF EXISTS endpt.create_warden_identity_and_jobs(
    UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT
);

CREATE OR REPLACE FUNCTION endpt.create_warden_identity_and_jobs(
    p_company_id UUID, p_username TEXT, p_display_name TEXT,
    p_password_hash TEXT, p_is_admin BOOLEAN, p_created_by UUID,
    p_endpoint_ids JSONB, p_profile_photo TEXT, p_profile_photo_mime TEXT,
    p_encrypted_payload TEXT
) RETURNS TABLE(identity_id UUID, queued INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_identity UUID; v_endpoint RECORD; v_job UUID; v_requested INTEGER; v_valid INTEGER;
BEGIN
    IF jsonb_typeof(p_endpoint_ids) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'endpoint ids must be an array';
    END IF;
    IF p_profile_photo IS NOT NULL AND (
        p_profile_photo_mime IS DISTINCT FROM 'image/png'
        OR char_length(p_profile_photo) > 700000
        OR left(p_profile_photo, 22) <> 'data:image/png;base64,'
    ) THEN
        RAISE EXCEPTION 'invalid profile photo';
    END IF;
    SELECT count(DISTINCT value) INTO v_requested FROM jsonb_array_elements_text(p_endpoint_ids);
    IF v_requested < 1 OR v_requested > 100 THEN RAISE EXCEPTION 'invalid target count'; END IF;
    SELECT count(*) INTO v_valid FROM endpt.endpoints e
      JOIN (SELECT DISTINCT value::uuid id FROM jsonb_array_elements_text(p_endpoint_ids)) x ON x.id=e.id
     WHERE e.company_id=p_company_id AND e.is_active=true AND COALESCE(e.platform,'windows')='windows';
    IF v_valid <> v_requested THEN RAISE EXCEPTION 'invalid endpoint target'; END IF;
    IF EXISTS (
        SELECT 1 FROM endpt.windows_users u JOIN endpt.endpoints e ON e.id=u.endpoint_id
        JOIN (SELECT DISTINCT value::uuid id FROM jsonb_array_elements_text(p_endpoint_ids)) x ON x.id=e.id
        WHERE e.company_id=p_company_id AND u.present=true AND lower(u.username)=lower(p_username)
    ) THEN RAISE EXCEPTION 'local account conflict'; END IF;

    INSERT INTO endpt.warden_identities(
        company_id,username,display_name,password_hash,is_admin,created_by,
        profile_photo,profile_photo_mime
    )
    VALUES(
        p_company_id,p_username,NULLIF(p_display_name,''),p_password_hash,p_is_admin,p_created_by,
        NULLIF(p_profile_photo,''),NULLIF(p_profile_photo_mime,'')
    )
    RETURNING id INTO v_identity;
    queued := 0;
    FOR v_endpoint IN SELECT e.id,e.branch_id FROM endpt.endpoints e
      JOIN (SELECT DISTINCT value::uuid id FROM jsonb_array_elements_text(p_endpoint_ids)) x ON x.id=e.id
      ORDER BY e.id
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(p_company_id,v_endpoint.branch_id,v_endpoint.id,'PROVISION_WARDEN_IDENTITY',p_encrypted_payload,'pending',p_created_by)
        RETURNING id INTO v_job;
        INSERT INTO endpt.warden_identity_assignments(identity_id,endpoint_id,status,password_version,last_job_id)
        VALUES(v_identity,v_endpoint.id,'pending',1,v_job);
        queued := queued+1;
    END LOOP;
    identity_id := v_identity;
    RETURN NEXT;
END;
$$;

REVOKE ALL ON FUNCTION endpt.create_warden_identity_and_jobs(
    UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT,TEXT,TEXT
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_warden_identity_and_jobs(
    UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT,TEXT,TEXT
) TO service_role;

CREATE OR REPLACE FUNCTION endpt.replace_windows_users(p_endpoint_id UUID, p_users JSONB)
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=endpt,public
AS $$
DECLARE v_count INTEGER;
BEGIN
    IF p_users IS NULL OR jsonb_typeof(p_users) IS DISTINCT FROM 'array'
       OR jsonb_array_length(p_users) > 512 THEN
        RAISE EXCEPTION 'invalid user inventory';
    END IF;

    UPDATE endpt.windows_users SET present=FALSE
    WHERE endpoint_id=p_endpoint_id;

    INSERT INTO endpt.windows_users (
        endpoint_id, username, display_name, sid, principal_name,
        account_type, domain_name, is_admin, is_enabled, present, last_synced
    )
    SELECT
        p_endpoint_id,
        item->>'username',
        NULLIF(item->>'display_name', ''),
        NULLIF(item->>'sid', ''),
        NULLIF(item->>'principal_name', ''),
        CASE WHEN item->>'account_type' IN ('local','domain','entra','microsoft','unknown')
             THEN item->>'account_type' ELSE 'unknown' END,
        NULLIF(item->>'domain_name', ''),
        COALESCE((item->>'is_admin')::BOOLEAN, FALSE),
        COALESCE((item->>'is_enabled')::BOOLEAN, TRUE),
        TRUE,
        now()
    FROM jsonb_array_elements(p_users) item
    WHERE NULLIF(item->>'username', '') IS NOT NULL
    ON CONFLICT (endpoint_id, username) DO UPDATE SET
        display_name=EXCLUDED.display_name,
        sid=EXCLUDED.sid,
        principal_name=EXCLUDED.principal_name,
        account_type=EXCLUDED.account_type,
        domain_name=EXCLUDED.domain_name,
        is_admin=EXCLUDED.is_admin,
        is_enabled=EXCLUDED.is_enabled,
        present=TRUE,
        last_synced=now();

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

REVOKE ALL ON FUNCTION endpt.replace_windows_users(UUID, JSONB) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.replace_windows_users(UUID, JSONB) TO service_role;

NOTIFY pgrst, 'reload schema';
COMMIT;

