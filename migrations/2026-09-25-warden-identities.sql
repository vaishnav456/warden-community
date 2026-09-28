BEGIN;

-- Warden-managed identities are tenant-owned accounts whose password and
-- endpoint assignment are controlled from Warden.  They deliberately live
-- beside (not inside) windows_users: that table is agent-reported inventory,
-- while these rows are desired state.
CREATE TABLE IF NOT EXISTS endpt.warden_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    display_name TEXT,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    password_version INTEGER NOT NULL DEFAULT 1 CHECK (password_version > 0),
    created_by UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, username)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_warden_identities_company_username_ci
    ON endpt.warden_identities(company_id, lower(username));

CREATE TABLE IF NOT EXISTS endpt.warden_identity_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id UUID NOT NULL REFERENCES endpt.warden_identities(id) ON DELETE CASCADE,
    endpoint_id UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','active','disabled','failed','revoked')),
    password_version INTEGER NOT NULL DEFAULT 1 CHECK (password_version > 0),
    last_job_id UUID REFERENCES endpt.jobs(id) ON DELETE SET NULL,
    last_error TEXT,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at TIMESTAMPTZ,
    UNIQUE (identity_id, endpoint_id)
);
CREATE INDEX IF NOT EXISTS idx_warden_identity_assignments_endpoint
    ON endpt.warden_identity_assignments(endpoint_id);

CREATE OR REPLACE FUNCTION endpt.create_warden_identity_and_jobs(
    p_company_id UUID, p_username TEXT, p_display_name TEXT,
    p_password_hash TEXT, p_is_admin BOOLEAN, p_created_by UUID,
    p_endpoint_ids JSONB, p_encrypted_payload TEXT
) RETURNS TABLE(identity_id UUID, queued INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_identity UUID; v_endpoint RECORD; v_job UUID; v_requested INTEGER; v_valid INTEGER;
BEGIN
    IF jsonb_typeof(p_endpoint_ids) IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'endpoint ids must be an array';
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

    INSERT INTO endpt.warden_identities(company_id,username,display_name,password_hash,is_admin,created_by)
    VALUES(p_company_id,p_username,NULLIF(p_display_name,''),p_password_hash,p_is_admin,p_created_by)
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

CREATE OR REPLACE FUNCTION endpt.rotate_warden_identity_password(
    p_company_id UUID, p_identity_id UUID, p_password_hash TEXT,
    p_created_by UUID, p_encrypted_payload TEXT
) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_identity RECORD; v_assignment RECORD; v_job UUID; v_count INTEGER := 0; v_version INTEGER;
BEGIN
    SELECT * INTO v_identity FROM endpt.warden_identities
     WHERE id=p_identity_id AND company_id=p_company_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'identity not found'; END IF;
    v_version := v_identity.password_version+1;
    FOR v_assignment IN
        SELECT a.id,a.endpoint_id,e.branch_id FROM endpt.warden_identity_assignments a
        JOIN endpt.endpoints e ON e.id=a.endpoint_id
        WHERE a.identity_id=p_identity_id AND a.status<>'revoked' AND e.is_active=true
        ORDER BY a.endpoint_id FOR UPDATE OF a
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(p_company_id,v_assignment.branch_id,v_assignment.endpoint_id,'RESET_PASSWORD',p_encrypted_payload,'pending',p_created_by)
        RETURNING id INTO v_job;
        UPDATE endpt.warden_identity_assignments SET status='pending',password_version=v_version,
               last_job_id=v_job,last_error=NULL,updated_at=now() WHERE id=v_assignment.id;
        v_count := v_count+1;
    END LOOP;
    IF v_count=0 THEN RAISE EXCEPTION 'identity has no active assignments'; END IF;
    UPDATE endpt.warden_identities SET password_hash=p_password_hash,password_version=v_version,
           password_changed_at=now(),updated_at=now() WHERE id=p_identity_id;
    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.set_warden_identity_enabled(
    p_company_id UUID, p_identity_id UUID, p_enabled BOOLEAN,
    p_created_by UUID, p_encrypted_payload TEXT
) RETURNS INTEGER
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_identity RECORD; v_assignment RECORD; v_job UUID; v_count INTEGER := 0;
BEGIN
    SELECT * INTO v_identity FROM endpt.warden_identities
     WHERE id=p_identity_id AND company_id=p_company_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'identity not found'; END IF;
    FOR v_assignment IN
        SELECT a.id,a.endpoint_id,e.branch_id FROM endpt.warden_identity_assignments a
        JOIN endpt.endpoints e ON e.id=a.endpoint_id
        WHERE a.identity_id=p_identity_id AND a.status<>'revoked' AND e.is_active=true
        ORDER BY a.endpoint_id FOR UPDATE OF a
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(p_company_id,v_assignment.branch_id,v_assignment.endpoint_id,
               CASE WHEN p_enabled THEN 'ENABLE_USER' ELSE 'DISABLE_USER' END,
               p_encrypted_payload,'pending',p_created_by)
        RETURNING id INTO v_job;
        UPDATE endpt.warden_identity_assignments SET status='pending',last_job_id=v_job,
               last_error=NULL,updated_at=now() WHERE id=v_assignment.id;
        v_count := v_count+1;
    END LOOP;
    UPDATE endpt.warden_identities SET is_enabled=p_enabled,updated_at=now() WHERE id=p_identity_id;
    RETURN v_count;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.reassign_warden_identity(
    p_company_id UUID, p_identity_id UUID, p_endpoint_ids JSONB,
    p_created_by UUID, p_provision_payload TEXT, p_revoke_payload TEXT
) RETURNS TABLE(provisioned INTEGER, revoked INTEGER)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_identity RECORD; v_endpoint RECORD; v_assignment RECORD; v_job UUID; v_requested INTEGER; v_valid INTEGER;
BEGIN
    IF jsonb_typeof(p_endpoint_ids) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'endpoint ids must be an array'; END IF;
    SELECT count(DISTINCT value) INTO v_requested FROM jsonb_array_elements_text(p_endpoint_ids);
    IF v_requested < 1 OR v_requested > 100 THEN RAISE EXCEPTION 'invalid target count'; END IF;
    SELECT * INTO v_identity FROM endpt.warden_identities
     WHERE id=p_identity_id AND company_id=p_company_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'identity not found'; END IF;
    SELECT count(*) INTO v_valid FROM endpt.endpoints e
      JOIN (SELECT DISTINCT value::uuid id FROM jsonb_array_elements_text(p_endpoint_ids)) x ON x.id=e.id
     WHERE e.company_id=p_company_id AND e.is_active=true AND COALESCE(e.platform,'windows')='windows';
    IF v_valid <> v_requested THEN RAISE EXCEPTION 'invalid endpoint target'; END IF;

    provisioned := 0; revoked := 0;
    FOR v_endpoint IN SELECT e.id,e.branch_id FROM endpt.endpoints e
      JOIN (SELECT DISTINCT value::uuid id FROM jsonb_array_elements_text(p_endpoint_ids)) x ON x.id=e.id
      WHERE NOT EXISTS (SELECT 1 FROM endpt.warden_identity_assignments a
                        WHERE a.identity_id=p_identity_id AND a.endpoint_id=e.id AND a.status IN ('pending','active'))
      ORDER BY e.id
    LOOP
        IF EXISTS (SELECT 1 FROM endpt.windows_users u WHERE u.endpoint_id=v_endpoint.id
                   AND u.present=true AND lower(u.username)=lower(v_identity.username))
           AND NOT EXISTS (SELECT 1 FROM endpt.warden_identity_assignments a
                           WHERE a.identity_id=p_identity_id AND a.endpoint_id=v_endpoint.id) THEN
            RAISE EXCEPTION 'local account conflict';
        END IF;
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(p_company_id,v_endpoint.branch_id,v_endpoint.id,'PROVISION_WARDEN_IDENTITY',p_provision_payload,'pending',p_created_by)
        RETURNING id INTO v_job;
        INSERT INTO endpt.warden_identity_assignments(identity_id,endpoint_id,status,password_version,last_job_id,last_error,updated_at)
        VALUES(p_identity_id,v_endpoint.id,'pending',v_identity.password_version,v_job,NULL,now())
        ON CONFLICT(identity_id,endpoint_id) DO UPDATE SET status='pending',password_version=EXCLUDED.password_version,
            last_job_id=EXCLUDED.last_job_id,last_error=NULL,updated_at=now();
        provisioned := provisioned+1;
    END LOOP;

    FOR v_assignment IN SELECT a.id,a.endpoint_id,e.branch_id FROM endpt.warden_identity_assignments a
      JOIN endpt.endpoints e ON e.id=a.endpoint_id
      WHERE a.identity_id=p_identity_id AND a.status IN ('pending','active','disabled','failed')
        AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_endpoint_ids) x WHERE x.value::uuid=a.endpoint_id)
      ORDER BY a.endpoint_id FOR UPDATE OF a
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(p_company_id,v_assignment.branch_id,v_assignment.endpoint_id,'DELETE_USER',p_revoke_payload,'pending',p_created_by)
        RETURNING id INTO v_job;
        UPDATE endpt.warden_identity_assignments SET status='revoked',last_job_id=v_job,
               last_error=NULL,updated_at=now() WHERE id=v_assignment.id;
        revoked := revoked+1;
    END LOOP;
    RETURN NEXT;
END;
$$;

GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.warden_identities TO service_role;
GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.warden_identity_assignments TO service_role;
REVOKE ALL ON FUNCTION endpt.create_warden_identity_and_jobs(UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_warden_identity_and_jobs(UUID,TEXT,TEXT,TEXT,BOOLEAN,UUID,JSONB,TEXT) TO service_role;
REVOKE ALL ON FUNCTION endpt.rotate_warden_identity_password(UUID,UUID,TEXT,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.rotate_warden_identity_password(UUID,UUID,TEXT,UUID,TEXT) TO service_role;
REVOKE ALL ON FUNCTION endpt.set_warden_identity_enabled(UUID,UUID,BOOLEAN,UUID,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.set_warden_identity_enabled(UUID,UUID,BOOLEAN,UUID,TEXT) TO service_role;
REVOKE ALL ON FUNCTION endpt.reassign_warden_identity(UUID,UUID,JSONB,UUID,TEXT,TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.reassign_warden_identity(UUID,UUID,JSONB,UUID,TEXT,TEXT) TO service_role;

NOTIFY pgrst, 'reload schema';
COMMIT;
