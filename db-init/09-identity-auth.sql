BEGIN;

ALTER TABLE endpt.warden_identities
    ADD COLUMN IF NOT EXISTS offline_access_hours INTEGER NOT NULL DEFAULT 24
        CHECK (offline_access_hours BETWEEN 0 AND 720),
    ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1
        CHECK (session_version > 0),
    ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0
        CHECK (failed_attempts >= 0),
    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS conditional_access JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS endpt.warden_identity_login_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    identity_id UUID REFERENCES endpt.warden_identities(id) ON DELETE SET NULL,
    endpoint_id UUID REFERENCES endpt.endpoints(id) ON DELETE SET NULL,
    username TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('success','invalid_credentials','disabled','locked','not_assigned','policy_denied')),
    reason TEXT,
    source_ip INET,
    offline_grant_hours INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_warden_login_events_company_created
    ON endpt.warden_identity_login_events(company_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_warden_login_events_identity_created
    ON endpt.warden_identity_login_events(identity_id,created_at DESC);

CREATE OR REPLACE FUNCTION endpt.bump_warden_identity_session_version()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path=endpt,public AS $$
BEGIN
    IF NEW.password_version IS DISTINCT FROM OLD.password_version
       OR (OLD.is_enabled=TRUE AND NEW.is_enabled=FALSE)
       OR NEW.offline_access_hours IS DISTINCT FROM OLD.offline_access_hours
       OR NEW.conditional_access IS DISTINCT FROM OLD.conditional_access THEN
        NEW.session_version := OLD.session_version+1;
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS trg_warden_identity_session_version ON endpt.warden_identities;
CREATE TRIGGER trg_warden_identity_session_version
BEFORE UPDATE ON endpt.warden_identities FOR EACH ROW
EXECUTE FUNCTION endpt.bump_warden_identity_session_version();

CREATE OR REPLACE FUNCTION endpt.record_warden_login_failure(
    p_identity_id UUID, p_lock_after INTEGER DEFAULT 5, p_lock_minutes INTEGER DEFAULT 15
) RETURNS TIMESTAMPTZ
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE v_attempts INTEGER; v_locked TIMESTAMPTZ;
BEGIN
    UPDATE endpt.warden_identities
       SET failed_attempts=failed_attempts+1,
           locked_until=CASE WHEN failed_attempts+1 >= p_lock_after
                             THEN now()+make_interval(mins=>p_lock_minutes)
                             ELSE locked_until END,
           updated_at=now()
     WHERE id=p_identity_id
     RETURNING failed_attempts,locked_until INTO v_attempts,v_locked;
    RETURN v_locked;
END;
$$;

CREATE OR REPLACE FUNCTION endpt.record_warden_login_success(p_identity_id UUID)
RETURNS VOID LANGUAGE sql SECURITY DEFINER SET search_path=endpt,public AS $$
    UPDATE endpt.warden_identities SET failed_attempts=0,locked_until=NULL,updated_at=now()
    WHERE id=p_identity_id;
$$;

GRANT SELECT,INSERT ON endpt.warden_identity_login_events TO service_role;
REVOKE ALL ON FUNCTION endpt.record_warden_login_failure(UUID,INTEGER,INTEGER) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.record_warden_login_failure(UUID,INTEGER,INTEGER) TO service_role;
REVOKE ALL ON FUNCTION endpt.record_warden_login_success(UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.record_warden_login_success(UUID) TO service_role;

NOTIFY pgrst, 'reload schema';
COMMIT;
