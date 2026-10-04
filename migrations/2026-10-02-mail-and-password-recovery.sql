BEGIN;
CREATE TABLE IF NOT EXISTS endpt.mail_settings (
    scope_key text PRIMARY KEY,
    company_id uuid UNIQUE REFERENCES endpt.companies(id) ON DELETE CASCADE,
    config_encrypted text NOT NULL,
    updated_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope_key='platform' AND company_id IS NULL) OR (company_id IS NOT NULL AND scope_key='company:'||company_id::text))
);
CREATE TABLE IF NOT EXISTS endpt.mail_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_key text NOT NULL UNIQUE,
    company_id uuid REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id uuid REFERENCES endpt.branches(id) ON DELETE SET NULL,
    admin_id uuid REFERENCES endpt.admin_users(id) ON DELETE CASCADE,
    category text NOT NULL, kind text NOT NULL, record_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL DEFAULT now()+interval '1 day',
    processed boolean NOT NULL DEFAULT false,
    claim_token uuid, lease_until timestamptz
);
CREATE TABLE IF NOT EXISTS endpt.mail_outbox (
    id uuid PRIMARY KEY,
    event_key text NOT NULL UNIQUE,
    company_id uuid REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id uuid REFERENCES endpt.branches(id) ON DELETE SET NULL,
    admin_id uuid REFERENCES endpt.admin_users(id) ON DELETE CASCADE,
    identity_id uuid REFERENCES endpt.warden_identities(id) ON DELETE CASCADE,
    category text NOT NULL,
    payload_encrypted text,
    status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sending','sent','failed','skipped')),
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now()+interval '1 day',
    claim_token uuid, lease_until timestamptz,
    result_code text, created_at timestamptz NOT NULL DEFAULT now(), sent_at timestamptz,
    CHECK(admin_id IS NOT NULL OR identity_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS mail_outbox_due ON endpt.mail_outbox(available_at) WHERE status IN ('pending','sending');
CREATE INDEX IF NOT EXISTS mail_events_due ON endpt.mail_events(created_at) WHERE NOT processed;
CREATE TABLE IF NOT EXISTS endpt.admin_password_reset_tokens (
    token_hash text PRIMARY KEY CHECK(token_hash ~ '^[0-9a-f]{64}$'),
    admin_id uuid NOT NULL REFERENCES endpt.admin_users(id) ON DELETE CASCADE,
    email_hash text NOT NULL,
    token_version integer NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT now()+interval '30 minutes',
    consumed_at timestamptz
);
CREATE INDEX IF NOT EXISTS admin_reset_admin ON endpt.admin_password_reset_tokens(admin_id);
ALTER TABLE endpt.mail_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpt.mail_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpt.mail_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpt.admin_password_reset_tokens ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON endpt.mail_settings,endpt.mail_events,endpt.mail_outbox,endpt.admin_password_reset_tokens FROM PUBLIC, anon;
GRANT SELECT,INSERT,UPDATE,DELETE ON endpt.mail_settings,endpt.mail_events,endpt.mail_outbox,endpt.admin_password_reset_tokens TO service_role;

CREATE OR REPLACE FUNCTION endpt.request_admin_password_reset(p_admin_id uuid,p_token_hash text,p_email_hash text,p_token_version integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE a endpt.admin_users;
BEGIN
 SELECT * INTO a FROM endpt.admin_users WHERE id=p_admin_id AND is_active FOR UPDATE;
 IF NOT FOUND OR coalesce(a.access_token_version,0)<>p_token_version
 OR encode(public.digest(lower(a.email),'sha256'),'hex')<>p_email_hash THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM endpt.admin_password_reset_tokens WHERE admin_id=p_admin_id
           AND created_at>now()-interval '1 minute') THEN RETURN false; END IF;
 UPDATE endpt.admin_password_reset_tokens SET consumed_at=now() WHERE admin_id=p_admin_id AND consumed_at IS NULL;
 INSERT INTO endpt.admin_password_reset_tokens(token_hash,admin_id,email_hash,token_version)
 VALUES(p_token_hash,p_admin_id,p_email_hash,p_token_version);
 RETURN true;
END $$;
CREATE OR REPLACE FUNCTION endpt.complete_admin_password_reset(p_token_hash text,p_password_hash text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE t endpt.admin_password_reset_tokens; a endpt.admin_users;
BEGIN
 -- Lock the account before the token, using the same order as issuance.
 SELECT * INTO t FROM endpt.admin_password_reset_tokens WHERE token_hash=p_token_hash;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO a FROM endpt.admin_users WHERE id=t.admin_id FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO t FROM endpt.admin_password_reset_tokens WHERE token_hash=p_token_hash FOR UPDATE;
 IF NOT FOUND OR t.consumed_at IS NOT NULL OR t.expires_at<=now() OR NOT a.is_active
 OR coalesce(a.access_token_version,0)<>t.token_version
 OR encode(public.digest(lower(a.email),'sha256'),'hex')<>t.email_hash THEN RETURN NULL; END IF;
 IF p_password_hash !~ '^\$2[aby]\$' THEN RAISE EXCEPTION 'invalid password hash'; END IF;
 UPDATE endpt.admin_users SET password_hash=p_password_hash,access_token_version=coalesce(access_token_version,0)+1,
 failed_attempts=0,locked_until=NULL WHERE id=a.id;
 UPDATE endpt.refresh_tokens SET revoked=true WHERE admin_id=a.id;
 UPDATE endpt.admin_password_reset_tokens SET consumed_at=now() WHERE admin_id=a.id AND consumed_at IS NULL;
 RETURN a.id;
END $$;

CREATE OR REPLACE FUNCTION endpt.claim_mail_event(p_claim uuid)
RETURNS SETOF endpt.mail_events LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
BEGIN
 RETURN QUERY UPDATE endpt.mail_events SET claim_token=p_claim,lease_until=now()+interval '5 minutes'
 WHERE id=(SELECT id FROM endpt.mail_events WHERE NOT processed AND expires_at>now()
 AND (lease_until IS NULL OR lease_until<now()) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *;
END $$;
CREATE OR REPLACE FUNCTION endpt.claim_mail_message(p_claim uuid)
RETURNS SETOF endpt.mail_outbox LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
BEGIN
 UPDATE endpt.mail_outbox SET status='skipped',payload_encrypted=NULL,result_code='expired'
 WHERE status IN ('pending','sending') AND expires_at<=now() AND (lease_until IS NULL OR lease_until<now());
 RETURN QUERY UPDATE endpt.mail_outbox SET status='sending',claim_token=p_claim,
 lease_until=now()+interval '5 minutes',attempts=attempts+1
 WHERE id=(SELECT id FROM endpt.mail_outbox WHERE status IN ('pending','sending') AND available_at<=now()
 AND expires_at>now() AND (lease_until IS NULL OR lease_until<now())
 ORDER BY available_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *;
END $$;

CREATE OR REPLACE FUNCTION endpt.mail_event_trigger()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE cat text; kind text; aid uuid; cid uuid; bid uuid; rid uuid; key text;
BEGIN
 rid:=NEW.id; cid:=NEW.company_id;
 IF NOT EXISTS(SELECT 1 FROM endpt.mail_settings WHERE scope_key='platform' OR company_id=cid) THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='admin_users' THEN
   aid:=NEW.id;
   IF TG_OP='INSERT' THEN cat:='security';kind:='account_created';
   ELSIF OLD.password_hash IS DISTINCT FROM NEW.password_hash THEN cat:='security';kind:='password_changed';
   ELSIF OLD.email IS DISTINCT FROM NEW.email THEN cat:='security';kind:='email_changed';
   ELSIF OLD.mfa_enabled IS DISTINCT FROM NEW.mfa_enabled THEN cat:='security';kind:='mfa_changed';
   ELSE RETURN NEW; END IF;
 ELSIF TG_TABLE_NAME='alerts' THEN
   IF NEW.is_resolved OR NEW.severity NOT IN ('critical','warning') THEN RETURN NEW; END IF;
   bid:=NEW.branch_id;cat:=CASE WHEN NEW.severity='critical' THEN 'alerts_critical' ELSE 'alerts_other' END;kind:='alert';
 ELSIF TG_TABLE_NAME='jobs' THEN
   IF NEW.status NOT IN ('failed','completed') OR OLD.status=NEW.status THEN RETURN NEW; END IF;
   bid:=NEW.branch_id;
   cat:=CASE WHEN NEW.status='failed' THEN 'jobs_failed'
             WHEN NEW.type='SYNC_WARDEN_HOME' THEN 'home_sync'
             WHEN NEW.type IN ('UPDATE_AGENT','REINSTALL_AGENT') THEN 'updates'
             ELSE 'jobs_completed' END;
   kind:=CASE WHEN NEW.status='failed' THEN 'job_failed' ELSE 'job_completed' END;
 ELSIF TG_TABLE_NAME='escalation_requests' THEN
   IF TG_OP='UPDATE' AND OLD.status=NEW.status THEN RETURN NEW; END IF;
   IF NEW.status NOT IN ('pending','pending_secondary','approved','denied') THEN RETURN NEW; END IF;
   bid:=NEW.branch_id;cat:='approvals';kind:='approval_'||NEW.status;
 ELSIF TG_TABLE_NAME='build_requests' THEN
   IF NEW.status NOT IN ('completed','failed') OR OLD.status=NEW.status THEN RETURN NEW; END IF;
   bid:=NEW.branch_id;cat:='updates';kind:='build_'||NEW.status;
 ELSIF TG_TABLE_NAME='notifications' THEN
   aid:=NEW.admin_id;cat:='general';kind:='notification';
 ELSE RETURN NEW; END IF;
 IF cat<>'security' AND NOT EXISTS(
   SELECT 1 FROM endpt.admin_users a WHERE a.is_active
   AND ((aid IS NOT NULL AND a.id=aid) OR (aid IS NULL AND a.company_id=cid))
   AND coalesce(a.notification_prefs->'email_categories'->>cat,CASE WHEN cat IN ('alerts_critical','jobs_failed') THEN 'true' ELSE 'false' END)='true'
   AND (a.role<>'branch_admin' OR (bid IS NOT NULL AND a.branch_id=bid))
   AND (cat<>'approvals' OR a.role IN ('company_admin','branch_admin','superadmin'))
 ) THEN RETURN NEW; END IF;
 key:=TG_TABLE_NAME||':'||rid||':'||kind||':'||gen_random_uuid();
 INSERT INTO endpt.mail_events(event_key,company_id,branch_id,admin_id,category,kind,record_id)
 VALUES(key,cid,bid,aid,cat,kind,rid);
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS mail_admin_event ON endpt.admin_users;
CREATE TRIGGER mail_admin_event AFTER INSERT OR UPDATE ON endpt.admin_users FOR EACH ROW EXECUTE FUNCTION endpt.mail_event_trigger();
DROP TRIGGER IF EXISTS mail_alert_event ON endpt.alerts;
CREATE TRIGGER mail_alert_event AFTER INSERT ON endpt.alerts FOR EACH ROW EXECUTE FUNCTION endpt.mail_event_trigger();
DROP TRIGGER IF EXISTS mail_job_event ON endpt.jobs;
CREATE TRIGGER mail_job_event AFTER UPDATE OF status ON endpt.jobs FOR EACH ROW EXECUTE FUNCTION endpt.mail_event_trigger();
DROP TRIGGER IF EXISTS mail_approval_event ON endpt.escalation_requests;
CREATE TRIGGER mail_approval_event AFTER INSERT OR UPDATE OF status ON endpt.escalation_requests FOR EACH ROW EXECUTE FUNCTION endpt.mail_event_trigger();
DROP TRIGGER IF EXISTS mail_build_event ON endpt.build_requests;
CREATE TRIGGER mail_build_event AFTER UPDATE OF status ON endpt.build_requests FOR EACH ROW EXECUTE FUNCTION endpt.mail_event_trigger();
DROP TRIGGER IF EXISTS mail_notification_event ON endpt.notifications;
CREATE TRIGGER mail_notification_event AFTER INSERT ON endpt.notifications FOR EACH ROW EXECUTE FUNCTION endpt.mail_event_trigger();
REVOKE ALL ON FUNCTION endpt.request_admin_password_reset(uuid,text,text,integer),endpt.complete_admin_password_reset(text,text),
 endpt.claim_mail_event(uuid),endpt.claim_mail_message(uuid),endpt.mail_event_trigger() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.request_admin_password_reset(uuid,text,text,integer),endpt.complete_admin_password_reset(text,text),
 endpt.claim_mail_event(uuid),endpt.claim_mail_message(uuid) TO service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
