BEGIN;
DROP INDEX IF EXISTS endpt.support_request_open_user;
CREATE INDEX IF NOT EXISTS support_request_user_time ON endpt.support_requests(company_id,endpoint_id,requester_key,created_at DESC);
CREATE TABLE IF NOT EXISTS endpt.support_forms (
 company_id uuid PRIMARY KEY REFERENCES endpt.companies(id) ON DELETE CASCADE,
 definition_encrypted text NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE endpt.support_forms ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON endpt.support_forms FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOR r IN SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated') LOOP
  EXECUTE format('REVOKE ALL ON endpt.support_forms FROM %I',r);
 END LOOP;
END $$;
GRANT ALL ON endpt.support_forms TO service_role;
-- State, ownership, thread insertion and timestamps change under the same row
-- lock. Service-role-only entry point; actor identity comes from authenticated
-- server context, never the browser form or the interactive pipe payload.
CREATE OR REPLACE FUNCTION endpt.support_ticket_action(
 p_company uuid,p_endpoint uuid,p_request uuid,p_action text,
 p_admin uuid DEFAULT NULL,p_requester text DEFAULT NULL,
 p_cipher text DEFAULT NULL,p_assignee uuid DEFAULT NULL,p_visit timestamptz DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE t endpt.support_requests; a endpt.admin_users; target endpt.admin_users; e endpt.endpoints;
BEGIN
 SELECT * INTO e FROM endpt.endpoints WHERE id=p_endpoint AND company_id=p_company;
 IF NOT FOUND THEN RETURN jsonb_build_object('error','not_found'); END IF;
 IF p_admin IS NOT NULL THEN
  SELECT * INTO a FROM endpt.admin_users WHERE id=p_admin AND is_active;
  IF NOT FOUND OR a.role NOT IN ('superadmin','company_admin','branch_admin','technician')
    OR (a.role<>'superadmin' AND a.company_id IS DISTINCT FROM p_company)
    OR (a.role='branch_admin' AND (a.branch_id IS NULL OR a.branch_id IS DISTINCT FROM e.branch_id))
  THEN RETURN jsonb_build_object('error','forbidden'); END IF;
 ELSE
  IF p_requester IS NULL OR p_requester !~ '^[0-9a-f]{64}$'
   OR p_action NOT IN ('create','reply','reopen')
  THEN RETURN jsonb_build_object('error','forbidden'); END IF;
 END IF;
 IF p_action='create' THEN
  IF p_cipher IS NULL OR length(p_cipher)>40000 THEN RETURN jsonb_build_object('error','invalid'); END IF;
  INSERT INTO endpt.support_requests(id,company_id,endpoint_id,requester_key,request_encrypted)
   VALUES(p_request,p_company,p_endpoint,p_requester,p_cipher) ON CONFLICT(id) DO NOTHING;
 END IF;
 SELECT * INTO t FROM endpt.support_requests WHERE id=p_request AND company_id=p_company AND endpoint_id=p_endpoint FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('error','not_found'); END IF;
 IF p_admin IS NULL AND t.requester_key IS DISTINCT FROM p_requester THEN
  RETURN jsonb_build_object('error','forbidden');
 END IF;
 IF p_admin IS NOT NULL AND a.role IN ('branch_admin','technician')
   AND t.claimed_by IS NOT NULL AND t.claimed_by<>p_admin AND p_action<>'create'
 THEN RETURN jsonb_build_object('error','forbidden'); END IF;
 IF p_action='create' THEN RETURN jsonb_build_object('id',t.id,'status',t.status); END IF;
 IF p_action='reply' THEN
  IF t.status='resolved' THEN RETURN jsonb_build_object('error','resolved'); END IF;
  IF p_cipher IS NULL OR length(p_cipher)>20000 THEN RETURN jsonb_build_object('error','invalid'); END IF;
  -- Caller-generated stable message UUID makes transport retries idempotent.
  INSERT INTO endpt.support_messages(id,company_id,request_id,author_admin_id,message_encrypted)
   VALUES(p_assignee,p_company,t.id,p_admin,p_cipher) ON CONFLICT(id) DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM endpt.support_messages WHERE id=p_assignee AND request_id=t.id AND company_id=p_company
    AND author_admin_id IS NOT DISTINCT FROM p_admin)
  THEN RETURN jsonb_build_object('error','conflict'); END IF;
 ELSIF p_action='claim' THEN
  IF p_admin IS NULL OR t.status<>'open' THEN RETURN jsonb_build_object('error','conflict'); END IF;
  UPDATE endpt.support_requests SET status='claimed',claimed_by=p_admin WHERE id=t.id;
 ELSIF p_action='assign' THEN
  IF p_admin IS NULL OR a.role NOT IN ('superadmin','company_admin','branch_admin') OR t.status='resolved'
   THEN RETURN jsonb_build_object('error','forbidden'); END IF;
  SELECT * INTO target FROM endpt.admin_users WHERE id=p_assignee AND company_id=p_company AND is_active;
  IF NOT FOUND OR target.role NOT IN ('company_admin','branch_admin','technician')
   OR (target.role='branch_admin' AND target.branch_id IS DISTINCT FROM e.branch_id)
   THEN RETURN jsonb_build_object('error','invalid_assignee'); END IF;
  UPDATE endpt.support_requests SET status='claimed',claimed_by=p_assignee WHERE id=t.id;
 ELSIF p_action='resolve' THEN
  IF p_admin IS NULL OR t.status='resolved' THEN RETURN jsonb_build_object('error','conflict'); END IF;
  UPDATE endpt.support_requests SET status='resolved',resolved_at=now() WHERE id=t.id;
 ELSIF p_action='reopen' THEN
  IF t.status<>'resolved' THEN RETURN jsonb_build_object('error','conflict'); END IF;
  UPDATE endpt.support_requests SET status='open',claimed_by=NULL,resolved_at=NULL,service_mode='queued',visit_at=NULL WHERE id=t.id;
 ELSIF p_action IN ('queued','remote','onsite','waiting_user') THEN
  IF p_admin IS NULL OR t.status<>'claimed' THEN RETURN jsonb_build_object('error','conflict'); END IF;
  IF p_action='onsite' AND (p_visit IS NULL OR p_visit<=now()) THEN RETURN jsonb_build_object('error','invalid'); END IF;
  UPDATE endpt.support_requests SET service_mode=p_action,visit_at=CASE WHEN p_action='onsite' THEN p_visit END WHERE id=t.id;
 ELSE RETURN jsonb_build_object('error','invalid');
 END IF;
 -- Actions become encrypted, user-visible history; replies already contain it.
 IF p_action<>'reply' AND p_cipher IS NOT NULL THEN
  INSERT INTO endpt.support_messages(company_id,request_id,author_admin_id,message_encrypted)
   VALUES(p_company,t.id,p_admin,p_cipher);
 END IF;
 UPDATE endpt.support_requests SET updated_at=now() WHERE id=t.id RETURNING * INTO t;
 RETURN jsonb_build_object('id',t.id,'status',t.status);
END $$;
REVOKE ALL ON FUNCTION endpt.support_ticket_action(uuid,uuid,uuid,text,uuid,text,text,uuid,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.support_ticket_action(uuid,uuid,uuid,text,uuid,text,text,uuid,timestamptz) TO service_role;
-- Generic notifications contain no ticket text, names or custom answers.
CREATE OR REPLACE FUNCTION endpt.notify_support_ticket()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE t endpt.support_requests; e endpt.endpoints;
BEGIN
 IF TG_TABLE_NAME='support_requests' THEN t:=NEW;
 ELSE
  IF NEW.author_admin_id IS NOT NULL THEN RETURN NEW; END IF;
  SELECT * INTO t FROM endpt.support_requests WHERE id=NEW.request_id AND company_id=NEW.company_id;
 END IF;
 SELECT * INTO e FROM endpt.endpoints WHERE id=t.endpoint_id AND company_id=t.company_id;
 INSERT INTO endpt.notifications(admin_id,company_id,title,message,type,link)
 SELECT id,t.company_id,'Helpdesk ticket updated','Open Helpdesk to review a new request or user reply.','info',
   '/operations/support/'||t.id::text FROM endpt.admin_users
 WHERE company_id=t.company_id AND is_active AND
  ((t.claimed_by IS NOT NULL AND id=t.claimed_by) OR
   (t.claimed_by IS NULL AND (role='company_admin' OR (role='branch_admin' AND branch_id=e.branch_id))));
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION endpt.notify_support_ticket() FROM PUBLIC;
DROP TRIGGER IF EXISTS support_ticket_notification ON endpt.support_requests;
CREATE TRIGGER support_ticket_notification AFTER INSERT ON endpt.support_requests
 FOR EACH ROW EXECUTE FUNCTION endpt.notify_support_ticket();
DROP TRIGGER IF EXISTS support_reply_notification ON endpt.support_messages;
CREATE TRIGGER support_reply_notification AFTER INSERT ON endpt.support_messages
 FOR EACH ROW EXECUTE FUNCTION endpt.notify_support_ticket();
NOTIFY pgrst,'reload schema';
COMMIT;
