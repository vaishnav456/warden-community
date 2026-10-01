-- Apply before the matching server release. Does not dispatch device jobs.
BEGIN;
ALTER TABLE endpt.admin_users ADD COLUMN IF NOT EXISTS access_token_version bigint NOT NULL DEFAULT 0;
ALTER TABLE endpt.compliance_results ADD COLUMN IF NOT EXISTS policy_fingerprint text;
ALTER TABLE endpt.remote_sessions ADD COLUMN IF NOT EXISTS branch_id uuid;
-- Legacy sessions have no historical branch evidence. Do not guess from current ownership.
CREATE OR REPLACE FUNCTION endpt.capture_remote_branch() RETURNS trigger
LANGUAGE plpgsql SET search_path=endpt,pg_temp AS $$
BEGIN
 SELECT e.branch_id INTO NEW.branch_id FROM endpt.endpoints e
 WHERE e.id=NEW.endpoint_id AND e.company_id=NEW.company_id;
 RETURN NEW;
END; $$;
DROP TRIGGER IF EXISTS remote_branch_receipt ON endpt.remote_sessions;
CREATE TRIGGER remote_branch_receipt BEFORE INSERT ON endpt.remote_sessions
 FOR EACH ROW EXECUTE FUNCTION endpt.capture_remote_branch();

CREATE OR REPLACE FUNCTION endpt.revoke_admin_sessions(p_admin_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
BEGIN
 UPDATE endpt.admin_users SET access_token_version=access_token_version+1 WHERE id=p_admin_id;
 UPDATE endpt.refresh_tokens SET revoked=true,revoked_at=now() WHERE admin_id=p_admin_id AND NOT revoked;
END; $$;
REVOKE ALL ON FUNCTION endpt.revoke_admin_sessions(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.revoke_admin_sessions(uuid) TO service_role;

-- Preserve review history when software disappears. Never cascade-delete findings.
DO $$
DECLARE constraint_name text;
BEGIN
 FOR constraint_name IN SELECT conname FROM pg_constraint
  WHERE conrelid='endpt.vulnerability_findings'::regclass
  AND confrelid='endpt.software_inventory'::regclass AND contype='f'
 LOOP EXECUTE format('ALTER TABLE endpt.vulnerability_findings DROP CONSTRAINT %I',constraint_name); END LOOP;
 ALTER TABLE endpt.vulnerability_findings ADD CONSTRAINT vulnerability_software_history_fk
  FOREIGN KEY(software_id) REFERENCES endpt.software_inventory(id) ON DELETE SET NULL;
END; $$;

CREATE OR REPLACE FUNCTION endpt.replace_software_inventory(p_endpoint_id uuid,p_items jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE item jsonb; matched uuid; retained uuid[]:='{}';
BEGIN
 IF jsonb_typeof(p_items) IS DISTINCT FROM 'array' OR jsonb_array_length(p_items)>10000 THEN
  RAISE EXCEPTION 'Invalid software inventory';
 END IF;
 PERFORM 1 FROM endpt.endpoints WHERE id=p_endpoint_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Unknown endpoint'; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(p_items) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR coalesce(item->>'name','')='' THEN
   RAISE EXCEPTION 'Invalid software item';
  END IF;
  matched:=NULL;
  SELECT id INTO matched FROM endpt.software_inventory
   WHERE endpoint_id=p_endpoint_id AND name=item->>'name'
   AND coalesce(version,'')=coalesce(item->>'version','')
   AND coalesce(publisher,'')=coalesce(item->>'publisher','')
   ORDER BY id LIMIT 1;
  IF matched IS NULL THEN
   INSERT INTO endpt.software_inventory(endpoint_id,name,version,publisher,install_date,install_location,executable_path)
   VALUES(p_endpoint_id,item->>'name',item->>'version',item->>'publisher',item->>'install_date',item->>'install_location',item->>'executable_path')
   RETURNING id INTO matched;
  ELSE
   UPDATE endpt.software_inventory SET install_date=item->>'install_date',
    install_location=item->>'install_location',executable_path=item->>'executable_path' WHERE id=matched;
  END IF;
  retained:=array_append(retained,matched);
 END LOOP;
 UPDATE endpt.vulnerability_findings SET status='remediated',resolved_at=now()
 WHERE endpoint_id=p_endpoint_id AND status='open'
 AND software_id IN(SELECT id FROM endpt.software_inventory WHERE endpoint_id=p_endpoint_id AND NOT(id=ANY(retained)));
 DELETE FROM endpt.software_inventory WHERE endpoint_id=p_endpoint_id AND NOT(id=ANY(retained));
 UPDATE endpt.endpoints SET software_inventory_at=now() WHERE id=p_endpoint_id;
END; $$;
REVOKE ALL ON FUNCTION endpt.replace_software_inventory(uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.replace_software_inventory(uuid,jsonb) TO service_role;

CREATE OR REPLACE FUNCTION endpt.promote_patch_deployment(p_deployment_id uuid) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE d endpt.patch_deployments; p endpt.patch_policies; actor endpt.admin_users;
 target record; job uuid; queued integer:=0; pilot_open integer; pilot_failed integer;
BEGIN
 SELECT * INTO d FROM endpt.patch_deployments WHERE id=p_deployment_id AND status IN('pilot','waiting') FOR UPDATE;
 IF NOT FOUND OR d.broad_at>now() THEN RETURN 0; END IF;
 SELECT * INTO p FROM endpt.patch_policies WHERE id=d.policy_id AND company_id=d.company_id AND enabled FOR SHARE;
 IF NOT FOUND OR p.reboot_mode NOT IN('never','notify') THEN
  UPDATE endpt.patch_deployments SET status='paused' WHERE id=d.id; RETURN 0;
 END IF;
 SELECT * INTO actor FROM endpt.admin_users WHERE id=d.created_by AND is_active FOR SHARE;
 IF NOT FOUND OR actor.role NOT IN('superadmin','company_admin','branch_admin')
  OR (actor.role<>'superadmin' AND actor.company_id IS DISTINCT FROM d.company_id)
  OR (actor.role='branch_admin' AND (p.scope_type<>'branch' OR actor.branch_id::text IS DISTINCT FROM (p.scope_value #>> '{}'))) THEN
  UPDATE endpt.patch_deployments SET status='paused' WHERE id=d.id; RETURN 0;
 END IF;
 SELECT count(*) FILTER(WHERE status IN('waiting','queued')),count(*) FILTER(WHERE status IN('failed','cancelled'))
 INTO pilot_open,pilot_failed FROM endpt.patch_deployment_targets WHERE deployment_id=d.id AND ring='pilot';
 IF pilot_failed>0 THEN UPDATE endpt.patch_deployments SET status='paused' WHERE id=d.id; RETURN -pilot_failed; END IF;
 IF pilot_open>0 THEN
  UPDATE endpt.patch_deployments SET status='waiting',broad_at=now()+interval '1 hour' WHERE id=d.id; RETURN 0;
 END IF;
 -- Pause the whole ring before dispatching any target if ownership/scope changed.
 IF EXISTS(SELECT 1 FROM endpt.patch_deployment_targets t LEFT JOIN endpt.endpoints e ON e.id=t.endpoint_id
 WHERE t.deployment_id=d.id AND t.ring='broad' AND t.status='waiting'
 AND (e.id IS NULL OR e.company_id IS DISTINCT FROM d.company_id OR NOT e.is_active
 OR (p.scope_type='branch' AND e.branch_id::text IS DISTINCT FROM (p.scope_value #>> '{}'))
 OR (p.scope_type='tag' AND NOT(coalesce(to_jsonb(e.tags),'[]'::jsonb) ? (p.scope_value #>> '{}')))
 OR (p.scope_type='endpoints' AND NOT(p.scope_value ? e.id::text)))) THEN
  UPDATE endpt.patch_deployments SET status='paused' WHERE id=d.id; RETURN 0;
 END IF;
 FOR target IN SELECT e.* FROM endpt.patch_deployment_targets t JOIN endpt.endpoints e ON e.id=t.endpoint_id
  WHERE t.deployment_id=d.id AND t.ring='broad' AND t.status='waiting' FOR UPDATE OF t,e LOOP
  -- Recheck under the endpoint row lock too; concurrent device moves wait.
  IF target.company_id IS DISTINCT FROM d.company_id OR NOT target.is_active
   OR (p.scope_type='branch' AND target.branch_id::text IS DISTINCT FROM (p.scope_value #>> '{}'))
   OR (p.scope_type='tag' AND NOT(coalesce(to_jsonb(target.tags),'[]'::jsonb) ? (p.scope_value #>> '{}')))
   OR (p.scope_type='endpoints' AND NOT(p.scope_value ? target.id::text)) THEN
   RAISE EXCEPTION 'Patch target scope changed during dispatch';
  END IF;
  INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
  VALUES(d.company_id,target.branch_id,target.id,'WINDOWS_UPDATE',d.encrypted_payload,'pending',d.created_by) RETURNING id INTO job;
  UPDATE endpt.patch_deployment_targets SET job_id=job,status='queued' WHERE deployment_id=d.id AND endpoint_id=target.id;
  queued:=queued+1;
 END LOOP;
 UPDATE endpt.patch_deployments SET status='broad' WHERE id=d.id;
 RETURN queued;
END; $$;
REVOKE ALL ON FUNCTION endpt.promote_patch_deployment(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.promote_patch_deployment(uuid) TO service_role;

CREATE OR REPLACE FUNCTION endpt.refresh_patch_deployment(p_job_id uuid,p_succeeded boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE deployment uuid;
BEGIN
 UPDATE endpt.patch_deployment_targets SET status=CASE WHEN p_succeeded THEN 'completed' ELSE 'failed' END
 WHERE job_id=p_job_id RETURNING deployment_id INTO deployment;
 IF deployment IS NULL THEN RETURN; END IF;
 PERFORM 1 FROM endpt.patch_deployments WHERE id=deployment FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM endpt.patch_deployment_targets WHERE deployment_id=deployment AND status IN('waiting','queued')) THEN
  UPDATE endpt.patch_deployments SET status=CASE WHEN EXISTS(SELECT 1 FROM endpt.patch_deployment_targets WHERE deployment_id=deployment AND status IN('failed','cancelled')) THEN 'paused' ELSE 'completed' END
  WHERE id=deployment AND status<>'cancelled';
 END IF;
END; $$;
NOTIFY pgrst,'reload schema';
COMMIT;
