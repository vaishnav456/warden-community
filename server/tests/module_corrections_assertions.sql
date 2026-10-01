DO $$
DECLARE ep uuid:='00000000-0000-0000-0000-000000000004'; actor uuid:='00000000-0000-0000-0000-000000000002';
 deployment uuid:='00000000-0000-0000-0000-000000000007'; job uuid; count_jobs integer;
BEGIN
 PERFORM endpt.revoke_admin_sessions(actor);
 IF (SELECT access_token_version FROM endpt.admin_users WHERE id=actor)<>1 OR EXISTS(SELECT 1 FROM endpt.refresh_tokens WHERE admin_id=actor AND NOT revoked) THEN RAISE EXCEPTION 'Session revoke failed'; END IF;
 PERFORM endpt.replace_software_inventory(ep,'[{"name":"Example","version":"1","publisher":"Vendor","install_location":"new"}]');
 IF NOT EXISTS(SELECT 1 FROM endpt.software_inventory WHERE id='00000000-0000-0000-0000-000000000005' AND install_location='new') THEN RAISE EXCEPTION 'Inventory identity changed'; END IF;
 IF NOT EXISTS(SELECT 1 FROM endpt.vulnerability_findings WHERE status='accepted' AND software_id IS NOT NULL) THEN RAISE EXCEPTION 'Review history lost'; END IF;
 BEGIN
  PERFORM endpt.replace_software_inventory(ep,'[{"name":"New"},{"bad":true}]');
  RAISE EXCEPTION 'Invalid inventory accepted';
 EXCEPTION WHEN raise_exception THEN
  IF SQLERRM='Invalid inventory accepted' THEN RAISE; END IF;
 END;
 IF (SELECT count(*) FROM endpt.software_inventory WHERE endpoint_id=ep)<>1 THEN RAISE EXCEPTION 'Inventory did not roll back'; END IF;
 PERFORM endpt.replace_software_inventory(ep,'[]');
 IF NOT EXISTS(SELECT 1 FROM endpt.vulnerability_findings WHERE status='accepted' AND software_id IS NULL) THEN RAISE EXCEPTION 'Removed software lost reviewed history'; END IF;
 INSERT INTO endpt.remote_sessions(endpoint_id,company_id) VALUES(ep,'00000000-0000-0000-0000-000000000001');
 UPDATE endpt.endpoints SET branch_id='00000000-0000-0000-0000-000000000009' WHERE id=ep;
 IF (SELECT branch_id FROM endpt.remote_sessions LIMIT 1)<>'00000000-0000-0000-0000-000000000003' THEN RAISE EXCEPTION 'Historical branch changed'; END IF;
 PERFORM endpt.promote_patch_deployment(deployment);
 IF (SELECT status FROM endpt.patch_deployments WHERE id=deployment)<>'paused' OR EXISTS(SELECT 1 FROM endpt.jobs) THEN RAISE EXCEPTION 'Moved target received patch'; END IF;
 UPDATE endpt.endpoints SET branch_id='00000000-0000-0000-0000-000000000003',company_id='00000000-0000-0000-0000-000000000009' WHERE id=ep;
 UPDATE endpt.patch_deployments SET status='pilot' WHERE id=deployment;
 PERFORM endpt.promote_patch_deployment(deployment);
 IF EXISTS(SELECT 1 FROM endpt.jobs) THEN RAISE EXCEPTION 'Foreign tenant received patch'; END IF;
 UPDATE endpt.endpoints SET company_id='00000000-0000-0000-0000-000000000001' WHERE id=ep;
 UPDATE endpt.patch_deployments SET status='pilot' WHERE id=deployment;
 UPDATE endpt.admin_users SET is_active=false WHERE id=actor;
 PERFORM endpt.promote_patch_deployment(deployment);
 IF EXISTS(SELECT 1 FROM endpt.jobs) THEN RAISE EXCEPTION 'Revoked actor dispatched patch'; END IF;
 UPDATE endpt.admin_users SET is_active=true WHERE id=actor;
 UPDATE endpt.patch_deployments SET status='pilot' WHERE id=deployment;
 count_jobs:=endpt.promote_patch_deployment(deployment);
 IF count_jobs<>1 THEN RAISE EXCEPTION 'Valid ring not dispatched'; END IF;
 SELECT id INTO job FROM endpt.jobs LIMIT 1;
 PERFORM endpt.refresh_patch_deployment(job,false);
 IF (SELECT status FROM endpt.patch_deployments WHERE id=deployment)<>'paused' THEN RAISE EXCEPTION 'Failed patch marked complete'; END IF;
END; $$;
SELECT 'module correction assertions passed' AS result;
