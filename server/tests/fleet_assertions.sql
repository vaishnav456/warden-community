BEGIN;
DO $$
DECLARE rule uuid; job uuid; count_jobs integer;
BEGIN
 INSERT INTO endpt.software_patch_rules(company_id,branch_id,app_id,inventory_name,publisher,target_version,package_sha256,enabled)
 VALUES('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000020','App','Publisher','2.0',repeat('a',64),true) RETURNING id INTO rule;
 SELECT count(*) INTO count_jobs FROM endpt.dispatch_software_patch(rule,'00000000-0000-0000-0000-000000000004',repeat('b',64),'encrypted');
 IF count_jobs<>0 THEN RAISE EXCEPTION 'Cross-tenant dispatch'; END IF;
 SELECT count(*) INTO count_jobs FROM endpt.dispatch_software_patch(rule,'00000000-0000-0000-0000-000000000005',repeat('b',64),'encrypted');
 IF count_jobs<>0 THEN RAISE EXCEPTION 'Cross-branch dispatch'; END IF;
 SELECT id INTO job FROM endpt.dispatch_software_patch(rule,'00000000-0000-0000-0000-000000000003',repeat('b',64),'encrypted');
 IF job IS NULL THEN RAISE EXCEPTION 'Approved dispatch absent'; END IF;
 SELECT count(*) INTO count_jobs FROM endpt.dispatch_software_patch(rule,'00000000-0000-0000-0000-000000000003',repeat('b',64),'encrypted');
 IF count_jobs<>0 THEN RAISE EXCEPTION 'Duplicate dispatch'; END IF;
 SELECT count(*) INTO count_jobs FROM endpt.dispatch_software_patch(rule,'00000000-0000-0000-0000-000000000003',repeat('c',64),'encrypted');
 IF count_jobs<>0 THEN RAISE EXCEPTION 'Parallel installer dispatch'; END IF;
 UPDATE endpt.jobs SET status='running',started_at=now(),lease_expires_at=now() WHERE id=job;
 IF endpt.renew_agent_job_lease('00000000-0000-0000-0000-000000000004',job) THEN RAISE EXCEPTION 'Cross-device lease renewed'; END IF;
 IF NOT endpt.renew_agent_job_lease('00000000-0000-0000-0000-000000000003',job) THEN RAISE EXCEPTION 'Active lease not renewed'; END IF;
 UPDATE endpt.jobs SET started_at=now()-interval '25 hours' WHERE id=job;
 IF endpt.renew_agent_job_lease('00000000-0000-0000-0000-000000000003',job) THEN RAISE EXCEPTION 'Unbounded job lease'; END IF;
 UPDATE endpt.jobs SET status='completed',started_at=now() WHERE id=job;
 IF endpt.renew_agent_job_lease('00000000-0000-0000-0000-000000000003',job) THEN RAISE EXCEPTION 'Terminal job lease'; END IF;
 DELETE FROM endpt.jobs WHERE id=job;
 SELECT count(*) INTO count_jobs FROM endpt.dispatch_software_patch(rule,'00000000-0000-0000-0000-000000000003',repeat('b',64),'encrypted');
 IF count_jobs<>0 THEN RAISE EXCEPTION 'Retained receipt lost deduplication'; END IF;
 UPDATE endpt.app_library SET deletion_requested_at=now();
 SELECT count(*) INTO count_jobs FROM endpt.dispatch_software_patch(rule,'00000000-0000-0000-0000-000000000003',repeat('d',64),'encrypted');
 IF count_jobs<>0 THEN RAISE EXCEPTION 'Deleting package dispatched'; END IF;
 INSERT INTO endpt.support_requests(company_id,endpoint_id,request_encrypted) VALUES('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','encrypted');
 BEGIN
  INSERT INTO endpt.support_requests(company_id,endpoint_id,request_encrypted) VALUES('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','encrypted');
  RAISE EXCEPTION 'Duplicate open request';
 EXCEPTION WHEN unique_violation THEN NULL; END;
 IF EXISTS(SELECT 1 FROM pg_proc p, LATERAL aclexplode(p.proacl) a WHERE p.oid IN ('endpt.dispatch_software_patch(uuid,uuid,text,text)'::regprocedure,'endpt.renew_agent_job_lease(uuid,uuid)'::regprocedure) AND a.grantee=0 AND a.privilege_type='EXECUTE') THEN RAISE EXCEPTION 'Public dispatch privilege'; END IF;
END $$;
ROLLBACK;
