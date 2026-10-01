DO $$
DECLARE r endpt.agent_rollouts; token uuid:=gen_random_uuid(); created integer;
BEGIN
 SELECT * INTO r FROM endpt.create_agent_rollout('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',NULL,1,1,0,0,
 '{"00000000-0000-0000-0000-000000000003":{"state":"waiting"}}');
 BEGIN
  PERFORM endpt.create_agent_rollout(r.company_id,r.build_id,NULL,1,1,0,0,r.targets);
  RAISE EXCEPTION 'Overlap accepted';
 EXCEPTION WHEN raise_exception THEN IF SQLERRM='Overlap accepted' THEN RAISE; END IF; END;
 IF NOT endpt.claim_agent_rollout(r.id,token) THEN RAISE EXCEPTION 'Lease failed'; END IF;
 IF endpt.claim_agent_rollout(r.id,gen_random_uuid()) THEN RAISE EXCEPTION 'Duplicate lease'; END IF;
 SELECT count(*) INTO created FROM endpt.dispatch_agent_rollout(r.id,token,'00000000-0000-0000-0000-000000000003','UPDATE_AGENT','encrypted-payload');
 IF created<>1 THEN RAISE EXCEPTION 'Job not created'; END IF;
 SELECT * INTO r FROM endpt.agent_rollouts WHERE id=r.id;
 IF r.targets->'00000000-0000-0000-0000-000000000003'->>'state'<>'queued' OR
  NOT EXISTS(SELECT 1 FROM endpt.jobs WHERE id=(r.targets->'00000000-0000-0000-0000-000000000003'->>'job_id')::uuid) THEN
  RAISE EXCEPTION 'Durable job receipt missing'; END IF;
 SELECT count(*) INTO created FROM endpt.dispatch_agent_rollout(r.id,token,'00000000-0000-0000-0000-000000000003','UPDATE_AGENT','encrypted-payload');
 IF created<>0 THEN RAISE EXCEPTION 'Duplicate dispatch after restart'; END IF;
 IF has_function_privilege('public','endpt.dispatch_agent_rollout(uuid,uuid,uuid,text,text)','execute') THEN RAISE EXCEPTION 'Public dispatch access'; END IF;
END $$;
