-- Additive only: no device jobs or retention changes are triggered by migration.
BEGIN;
CREATE TABLE IF NOT EXISTS endpt.agent_rollouts (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
 build_id uuid NOT NULL REFERENCES endpt.build_requests(id),
 created_by uuid REFERENCES endpt.admin_users(id),
 status text NOT NULL DEFAULT 'canary' CHECK (status IN ('canary','expanding','paused','rolling_back','completed','cancelled')),
 canary_count integer NOT NULL CHECK (canary_count BETWEEN 1 AND 1000),
 batch_size integer NOT NULL CHECK (batch_size BETWEEN 1 AND 1000),
 window_start integer NOT NULL CHECK (window_start BETWEEN 0 AND 23),
 window_end integer NOT NULL CHECK (window_end BETWEEN 0 AND 23),
 targets jsonb NOT NULL DEFAULT '{}'::jsonb,
 pause_reason text,
 lease_token uuid,
 lease_until timestamptz,
 created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE endpt.agent_rollouts ENABLE ROW LEVEL SECURITY;
CREATE INDEX IF NOT EXISTS agent_rollouts_active_company ON endpt.agent_rollouts(company_id,created_at DESC)
 WHERE status IN ('canary','expanding','paused','rolling_back');
GRANT ALL ON endpt.agent_rollouts TO service_role;
CREATE OR REPLACE FUNCTION endpt.claim_agent_rollout(p_id uuid,p_token uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
 UPDATE endpt.agent_rollouts SET lease_token=p_token,lease_until=now()+interval '10 minutes'
 WHERE id=p_id AND (lease_until IS NULL OR lease_until<now());
 RETURN FOUND;
END; $$;
REVOKE ALL ON FUNCTION endpt.claim_agent_rollout(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.claim_agent_rollout(uuid,uuid) TO service_role;
ALTER TABLE endpt.home_spaces ADD COLUMN IF NOT EXISTS history_days integer NOT NULL DEFAULT 0 CHECK(history_days BETWEEN 0 AND 365);
ALTER TABLE endpt.build_requests ADD COLUMN IF NOT EXISTS deletion_requested_at timestamptz;
-- Creation serializes overlapping campaigns per tenant. Service callers still
-- validate artifact digests; SQL independently enforces target ownership.
CREATE OR REPLACE FUNCTION endpt.create_agent_rollout(p_company uuid,p_build uuid,p_actor uuid,
 p_canary integer,p_batch integer,p_start integer,p_end integer,p_targets jsonb)
RETURNS SETOF endpt.agent_rollouts LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('rollout:'||p_company::text,0));
 IF jsonb_typeof(p_targets) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Invalid targets'; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(p_targets)) NOT BETWEEN 1 AND 1000 THEN
  RAISE EXCEPTION 'Invalid targets';
 END IF;
 IF EXISTS(SELECT 1 FROM jsonb_object_keys(p_targets) k WHERE NOT EXISTS
   (SELECT 1 FROM endpt.endpoints e WHERE e.id::text=k AND e.company_id=p_company)) THEN
  RAISE EXCEPTION 'Target ownership changed';
 END IF;
 IF EXISTS(SELECT 1 FROM endpt.agent_rollouts r WHERE r.company_id=p_company
  AND r.status IN ('canary','expanding','paused','rolling_back')
  AND EXISTS(SELECT 1 FROM jsonb_object_keys(p_targets) k WHERE r.targets ? k)) THEN
  RAISE EXCEPTION 'A target already belongs to an active rollout';
 END IF;
 RETURN QUERY INSERT INTO endpt.agent_rollouts(company_id,build_id,created_by,canary_count,batch_size,window_start,window_end,targets)
 VALUES(p_company,p_build,p_actor,p_canary,p_batch,p_start,p_end,p_targets) RETURNING *;
END; $$;
REVOKE ALL ON FUNCTION endpt.create_agent_rollout(uuid,uuid,uuid,integer,integer,integer,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_agent_rollout(uuid,uuid,uuid,integer,integer,integer,integer,jsonb) TO service_role;

-- Job insertion and target receipt commit together: restart cannot leave an
-- untracked update job or accidentally dispatch that target a second time.
CREATE OR REPLACE FUNCTION endpt.dispatch_agent_rollout(p_id uuid,p_token uuid,p_endpoint uuid,p_type text,p_payload text)
RETURNS SETOF endpt.jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE r endpt.agent_rollouts; e endpt.endpoints; j endpt.jobs; current_state text;
BEGIN
 SELECT * INTO r FROM endpt.agent_rollouts WHERE id=p_id FOR UPDATE;
 IF NOT FOUND OR r.lease_token IS DISTINCT FROM p_token OR r.lease_until<=now()
  OR r.status NOT IN ('canary','expanding','rolling_back') THEN RETURN; END IF;
 current_state := r.targets->p_endpoint::text->>'state';
 IF (r.status='rolling_back' AND current_state NOT IN ('verified','failed'))
  OR (r.status<>'rolling_back' AND current_state IS DISTINCT FROM 'waiting') THEN RETURN; END IF;
 IF p_type IS DISTINCT FROM (CASE WHEN r.status='rolling_back' THEN 'REINSTALL_AGENT' ELSE 'UPDATE_AGENT' END) THEN
  RAISE EXCEPTION 'Invalid rollout operation';
 END IF;
 SELECT * INTO e FROM endpt.endpoints WHERE id=p_endpoint AND company_id=r.company_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Target ownership changed'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_endpoint::text||':UPDATE_AGENT',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_endpoint::text||':REINSTALL_AGENT',0));
 IF EXISTS(SELECT 1 FROM endpt.jobs WHERE endpoint_id=p_endpoint AND type IN ('UPDATE_AGENT','REINSTALL_AGENT')
  AND status IN ('pending','approved','running')) THEN RETURN; END IF;
 INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
 VALUES(r.company_id,e.branch_id,e.id,p_type,p_payload,'pending',NULL) RETURNING * INTO j;
 UPDATE endpt.agent_rollouts SET targets=jsonb_set(targets,ARRAY[p_endpoint::text],
  (r.targets->p_endpoint::text)||jsonb_build_object('state',CASE WHEN r.status='rolling_back' THEN 'rollback_queued' ELSE 'queued' END,'job_id',j.id::text)) WHERE id=p_id;
 RETURN NEXT j;
END; $$;
REVOKE ALL ON FUNCTION endpt.dispatch_agent_rollout(uuid,uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.dispatch_agent_rollout(uuid,uuid,uuid,text,text) TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
