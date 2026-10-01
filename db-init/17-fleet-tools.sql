BEGIN;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS software_inventory_at timestamptz;
ALTER TABLE endpt.remote_sessions ADD COLUMN IF NOT EXISTS connection_quality jsonb;
CREATE TABLE IF NOT EXISTS endpt.software_patch_rules (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
 branch_id uuid REFERENCES endpt.branches(id) ON DELETE CASCADE,
 app_id uuid NOT NULL REFERENCES endpt.app_library(id) ON DELETE CASCADE,
 inventory_name text NOT NULL CHECK(length(inventory_name) BETWEEN 1 AND 160),
 publisher text NOT NULL CHECK(length(publisher) BETWEEN 1 AND 160),
 target_version text NOT NULL CHECK(length(target_version) BETWEEN 1 AND 80),
 package_sha256 text NOT NULL CHECK(package_sha256 ~ '^[0-9a-f]{64}$'),
 install_args text NOT NULL DEFAULT '',
 approved_by uuid REFERENCES endpt.admin_users(id),
 enabled boolean NOT NULL DEFAULT false,
 window_start integer NOT NULL DEFAULT 0 CHECK(window_start BETWEEN 0 AND 23),
 window_end integer NOT NULL DEFAULT 0 CHECK(window_end BETWEEN 0 AND 23),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS endpt.software_patch_receipts (
 rule_id uuid NOT NULL REFERENCES endpt.software_patch_rules(id) ON DELETE CASCADE,
 endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
 inventory_digest text NOT NULL CHECK(inventory_digest ~ '^[0-9a-f]{64}$'),
 job_id uuid REFERENCES endpt.jobs(id) ON DELETE SET NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(rule_id,endpoint_id,inventory_digest)
);
CREATE TABLE IF NOT EXISTS endpt.support_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
 endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
 request_encrypted text NOT NULL,
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','claimed','resolved')),
 claimed_by uuid REFERENCES endpt.admin_users(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 resolved_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS support_request_open_device ON endpt.support_requests(endpoint_id) WHERE status IN ('open','claimed');
CREATE TABLE IF NOT EXISTS endpt.branch_traffic_rules (
 company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
 branch_id uuid NOT NULL REFERENCES endpt.branches(id) ON DELETE CASCADE,
 business_start integer NOT NULL CHECK(business_start BETWEEN 0 AND 23),
 business_end integer NOT NULL CHECK(business_end BETWEEN 0 AND 23),
 business_kbps integer NOT NULL CHECK(business_kbps BETWEEN 16 AND 1048576),
 offhours_kbps integer NOT NULL CHECK(offhours_kbps BETWEEN 16 AND 1048576),
 defer_updates boolean NOT NULL DEFAULT false,
 package_cache_node_id uuid REFERENCES endpt.home_storage_nodes(id) ON DELETE SET NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(company_id,branch_id)
);
ALTER TABLE endpt.software_patch_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpt.software_patch_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpt.support_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpt.branch_traffic_rules ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON endpt.software_patch_rules,endpt.software_patch_receipts,endpt.support_requests,endpt.branch_traffic_rules FROM PUBLIC;
GRANT ALL ON endpt.software_patch_rules,endpt.software_patch_receipts,endpt.support_requests,endpt.branch_traffic_rules TO service_role;
CREATE OR REPLACE FUNCTION endpt.dispatch_software_patch(p_rule uuid,p_endpoint uuid,p_digest text,p_payload text)
RETURNS SETOF endpt.jobs LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE r endpt.software_patch_rules; e endpt.endpoints; j endpt.jobs;
BEGIN
 SELECT * INTO r FROM endpt.software_patch_rules WHERE id=p_rule AND enabled FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO e FROM endpt.endpoints WHERE id=p_endpoint AND company_id=r.company_id;
 IF NOT FOUND OR (r.branch_id IS NOT NULL AND e.branch_id IS DISTINCT FROM r.branch_id) THEN RETURN; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_endpoint::text||':INSTALL_APP',0));
 IF EXISTS(SELECT 1 FROM endpt.software_patch_receipts WHERE rule_id=p_rule AND endpoint_id=p_endpoint AND inventory_digest=p_digest)
 OR EXISTS(SELECT 1 FROM endpt.jobs WHERE endpoint_id=p_endpoint AND type='INSTALL_APP' AND status IN ('pending','running','awaiting_approval')) THEN RETURN; END IF;
 IF NOT EXISTS(SELECT 1 FROM endpt.app_library WHERE id=r.app_id AND deletion_requested_at IS NULL AND (company_id IS NULL OR company_id=r.company_id)) THEN RETURN; END IF;
 INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
 VALUES(r.company_id,e.branch_id,e.id,'INSTALL_APP',p_payload,'pending',r.approved_by) RETURNING * INTO j;
 INSERT INTO endpt.software_patch_receipts(rule_id,endpoint_id,inventory_digest,job_id) VALUES(p_rule,p_endpoint,p_digest,j.id);
 RETURN NEXT j;
END; $$;
REVOKE ALL ON FUNCTION endpt.dispatch_software_patch(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.dispatch_software_patch(uuid,uuid,text,text) TO service_role;
NOTIFY pgrst,'reload schema';
CREATE OR REPLACE FUNCTION endpt.renew_agent_job_lease(p_endpoint uuid,p_job uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,pg_temp AS $$
DECLARE renewed uuid;
BEGIN
 UPDATE endpt.jobs SET lease_expires_at=now()+interval '15 minutes'
 WHERE id=p_job AND endpoint_id=p_endpoint AND status='running' AND started_at>now()-interval '24 hours'
 RETURNING id INTO renewed;
 RETURN renewed IS NOT NULL;
END; $$;
REVOKE ALL ON FUNCTION endpt.renew_agent_job_lease(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.renew_agent_job_lease(uuid,uuid) TO service_role;
COMMIT;
