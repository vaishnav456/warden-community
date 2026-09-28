-- Effective policy hierarchy, patch rollout orchestration, network-flow
-- telemetry and evidence-backed vulnerability findings.

CREATE TABLE IF NOT EXISTS endpt.policy_assignments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    template_id uuid NOT NULL REFERENCES endpt.policy_templates(id) ON DELETE CASCADE,
    scope_type text NOT NULL CHECK (scope_type IN ('tenant','branch','tag','endpoint')),
    scope_value text,
    priority integer NOT NULL DEFAULT 0 CHECK (priority BETWEEN -1000 AND 1000),
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope_type = 'tenant' AND scope_value IS NULL) OR
           (scope_type <> 'tenant' AND length(trim(scope_value)) > 0))
);
CREATE INDEX IF NOT EXISTS idx_policy_assignments_company_scope
    ON endpt.policy_assignments(company_id, scope_type, scope_value) WHERE enabled;

CREATE TABLE IF NOT EXISTS endpt.patch_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    name text NOT NULL,
    scope_type text NOT NULL CHECK (scope_type IN ('tenant','branch','tag','endpoints')),
    scope_value jsonb NOT NULL DEFAULT 'null'::jsonb,
    severities text[] NOT NULL DEFAULT ARRAY['Critical','Important']::text[],
    pilot_percentage integer NOT NULL DEFAULT 10 CHECK (pilot_percentage BETWEEN 1 AND 100),
    broad_after_hours integer NOT NULL DEFAULT 24 CHECK (broad_after_hours BETWEEN 0 AND 720),
    deadline_hours integer NOT NULL DEFAULT 168 CHECK (deadline_hours BETWEEN 1 AND 2160),
    maintenance_start time,
    maintenance_end time,
    timezone text NOT NULL DEFAULT 'UTC',
    reboot_mode text NOT NULL DEFAULT 'notify' CHECK (reboot_mode IN ('never','notify','force_at_deadline')),
    enabled boolean NOT NULL DEFAULT true,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(company_id, name)
);
CREATE INDEX IF NOT EXISTS idx_patch_policies_company ON endpt.patch_policies(company_id, enabled);

CREATE TABLE IF NOT EXISTS endpt.patch_deployments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    policy_id uuid NOT NULL REFERENCES endpt.patch_policies(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'pilot' CHECK (status IN ('pilot','waiting','broad','completed','paused','cancelled')),
    started_at timestamptz NOT NULL DEFAULT now(),
    broad_at timestamptz NOT NULL,
    deadline_at timestamptz NOT NULL,
    encrypted_payload text NOT NULL,
    created_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_patch_deployments_due ON endpt.patch_deployments(status, broad_at);

CREATE TABLE IF NOT EXISTS endpt.patch_deployment_targets (
    deployment_id uuid NOT NULL REFERENCES endpt.patch_deployments(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    ring text NOT NULL CHECK (ring IN ('pilot','broad')),
    job_id uuid REFERENCES endpt.jobs(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'waiting' CHECK (status IN ('waiting','queued','completed','failed','cancelled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(deployment_id, endpoint_id)
);
CREATE INDEX IF NOT EXISTS idx_patch_targets_job ON endpt.patch_deployment_targets(job_id) WHERE job_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS endpt.network_flows (
    id bigserial PRIMARY KEY,
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    protocol text NOT NULL CHECK (protocol IN ('tcp','udp')),
    direction text NOT NULL DEFAULT 'outbound' CHECK (direction IN ('inbound','outbound','unknown')),
    local_address inet,
    local_port integer CHECK (local_port BETWEEN 0 AND 65535),
    remote_address inet,
    remote_port integer CHECK (remote_port BETWEEN 0 AND 65535),
    process_id integer,
    process_name text,
    process_path text,
    state text,
    policy_action text CHECK (policy_action IS NULL OR policy_action IN ('allow','block','unmatched')),
    policy_rule text,
    policy_weight integer,
    observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_network_flows_endpoint_time ON endpt.network_flows(endpoint_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_network_flows_company_time ON endpt.network_flows(company_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS endpt.vulnerability_advisories (
    id text PRIMARY KEY,
    source text NOT NULL,
    vendor text,
    product text,
    title text NOT NULL,
    description text,
    severity text,
    cvss numeric(3,1),
    known_exploited boolean NOT NULL DEFAULT false,
    remediation text,
    source_url text,
    published_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpt.vulnerability_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    endpoint_id uuid NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    software_id uuid REFERENCES endpt.software_inventory(id) ON DELETE CASCADE,
    advisory_id text NOT NULL REFERENCES endpt.vulnerability_advisories(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','remediated','false_positive')),
    confidence text NOT NULL CHECK (confidence IN ('exact','high','potential')),
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE(endpoint_id, software_id, advisory_id)
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_company
    ON endpt.vulnerability_findings(company_id, status, confidence);

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.policy_assignments TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.patch_policies TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.patch_deployments TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.patch_deployment_targets TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.network_flows TO service_role;
GRANT USAGE, SELECT ON SEQUENCE endpt.network_flows_id_seq TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.vulnerability_advisories TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.vulnerability_findings TO service_role;

CREATE OR REPLACE FUNCTION endpt.create_patch_deployment(
    p_company_id uuid, p_policy_id uuid, p_pilot_ids uuid[], p_broad_ids uuid[],
    p_encrypted_payload text, p_created_by uuid
) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE p endpt.patch_policies%ROWTYPE; deployment uuid; endpoint_id uuid; job uuid;
BEGIN
    SELECT * INTO p FROM endpt.patch_policies
     WHERE id=p_policy_id AND company_id=p_company_id AND enabled FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'patch policy not found'; END IF;
    INSERT INTO endpt.patch_deployments(
        company_id,policy_id,status,broad_at,deadline_at,encrypted_payload,created_by
    ) VALUES (
        p_company_id,p_policy_id,
        CASE WHEN cardinality(p_broad_ids)=0 THEN 'broad' ELSE 'pilot' END,
        now()+make_interval(hours=>p.broad_after_hours),
        now()+make_interval(hours=>p.deadline_hours),p_encrypted_payload,p_created_by
    ) RETURNING id INTO deployment;
    FOREACH endpoint_id IN ARRAY p_pilot_ids LOOP
        IF NOT EXISTS(SELECT 1 FROM endpt.endpoints WHERE id=endpoint_id AND company_id=p_company_id AND is_active) THEN
            RAISE EXCEPTION 'invalid patch target';
        END IF;
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        SELECT p_company_id,e.branch_id,e.id,'WINDOWS_UPDATE',p_encrypted_payload,'pending',p_created_by
          FROM endpt.endpoints e WHERE e.id=endpoint_id RETURNING id INTO job;
        INSERT INTO endpt.patch_deployment_targets(deployment_id,endpoint_id,ring,job_id,status)
        VALUES(deployment,endpoint_id,'pilot',job,'queued');
    END LOOP;
    FOREACH endpoint_id IN ARRAY p_broad_ids LOOP
        IF NOT EXISTS(SELECT 1 FROM endpt.endpoints WHERE id=endpoint_id AND company_id=p_company_id AND is_active) THEN
            RAISE EXCEPTION 'invalid patch target';
        END IF;
        INSERT INTO endpt.patch_deployment_targets(deployment_id,endpoint_id,ring,status)
        VALUES(deployment,endpoint_id,'broad','waiting');
    END LOOP;
    RETURN deployment;
END; $$;

CREATE OR REPLACE FUNCTION endpt.promote_patch_deployment(p_deployment_id uuid)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE d endpt.patch_deployments%ROWTYPE; target record; job uuid; queued integer:=0;
        pilot_total integer; pilot_open integer; pilot_failed integer;
BEGIN
    SELECT * INTO d FROM endpt.patch_deployments WHERE id=p_deployment_id AND status IN('pilot','waiting') FOR UPDATE;
    IF NOT FOUND OR d.broad_at>now() THEN RETURN 0; END IF;
    SELECT count(*), count(*) FILTER(WHERE status IN('waiting','queued')),
           count(*) FILTER(WHERE status='failed')
      INTO pilot_total,pilot_open,pilot_failed FROM endpt.patch_deployment_targets
     WHERE deployment_id=d.id AND ring='pilot';
    IF pilot_open>0 THEN
        UPDATE endpt.patch_deployments SET status='waiting',broad_at=now()+interval '1 hour' WHERE id=d.id;
        RETURN 0;
    END IF;
    IF pilot_failed>=2 OR pilot_failed*100>GREATEST(pilot_total,1)*20 THEN
        UPDATE endpt.patch_deployments SET status='paused' WHERE id=d.id;
        RETURN -pilot_failed;
    END IF;
    FOR target IN SELECT t.endpoint_id,e.branch_id FROM endpt.patch_deployment_targets t
        JOIN endpt.endpoints e ON e.id=t.endpoint_id
        WHERE t.deployment_id=d.id AND t.ring='broad' AND t.status='waiting' FOR UPDATE OF t
    LOOP
        INSERT INTO endpt.jobs(company_id,branch_id,endpoint_id,type,payload,status,created_by)
        VALUES(d.company_id,target.branch_id,target.endpoint_id,'WINDOWS_UPDATE',d.encrypted_payload,'pending',d.created_by)
        RETURNING id INTO job;
        UPDATE endpt.patch_deployment_targets SET job_id=job,status='queued'
         WHERE deployment_id=d.id AND endpoint_id=target.endpoint_id;
        queued:=queued+1;
    END LOOP;
    UPDATE endpt.patch_deployments SET status='broad' WHERE id=d.id;
    RETURN queued;
END; $$;

CREATE OR REPLACE FUNCTION endpt.refresh_patch_deployment(p_job_id uuid, p_succeeded boolean)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=endpt,public AS $$
DECLARE deployment uuid; open_count integer;
BEGIN
    UPDATE endpt.patch_deployment_targets SET status=CASE WHEN p_succeeded THEN 'completed' ELSE 'failed' END
     WHERE job_id=p_job_id RETURNING deployment_id INTO deployment;
    IF deployment IS NULL THEN RETURN; END IF;
    SELECT count(*) INTO open_count FROM endpt.patch_deployment_targets
     WHERE deployment_id=deployment AND status IN('waiting','queued');
    IF open_count=0 THEN UPDATE endpt.patch_deployments SET status='completed' WHERE id=deployment; END IF;
END; $$;

REVOKE ALL ON FUNCTION endpt.create_patch_deployment(uuid,uuid,uuid[],uuid[],text,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION endpt.promote_patch_deployment(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION endpt.refresh_patch_deployment(uuid,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.create_patch_deployment(uuid,uuid,uuid[],uuid[],text,uuid) TO service_role;
GRANT EXECUTE ON FUNCTION endpt.promote_patch_deployment(uuid) TO service_role;
GRANT EXECUTE ON FUNCTION endpt.refresh_patch_deployment(uuid,boolean) TO service_role;
