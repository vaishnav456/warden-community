-- Apply after operational foundations; service-role reads only.
CREATE INDEX IF NOT EXISTS idx_compliance_fleet_latest
 ON endpt.compliance_results(company_id,endpoint_id,scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_patch_fleet_endpoint
 ON endpt.patch_inventory(company_id,endpoint_id);
CREATE INDEX IF NOT EXISTS idx_build_fleet_latest
 ON endpt.build_requests(target_platform,completed_at DESC,id DESC)
 WHERE status='completed' AND sha256 IS NOT NULL;
CREATE OR REPLACE FUNCTION endpt.agent_version_parts(value text)
RETURNS integer[] LANGUAGE sql IMMUTABLE SECURITY INVOKER AS $$
 SELECT CASE WHEN value ~ '^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}$'
 THEN string_to_array(value,'.')::integer[] ELSE NULL END;
$$;
REVOKE ALL ON FUNCTION endpt.agent_version_parts(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.agent_version_parts(text) TO service_role;

CREATE OR REPLACE FUNCTION endpt.dashboard_fleet(p_company_id uuid,p_branch_id uuid DEFAULT NULL,
 p_now timestamptz DEFAULT now())
RETURNS jsonb LANGUAGE sql STABLE SECURITY INVOKER SET search_path=endpt,pg_temp AS $$
 WITH scoped AS (
  SELECT e.id,e.last_seen,e.status,e.agent_version,lower(coalesce(nullif(e.platform,''),'windows')) || '-' ||
   CASE WHEN lower(coalesce(e.platform,'windows'))='windows' THEN 'amd64'
        WHEN lower(e.arch) IN ('arm64','aarch64') THEN 'arm64' ELSE 'amd64' END AS target
  FROM endpt.endpoints e WHERE e.company_id=p_company_id AND e.is_active=true
   AND (p_branch_id IS NULL OR e.branch_id=p_branch_id)
 ), latest_builds AS MATERIALIZED (
  SELECT DISTINCT ON (target_platform) target_platform,endpt.agent_version_parts(agent_version) AS version
  FROM endpt.build_requests WHERE status='completed' AND sha256 IS NOT NULL
  ORDER BY target_platform,completed_at DESC,id DESC
 ), facts AS (
  SELECT e.id,e.last_seen,e.status,
   coalesce(e.status='online' AND e.last_seen BETWEEN p_now-interval '3 minutes' AND p_now,false) AS online,
   endpt.agent_version_parts(e.agent_version) AS installed,
   b.version AS published,
   CASE WHEN c.scanned_at NOT BETWEEN p_now-interval '24 hours' AND p_now OR c.scanned_at IS NULL
    OR coalesce(c.checks,0)=0 THEN 'unknown'
    WHEN c.failed THEN 'attention' WHEN c.passed THEN 'pass' ELSE 'unknown' END AS encryption,
   EXISTS(SELECT 1 FROM endpt.patch_inventory p WHERE p.company_id=p_company_id AND p.endpoint_id=e.id) AS patches
  FROM scoped e
  LEFT JOIN latest_builds b ON b.target_platform=e.target
  LEFT JOIN LATERAL (
   SELECT r.scanned_at,count(*) FILTER(WHERE v->>'check' IN ('bitlocker_enabled','disk_encryption_enabled')) AS checks,
    bool_or(v->>'status'='fail') FILTER(WHERE v->>'check' IN ('bitlocker_enabled','disk_encryption_enabled')) AS failed,
    bool_and(coalesce(v->>'status'='pass',false)) FILTER(WHERE v->>'check' IN ('bitlocker_enabled','disk_encryption_enabled')) AS passed
   FROM (SELECT scanned_at,results FROM endpt.compliance_results
    WHERE company_id=p_company_id AND endpoint_id=e.id ORDER BY scanned_at DESC LIMIT 1) r
   LEFT JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(r.results::jsonb)='array'
     THEN r.results::jsonb ELSE '[]'::jsonb END) v ON true GROUP BY r.scanned_at
  ) c ON true
 ), flags AS (
  SELECT *,coalesce(installed<published,false) AS needs_update,
   installed IS NULL OR published IS NULL AS unknown_agent FROM facts
 ), totals AS (
  SELECT count(*) AS total,count(*) FILTER(WHERE online) AS online,
   count(*) FILTER(WHERE NOT online) AS offline,
   count(*) FILTER(WHERE status='online' AND NOT online) AS stale,
   count(*) FILTER(WHERE needs_update) AS updates,
   count(*) FILTER(WHERE unknown_agent) AS unknown_agent,
   count(*) FILTER(WHERE encryption='attention') AS encryption_attention,
   count(*) FILTER(WHERE encryption='unknown') AS encryption_unknown,
   count(*) FILTER(WHERE patches) AS patch_attention FROM flags
 )
 SELECT jsonb_build_object(
  'total_count',totals.total,
  'online_count',totals.online,
  'offline_count',totals.offline,
  'stale_count',totals.stale,
  'health',jsonb_build_object(
   'agent_updates',totals.updates,
   'agent_unknown',totals.unknown_agent,
   'encryption_attention',totals.encryption_attention,
   'encryption_unknown',totals.encryption_unknown,
   'patch_attention',totals.patch_attention),
  'endpoints',coalesce((SELECT jsonb_agg(to_jsonb(e) || jsonb_build_object(
   '_online',sample.online,'_fresh',sample.last_seen BETWEEN p_now-interval '3 minutes' AND p_now,
   '_agent_update',needs_update,'_agent_unknown',unknown_agent,
   '_encryption',encryption,'_patch_attention',patches,
   '_offline_age',CASE WHEN sample.last_seen IS NULL THEN 'never' WHEN sample.last_seen<=p_now-interval '24 hours' THEN 'days' ELSE 'recent' END)
   ORDER BY sample.online,needs_update DESC,sample.last_seen ASC NULLS FIRST,sample.id)
   FROM (SELECT * FROM flags ORDER BY online,needs_update DESC,last_seen ASC NULLS FIRST,id LIMIT 10) sample
   JOIN endpt.endpoints e ON e.id=sample.id),'[]'::jsonb)) FROM totals;
$$;
REVOKE ALL ON FUNCTION endpt.dashboard_fleet(uuid,uuid,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.dashboard_fleet(uuid,uuid,timestamptz) TO service_role;

CREATE OR REPLACE FUNCTION endpt.sample_endpoint_metrics(p_company_id uuid,p_endpoint_id uuid,
 p_hours integer DEFAULT 24,p_points integer DEFAULT 240,p_now timestamptz DEFAULT now())
RETURNS SETOF endpt.endpoint_metrics LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=endpt,pg_temp AS $$
BEGIN
 IF p_hours IS NULL OR p_points IS NULL OR p_now IS NULL
    OR p_hours NOT BETWEEN 1 AND 168 OR p_points NOT BETWEEN 1 AND 1440 THEN
  RAISE EXCEPTION 'Invalid metric sample bounds';
 END IF;
 RETURN QUERY SELECT (picked.metric).* FROM (
  SELECT DISTINCT ON (least(p_points-1,floor(extract(epoch FROM (m.collected_at-(p_now-make_interval(hours=>p_hours)))) /
    (p_hours*3600.0/p_points)))) m AS metric
  FROM endpt.endpoint_metrics m
  WHERE m.endpoint_id=p_endpoint_id AND m.collected_at>p_now-make_interval(hours=>p_hours)
   AND m.collected_at<=p_now
   AND EXISTS(SELECT 1 FROM endpt.endpoints e WHERE e.id=p_endpoint_id AND e.company_id=p_company_id)
  ORDER BY least(p_points-1,floor(extract(epoch FROM (m.collected_at-(p_now-make_interval(hours=>p_hours)))) /
    (p_hours*3600.0/p_points))),m.collected_at DESC,m.id DESC
 ) picked ORDER BY (picked.metric).collected_at;
END $$;
REVOKE ALL ON FUNCTION endpt.sample_endpoint_metrics(uuid,uuid,integer,integer,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION endpt.sample_endpoint_metrics(uuid,uuid,integer,integer,timestamptz) TO service_role;
