SET ROLE service_role;
DO $$
DECLARE data jsonb; samples integer;
BEGIN
 data=endpt.dashboard_fleet('11111111-1111-1111-1111-111111111111',NULL,'2026-10-04 10:00Z');
 IF data->>'total_count'<>'2' OR data->>'online_count'<>'1' OR data->>'stale_count'<>'1'
  OR data->'health'->>'agent_updates'<>'1' OR data->'health'->>'encryption_attention'<>'1'
  OR data->'health'->>'patch_attention'<>'1' THEN RAISE EXCEPTION 'Fleet summary mismatch: %',data; END IF;
 data=endpt.dashboard_fleet('11111111-1111-1111-1111-111111111111','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','2026-10-04 10:00Z');
 IF data->>'total_count'<>'1' THEN RAISE EXCEPTION 'Branch/tenant leak'; END IF;
 SELECT count(*) INTO samples FROM endpt.sample_endpoint_metrics('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',1,60,'2026-10-04 10:00Z');
 IF samples<>60 THEN RAISE EXCEPTION 'Unexpected sample count: %',samples; END IF;
 SELECT count(*) INTO samples FROM endpt.sample_endpoint_metrics('22222222-2222-2222-2222-222222222222','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',1,60,'2026-10-04 10:00Z');
 IF samples<>0 THEN RAISE EXCEPTION 'Cross-tenant metric leak'; END IF;
 IF EXISTS(SELECT FROM endpt.sample_endpoint_metrics('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',1,60,'2026-10-04 10:00Z') WHERE metrics_encrypted IS NULL OR cpu_pct IS NOT NULL)
 THEN RAISE EXCEPTION 'Metric encryption changed'; END IF;
END $$;
RESET ROLE;
BEGIN;
INSERT INTO endpt.endpoint_metrics(endpoint_id,collected_at,cpu_pct,metrics_encrypted)
 VALUES('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','2026-10-04 10:00Z',NULL,'v2:boundary');
SET LOCAL ROLE service_role;
DO $$ DECLARE samples integer; rejected boolean=false; BEGIN
 SELECT count(*) INTO samples FROM endpt.sample_endpoint_metrics(
  '11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',1,60,'2026-10-04 10:00Z');
 IF samples<>60 THEN RAISE EXCEPTION 'Inclusive boundary exceeded sample bound'; END IF;
 BEGIN
  PERFORM endpt.sample_endpoint_metrics('11111111-1111-1111-1111-111111111111',
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',NULL,60,'2026-10-04 10:00Z');
 EXCEPTION WHEN raise_exception THEN rejected=true;
 END;
 IF NOT rejected THEN RAISE EXCEPTION 'NULL sample bounds accepted'; END IF;
END $$;
ROLLBACK;
DO $$ BEGIN
 IF has_function_privilege('fleet_anon','endpt.dashboard_fleet(uuid,uuid,timestamptz)','EXECUTE')
 OR has_function_privilege('fleet_anon','endpt.sample_endpoint_metrics(uuid,uuid,integer,integer,timestamptz)','EXECUTE')
 THEN RAISE EXCEPTION 'Anonymous RPC privilege'; END IF;
END $$;
SELECT 'Fleet counts, latest scan, branch/tenant isolation, bounded encrypted samples and permissions passed' AS result;
