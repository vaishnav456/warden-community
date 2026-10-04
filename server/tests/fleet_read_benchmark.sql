-- Synthetic query-level probe only. Run after fleet_read_fixture.sql and migration.
-- Everything added by this probe is rolled back.
BEGIN;
INSERT INTO endpt.endpoints
SELECT md5('fleet-endpoint-'||i)::uuid,'11111111-1111-1111-1111-111111111111',
 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',true,'online',
 '2026-10-04 10:00Z'::timestamptz,'windows','amd64','2.6.9'
FROM generate_series(1,10000) i;
INSERT INTO endpt.compliance_results
SELECT md5('fleet-endpoint-'||i)::uuid,'11111111-1111-1111-1111-111111111111',
 '2026-10-04 09:00Z'::timestamptz-make_interval(hours=>history),
 '[{"check":"bitlocker_enabled","status":"pass"}]'::jsonb
FROM generate_series(1,10000) i CROSS JOIN generate_series(0,4) history;
ANALYZE endpt.endpoints;
ANALYZE endpt.compliance_results;
ANALYZE endpt.patch_inventory;
ANALYZE endpt.build_requests;
SET LOCAL ROLE service_role;
DO $$ DECLARE data jsonb; BEGIN
 data=endpt.dashboard_fleet('11111111-1111-1111-1111-111111111111',NULL,'2026-10-04 10:00Z');
 IF data->>'total_count'<>'10002' OR jsonb_array_length(data->'endpoints')<>10 THEN
  RAISE EXCEPTION 'Fleet sampling/count regression';
 END IF;
END $$;
EXPLAIN (ANALYZE,BUFFERS)
SELECT endpt.dashboard_fleet('11111111-1111-1111-1111-111111111111',NULL,'2026-10-04 10:00Z');
EXPLAIN (ANALYZE,BUFFERS)
SELECT * FROM endpt.sample_endpoint_metrics('11111111-1111-1111-1111-111111111111',
 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',1,60,'2026-10-04 10:00Z');
ROLLBACK;
