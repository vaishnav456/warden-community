-- Synthetic isolated fixture only: never run against an application database.
-- Inserts and statistics are rolled back; no production capacity claim.
BEGIN;
INSERT INTO endpt.jobs(company_id,branch_id,status,created_at)
SELECT md5((i % 100)::text)::uuid, NULL,
       CASE WHEN i % 3 = 0 THEN 'pending' WHEN i % 3 = 1 THEN 'running' ELSE 'failed' END,
       '2026-10-04 09:00Z'::timestamptz
FROM generate_series(1,100000) i;
INSERT INTO endpt.alerts(company_id,branch_id,is_resolved,snoozed_until,severity)
SELECT md5((i % 100)::text)::uuid, NULL, false, NULL, 'critical'
FROM generate_series(1,100000) i;
INSERT INTO endpt.escalation_requests(company_id,branch_id,status,expires_at)
SELECT md5((i % 100)::text)::uuid, NULL, 'pending', '2026-10-04 11:00Z'::timestamptz
FROM generate_series(1,100000) i;
ANALYZE endpt.jobs;
ANALYZE endpt.alerts;
ANALYZE endpt.escalation_requests;
SET LOCAL ROLE service_role;
EXPLAIN (ANALYZE, BUFFERS)
SELECT count(*) FROM endpt.jobs
WHERE company_id=md5('1')::uuid AND status IN ('pending','running','failed');
EXPLAIN (ANALYZE, BUFFERS)
SELECT endpt.dashboard_counts(md5('1')::uuid, NULL, '2026-10-04 10:00Z');
SELECT endpt.dashboard_counts(md5('1')::uuid, NULL, '2026-10-04 10:00Z');
ROLLBACK;
