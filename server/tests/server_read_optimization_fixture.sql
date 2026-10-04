CREATE ROLE service_role;
CREATE ROLE read_optimization_anon;
CREATE SCHEMA endpt;
CREATE TABLE endpt.jobs (id bigint GENERATED ALWAYS AS IDENTITY, company_id uuid, branch_id uuid, status text, created_at timestamptz);
CREATE TABLE endpt.alerts (id bigint GENERATED ALWAYS AS IDENTITY, company_id uuid, branch_id uuid, is_resolved boolean, snoozed_until timestamptz, severity text);
CREATE TABLE endpt.escalation_requests (id bigint GENERATED ALWAYS AS IDENTITY, company_id uuid, branch_id uuid, status text, expires_at timestamptz);
GRANT USAGE ON SCHEMA endpt TO service_role, read_optimization_anon;
GRANT SELECT ON ALL TABLES IN SCHEMA endpt TO service_role;
INSERT INTO endpt.jobs(company_id,branch_id,status,created_at) VALUES
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','pending','2026-09-01Z'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','running','2026-09-01Z'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','failed','2026-10-03 10:00Z'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','failed','2026-10-03 09:59Z'),
('11111111-1111-1111-1111-111111111111','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','pending','2026-10-04Z'),
('22222222-2222-2222-2222-222222222222','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','pending','2026-10-04Z');
INSERT INTO endpt.alerts(company_id,branch_id,is_resolved,snoozed_until,severity) VALUES
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',false,NULL,'critical'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',false,'2026-10-04 10:00Z','critical'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',false,'2026-10-04 10:01Z','critical'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',true,NULL,'critical'),
('11111111-1111-1111-1111-111111111111','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',false,NULL,'warning'),
('22222222-2222-2222-2222-222222222222','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',false,NULL,'critical');
INSERT INTO endpt.escalation_requests(company_id,branch_id,status,expires_at) VALUES
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','pending','2026-10-04 11:00Z'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','pending_secondary','2026-10-04 11:00Z'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','pending','2026-10-04 10:00Z'),
('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','approved','2026-10-04 11:00Z'),
('11111111-1111-1111-1111-111111111111','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb','pending','2026-10-04 11:00Z'),
('22222222-2222-2222-2222-222222222222','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','pending','2026-10-04 11:00Z');
