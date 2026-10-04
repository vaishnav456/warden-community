CREATE ROLE service_role;
CREATE ROLE fleet_anon;
CREATE SCHEMA endpt;
CREATE TABLE endpt.endpoints(id uuid PRIMARY KEY,company_id uuid,branch_id uuid,is_active boolean,status text,last_seen timestamptz,platform text,arch text,agent_version text);
CREATE TABLE endpt.build_requests(id uuid PRIMARY KEY,status text,sha256 text,target_platform text,agent_version text,completed_at timestamptz);
CREATE TABLE endpt.compliance_results(endpoint_id uuid,company_id uuid,scanned_at timestamptz,results jsonb);
CREATE TABLE endpt.patch_inventory(id uuid PRIMARY KEY,company_id uuid,endpoint_id uuid);
CREATE TABLE endpt.endpoint_metrics(id bigint GENERATED ALWAYS AS IDENTITY,endpoint_id uuid,collected_at timestamptz,cpu_pct numeric,metrics_encrypted text);
GRANT USAGE ON SCHEMA endpt TO service_role,fleet_anon;
GRANT SELECT ON ALL TABLES IN SCHEMA endpt TO service_role;
INSERT INTO endpt.endpoints VALUES
('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','11111111-1111-1111-1111-111111111111','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',true,'online','2026-10-04 10:00Z','windows','amd64','2.6.9'),
('cccccccc-cccc-cccc-cccc-cccccccccccc','11111111-1111-1111-1111-111111111111','dddddddd-dddd-dddd-dddd-dddddddddddd',true,'online','2026-10-04 09:00Z','linux','arm64','bad'),
('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee','22222222-2222-2222-2222-222222222222','bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',true,'online','2026-10-04 10:00Z','windows','amd64','2.6.9');
INSERT INTO endpt.build_requests VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','completed','sha','windows-amd64','2.6.10','2026-10-04 09:00Z');
INSERT INTO endpt.compliance_results VALUES
('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','11111111-1111-1111-1111-111111111111','2026-10-04 09:00Z','[{"check":"bitlocker_enabled","status":"fail"}]'),
('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','11111111-1111-1111-1111-111111111111','2026-10-03 09:00Z','[{"check":"bitlocker_enabled","status":"pass"}]');
INSERT INTO endpt.patch_inventory VALUES ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
INSERT INTO endpt.endpoint_metrics(endpoint_id,collected_at,cpu_pct,metrics_encrypted)
SELECT 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '2026-10-04 09:00Z'::timestamptz+make_interval(secs=>i),NULL,'v2:encrypted-'||i FROM generate_series(0,3600) i;
