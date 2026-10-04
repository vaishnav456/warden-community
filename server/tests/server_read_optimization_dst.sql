-- A rolling 24 hours must not become 23/25 hours at a daylight-saving change.
BEGIN;
INSERT INTO endpt.jobs(company_id, branch_id, status, created_at) VALUES
('33333333-3333-3333-3333-333333333333', NULL, 'failed', '2026-03-07 12:00Z'),
('33333333-3333-3333-3333-333333333333', NULL, 'failed', '2026-03-07 12:30Z'),
('44444444-4444-4444-4444-444444444444', NULL, 'failed', '2026-11-01 11:59Z'),
('44444444-4444-4444-4444-444444444444', NULL, 'failed', '2026-11-01 12:00Z');
SET LOCAL ROLE service_role;
SET LOCAL TIME ZONE 'America/New_York';
DO $$
BEGIN
    IF (endpt.dashboard_counts('33333333-3333-3333-3333-333333333333', NULL,
        '2026-03-08 12:00Z')->>'failed_jobs')::integer <> 2 THEN
        RAISE EXCEPTION 'Spring DST changed the rolling 24-hour window';
    END IF;
    IF (endpt.dashboard_counts('44444444-4444-4444-4444-444444444444', NULL,
        '2026-11-02 12:00Z')->>'failed_jobs')::integer <> 1 THEN
        RAISE EXCEPTION 'Autumn DST changed the rolling 24-hour window';
    END IF;
END $$;
ROLLBACK;
SELECT 'Spring and autumn daylight-saving boundaries passed' AS result;
