SET ROLE service_role;
DO $$
DECLARE actual jsonb;
BEGIN
  SET LOCAL timezone = 'Asia/Kolkata';
  actual := endpt.dashboard_counts('11111111-1111-1111-1111-111111111111','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','2026-10-04 10:00Z');
  IF actual <> '{"pending_escalations":2,"open_alerts":2,"critical_alerts":2,"failed_jobs":1,"pending_jobs":1,"running_jobs":1}'::jsonb THEN
    RAISE EXCEPTION 'Branch counts mismatch: %', actual;
  END IF;
  actual := endpt.dashboard_counts('11111111-1111-1111-1111-111111111111',NULL,'2026-10-04 15:30+05:30');
  IF actual <> '{"pending_escalations":3,"open_alerts":3,"critical_alerts":2,"failed_jobs":1,"pending_jobs":2,"running_jobs":1}'::jsonb THEN
    RAISE EXCEPTION 'Company counts/timezone mismatch: %', actual;
  END IF;
  actual := endpt.dashboard_counts('22222222-2222-2222-2222-222222222222','aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','2026-10-04 10:00Z');
  IF actual <> '{"pending_escalations":1,"open_alerts":1,"critical_alerts":1,"failed_jobs":0,"pending_jobs":1,"running_jobs":0}'::jsonb THEN
    RAISE EXCEPTION 'Tenant isolation mismatch: %', actual;
  END IF;
  actual := endpt.dashboard_counts('33333333-3333-3333-3333-333333333333',NULL,'2026-10-04 10:00Z');
  IF EXISTS (SELECT 1 FROM jsonb_each_text(actual) WHERE value <> '0') THEN
    RAISE EXCEPTION 'Empty tenant did not return zero counters';
  END IF;
END;
$$;
RESET ROLE;
DO $$
BEGIN
  IF has_function_privilege('read_optimization_anon','endpt.dashboard_counts(uuid,uuid,timestamptz)','EXECUTE') THEN
    RAISE EXCEPTION 'Anonymous access must not be granted';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_proc WHERE oid='endpt.dashboard_counts(uuid,uuid,timestamptz)'::regprocedure AND prosecdef) THEN
    RAISE EXCEPTION 'Aggregate must not elevate database privileges';
  END IF;
END;
$$;
SELECT 'Aggregate counts, UTC boundaries, tenant/branch isolation and permissions passed' AS result;
