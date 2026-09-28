-- Grants for PostgREST's service_role. Supabase's hosted stack gives
-- service_role an automatic RLS-bypass "superpower" tied to its JWT — plain
-- PostgREST has no such magic, so service_role here is a real Postgres role
-- (created BYPASSRLS in 01-roles.sql) that needs real, explicit grants. RLS
-- itself is left disabled on every table (see 02-schema.sql) — this app's
-- access control is entirely at the Flask layer (role checks in
-- middleware/auth.py), matching how it always ran against Supabase without
-- ever defining a single RLS policy of its own.
GRANT USAGE ON SCHEMA endpt TO service_role;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA endpt TO service_role;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA endpt TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA endpt GRANT ALL PRIVILEGES ON TABLES TO service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA endpt GRANT ALL PRIVILEGES ON SEQUENCES TO service_role;

-- anon exists only because PGRST_DB_ANON_ROLE must reference something real
-- (db.py never sends an unauthenticated request) — deliberately zero grants.
GRANT USAGE ON SCHEMA endpt TO anon;
