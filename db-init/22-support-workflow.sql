BEGIN;
ALTER TABLE endpt.support_requests ADD COLUMN IF NOT EXISTS requester_key text;
DROP INDEX IF EXISTS endpt.support_request_open_device;
CREATE UNIQUE INDEX IF NOT EXISTS support_request_open_user ON endpt.support_requests(company_id,endpoint_id,requester_key) WHERE status IN ('open','claimed') AND requester_key IS NOT NULL;
ALTER TABLE endpt.support_requests ADD COLUMN IF NOT EXISTS service_mode text NOT NULL DEFAULT 'queued'
 CHECK(service_mode IN ('queued','remote','onsite','waiting_user'));
ALTER TABLE endpt.support_requests ADD COLUMN IF NOT EXISTS visit_at timestamptz;
ALTER TABLE endpt.support_requests ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
CREATE TABLE IF NOT EXISTS endpt.support_messages (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
 request_id uuid NOT NULL REFERENCES endpt.support_requests(id) ON DELETE CASCADE,
 author_admin_id uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
 message_encrypted text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS support_messages_request_time ON endpt.support_messages(request_id,created_at);
ALTER TABLE endpt.support_messages ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON endpt.support_messages FROM PUBLIC;
DO $$ DECLARE role_name text; BEGIN
 FOR role_name IN SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated') LOOP
  EXECUTE format('REVOKE ALL ON endpt.support_messages FROM %I',role_name);
 END LOOP;
END $$;
GRANT ALL ON endpt.support_messages TO service_role;
NOTIFY pgrst,'reload schema';
COMMIT;
