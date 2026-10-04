BEGIN;
CREATE TABLE IF NOT EXISTS endpt.agent_module_policies (
 company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
 module_id text NOT NULL CHECK(module_id='helpdesk'),
 enabled boolean NOT NULL DEFAULT false,
 updated_by uuid REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(company_id,module_id)
);
ALTER TABLE endpt.agent_module_policies ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON endpt.agent_module_policies FROM PUBLIC;
DO $$ DECLARE r text; BEGIN
 FOR r IN SELECT rolname FROM pg_roles WHERE rolname IN ('anon','authenticated') LOOP
  EXECUTE format('REVOKE ALL ON endpt.agent_module_policies FROM %I',r);
 END LOOP;
END $$;
GRANT ALL ON endpt.agent_module_policies TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
