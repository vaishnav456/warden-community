CREATE TABLE IF NOT EXISTS endpt.platform_feature_flags (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    key text NOT NULL UNIQUE CHECK (key ~ '^[a-z0-9_]+$'),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    stage text NOT NULL DEFAULT 'alpha' CHECK (stage IN ('alpha','beta','ga','retired')),
    is_enabled boolean NOT NULL DEFAULT false,
    rollout_percent integer NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100),
    platforms jsonb NOT NULL DEFAULT '["windows"]'::jsonb,
    created_by uuid REFERENCES endpt.admin_users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpt.tenant_feature_overrides (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    flag_id uuid NOT NULL REFERENCES endpt.platform_feature_flags(id) ON DELETE CASCADE,
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    reason text NOT NULL CHECK (length(trim(reason)) >= 3),
    expires_at timestamptz,
    created_by uuid REFERENCES endpt.admin_users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(flag_id, company_id)
);

CREATE TABLE IF NOT EXISTS endpt.tenant_onboarding (
    company_id uuid PRIMARY KEY REFERENCES endpt.companies(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'not_started' CHECK (status IN ('not_started','in_progress','blocked','complete')),
    steps jsonb NOT NULL DEFAULT '{}'::jsonb,
    owner_id uuid REFERENCES endpt.admin_users(id),
    target_date date,
    notes text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpt.platform_incidents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    title text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    status text NOT NULL DEFAULT 'investigating' CHECK (status IN ('investigating','identified','monitoring','resolved')),
    affected_tenants jsonb NOT NULL DEFAULT '[]'::jsonb,
    summary text NOT NULL DEFAULT '',
    created_by uuid REFERENCES endpt.admin_users(id),
    resolved_by uuid REFERENCES endpt.admin_users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE TABLE IF NOT EXISTS endpt.platform_recovery_checks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    check_type text NOT NULL CHECK (check_type IN ('database_backup','restore_test','uploads_backup','agent_artifacts','tenant_export','disaster_recovery')),
    status text NOT NULL CHECK (status IN ('passed','warning','failed')),
    notes text NOT NULL DEFAULT '',
    evidence text NOT NULL DEFAULT '',
    checked_at timestamptz NOT NULL DEFAULT now(),
    checked_by uuid REFERENCES endpt.admin_users(id)
);

CREATE INDEX IF NOT EXISTS platform_incidents_status_idx ON endpt.platform_incidents(status, created_at DESC);
CREATE INDEX IF NOT EXISTS recovery_checks_type_time_idx ON endpt.platform_recovery_checks(check_type, checked_at DESC);
CREATE INDEX IF NOT EXISTS feature_overrides_company_idx ON endpt.tenant_feature_overrides(company_id);

INSERT INTO endpt.platform_feature_flags (key,name,description,stage,is_enabled,rollout_percent,platforms)
VALUES
 ('macos_agent','macOS agent','Cross-platform inventory, jobs and remote capabilities for macOS.','alpha',false,0,'["macos"]'),
 ('linux_agent','Linux agent','Cross-platform inventory, jobs and remote capabilities for Linux.','alpha',false,0,'["linux"]'),
 ('home_nodes','Warden Home Nodes','Tenant-operated peer file services and managed home directories.','alpha',false,0,'["windows","linux"]'),
 ('autopilot_sync','Windows Autopilot sync','Tenant-owned Microsoft Graph integration for zero-touch enrollment.','beta',true,100,'["windows"]'),
 ('packet_capture','Packet capture','Bounded, audited packet capture for endpoint troubleshooting.','beta',true,100,'["windows"]')
ON CONFLICT (key) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  endpt.platform_feature_flags, endpt.tenant_feature_overrides,
  endpt.tenant_onboarding, endpt.platform_incidents, endpt.platform_recovery_checks
TO service_role;
NOTIFY pgrst, 'reload schema';
