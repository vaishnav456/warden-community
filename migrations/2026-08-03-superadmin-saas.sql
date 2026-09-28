-- Provider-neutral SaaS control plane. Lemon Squeezy identifiers are reserved
-- but intentionally nullable until the billing integration is enabled.
CREATE TABLE IF NOT EXISTS endpt.plans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code text NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9_]+$'),
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    is_active boolean NOT NULL DEFAULT true,
    is_public boolean NOT NULL DEFAULT true,
    sort_order integer NOT NULL DEFAULT 0,
    endpoint_limit integer CHECK (endpoint_limit IS NULL OR endpoint_limit >= 0),
    admin_limit integer CHECK (admin_limit IS NULL OR admin_limit >= 0),
    branch_limit integer CHECK (branch_limit IS NULL OR branch_limit >= 0),
    audit_retention_days integer NOT NULL DEFAULT 30 CHECK (audit_retention_days > 0),
    features jsonb NOT NULL DEFAULT '{}'::jsonb,
    support_tier text NOT NULL DEFAULT 'standard',
    monthly_price_cents integer CHECK (monthly_price_cents IS NULL OR monthly_price_cents >= 0),
    annual_price_cents integer CHECK (annual_price_cents IS NULL OR annual_price_cents >= 0),
    currency char(3) NOT NULL DEFAULT 'USD',
    provider_product_id text,
    provider_monthly_variant_id text,
    provider_annual_variant_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpt.subscriptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL UNIQUE REFERENCES endpt.companies(id) ON DELETE CASCADE,
    plan_id uuid NOT NULL REFERENCES endpt.plans(id),
    provider text NOT NULL DEFAULT 'manual',
    provider_customer_id text,
    provider_subscription_id text UNIQUE,
    status text NOT NULL DEFAULT 'active'
      CHECK (status IN ('on_trial','active','paused','past_due','unpaid','cancelled','expired')),
    lifecycle_state text NOT NULL DEFAULT 'active'
      CHECK (lifecycle_state IN ('active','grace','read_only','suspended','deletion_pending')),
    billing_interval text NOT NULL DEFAULT 'manual'
      CHECK (billing_interval IN ('manual','monthly','annual')),
    quantity integer NOT NULL DEFAULT 1 CHECK (quantity > 0),
    recurring_amount_cents integer NOT NULL DEFAULT 0 CHECK (recurring_amount_cents >= 0),
    currency char(3) NOT NULL DEFAULT 'USD',
    trial_ends_at timestamptz,
    renews_at timestamptz,
    cancel_at timestamptz,
    ends_at timestamptz,
    test_mode boolean NOT NULL DEFAULT false,
    last_synced_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpt.entitlement_overrides (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    entitlement_key text NOT NULL,
    value jsonb NOT NULL,
    reason text NOT NULL CHECK (length(trim(reason)) >= 3),
    expires_at timestamptz,
    created_by uuid REFERENCES endpt.admin_users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    revoked_by uuid REFERENCES endpt.admin_users(id)
);
CREATE INDEX IF NOT EXISTS entitlement_overrides_active_idx
  ON endpt.entitlement_overrides(company_id, entitlement_key)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS endpt.usage_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    captured_at timestamptz NOT NULL DEFAULT now(),
    endpoints integer NOT NULL DEFAULT 0,
    online_endpoints integer NOT NULL DEFAULT 0,
    admins integer NOT NULL DEFAULT 0,
    branches integer NOT NULL DEFAULT 0,
    remote_sessions_30d integer NOT NULL DEFAULT 0,
    jobs_30d integer NOT NULL DEFAULT 0,
    failed_jobs_30d integer NOT NULL DEFAULT 0,
    transfer_bytes_30d bigint NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS usage_snapshots_company_time_idx
  ON endpt.usage_snapshots(company_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS endpt.tenant_lifecycle_actions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    action text NOT NULL,
    previous_state text,
    new_state text,
    reason text NOT NULL CHECK (length(trim(reason)) >= 3),
    effective_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    created_by uuid REFERENCES endpt.admin_users(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS endpt.webhook_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider text NOT NULL,
    provider_event_id text NOT NULL,
    event_name text NOT NULL,
    company_id uuid REFERENCES endpt.companies(id) ON DELETE SET NULL,
    status text NOT NULL DEFAULT 'received'
      CHECK (status IN ('received','processed','failed','ignored')),
    payload_digest text,
    attempts integer NOT NULL DEFAULT 0,
    error text,
    test_mode boolean NOT NULL DEFAULT false,
    received_at timestamptz NOT NULL DEFAULT now(),
    processed_at timestamptz,
    UNIQUE(provider, provider_event_id)
);

INSERT INTO endpt.plans
  (code,name,description,is_public,sort_order,endpoint_limit,admin_limit,branch_limit,
   audit_retention_days,features,support_tier,monthly_price_cents,annual_price_cents)
VALUES
  ('legacy','Legacy','Compatibility plan for existing tenants (editable)',false,0,2,NULL,NULL,3650,
   '{"inventory":true,"jobs":true,"remote_control":true,"file_transfer":true,"policy_management":true,"advanced_reporting":true,"api_access":true}'::jsonb,
   'priority',0,0),
  ('starter','Starter','Core endpoint inventory and management',true,10,25,5,3,30,
   '{"inventory":true,"jobs":true,"remote_control":false,"file_transfer":false,"policy_management":true,"advanced_reporting":false,"api_access":false}'::jsonb,
   'standard',4900,49000),
  ('business','Business','Remote support and expanded operations',true,20,250,25,25,365,
   '{"inventory":true,"jobs":true,"remote_control":true,"file_transfer":true,"policy_management":true,"advanced_reporting":true,"api_access":true}'::jsonb,
   'priority',19900,199000),
  ('enterprise','Enterprise','Custom scale, retention and support',true,30,NULL,NULL,NULL,2555,
   '{"inventory":true,"jobs":true,"remote_control":true,"file_transfer":true,"policy_management":true,"advanced_reporting":true,"api_access":true}'::jsonb,
   'enterprise',NULL,NULL)
ON CONFLICT (code) DO NOTHING;

INSERT INTO endpt.subscriptions (company_id, plan_id, provider, status, lifecycle_state)
SELECT c.id, p.id, 'manual', 'active', 'active'
FROM endpt.companies c CROSS JOIN endpt.plans p
WHERE p.code='legacy'
ON CONFLICT (company_id) DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  endpt.plans, endpt.subscriptions, endpt.entitlement_overrides,
  endpt.usage_snapshots, endpt.tenant_lifecycle_actions, endpt.webhook_events
TO service_role;
GRANT USAGE ON SCHEMA endpt TO service_role;
NOTIFY pgrst, 'reload schema';
