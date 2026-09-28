-- Tenant-owned external integration credentials. The application encrypts
-- config_encrypted with the tenant DEK before it reaches PostgreSQL.
CREATE TABLE IF NOT EXISTS endpt.tenant_integrations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id       UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL CHECK (provider IN ('microsoft_entra')),
    config_encrypted TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,
    status           TEXT NOT NULL DEFAULT 'not_tested'
                         CHECK (status IN ('not_tested', 'connected', 'error', 'disabled')),
    metadata         JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_tested_at   TIMESTAMPTZ,
    last_error       TEXT,
    created_by       UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, provider)
);
CREATE INDEX IF NOT EXISTS idx_tenant_integrations_company
    ON endpt.tenant_integrations(company_id, enabled);

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.tenant_integrations TO service_role;
NOTIFY pgrst, 'reload schema';
