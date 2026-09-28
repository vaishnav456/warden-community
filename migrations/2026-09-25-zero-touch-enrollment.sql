-- Windows zero-touch enrollment profiles and pre-registered device claims.
-- Profiles are deliberately separate from short-lived enrollment tokens:
-- an installer can be rebuilt/rotated without losing its assignment rules.

CREATE TABLE IF NOT EXISTS endpt.enrollment_profiles (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id               UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    branch_id                UUID REFERENCES endpt.branches(id) ON DELETE SET NULL,
    name                     TEXT NOT NULL,
    deployment_method        TEXT NOT NULL DEFAULT 'intune'
                                 CHECK (deployment_method IN ('manual', 'gpo', 'intune', 'autopilot', 'sccm', 'rmm')),
    hostname_pattern         TEXT,
    domain_suffix            TEXT,
    require_pre_registration BOOLEAN NOT NULL DEFAULT FALSE,
    reclaim_existing         BOOLEAN NOT NULL DEFAULT TRUE,
    is_active                BOOLEAN NOT NULL DEFAULT TRUE,
    created_by               UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, name)
);
CREATE INDEX IF NOT EXISTS idx_enrollment_profiles_company
    ON endpt.enrollment_profiles(company_id, is_active);
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrollment_profiles_company_name_ci
    ON endpt.enrollment_profiles(company_id, lower(name));
ALTER TABLE endpt.enrollment_profiles
    ALTER COLUMN deployment_method SET DEFAULT 'intune';

CREATE TABLE IF NOT EXISTS endpt.enrollment_device_claims (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id         UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    profile_id         UUID NOT NULL REFERENCES endpt.enrollment_profiles(id) ON DELETE CASCADE,
    hardware_id        TEXT NOT NULL,
    expected_hostname  TEXT,
    provider_device_id TEXT,
    assigned_user      TEXT,
    status             TEXT NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending', 'enrolled', 'released')),
    endpoint_id        UUID REFERENCES endpt.endpoints(id) ON DELETE SET NULL,
    enrolled_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (company_id, hardware_id)
);
CREATE INDEX IF NOT EXISTS idx_enrollment_claims_profile
    ON endpt.enrollment_device_claims(profile_id, status);

ALTER TABLE endpt.enrollment_tokens
    ADD COLUMN IF NOT EXISTS profile_id UUID REFERENCES endpt.enrollment_profiles(id) ON DELETE SET NULL;
ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS enrollment_profile_id UUID REFERENCES endpt.enrollment_profiles(id) ON DELETE SET NULL;
ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS device_identity JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Older agents reported the SMBIOS UUID with vendor-dependent casing.
-- Canonicalise it before new zero-touch matching starts.
UPDATE endpt.endpoints SET hardware_id = lower(trim(hardware_id))
 WHERE hardware_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_profile ON endpt.enrollment_tokens(profile_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_company_hardware
    ON endpt.endpoints(company_id, hardware_id) WHERE hardware_id IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.enrollment_profiles TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.enrollment_device_claims TO service_role;

NOTIFY pgrst, 'reload schema';
