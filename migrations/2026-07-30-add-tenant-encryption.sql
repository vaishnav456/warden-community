-- Per-tenant envelope encryption (see server/services/tenant_crypto.py) and
-- the access-grant gate that stops superadmin cross-tenant viewing without
-- explicit tenant approval (see middleware/auth.py company_required()).
--
-- Written against the `endpt` schema — db.py's _get/_post/_patch send
-- Accept-Profile/Content-Profile: endpt on every request, so unqualified
-- table names here would resolve against `public` instead and never match
-- what the app actually queries. Applies to nothing live right now — the
-- `endpt` Supabase schema was dropped 2026-07-30 pending a dedicated
-- Postgres instance; keep this alongside the other pending migrations from
-- that same session until that instance exists (with `endpt` recreated
-- there under the same name).

ALTER TABLE endpt.companies ADD COLUMN IF NOT EXISTS encryption_mode text NOT NULL DEFAULT 'managed';
ALTER TABLE endpt.companies ADD COLUMN IF NOT EXISTS wrapped_dek text;
ALTER TABLE endpt.companies ADD COLUMN IF NOT EXISTS byok_salt text;

ALTER TABLE endpt.companies ADD CONSTRAINT companies_encryption_mode_check
    CHECK (encryption_mode IN ('managed', 'byok'));

CREATE TABLE IF NOT EXISTS endpt.tenant_access_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    requested_by uuid NOT NULL REFERENCES endpt.admin_users(id),
    reason text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'denied', 'revoked')),
    reviewed_by uuid REFERENCES endpt.admin_users(id),
    reviewed_at timestamptz,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenant_access_grants_company
    ON endpt.tenant_access_grants(company_id, status);
CREATE INDEX IF NOT EXISTS idx_tenant_access_grants_requester
    ON endpt.tenant_access_grants(requested_by, status);
