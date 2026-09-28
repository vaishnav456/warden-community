-- Crash-safe, idempotent enrollment identity. installation_id is generated
-- once on the endpoint before its first network request and is not hardware
-- derived, so cloned/replaced hardware cannot accidentally steal an identity.
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS hardware_id TEXT;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS installation_id TEXT;
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS enrollment_token_id UUID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_company_installation
    ON endpt.endpoints(company_id, installation_id)
    WHERE installation_id IS NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'endpoints_enrollment_token_id_fkey'
          AND conrelid = 'endpt.endpoints'::regclass
    ) THEN
        ALTER TABLE endpt.endpoints
            ADD CONSTRAINT endpoints_enrollment_token_id_fkey
            FOREIGN KEY (enrollment_token_id)
            REFERENCES endpt.enrollment_tokens(id) ON DELETE SET NULL;
    END IF;
END $$;
