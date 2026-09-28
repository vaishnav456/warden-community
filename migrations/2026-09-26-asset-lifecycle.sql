ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS asset_tag TEXT,
    ADD COLUMN IF NOT EXISTS asset_state TEXT NOT NULL DEFAULT 'in_service',
    ADD COLUMN IF NOT EXISTS assigned_to TEXT,
    ADD COLUMN IF NOT EXISTS purchase_date DATE,
    ADD COLUMN IF NOT EXISTS warranty_expiry DATE,
    ADD COLUMN IF NOT EXISTS asset_metadata JSONB NOT NULL DEFAULT '{}'::jsonb;

DO $$ BEGIN
    ALTER TABLE endpt.endpoints ADD CONSTRAINT endpoints_asset_state_check
        CHECK (asset_state IN ('stock','in_service','repair','retired','disposed','lost'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS idx_endpoints_company_asset_state
    ON endpt.endpoints(company_id, asset_state);
CREATE UNIQUE INDEX IF NOT EXISTS idx_endpoints_company_asset_tag
    ON endpt.endpoints(company_id, lower(asset_tag)) WHERE asset_tag IS NOT NULL;
