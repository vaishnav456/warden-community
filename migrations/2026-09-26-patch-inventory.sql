CREATE TABLE IF NOT EXISTS endpt.patch_inventory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    endpoint_id     UUID NOT NULL REFERENCES endpt.endpoints(id) ON DELETE CASCADE,
    update_id       TEXT NOT NULL,
    title           TEXT NOT NULL,
    kb_articles     TEXT[] NOT NULL DEFAULT '{}',
    severity        TEXT,
    categories      TEXT[] NOT NULL DEFAULT '{}',
    reboot_required BOOLEAN NOT NULL DEFAULT FALSE,
    reported_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(endpoint_id, update_id)
);
CREATE INDEX IF NOT EXISTS idx_patch_inventory_company ON endpt.patch_inventory(company_id, severity);
GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.patch_inventory TO service_role;
