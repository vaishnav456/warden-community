ALTER TABLE endpt.software_inventory
    ADD COLUMN IF NOT EXISTS install_location TEXT,
    ADD COLUMN IF NOT EXISTS executable_path TEXT;

CREATE INDEX IF NOT EXISTS idx_software_inventory_executable
    ON endpt.software_inventory(endpoint_id, executable_path)
    WHERE executable_path IS NOT NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.software_inventory TO service_role;
