-- Agent-reported operating-system family and command capabilities.
-- Capabilities are authoritative for dispatch/UI; os_name remains the
-- human-readable inventory value (for example "Ubuntu 24.04" or "macOS 15").
ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'windows'
        CHECK (platform IN ('windows', 'linux', 'darwin', 'unknown')),
    ADD COLUMN IF NOT EXISTS capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS capability_details JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_endpoints_platform
    ON endpt.endpoints(company_id, platform);

ALTER TABLE endpt.build_requests
    ADD COLUMN IF NOT EXISTS target_platform TEXT NOT NULL DEFAULT 'windows-amd64'
        CHECK (target_platform IN ('windows-amd64', 'linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64'));
CREATE INDEX IF NOT EXISTS idx_build_requests_target_latest
    ON endpt.build_requests(target_platform, completed_at DESC)
    WHERE status = 'completed';
