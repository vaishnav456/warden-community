-- Apply before deploying the matching server/agent. Upgrade is per endpoint:
-- its first verified v1 request permanently disables token-only authentication.
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS
    request_device_proof_required BOOLEAN NOT NULL DEFAULT false;
