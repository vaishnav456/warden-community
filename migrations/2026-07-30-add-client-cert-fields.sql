-- Adds per-endpoint mTLS client-certificate tracking to endpt.endpoints,
-- needed for server/services/agent_ca.py + middleware/auth.py's
-- Cf-Client-Cert-Sha256 cross-check.
--
-- See migrations/2026-07-30-add-last-seen-ip.sql for the same caveat:
-- This migration targets an older installation's endpt.endpoints table.
--
--   psql "$SUPABASE_DB_URL" -f migrations/2026-07-30-add-client-cert-fields.sql

ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS client_cert_fingerprint text,
    ADD COLUMN IF NOT EXISTS cloudflare_cert_id text;

COMMENT ON COLUMN endpt.endpoints.client_cert_fingerprint IS
    'SHA-256 fingerprint of this endpoint''s Cloudflare-issued mTLS client certificate '
    '(server/services/agent_ca.py). Cross-checked against the Cf-Client-Cert-Sha256 header '
    'Cloudflare forwards, when config.REQUIRE_CLIENT_CERT is enabled.';

COMMENT ON COLUMN endpt.endpoints.cloudflare_cert_id IS
    'Cloudflare''s own certificate ID for this endpoint''s client cert — needed to call '
    'agent_ca.revoke_agent_cert() and actually delete it from Cloudflare, not just clear '
    'the fingerprint locally.';
