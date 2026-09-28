-- Adds last_seen_ip tracking to endpt.endpoints, needed for the
-- connection-anomaly detection in server/services/alert_engine.py
-- (IP-change flagging on heartbeat).
--
-- NOTE: this migration targets an older installation's endpt.endpoints table.
-- Fresh installations already contain this column in db-init/02-schema.sql.
-- Apply this standalone migration only when upgrading a deployment that
-- predates that consolidated schema:
--
--   psql "$SUPABASE_DB_URL" -f migrations/2026-07-30-add-last-seen-ip.sql
--
-- or via the Supabase SQL editor.

ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS last_seen_ip text;

COMMENT ON COLUMN endpt.endpoints.last_seen_ip IS
    'Client IP of the most recent heartbeat, as resolved by middleware/security.py::_get_ip() '
    '(CF-Connecting-IP if TRUST_CLOUDFLARE, else ProxyFix-adjusted remote_addr). '
    'Used by alert_engine.py to flag endpoints whose source IP changes unexpectedly.';
