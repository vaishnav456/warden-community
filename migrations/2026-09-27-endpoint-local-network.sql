-- Agent-reported LAN identity for topology.  last_seen_ip remains the
-- server-observed transport address and is intentionally kept separate.
ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS local_ip TEXT,
    ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT 'unknown'
        CHECK (device_type IN ('desktop', 'laptop', 'server', 'iot', 'unknown'));

ALTER TABLE endpt.topology_floors ALTER COLUMN building SET DEFAULT 'Office';

NOTIFY pgrst, 'reload schema';
