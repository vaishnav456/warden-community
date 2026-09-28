BEGIN;
ALTER TABLE endpt.endpoints
    ADD COLUMN IF NOT EXISTS net_sent_mbps double precision,
    ADD COLUMN IF NOT EXISTS net_recv_mbps double precision,
    ADD COLUMN IF NOT EXISTS topology_telemetry jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS endpt.topology_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id uuid NOT NULL REFERENCES endpt.companies(id) ON DELETE CASCADE,
    floor_id uuid NOT NULL REFERENCES endpt.topology_floors(id) ON DELETE CASCADE,
    captured_at timestamptz NOT NULL DEFAULT now(),
    state jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_topology_snapshots_floor_time
    ON endpt.topology_snapshots(company_id, floor_id, captured_at DESC);
GRANT SELECT, INSERT, DELETE ON endpt.topology_snapshots TO service_role;
NOTIFY pgrst, 'reload schema';
COMMIT;
