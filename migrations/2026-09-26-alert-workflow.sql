ALTER TABLE endpt.alerts
    ADD COLUMN IF NOT EXISTS assigned_to UUID REFERENCES endpt.admin_users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_alerts_assigned_open
    ON endpt.alerts(assigned_to, created_at DESC) WHERE is_resolved = FALSE;
