ALTER TABLE endpt.remote_sessions
    ADD COLUMN IF NOT EXISTS access_mode text NOT NULL DEFAULT 'full_control'
        CHECK (access_mode IN ('view_only','full_control','unattended')),
    ADD COLUMN IF NOT EXISTS capabilities jsonb NOT NULL DEFAULT
        '{"view":true,"control":true,"clipboard":true,"file_transfer":true,"process_manager":true,"reboot":true}'::jsonb,
    ADD COLUMN IF NOT EXISTS reason text,
    ADD COLUMN IF NOT EXISTS consent_required boolean NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_remote_sessions_admin_active
    ON endpt.remote_sessions(admin_id, status) WHERE status = 'active';
