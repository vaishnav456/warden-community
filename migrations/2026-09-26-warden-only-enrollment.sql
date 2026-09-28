-- Optional post-enrollment Windows lockdown.  The recovery credential is
-- stored as a tenant-encrypted JSON envelope, never as plaintext columns.
ALTER TABLE endpt.enrollment_profiles
    ADD COLUMN IF NOT EXISTS warden_only_mode BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS lockdown_config JSONB;

GRANT SELECT, INSERT, UPDATE, DELETE ON endpt.enrollment_profiles TO service_role;
