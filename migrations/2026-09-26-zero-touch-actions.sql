-- Post-enrollment policy, application, inventory, and patch actions for
-- reusable zero-touch profiles. IDs are validated tenant-side before save and
-- again before dispatch; the JSON shape keeps future actions additive.
ALTER TABLE endpt.enrollment_profiles
    ADD COLUMN IF NOT EXISTS post_enrollment JSONB NOT NULL DEFAULT '{}'::jsonb;
