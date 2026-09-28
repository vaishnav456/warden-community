ALTER TABLE endpt.branches
    ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT 'UTC';

NOTIFY pgrst, 'reload schema';
