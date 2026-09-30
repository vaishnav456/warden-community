BEGIN;
-- Stored using the same tenant encryption as other endpoint text fields.
ALTER TABLE endpt.endpoints ADD COLUMN IF NOT EXISTS display_name text;
NOTIFY pgrst, 'reload schema';
COMMIT;
