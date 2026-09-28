-- Organization envelope encryption (the historical module filename remains
-- server/services/tenant_crypto.py for upgrade compatibility).
--
-- Written against the `endpt` schema — db.py's _get/_post/_patch send
-- Accept-Profile/Content-Profile: endpt on every request, so unqualified
-- table names here would resolve against `public` instead and never match
-- what the app actually queries. Applies to nothing live right now — the
-- `endpt` Supabase schema was dropped 2026-07-30 pending a dedicated
-- Postgres instance; keep this alongside the other pending migrations from
-- that same session until that instance exists (with `endpt` recreated
-- there under the same name).

ALTER TABLE endpt.companies ADD COLUMN IF NOT EXISTS encryption_mode text NOT NULL DEFAULT 'managed';
ALTER TABLE endpt.companies ADD COLUMN IF NOT EXISTS wrapped_dek text;
ALTER TABLE endpt.companies ADD COLUMN IF NOT EXISTS byok_salt text;

ALTER TABLE endpt.companies ADD CONSTRAINT companies_encryption_mode_check
    CHECK (encryption_mode IN ('managed', 'byok'));
