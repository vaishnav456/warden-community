-- Convert a SAME-RELEASE Warden database to the community edition boundary.
-- Run tools/community_migration_preflight.sql and take a verified backup first.
-- This deliberately refuses ambiguous multi-organization/platform-admin data.
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('warden-community-single-organization'));

DO $$
DECLARE
    organization_count INTEGER;
    unsupported_admin_count INTEGER;
BEGIN
    SELECT count(*) INTO organization_count FROM endpt.companies;
    IF organization_count <> 1 THEN
        RAISE EXCEPTION
            'community conversion requires exactly one organization; found %',
            organization_count;
    END IF;

    SELECT count(*) INTO unsupported_admin_count
      FROM endpt.admin_users
     WHERE company_id IS NULL
        OR role NOT IN ('company_admin', 'branch_admin', 'technician');
    IF unsupported_admin_count <> 0 THEN
        RAISE EXCEPTION
            'community conversion found % unsupported platform/unscoped admin account(s); resolve them explicitly before retrying',
            unsupported_admin_count;
    END IF;
END;
$$;

ALTER TABLE endpt.companies ADD COLUMN IF NOT EXISTS singleton BOOLEAN;
UPDATE endpt.companies SET singleton = TRUE WHERE singleton IS DISTINCT FROM TRUE;
ALTER TABLE endpt.companies ALTER COLUMN singleton SET DEFAULT TRUE;
ALTER TABLE endpt.companies ALTER COLUMN singleton SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'endpt.companies'::regclass
           AND contype = 'c'
           AND pg_get_constraintdef(oid) = 'CHECK (singleton)'
    ) THEN
        ALTER TABLE endpt.companies
            ADD CONSTRAINT companies_singleton_true_check CHECK (singleton);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conrelid = 'endpt.companies'::regclass
           AND contype = 'u'
           AND pg_get_constraintdef(oid) = 'UNIQUE (singleton)'
    ) THEN
        ALTER TABLE endpt.companies
            ADD CONSTRAINT companies_singleton_unique UNIQUE (singleton);
    END IF;
END;
$$;

COMMIT;
NOTIFY pgrst, 'reload schema';
