\set ON_ERROR_STOP on

-- Read-only compatibility report for importing an existing Warden database
-- into the single-organization community server.
SELECT current_database() AS database, now() AS checked_at;

SELECT count(*) AS organization_count FROM endpt.companies;
SELECT id, slug, name, is_active FROM endpt.companies ORDER BY created_at, id;

SELECT role, count(*) AS accounts
  FROM endpt.admin_users
 GROUP BY role
 ORDER BY role;

SELECT count(*) AS unsupported_admin_accounts
  FROM endpt.admin_users
 WHERE company_id IS NULL
    OR role NOT IN ('company_admin', 'branch_admin', 'technician');

SELECT count(*) AS endpoints,
       count(*) FILTER (WHERE is_active) AS active_endpoints
  FROM endpt.endpoints;

SELECT count(*) FILTER (WHERE wrapped_dek IS NOT NULL) AS organizations_with_wrapped_dek,
       count(*) FILTER (WHERE encryption_mode = 'byok') AS byok_organizations
  FROM endpt.companies;

SELECT to_regclass('endpt.subscriptions') AS legacy_subscriptions,
       to_regclass('endpt.platform_feature_flags') AS legacy_feature_flags,
       to_regclass('endpt.platform_feature_overrides') AS legacy_feature_overrides;

\echo 'PASS requires organization_count = 1 and unsupported_admin_accounts = 0.'
\echo 'Legacy SaaS tables are reported but are not imported, merged, or deleted automatically.'
