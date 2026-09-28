# Single-organization boundary

Warden Community manages exactly one organization per deployment. It does not
contain a platform administrator, organization creation or switching, SaaS
subscriptions, cross-organization access grants, or global application
publishing.

The boundary is enforced in three places:

1. PostgreSQL gives `endpt.companies.singleton` a unique checked value, so a
   second organization cannot be inserted.
2. Authentication resolves the one active organization and rejects an account
   or token linked to a different organization.
3. The web application exposes only organization administrator, branch
   administrator, and technician roles.

`company_id` remains on records as an ownership and referential-integrity key.
That keeps authorization joins explicit and avoids weakening data isolation if
the software is extended. A few legacy internal identifiers also remain for
safe upgrades: the persisted policy scope value `tenant`, the
`tenant_integrations` table, the `tenant_crypto.py` module, audit event names,
and `TENANT_MASTER_KEK_B64`. They do not provide multiple-organization
behavior and must not be exposed as a second-organization API.

Fresh deployments must use `db-init/02-schema.sql` and bootstrap exactly one
administrator with `db-init/04-bootstrap-admin.sql.example`. A database that
already contains more than one active organization is intentionally rejected;
split or migrate that data before using Warden Community.
