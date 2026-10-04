# Server optimization validation — 2026-10-04

## Implemented

- Split database access into domain modules while retaining the existing db facade.
- Close HTTP responses explicitly, including parse/error paths; preserve TLS,
  authentication, schema profiles and timeouts. Do not retry writes.
- Replace six dashboard counter requests with one scoped aggregate RPC.
- Add partial indexes for dashboard jobs, unresolved alerts and pending approvals.
- Use exact metadata counts rather than downloading rows to count them.
- Fetch narrow dashboard projections and cache build summaries per platform
  within a request. Skip the redundant initial endpoint-name sort.
- Follow pagination metadata for fleet, inventory, branch and monitoring reads.
  Reject invalid or exhausted page bounds instead of returning partial results.
- Preserve company and branch constraints, including explicit bulk endpoint lists.
- Use an elapsed 24-hour failed-job window across daylight-saving transitions.

## Verification

The full offline server suites passed: hosted 666 tests and Community 645 tests.
Real PostgreSQL 16 checks passed for tenant/branch isolation, permission denial,
UTC-equivalent timestamps, both DST transitions and repeated migration application.
The workflow server-read-optimization.yml repeats the SQL regression checks in
a disposable database; it has not yet run remotely for these local changes.

The optional server/tests/server_read_optimization_benchmark.sql inserts 100,000
records per table across 100 synthetic tenants into the isolated fixture, then
rolls back. The observed single aggregate execution was 3.898 ms. The scoped
job count used idx_jobs_dashboard_scope and took 0.711 ms. These warm/local,
query-level measurements exclude HTTP, network, decryption, rendering and live
concurrency. They do not establish supported tenant or endpoint capacity.

## Release safety

These optimization changes are local development work, not a deployed release.
Before release, back up the database and apply
migrations/2026-10-04-server-read-optimization.sql during a suitable maintenance
window. Ordinary index creation takes write locks on populated tables.
New installations receive the same schema through db-init/26.

The server falls back to the previous scoped counter reads only when PostgREST
reports the aggregate function missing (PGRST202). Authorization and database
errors still fail; they do not become misleading zero counts.

Pagination traverses live rows, not a transaction snapshot. Concurrent insertion,
deletion or reordering can affect a multi-page read. A future production load
test should measure end-to-end latency, database I/O, worker saturation and
remote-session traffic using representative anonymized data.

Community retains its application-only entry flow and no marketing landing page.

The subsequent fleet/scheduler/telemetry pass and its current test evidence are
documented in [FLEET_READ_OPTIMIZATION.md](FLEET_READ_OPTIMIZATION.md).
Pooling and experimental process separation remain disabled by default.
