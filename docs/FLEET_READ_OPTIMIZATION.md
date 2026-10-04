# Fleet read optimization — development candidate

These changes are source-only on develop in both editions. No live database,
server, agent or Home rollout is implied. Community remains application-only.

## Implemented behavior

- Auto-update eligibility uses two ordered, paged, tenant-scoped metadata reads
  for recent UPDATE_AGENT jobs and active remote sessions. Campaign boundaries
  remain enforced; an eligible endpoint's remote session is checked again before
  dispatch, and the existing atomic job RPC still prevents duplicate in-flight work.
- Latest builds and verified Credential Provider payload measurements are reused
  per platform within one scheduler pass, not globally. Job creation, encrypted
  payload handling, signed artifacts and endpoint authorization are unchanged.
- Tenant encryption metadata is request-local, keyed by tenant. Company PATCH
  invalidates that cache. Nothing shares unlocked keys across HTTP requests.
- dashboard_fleet computes full active-fleet counts and health indicators in
  PostgreSQL. Only ten attention rows are serialized and decrypted in Python.
  Offline devices sort first, then pending agent updates, then oldest reports;
  friendly-name alphabetical ordering is no longer the attention tie-breaker.
  Alerts/jobs outside the sample resolve names through one scoped ID batch.
- Endpoint charts request at most 240 observations. The database retains the
  latest observation per elapsed-time bucket and returns encrypted metric rows;
  Python decrypts only the bounded sample. This is not an average, an extrema
  sampler, block-level sync, or deletion of historical data.
- Existing callers without max_points still receive the full paged metric history.
  Only a missing PostgREST RPC (404/PGRST202) activates compatibility reads;
  authorization, transport and malformed-response errors fail rather than showing
  misleading zeros. The compatibility metric path can download the full history
  before sampling, so install the migration to obtain database-side bounds.

## Migration and tests

Apply migrations/2026-10-04-fleet-read-optimization.sql after the preceding
candidate migrations. New installations use the identical db-init/28 file.
Existing database volumes do not rerun init scripts. Refresh PostgREST's schema
cache after applying the migration. Ordinary index creation can block writes;
measure locks and schedule deployment before touching a populated database.
The RPCs are service-role only, SECURITY INVOKER, and explicitly constrain tenant
and branch. The metric RPC checks endpoint ownership and rejects invalid/NULL
bounds; the inclusive final timestamp cannot create an extra bucket.

Full offline regressions passed: hosted 704 and Community 683.
Real PostgreSQL 16 checks cover repeat migration application, numeric version
comparison, newest compliance results, branch/tenant isolation, denied anonymous
execution, encrypted samples, inclusive boundaries and NULL bounds.
The fleet-read-optimization.yml workflow repeats SQL checks on an isolated
database; local success does not mean GitHub CI has already run.

The optional fleet_read_benchmark.sql creates 10,000 additional endpoints and
50,000 compliance records in a transaction, checks a total of 10,002 with a
ten-row sample, then rolls back. One local warm query-level observation was
413.565 ms for the fleet RPC and 4.866 ms for 60 metric samples. These exclude
HTTP, rendering, realistic record sizes, network latency and concurrency. They
are not an endpoint/tenant capacity commitment.

## Opt-in database connection reuse

WARDEN_DB_HTTP_POOL=false is the default. With true and no configured urllib
proxy, a bounded standard-library pool targets only the configured database
origin. WARDEN_DB_HTTP_POOL_SIZE defaults to 8 (allowed 1..32), with a one-second
slot wait and the existing 15-second socket timeout. Fully consumed responses
reuse connections; partial bodies and failures discard them. It never follows
redirects or retries requests/writes, and HTTPS requires verified certificates.
Configured proxies retain urllib's existing behavior rather than being bypassed.
A stale keep-alive socket may fail a request; no hidden retry can duplicate a write.
Loopback HTTP/1.1 tests confirmed five consumed requests use one connection.
Keep pooling disabled until a staging comparison measures errors and p95 latency.

## Experimental process separation, not a production scale-out switch

Combined mode remains the deployment default, with one eight-thread API worker,
one scheduler owner and one relay registry. No worker increase or service split
has been deployed. Role entry points are available only with explicit
WARDEN_ALLOW_SPLIT_SERVICES=true:

- API: WARDEN_PROCESS_ROLE=api, normal Gunicorn command and
  WARDEN_RELAY_HEALTH_URL pointing to the private relay /ready listener.
- Background: python -m services.background_runner.
- Relay: python -m services.relay_runner; private readiness on HOST:35022.
  Reverse-proxy WebSocket paths must target this owner's port 35021, not the API.

Run exactly one background owner and one relay owner against a database; never
run either beside a combined owner. Keep readiness and database ports private.
Use separate resource budgets and preserve protected environment files, storage
mounts, read-only roots, non-root ownership and shutdown grace periods on Ubuntu.

This separation is staging scaffolding, not supported horizontal scaling yet:
BYOK unlocked keys, adaptive load state, admission fairness, metrics and WebSocket
pairing remain process-local. BYOK unlock coordination, cross-process telemetry,
remote/Home reconnects and a complete shutdown/restore pilot must be qualified
before enabling a split. Do not increase API workers as a substitute for that
work. The role gate is not a distributed ownership lease or leader election.

## Remaining operational acceptance

Provision private Ubuntu staging; restore representative anonymized data;
exercise heartbeat bursts, simultaneous approved remote sessions, Home traffic,
slow database calls, SIGTERM/restarts, locked/unlocked BYOK and restore.
Record end-to-end p95 latency, errors, DB I/O, queue age, CPU/memory and video
encoding cost. Choose production capacity and whether to enable pooling only
after those results. No Redis/Kafka service was added by this optimization pass.
