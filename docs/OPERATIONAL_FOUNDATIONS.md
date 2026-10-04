# Operational foundations

These changes target the existing single-process server. Redis and Kafka are
not required. They are source changes, not a deployment or fleet rollout.

Validation on 2026-10-04: full Linux-container suites passed (682 hosted,
661 Community), including the actual Gunicorn SIGTERM/in-flight-request smoke
test. PostgreSQL retry/crash/idempotency assertions and a synthetic dump/restore
passed. Candidate preflight, whitespace and 81-entry notice coverage checks
passed. No production load, full production recovery or Ubuntu cutover was run.

## Monitoring

- /status/performance: bounded process-local HTTP/database latency histograms,
  database errors and heavy-request concurrency. Hosted: platform administrator
  with MFA. Community: organization administrator. No public metrics endpoint.
- /status/queue: tenant/branch-scoped pending, running and failed job counts,
  plus the age of the oldest pending job. No decrypted payloads.
- /status/mail-queue: organization-admin view of failed deliveries and
  dead-lettered event metadata. No recipient addresses or message bodies.
- /ready: returns 503 while draining, otherwise checks database/relay readiness.
  Existing /health remains available.

Counters reset at worker restart; they are not durable audit evidence. HTTP
timing covers processing through response creation, not streamed download
duration. No raw URL, query string, tenant ID, token or payload is a metric label.
Connect an authenticated collector through the private management path if
durable historical graphs/alerts are needed.

## Fairness and work reliability

WARDEN_HEAVY_REQUEST_CAPACITY defaults to six concurrently admitted heavy
requests within the current eight-thread process. Reports, package reconciliation,
multipart uploads and bulk/deploy/export POSTs participate. Tenant identities
come from authenticated server context, not caller-supplied headers.

Idle capacity can be borrowed; contention limits one tenant's share. Excess work
receives 429 with Retry-After. Drain receives 503. Admission slots release on
request teardown, including failures. Agent heartbeat/results and Home/build APIs
are excluded so throttling does not drop essential device control traffic.
This is concurrency fairness, not byte-bandwidth fairness or a distributed limit.

Existing PostgreSQL job leases and unique creation guards remain authoritative.
Mail fanout now has bounded attempts, delayed retry and a dead-letter timestamp.
Dead-letter event metadata is retained for seven days for operator review.
Claim functions recover abandoned leases but never exceed six attempts, including
crashes on the final attempt. Terminal delivery failures clear encrypted payloads.
SMTP acceptance followed by worker death can still result in duplicate mail;
this is not exactly-once delivery. Do not automatically replay password-reset
emails or privileged device jobs; review/fix the cause and issue fresh actions.

## Shutdown

Gunicorn worker handlers preserve Gunicorn's existing signal behavior and set a
cooperative stop event. Background loops stop claiming new work; current units
can finish within a bounded drain window. Relay sockets receive restart code
1012 where the process has time to close them. Compose permits 45 seconds for
shutdown; Gunicorn retains its 30-second graceful timeout. Hung work may still
be killed and recovered through durable leases. Remote sessions are not seamless
across a restart and must reconnect/re-authorize.

## Storage reconciliation

/operations/storage/reconciliation holds the tenant upload lease and reports
missing package references and unreferenced files in that tenant's package
directory. It is read-only, validates canonical paths and rejects symlinks.
The scan is bounded at 10,000 files and explicitly marks incomplete reports.
Only fingerprints, not unreferenced filenames, are returned.

An unreferenced file is not proof it is safe to delete. Branding, builds,
database accounting and Home Node disks are outside this report's scope.
Use existing approved package deletion/installer cleanup flows; do not implement
automatic deletion based on a report. This report does not repair quota totals.

## Tests, release and recovery

tools/load_test_server.py provides bounded concurrent GET-only development probes
and reports status distribution, throughput and median/p95 latency. It requires
--confirm-development, blocks redirects/credential-bearing URLs, and verifies
TLS outside loopback. Read authentication from WARDEN_LOAD_TEST_TOKEN rather
than putting tokens in command-line arguments. It does not simulate heartbeat
writes, file sync, or video encoding; those need separate isolated workloads.

tools/release_preflight.py checks Python syntax and migration/init consistency.
The operational-foundations workflow runs full server regressions, license
inventory, repeatable SQL crash/retry checks, and synthetic dump/restore checks
on Linux runners. Remote CI evidence is only available after publication.

Apply the existing mail migration, then the server-read-optimization migration
and operational-foundations migration, before deploying the matching server.
db-init/26 and /27 are for fresh installations only; init scripts do not upgrade
an existing database. Keep a verified backup, immutable candidate image and
previous image for rollback. These additive migrations are backward compatible
with the old claim clients; do not reverse them automatically on image rollback.

tools/verify_development_restore.py refuses anything except a labelled,
network-isolated, tmpfs-backed synthetic test container. It verifies restored
rows and a required claim function, then removes only its own temporary database.
It is not a production backup/restore command.

tools/verify_recovery_bundle.py verifies relative-file SHA-256/size entries and
an AES-256-GCM probe using WARDEN_RECOVERY_PROBE_KEY_B64. Manifest version 1 uses
files [{path,bytes,sha256}], encrypted_probe (base64 nonce+ciphertext+tag) and
probe_sha256. The probe AAD is warden-recovery-probe-v1. The manifest/key must be
obtained from a protected, trusted backup process; hashes alone do not authenticate
an attacker-controlled manifest. This probe does not verify every tenant key.

A production drill must also restore uploads/build artifacts, server signing and
encryption material, device CA, and tenant/BYOK recovery material under restricted
access; then verify decryption and application behavior against isolated devices.
Never run a restored server with production URLs, SMTP or auto-update enabled.
