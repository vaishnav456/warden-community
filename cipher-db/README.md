# Ciphertext database runtime

This component stores complete application records as `wdb1:` authenticated
ciphertext in PostgreSQL. Each table has an opaque UUID, each record has an
independent opaque UUID, and the complete schema, original primary keys, row
counts, membership digests, and sequence counters are encrypted. Empty tables
are included. PostgreSQL receives no business columns, readable SQL routines,
decryption functions, or keys.

The separate application runtime decrypts into **memory only** and executes the
original PostgreSQL schema, constraints and atomic routines using native
PostgreSQL 16. The disposable query projection runs inside the trusted runtime
container; its data directory, WAL, temporary files and SQL socket reside in a
private tmpfs mount. It has no TCP listener, no published port and no socket
mount in the web container. Startup rejects a persistent projection filesystem,
enabled container swap or enabled core dumps. PGlite remains available for
offline capture and compatibility tests, not as the live query engine.
Warden's database interface carries encrypted request and response envelopes
over an authenticated private Unix socket. Readable query results exist inside
the trusted application boundary. They are never returned by the persistent
database or sent as readable responses across its application interface.
Existing field encryption and server-controlled BYOK unlock/lock rules remain
inside this complete-record storage layer. The outer storage layer uses the
existing platform key custody service; it does not turn every record into a
tenant-owned BYOK record.

This is server-side encryption. An attacker controlling the trusted application,
its key-service credentials, or host root can request decryption or inspect
memory. A compromised database alone does not receive a decryption capability.
System catalogs, opaque IDs, ciphertext sizes, counts and traffic timing remain
observable. Protect swap, core dumps, diagnostic collection, and backups; do
not retain a readable legacy database after claiming a completed cutover.

## Durability and validation

SQL writes, cascades and trigger effects are journaled in memory. Deferred
constraints and triggers are checked before the durable encrypted commit, so
a rejected SQL transaction cannot persist its records. Complete
encrypted records and an encrypted manifest commit atomically in PostgreSQL
before the caller receives success. A separate private, fsynced checkpoint
detects database rollback and reconciles an interrupted commit at restart.
Only one runtime can own a database: a dedicated connection holds an advisory
lock, and loss of that connection never creates an automatic replacement.

The runtime upgrades a verified legacy checkpoint to a private append journal.
Each encrypted commit still flushes its intent before the PostgreSQL commit and
flushes confirmation before acknowledgment. It avoids creating and renaming
checkpoint files on every write. Checksummed records, bounded compaction and
interrupted-tail recovery retain rollback rejection; I/O failures close access.
The active checkpoint is `CIPHER_CHECKPOINT` plus `.journal`; retain that file
with the encrypted store during recovery. The `.legacy` file is a retired
checkpoint marker, not the current recovery state. Removing the journal never
enables automatic legacy fallback. An older runtime cannot be used with this
checkpoint format without an operator-verified recovery procedure.

Startup authenticates every record and verifies table and record membership.
A five-minute storage audit verifies that persisted ciphertext still matches
the trusted snapshot; failures close access. It captures authenticated expected
membership while holding the writer mutex briefly, then streams bounded batches
on a separate read-only PostgreSQL snapshot while application queries continue.
Linux operators can request the same scan with `SIGUSR2`; logs contain only its
status and duration. Requests have unique IDs, a
30-second acceptance window, purpose-bound authentication and replay rejection.
Replay retention uses monotonic expiry and a bounded 500,000-entry registry;
normal requests examine only expired entries and the first unexpired entry.
Aggregate buffered request bodies are bounded to 192 MiB across connections.
Capacity rejection returns 503; it never disables replay checks or durability.
Requests issued before the current runtime started are rejected. There are no
automatic write retries or plaintext fallbacks. The application executes as
the original `service_role`, retaining table/function grants, row-security
bypass attributes and audit-log restrictions.

## Build and tests

From the repository root:

```text
docker build -f cipher-db/Dockerfile -t warden-cipher-runtime .
cd cipher-db
npm ci --ignore-scripts
npm test
```

Node 24 is required for the test command. Tests use synthetic data and generated
test-only keys. Linux additionally tests durable checkpoints. Set
`WARDEN_CIPHER_TEST_DSN` **only to an empty disposable database** to enable the
real PostgreSQL test; it creates and removes its owned `warden_cipher` schema.
CI runs that test against disposable PostgreSQL 16, plus restart, mutation,
concurrency, cascade, deferred constraints, rollback, tamper, numeric precision
and role checks.

GET/HEAD queries use PostgreSQL-enforced read-only transactions, avoiding write
journal and sequence bookkeeping. Writes still persist sequence-only changes,
enforce deferred constraints and checkpoint before success. Restores run
`ANALYZE` in memory to rebuild planner statistics; sequence reads are batched.

RPCs declared `STABLE` or `IMMUTABLE` in the trusted SQL catalog also use these
read-only transactions. Cold catalog lookups use readers, so dashboard functions
can run while an encrypted write waits for storage. PostgreSQL still enforces
read-only execution; client flags cannot classify a mutating routine as a read.

The private interface accepts an encrypted batch of one to eight operations in
one atomic transaction. Login bookkeeping and refresh-session creation share
one commit, as do a heartbeat update and its sampled metric. Any operation or
durability failure aborts the entire batch; clients never retry or fall back to
separate writes after a lost response. Runtime support must be deployed before
the app uses batches; roll the app back first when reverting this change.

Unread notification counts are reused only within one web request, and a
database mutation invalidates that request's count. Authentication, session
revocation, tenant access and vault state continue to be checked without a
cross-request plaintext cache.

The native runtime pools up to 16 concurrent read-only, repeatable-read
transactions. Readers see committed, durably encrypted records while a pending
writer waits for custody or disk flushes. Each reader verifies the ciphertext
head on an independent connection without changing the writer's checkpoint.
Recovery drains readers and replaces the projection before access resumes.

The single fenced writer groups up to 128 arriving requests, with a five
millisecond collection window and a bounded queue of 1,024 requests. Savepoints
isolate rejected requests, enforce deferred constraints and restore rejected
sequence changes. Successful requests share the encrypted commit and both
checkpoint flushes; none receives success before durability and local commit.
Custody encryption and ciphertext inserts use bounded batches. Repeated changes
to one row are encrypted once. The runtime retains primary-key routing and
authenticated counts/digests instead of a second full ciphertext dataset in JS.

These changes do not establish a fleet-capacity guarantee. Benchmark heartbeat latency, command
delivery, writes, audit overlap and recovery on the intended workload before
increasing deployment scale. Redis or another
cache must not store readable records or bypass tenant/BYOK authorization.
The [10,000-endpoint architecture target](../docs/ENCRYPTED_FLEET_CAPACITY.md)
sets out the database decision, workload and acceptance tests. Runtime logs
report bounded aggregate queue, guard, query and persistence timings without
SQL, identifiers or values.

## Private configuration

Run on Linux as UID 10005/GID 10001, with a read-only root filesystem, dropped
capabilities, no public ports, disabled core dumps and a private database
network. Keep these paths outside the repository:

| Setting | Purpose |
| --- | --- |
| `CIPHER_CONNECTION_FILE` | JSON connection settings for the ciphertext store; never print or commit it |
| `CIPHER_DATASET` | Stable random UUID identifying this installation |
| `CIPHER_CHECKPOINT` | Durable private checkpoint outside PostgreSQL, accessible only to this runtime |
| `CIPHER_SOCKET` | Private Unix socket shared with Warden; directory restricted to runtime/application users |
| `CIPHER_TOKEN_FILE` | Separate random URL-safe token, at least 43 characters; mounted read-only in runtime and Warden |
| `CIPHER_QUERY_ENGINE` | Must be `native`; no automatic single-connection or disk-backed fallback |
| `CIPHER_PROJECTION_ROOT` | Private Linux tmpfs mount; default `/run/warden-projection`, never shared with the web container |
| `KEY_SERVICE_SOCKET` | Existing custody application's private socket |
| `KEY_SERVICE_TOKEN_FILE` | Existing key-service authorization file; no master key is mounted in the runtime |

Warden must set `WARDEN_DATABASE_MODE=ciphertext`, the same dataset/socket/token
paths, and retain its existing key-service connection. Ciphertext mode refuses
missing configuration and does not load the legacy database credentials.
The runtime's database login should have access only to the opaque storage
schema; bootstrap uses a separate operator account. Restrict key/socket files
and checkpoint directories, and keep the key-service deployment independent
of the database. Key custody can move to another server using a pinned,
authenticated SSH Unix-socket tunnel without changing record encryption or
exporting keys to this component.

The optional [Compose overlay](../docker-compose.cipher.yml), applied after the
key-service overlay, provides private storage/network/socket volumes, health
checks, disabled runtime/application/key-service swap and disabled runtime and
key-service core dumps. Its private configuration paths
and stable dataset UUID must match the verified capture. Starting the overlay
against an uncaptured database fails closed; it does not perform a migration
or retire the old database automatically.

The overlay reserves a 4 GiB runtime memory limit, no swap, a 3 GiB projection
tmpfs and 128 processes. tmpfs pages count against that memory limit. Adjust
these bounded settings to measured dataset size and recovery peak, rather than
assuming the limit proves fleet capacity. `init: true` reaps PostgreSQL children;
the runtime gets 120 seconds for graceful shutdown. Only the volatile projection
disables its own fsync/WAL durability; the persistent ciphertext store and
private checkpoint retain their durable flushes.

`benchmark.mjs` is an explicitly guarded synthetic SQL/durability benchmark. It
requires `WARDEN_CIPHER_BENCHMARK=synthetic-only`, an empty disposable ciphertext
database, a private checkpoint directory and the test-only `tests/box.mjs`
fixture mounted under `/app/tests`. It seeds 10,000 synthetic records, exercises
three durable write requests plus a concurrent read per cycle at 333/second and
a short 999/second burst, and overlaps a storage audit. It reports drops,
failures, drain throughput and latency percentiles. It excludes HTTP, endpoint
authentication, the real custody service, dashboards and relays; its results
must not be described as a 10,000-endpoint application acceptance test.

## Migration and cutover

`node migrate.mjs` bootstraps **an empty target database** and leaves the source
unchanged. Additionally provide private `CIPHER_SOURCE_CONNECTION_FILE` and
`CIPHER_SOURCE_SCHEMA` paths. The schema file is a reviewed `pg_dump
--schema-only --no-owner` result containing grants but no data or passwords.
Bootstrap captures the original row-security role attributes, all ordinary
application tables, raw JSON records and sequence state in a read-only,
repeatable-read snapshot. It refuses partitions, materialized views, foreign
tables, missing primary keys and unexpected target relations rather than
silently omitting data. Restore retains numeric precision, nulls, arrays and
identity values. It then reopens the encrypted target, authenticates all rows,
and compares counts and raw-JSON multiset fingerprints with the source snapshot.

Complete a development pilot and representative application/automation checks
first. Quiesce every writer before the final capture; a copy taken while writers
remain active is a pilot snapshot, not a cutover. Verify the captured schema is
current and all source records match, start the private runtime, switch Warden,
and verify application flows and restart recovery. Retain an authenticated
encrypted rollback backup and custody keys/checkpoints. Remove readable legacy
tables, credentials, WAL/backups and old volumes through the operator's verified
retirement procedure. A successful bootstrap alone does not encrypt the old
live database or establish a completed production deployment.

Schema upgrades need a new authenticated catalog and a verified upgrade path;
legacy SQL migration tools must not be run against the opaque store. Unsupported
REST syntax fails closed. This runtime is shared by Hosted and Community; it
does not add Hosted marketing, trials, subscriptions or platform administration
to Community.

### Compressed manifest metadata

The runtime compresses only private manifest metadata with bounded DEFLATE before
AES authentication/encryption. Row records and query envelopes retain their
existing format. Legacy manifests remain readable. The encoding and original
length are inside the encrypted document; decompression enforces a 64 MiB limit
and exact length. Database storage still exposes opaque IDs and ciphertext only.
New compressed manifests require this runtime or a newer compatible version;
do not downgrade to a runtime without `manifest.mjs`. Recovery must preserve the
current ciphertext snapshot and matching private checkpoint journal.

Aggregate profiling also reports metadata encoding, durable intent, cold-store
commit and durable confirmation timings. It never logs queries or record values.
