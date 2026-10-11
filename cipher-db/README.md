# Ciphertext database runtime

This component stores complete application records as `wdb1:` authenticated
ciphertext in PostgreSQL. Each table has an opaque UUID, each record has an
independent opaque UUID, and the complete schema, original primary keys, row
counts, membership digests, and sequence counters are encrypted. Empty tables
are included. PostgreSQL receives no business columns, readable SQL routines,
decryption functions, or keys.

The separate application runtime decrypts into **memory only** and executes the
original PostgreSQL schema, constraints and atomic routines using PGlite 18.3.
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

Startup authenticates every record and verifies table and record membership.
A five-minute storage audit verifies that persisted ciphertext still matches
the trusted snapshot; failures close access. It captures authenticated expected
membership while holding the writer mutex briefly, then streams bounded batches
on a separate read-only PostgreSQL snapshot while application queries continue.
Linux operators can request the same scan with `SIGUSR2`; logs contain only its
status and duration. Requests have unique IDs, a
30-second acceptance window, purpose-bound authentication and replay rejection.
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

PGlite has one exclusive SQL connection. These changes reduce queueing, but do
not establish a fleet-capacity guarantee. Benchmark heartbeat latency, command
delivery, writes, audit overlap and recovery on the intended workload before
increasing deployment scale. A native concurrent SQL engine inside the trusted
memory boundary requires a separate verified implementation. Redis or another
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
