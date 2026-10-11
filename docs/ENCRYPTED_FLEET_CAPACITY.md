# Encrypted fleet architecture: target 10,000 endpoints

The target is 10,000 enrolled endpoints, confirmed on 2026-10-11. This is a
design target, not a tested capacity claim. The current live encrypted runtime
has not passed a 10,000-endpoint workload test.

## Database decision

Keep PostgreSQL as the durable ciphertext store. The runtime now implements a
concurrent native PostgreSQL projection inside the trusted application boundary.
Fleet workload acceptance is still required before claiming this scale. Redis is an optional queue or
cache alongside it. Cassandra is not the next primary database for Warden.

| Component | Appropriate use | Constraint for this application |
| --- | --- | --- |
| PostgreSQL ciphertext store | Durable atomic encrypted record and manifest commits | It must never receive business columns, decrypting functions or keys |
| Native PostgreSQL query projection, implemented | Up to 16 concurrent relational readers, existing SQL routines and a single grouped durable writer inside the trusted boundary | Readable files/WAL/spills/socket remain in private tmpfs, with swap/core dumps disabled and no TCP listener |
| Redis, optional | Bounded queues, wake-up notifications and measured caches | Persist only authenticated ciphertext and opaque routing IDs; it cannot replace job authorization or the durable source of truth |
| Cassandra | A separate, deliberately redesigned high-volume append workload, if measurements justify it | CQL lacks joins and subqueries; existing relational routines, foreign keys and query patterns need redesign |
| Additional PGlite instances | Possible isolated tenant shards after implementing routing and fencing | Starting multiple writers on one dataset is prohibited; one instance still serializes its queries |

The immediate performance release streams integrity audits on a separate
repeatable-read snapshot, batches sequence reads, rebuilds planner statistics
after restore, uses a durable append checkpoint journal, compresses private
manifest metadata before authenticated encryption and makes GET/HEAD
transactions read-only. Rows retain their ciphertext format; new manifests and
the checkpoint journal require the compatible updated runtime for recovery.
The concurrent release replaces the live PGlite connection, groups up to 128
write requests behind one durable encrypted commit, batches custody encryption
and ciphertext inserts, and removes the second retained ciphertext copy from
runtime memory. Reads cannot see undurable writes. Recovery, constraint failures,
sequence rollback, actual ciphertext storage and query compatibility have new
native integration tests. This is not yet proof of 10,000-endpoint support.

The read-path release also routes catalog-declared stable/immutable RPCs through
PostgreSQL-enforced read-only transactions. An encrypted batch combines login
bookkeeping with session creation, or a heartbeat snapshot with its selected
metric, into one atomic durable commit. It accepts at most eight operations and
rolls back the whole request on failure. Request-local notification counts
avoid duplicate reads without caching authorization between requests. Deploy
the batch-capable runtime before this app version; revert the app first.
Thirty-two runtime/storage tests and 776 Hosted / 755 Community server tests
passed in isolated Linux qualification. These regressions establish correctness,
not fleet throughput or a response-time guarantee.

The follow-up dashboard release narrows the bounded attention sample to card
labels, displayed metrics and existing fleet flags. Extra activity labels use
a scoped name-only endpoint projection. Default inventory reads retain their
existing fields. Tenant and branch checks remain in place, and no authorization
or plaintext results are cached across requests. A read-only production profile
reduced tenant decryption calls from 804 to 342 and data assembly from
4.6-6.2 seconds to 1.6-2.0 seconds in two initial samples. These profiles exclude browser
rendering and sign-in; they are not a fleet throughput or latency guarantee.

## Immediate deployment guardrails

The encrypted Compose overlay bounds the build worker to 2 GiB and 256 processes,
and the ciphertext PostgreSQL service to 1 GiB and 128 processes. Their swap
allowance equals their memory limit. These are shared-host starting limits,
not 10,000-endpoint sizing; monitor build completion, OOM events and query latency
and adjust to measured workloads. Core services use bounded local Docker logs
(three 10 MiB files); changed log settings take effect when containers are
recreated. Existing deployment overrides may differ.

On the current server, build/database memory and process limits were updated
without restarting the web service, and two unused migration key-service
containers were stopped after confirming that live callers use separate sockets.
Their volumes were retained. Existing live log rotation was already bounded;
the tighter rotation is saved for the next container recreation.

Keep the single web worker until relay ownership is separated. Its HTTP thread
count now defaults to 32 and can be configured with `WARDEN_HTTP_THREADS` (4–128).
Admission uses the same setting. An integrity report shares the heartbeat's
endpoint update, removing one durable write per reported heartbeat. These
changes preserve process-local relay ownership; they require workload testing.

## Workload to reproduce

The current agent polls every 30 seconds and has a 10-second heartbeat timeout.
10,000 continuously online agents therefore generate about 333 heartbeats per
second, or 28.8 million per day, before retries, inventory, metrics, Home traffic,
dashboard reads and command results. One heartbeat can make several database
and custody calls; 333 heartbeats per second is not 333 SQL operations per second.

Use synthetic or properly anonymized records in an isolated deployment. Measure
the actual calls and bytes per heartbeat, retained telemetry, tenant distribution,
command mixes and inventory sizes. Reproduce reconnect bursts, locked BYOK
tenants, expired leases and an audit running during command delivery. Do not
generate enrollment/update URLs for production devices from a development test.

Proposed acceptance targets, not measured results:

- Sustain 333 heartbeats/second, then test a 3x reconnect burst with bounded
  queueing. Report p50/p95/p99 and failures rather than averages alone.
- Target heartbeat p99 below 3 seconds, with no successful dispatch response
  arriving after the installed agent's 10-second timeout during the test.
- Verify end-to-end command receipt and results, not just a server-side leased
  status. Exercise lost responses, lease expiry and duplicate delivery.
- Run dashboards, workers and remote streams concurrently. Start with 50
  simultaneous remote sessions as a sizing assumption; adjust to the actual
  expected support workload and measured frame bandwidth.
- Force audit overlap and restart recovery; verify ciphertext-only persistent
  storage, authenticated membership, rollback rejection and unchanged tenant
  authorization. Record recovery duration and peak memory.

### Isolated measurement on 2026-10-11

The controller benchmark seeded 10,000 synthetic records and issued three
separate durable write requests and one concurrent read per cycle. The runtime
had a 2-CPU limit, 4 GiB memory with no swap, a private tmpfs projection and real
durable ciphertext/checkpoint storage on the existing shared virtual disk.
The first run targeting 333 cycles/second completed 1,572 cycles, dropped 5,088
at its bounded admission limit, and drained in 27.83 seconds: 56 cycles/second,
p95 9.292 seconds and p99 9.372 seconds. No SQL requests failed and the
overlapping integrity audit passed. The 999/second burst reached 50 cycles/second.

A second run with phase diagnostics and isolated qualification tests running
alongside it reached 49 cycles/second. Mean write-batch phases were 201 ms of
SQL execution, 216 ms for checkpoint intent, 152 ms for the ciphertext-store
commit and 217 ms for checkpoint confirmation. These measurements identify
durable storage flush latency as a substantial remaining bottleneck. Encryption
in this synthetic run used a generated test key; it excludes the real custody
service, HTTP, endpoint authentication, dashboards and remote streams.

This fails the fleet acceptance target. The native runtime improves concurrency
but this host has not demonstrated 10,000-endpoint capacity. Keep the agent's
30-second polling interval and 10-second timeout. Evaluate faster durable
storage, reviewed reductions in heartbeat write fan-out and isolated dataset
shards against the full workload before increasing fleet size. Never disable
persistent-store or checkpoint flushes to improve the benchmark score.

### Live response and relay measurements

After the native rollout, the measured production sign-in POST took 5.580
seconds and the following dashboard GET took 5.680 seconds. Seven fresh
successful heartbeats took 1.008–4.726 seconds, with no response exceeding the
installed agent's 10-second timeout in that small sample. Native SQL reads
averaged 2–8 ms in bounded runtime diagnostics; durable write batches still
spent hundreds of milliseconds in persistence. These are observations of the
current small fleet, not proof of an infrastructure capacity or latency SLA.

The ciphertext database and private checkpoint use the same ext4 virtual
device. An isolated `pg_test_fsync` probe on the development filesystem showed
large variability: one 8 KiB `fdatasync` write averaged 87 ms, while two writes
averaged 162 ms; `fsync` averaged roughly 290–300 ms. `open_datasync` was faster
for one write but slower for two. Keep the existing durable WAL settings until
a representative benchmark justifies a change. CPU and memory availability do
not remove these flush waits. A separate low-latency durable disk for the
ciphertext store and checkpoint is the principal infrastructure candidate.

Remote setup also waits for the installed agent's 30-second poll: a fresh
session's job waited 14.836 seconds for pickup and completed about three seconds
later. Reducing that wait needs a separately tested command wake-up channel or
agent polling change; it cannot be fixed by adding HTTP workers alone. Streaming
does not make a database commit for each frame. The relay explicitly yields with
`await asyncio.sleep(0)` after forwarding messages so receiving and control tasks
can run even when a WebSocket send completes without suspending the current task.

Agent JPEG quality remains 60. The relay negotiates WebSocket Deflate by default,
configurable with `WARDEN_REMOTE_WS_COMPRESSION=deflate|none`. A synthetic UI JPEG
A/B test saved 19–35% of frame bytes with Deflate. This measurement does not prove
bandwidth savings or FPS improvements for the affected session; compressibility
and CPU costs depend on the frame content and workload.

The browser parses binary frame headers directly and uses generation-aware,
bounded rendering. It coalesces obsolete updates before a newer full snapshot,
bounds pending frames and bytes, rejects decodes from a reset stream, and waits
for a full baseline after overflow or decode failure. Viewport requests use the
displayed canvas size and device pixel ratio while retaining the native aspect
ratio, reducing unnecessary full-resolution transmission. Live permission checks
select only current authority fields rather than credentials or MFA secrets.
They remain fresh, with the same revalidation interval and fail-closed behavior.
Authorization, consent and BYOK enforcement remain unchanged. No new agent binaries or fleet update are
included; endpoint capture remains a separate deployment item. Idle frame age
measures time since the last drawn update, not end-to-end input latency. Nineteen
browser queue/renderer regressions and both complete server suites passed,
including real compressed/uncompressed binary transport, large frames and live
revocation. A new affected-session movement test remains a separate check.

The capture source now skips a pointer-only DXGI acquisition only after a
successful snapshot and only when the desktop timestamp, accumulated frames
and metadata size are all zero. Initial capture, failed copies, monitor changes
and uncertain metadata retain complete-image recovery. GDI fallback resizes
raw pixels to the requested viewport before the existing quality-60 JPEG
encoder; native input coordinates remain unchanged. These paths require a
qualified agent build and device update, separate from the web deployment.

The browser coalesces pointer movement once per display frame and flushes it
before button, key or scroll actions. Numeric diagnostics distinguish incoming
frames/bytes, browser decoding, queue depth, relay send waits, relay loop delay
and relay–device RTT. The relay retains at most 120 send-wait samples per session;
it stores no frame content. Diagnostics reuse existing rate-limited pongs and
15-second encrypted quality receipts, adding no per-frame database calls.

## Implementation sequence

1. Profile SQL execution, runtime queueing, custody calls, encrypted commits and
   application request fan-out separately. Keep diagnostic aggregates free of
   SQL text, query values, keys and identities.
   Check disk flush latency and I/O pressure as well as CPU and memory. Shared
   virtual storage can dominate commit latency even when SQL and AES are fast;
   evaluate dedicated low-latency durable storage before changing database brands.
2. Consolidate the heartbeat's related work into reviewed atomic operations.
   Preserve lease fencing, tenant/BYOK checks and response signatures. A longer
   agent timeout alone does not solve saturation or prove delivery.
3. Implemented: a native concurrent query projection behind the existing encrypted
   request/response interface. Keep the persistent opaque PostgreSQL store and
   separate custody service. The app must not receive direct plaintext SQL
   credentials. The projection's data directory, WAL, temporary files and logs
   need volatile mounts, disabled swap/core dumps and no readable backup path.
4. Implemented: a single fenced durable writer with bounded group commits. Preserve deferred-constraint
   checks, sequence-only writes, authenticated manifests and private checkpoints.
   Acknowledge only after the encrypted commit is durable. Test every crash
   boundary between projection execution, durable commit and acknowledgment;
   rebuild from the verified encrypted store when projection state is uncertain.
   Define read visibility explicitly so concurrent reads never expose an
   uncommitted or undurable write.
5. Separate HTTP/API, scheduler, build/outbox work and remote relay ownership
   before scaling processes. The current relay registry is process-local:
   increasing Gunicorn workers alone can split browser and agent connections
   between different registries and break remote sessions.
6. Add Redis only when a measured queue/cache benefit is demonstrated. Jobs
   remain durably recorded and authorized in Warden. Redis notifications may be
   lost or duplicated; consumers reconcile against durable leases. Define replay,
   TTL, invalidation, restart and outage behavior, and keep BYOK lock/expiry
   enforcement on every authorized use rather than in a cache.
7. If the fenced writer or memory footprint remains the limit, implement isolated
   tenant/dataset shards with reviewed routing, global control-plane operations
   and independent checkpoints. Benchmark again before assigning fleet capacity.

Deploy candidates to development first and retain verified encrypted recovery
backups. Redis remains optional and is not enabled by this document. The native
projection is implemented in source; deployed status and measured workload
results must be verified separately.
Community retains its local entry flow, single organization and configured
server URL; this design does not introduce hosted platform or trial features.

## Primary references

- [PGlite documentation: one exclusive database connection](https://pglite.dev/docs/)
- [PostgreSQL concurrency control](https://www.postgresql.org/docs/16/mvcc-intro.html)
- [PostgreSQL transaction snapshots and read-only mode](https://www.postgresql.org/docs/18/sql-set-transaction.html)
- [Redis data types: caching, queuing and event processing](https://redis.io/docs/latest/develop/data-types/)
- [Redis persistence and durability choices](https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/)
- [Cassandra CQL data manipulation and query restrictions](https://cassandra.apache.org/doc/stable/cassandra/developing/cql/dml.html)
- [Node.js bounded DEFLATE decompression](https://nodejs.org/api/zlib.html)
- [PostgreSQL WAL flush configuration and durability](https://www.postgresql.org/docs/16/runtime-config-wal.html)
- [PostgreSQL filesystem flush diagnostic](https://www.postgresql.org/docs/16/pgtestfsync.html)
- [WebSocket compression CPU and memory tradeoffs](https://websockets.readthedocs.io/en/stable/topics/compression.html)
- [WebSocket asyncio scheduling and explicit yielding](https://websockets.readthedocs.io/en/stable/faq/asyncio.html#why-does-my-program-never-receive-any-messages)
