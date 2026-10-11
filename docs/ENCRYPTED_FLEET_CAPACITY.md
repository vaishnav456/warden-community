# Encrypted fleet architecture: target 10,000 endpoints

The target is 10,000 enrolled endpoints, confirmed on 2026-10-11. This is a
design target, not a tested capacity claim. The current live encrypted runtime
has not passed a 10,000-endpoint workload test.

## Database decision

Keep PostgreSQL as the durable ciphertext store. Replace the single-connection
PGlite query projection with a concurrent native SQL engine inside the trusted
application boundary before claiming this scale. Redis is an optional queue or
cache alongside it. Cassandra is not the next primary database for Warden.

| Component | Appropriate use | Constraint for this application |
| --- | --- | --- |
| PostgreSQL ciphertext store | Durable atomic encrypted record and manifest commits | It must never receive business columns, decrypting functions or keys |
| Native PostgreSQL query projection, proposed | Concurrent relational reads and existing SQL routines inside the trusted boundary | Readable data, WAL and temporary files must stay in protected volatile memory; integration and recovery require new verification |
| Redis, optional | Bounded queues, wake-up notifications and measured caches | Persist only authenticated ciphertext and opaque routing IDs; it cannot replace job authorization or the durable source of truth |
| Cassandra | A separate, deliberately redesigned high-volume append workload, if measurements justify it | CQL lacks joins and subqueries; existing relational routines, foreign keys and query patterns need redesign |
| Additional PGlite instances | Possible isolated tenant shards after implementing routing and fencing | Starting multiple writers on one dataset is prohibited; one instance still serializes its queries |

The immediate performance release streams integrity audits on a separate
repeatable-read snapshot, batches sequence reads, rebuilds planner statistics
after restore, uses a durable append checkpoint journal, compresses private
manifest metadata before authenticated encryption and makes GET/HEAD
transactions read-only. Rows retain their ciphertext format; new manifests and
the checkpoint journal require the compatible updated runtime for recovery.
These changes do not remove PGlite's exclusive connection or prove
10,000-endpoint support.

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

Keep the single web worker until relay ownership is separated. Database switching
or additional web workers do not substitute for storage and concurrency testing.

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
3. Build a native concurrent query projection behind the existing encrypted
   request/response interface. Keep the persistent opaque PostgreSQL store and
   separate custody service. The app must not receive direct plaintext SQL
   credentials. The projection's data directory, WAL, temporary files and logs
   need volatile mounts, disabled swap/core dumps and no readable backup path.
4. Retain a single fenced durable writer initially. Preserve deferred-constraint
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
backups. Neither Redis nor a native projection is enabled by this document.
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
