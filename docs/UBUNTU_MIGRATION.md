# Ubuntu deployment plan

No host migration is performed by these source changes. Provision an isolated
Ubuntu staging server before selecting a production cutover date.

## Target layout

Use a supported Ubuntu LTS release with Docker Engine and the Compose plugin.
Follow the official installation guide:
https://docs.docker.com/engine/install/ubuntu/
Keep the server, PostgreSQL, PostgREST and build service containerized; do not
move server development or production repositories onto the Windows test laptop.
The new operational tools are Python-based and the workflows target Linux runners.

Use a dedicated deployment checkout, protected environment files, named data
volumes and private Docker networks. Preserve application UID/GID ownership
(server 10001:10001), read-only root filesystems and scoped writable volumes.
Do not broadly chmod data/world-readable or mount the Docker socket in the app.

Publish only the intended reverse-proxy ingress. Keep PostgreSQL, PostgREST,
build-service and application/relay ports off public host interfaces.
Docker-published ports can bypass UFW rules; verify Docker-aware firewall policy
and external reachability, not just ufw status. Restrict SSH to management access.
Do not change trusted proxy/mTLS settings until the actual ingress is verified.

## Staging acceptance

1. Verify candidate syntax, migration parity, full regressions, dependency/security
   checks and third-party notices. Record commit and immutable image digests.
2. Restore an encrypted backup into private staging. Restore uploads, artifacts,
   signing/encryption secrets, device CA and required tenant/BYOK recovery material.
3. Apply ordered migrations explicitly. Existing database volumes do not rerun
   db-init. Measure index-creation locks on representative data.
4. Use staging-specific URLs and credentials. Disable outgoing SMTP, production
   auto-updates and real-device commands until configured for synthetic/pilot data.
5. Verify login/MFA, locked/unlocked BYOK behavior, heartbeat encryption, queued
   jobs, module verification, Home sync and approved remote sessions on pilot devices.
6. Run GET load probes and separate controlled heartbeat/reconnect/video workloads.
   Measure p95 latency, database time, queue age, CPU, memory, disk I/O and errors.
7. Exercise SIGTERM/restart, abandoned-job/mail leases, restore/decryption and
   storage reports. Confirm the previous image starts against the additive schema.

## Cutover and rollback

Arrange a maintenance window. Drain writes/schedulers, create a final consistent
database and file backup, validate hashes and restore it into Ubuntu, then verify
readiness before routing production ingress to the new server.

Retain public agent/Home communication and update URLs where possible. Preserve
the signing keys and CA; an unplanned rotation can invalidate installed-agent
trust. Community uses its own configured URL and stays application-only.

Never run both old and restored copies as active schedulers for the same devices.
Keep the old host stopped and isolated until acceptance. If the new server has
accepted writes, restoring the old snapshot loses those writes: rollback requires
a defined data reconciliation plan, not merely a DNS change.

The actual Ubuntu host, DNS/ingress, capacity limits and backup storage remain
operator choices. This document is a migration checklist, not proof of a tested
production cutover or an automatic deployment script.

Keep combined mode and one API worker during the initial migration. Experimental
role separation and opt-in connection reuse have additional acceptance gates in
[FLEET_READ_OPTIMIZATION.md](FLEET_READ_OPTIMIZATION.md), including process-local
BYOK unlock state and telemetry. Do not enable them as part of an untested cutover.
