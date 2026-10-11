# Warden Community

Warden is an open endpoint-management platform for Windows, Linux, and macOS environments.

Prefer a managed service? [Try hosted Warden free for 14 days](https://warden.uranledgr.com/trial?source=github). No card is required. Trial organizations and enrolled endpoints are deleted when the trial ends unless the organization upgrades.

Hosted trials are separate from this self-hosted project. See [Hosted trial terms and data handling](docs/HOSTED_TRIAL.md).

> **Project status: alpha.** This repository is suitable for development and controlled pilots. Review the security model, test recovery, and use signed production artifacts before managing important endpoints.

## Download and install

The first public release is [Warden Community v0.1.0-alpha.1](https://github.com/vaishnav456/warden-community/releases/tag/v0.1.0-alpha.1).

- [Download the source ZIP](https://github.com/vaishnav456/warden-community/releases/download/v0.1.0-alpha.1/warden-community-0.1.0-alpha.1-source.zip)
- [Download SHA256SUMS.txt](https://github.com/vaishnav456/warden-community/releases/download/v0.1.0-alpha.1/SHA256SUMS.txt)
- [Read the release's installation and migration guide](https://github.com/vaishnav456/warden-community/blob/v0.1.0-alpha.1/docs/INSTALLATION_AND_MIGRATION.md)

Verify the ZIP against `SHA256SUMS.txt` before extracting it. You can also check out the exact release with Git:

```bash
git clone --branch v0.1.0-alpha.1 --depth 1 https://github.com/vaishnav456/warden-community.git
cd warden-community
```

This is a **source release**, not a preconfigured server appliance or universal Windows installer. Self-hosting requires a Linux server with Docker Compose, your own HTTPS origin, and independently generated configuration and secrets; follow the installation guide before starting the stack.

Generate endpoint and Warden Home installers from your own instance so they use its URL, trust configuration and enrollment settings. Warden Community manages one organization.

## The problem Warden solves

Small businesses often face an awkward choice: pay for enterprise MDM suites priced and designed for larger IT teams, or manage devices with disconnected tools and manual effort. Keeping computers secure and consistent across Windows, Linux, and macOS can mean juggling separate systems for inventory, accounts, policy, and updates. Remote desktop and support can be another pain point: access may require a separate product, extra setup, or troubleshooting across different tools, making it difficult for a small team to help staff quickly.

Warden aims to give small organizations one self-hosted place to enroll and manage supported devices, apply policy, run administrative jobs, and provide remote support. It makes effective policy visible and presents controls supported by each endpoint, reducing the need to stitch together separate management tools. The community edition is designed for one organization; feature coverage varies by platform, and several integrations remain alpha.

## What makes Warden different

- A built-in directory can provision endpoint accounts and sign-in identities without Active Directory or Microsoft Entra.
- Policy resolves predictably from organization to branch, group/tag, and endpoint, with an explanation of the effective result.
- The console is capability-aware: Windows, Linux, and macOS endpoints show only the controls their agent supports.
- Responsive endpoint cards show reported health, local and connection IP addresses, and Windows drive used/total/free capacity when supported by the agent.
- Interactive topology maps place endpoints, rooms, network equipment, and links on a live floor plan.
- Warden Home (alpha) provides organization-owned home folders and shared drives with direct peer-to-peer transfer, replicas, and failover.
- Windows controls include enrollment lockdown, BitLocker recovery escrow, managed firewall rules, remote support, and signed agent updates.

Windows currently has the broadest management coverage. Linux, macOS, Warden Home, and zero-touch integrations are alpha.

## Repository layout

| Path | Purpose | License |
| --- | --- | --- |
| `server/` | Web console, API, policy and job control plane | AGPL-3.0-only |
| `build-service/` | Isolated agent build service | AGPL-3.0-only |
| `db-init/`, `migrations/` | PostgreSQL/PostgREST schema | AGPL-3.0-only |
| `agent-go/` | Windows endpoint agent | Apache-2.0 |
| `agent-posix/` | Linux/macOS endpoint agent | Apache-2.0 |
| `home-node/` | Peer-to-peer storage node | Apache-2.0 |
| `windows-credential-provider/` | Windows sign-in provider | Apache-2.0 |

See [LICENSING.md](LICENSING.md) for the complete boundary.

Read-only dashboard routines use the existing memory-based SQL read workers.
Related login writes, and heartbeat updates with sampled metrics, use one
encrypted atomic request to reduce durable flushes. Notification counts are
reused within a single request and invalidated by writes. Session, replay and
vault checks retain their existing enforcement; persistent encryption and
durability remain enabled.

Dashboard cards use only their required endpoint fields, while activity labels
use scoped name-only reads. Full inventory queries retain their default fields.
No authorization or plaintext results are cached across requests. Fleet workload
qualification remains separate from these read-path optimizations.

Remote streaming keeps agent JPEG quality at 60 and negotiates WebSocket
Deflate by default; set `WARDEN_REMOTE_WS_COMPRESSION=none` to disable it, or
`deflate` to enable negotiation. A synthetic UI JPEG A/B test reduced frame size
by 19–35%; this does not establish bandwidth or FPS improvements for an affected
remote session.

The relay yields between forwarded messages, while the browser uses direct
binary header parsing and generation-aware, bounded frame rendering. It replaces
obsolete updates with a newer full snapshot and requires a full baseline after
overflow or corruption. Viewport requests use the displayed canvas, device pixel
ratio and native aspect ratio to avoid unnecessary full-resolution transmission.
Fresh relay permission checks select only authority fields, avoiding unrelated
account data and MFA-secret decryption. Authorization, consent and BYOK
enforcement remain in place. These changes do
not include new agent binaries or a fleet update.

The agent capture source skips confirmed cursor-only DXGI acquisitions after
its first successful snapshot and sizes fallback GDI images to the requested
viewport before JPEG encoding. Initial snapshots, monitor changes and uncertain
metadata still require a complete image. Applying these capture changes requires
a separately qualified agent build and device update.

Pointer movement is coalesced to one latest position per browser display frame;
button, key and scroll actions first send the pending position. The remote
statistics tooltip separates browser decode time, bounded queue depth, relay
send waits and relay–device RTT. Browser–relay RTT excludes the device leg;
frame age measures time since the last displayed update, not input latency.
These numeric measurements reuse existing ping and quality reports without
per-frame database writes or cached authorization.

## Security design

Warden treats the control plane, endpoint agents, Home Nodes, build service, and release pipeline as separate trust boundaries. Important controls include signed commands, short-lived device certificates, organization envelope encryption, endpoint job leasing, TLS validation, and explicit organization authorization.

Start with:

- [Security policy](SECURITY.md)
- [Installation, upgrades, and data migration](docs/INSTALLATION_AND_MIGRATION.md)
- [Device PKI](docs/WARDEN_DEVICE_PKI.md)
- [Endpoint connection lifecycle](docs/ENDPOINT_CONNECTION.md)
- [Data encryption](docs/DATA_ENCRYPTION.md)
- [Third-party assets](docs/THIRD_PARTY_ASSETS.md)
- [Optional Windows policy catalog](docs/POLICY_CATALOG.md)

Never place production credentials, enrollment tokens, private keys, customer exports, signing certificates, recovery keys, or database dumps in this repository.

## Development quick start

Requirements:

- Docker with Compose
- Python 3.12+ for direct server development
- Go versions declared by each module
- Visual Studio 2022 Community with the Desktop development with C++ workload for the Windows Credential Provider

For a real installation, including generated secrets, HTTPS, backup, upgrade,
single-organization import, and existing-agent continuity, follow
[Installation, upgrades, and data migration](docs/INSTALLATION_AND_MIGRATION.md).

For direct development, create local configuration from the examples:

```powershell
Copy-Item .env.example .env
Copy-Item server/.env.example server/.env
Copy-Item build-service/.env.example build-service/.env
Copy-Item db-init/01-roles.sql.example db-init/01-roles.sql
Copy-Item db-init/04-bootstrap-admin.sql.example db-init/04-bootstrap-admin.sql
```

Replace every `change-me` value and generated JWT placeholder before starting any service. Keep PostgREST and PostgreSQL on a private container network.

Start the development stack:

```powershell
docker compose up --build
```

Run the main test suites:

```powershell
Push-Location server
python -m unittest discover -s tests -q
Pop-Location

# Windows agent tests require Windows.
Push-Location agent-go
go test ./...
Pop-Location

Push-Location agent-posix
go test ./...
Pop-Location

Push-Location home-node
go test ./...
Pop-Location
```

Self-hosting under another domain or organization name is supported; see
[Branding and public URLs](docs/BRANDING.md). The community edition enforces a
single organization and contains no SaaS organization-management control plane.
The enforced boundary and retained compatibility identifiers are documented in
[Single-organization boundary](docs/SINGLE_ORGANIZATION.md).

The included Compose configuration is a development starting point, not a hardened production deployment.

## Database key custody

The optional [Warden key service](key-service/README.md) stores the database
encryption master key and unlocked organization keys in a separate application.
Warden requests authenticated encryption and decryption over a private Unix
socket; the API never exports raw keys. Production and development must use
separate keys, credentials and socket volumes.

This separates key custody from the web application. It does not protect against
an attacker controlling the entire host, or stop a compromised application from
using its authorized decryption access. It also does not encrypt every database
column: readable fields and historical records require a separate migration.
See the service guide for installation, compatibility and recovery.

BYOK uses the existing HTTPS web application, with no Admin or Tenant executable.
The server chooses a fixed random unlock period of **7–30 days** and shows its
expiry in Security settings. **Lock workspace** takes effect in the key service
immediately. Browser activity never extends the period, and a key-service restart
locks the vault. This server-based model trusts the running server with decryption;
hardening does not guarantee confidentiality after a full host compromise.

To inventory every application table without exporting record values, set
`DATABASE_URL` privately and run `python tools/audit_table_encryption.py`. The
read-only report includes column types and format counts; it exits with status 2
when populated fields are not uniformly versioned ciphertext. Valid older
ciphertext needs authenticated checks through Warden, and empty tables do not
prove that future writes will be encrypted.

## Trusted admin and all-table encryption

For organizations with automatic agent updates enabled, a verified newer release
can supersede an unfinished campaign for an older version. The old campaign is
marked cancelled with a supersession reason; its targets, job records and history
remain intact. Existing update jobs finish before the normal updater considers
the newer release. Explicit pauses, failed updates, failed canaries and rollbacks
remain protected. A known worker-error pause is released only after every
referenced job has completed successfully.

The newer release uses the normal updater's platform, entitlement, remote-session,
recent-update and update/reinstall checks. It does not inherit the old campaign's
canary approval or batching schedule. This follows the organization's automatic
latest-release policy; organizations requiring each release to complete a reviewed
campaign should keep automatic updates disabled. The pre-dispatch update/reinstall
checks do not create an atomic lock against concurrent manual reinstall requests.
The separate [trusted admin application](trusted-admin/README.md) creates and
verifies encrypted copies of every application table, including full rows and
table definitions. It has a private localhost interface and can move from the
Warden host to a separate trusted machine without changing the public server.
The public application receives no keys or decryption API for these copies.

This is a migration workspace, not a completed live migration. Existing Warden
tables and agents still use the current server workflows. Client-only reporting,
command signing, enrollment and automation must replace those workflows before
live cutover. Running the admin app on the same host also leaves unlocked data
accessible to a host attacker; move it to a trusted machine for host isolation.
See its guide for installation, verification, portability and the cutover checks.

## Optional agent modules

See [Optional agent modules](docs/AGENT_MODULES.md) for separate Core and Helpdesk build targets and organization controls. The new Windows module installation path still needs a native pilot before release.

## Third party software

Warden uses third-party Go and Python libraries, browser assets, fonts and Unicode data. See [Third party notices](THIRD_PARTY_NOTICES.md), the [dependency inventory](third_party/inventory.json) and the collected [upstream license texts](third_party/licenses). These components retain their own licenses; their notices do not change Warden's edition-specific licensing in [LICENSING.md](LICENSING.md).

Run `python tools/check_third_party.py` when dependencies change. Release packages also need the relevant notices; repository credits alone are not a compliance certification.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security vulnerabilities must be reported privately according to [SECURITY.md](SECURITY.md), not in public issues.

## Trademark

The source licenses do not grant permission to imply that modified deployments are official Warden services. See [TRADEMARKS.md](TRADEMARKS.md).

## Complete-record ciphertext storage

The shared [ciphertext database runtime](cipher-db/README.md) stores every field
of every application record inside authenticated ciphertext, including original
IDs, names, numbers and timestamps. Empty tables and schema definitions are
included. PostgreSQL and its private application interface expose only opaque
identifiers and encrypted envelopes. SQL and decryption run in trusted server
memory, while the separate key service keeps custody of the master key.
Existing web BYOK unlock/lock rules remain in place; no Admin/Tenant executable
is needed. Full host or trusted-application compromise can still expose data.

Hosted development and production completed verified 86-table migrations on
2026-10-11 (4,663 and 595,099 records in their final snapshots), with full
encrypted rollback restoration and application/interface checks. Validation
includes native concurrency, grouped durability, recovery and ciphertext-store
integration tests and 742 Community server regressions. The live query engine
uses private volatile PostgreSQL with pooled readers and batched encrypted
writes. Remote streaming avoids redundant JPEG/opaque traffic compression and bounds queued frames and bytes, resynchronizing after overflow or corruption; see [fleet capacity](docs/ENCRYPTED_FLEET_CAPACITY.md) for workload limits. Community requires its own verified migration and deployment;
this source update does not claim a Community live cutover. It preserves Community's configured server URL,
single organization and login/dashboard entry, without adding Hosted marketing,
trials, subscriptions or platform administration. See the runtime guide for
private configuration, tests, migration and recovery.
