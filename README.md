# Warden Community

Warden is an open endpoint-management and secure remote-operations platform for Windows, Linux, and macOS environments. It combines enrollment, identity and local-account management, policy deployment, inventory, remote support, network controls, topology, and encrypted Warden Home storage.

> **Project status: alpha.** This repository is suitable for development and controlled pilots. Review the security model, test recovery, and use signed production artifacts before managing important endpoints.

## Features

- **Enrollment and fleet management** — scoped and expiring enrollment
  profiles, single-use or bounded reusable installers, hardware-aware device
  reclaim, branches, groups/tags, bulk actions, endpoint health, inventory,
  asset lifecycle, and automatic agent-update controls.
- **Cross-platform agents** — Windows management plus alpha Linux and macOS
  agents with platform-specific capability reporting. The console shows only
  actions supported by the selected endpoint.
- **Directory and device identity** — a Warden-native directory that works
  without Active Directory or Microsoft Entra, email-based identities, local
  account provisioning, endpoint assignment, password lifecycle, profile
  photos, offline-access windows, and an optional Windows Credential Provider.
- **Policy and compliance** — reusable and cloneable policy templates,
  organization → branch → group/tag → endpoint precedence, effective-policy
  explanation, drift reporting, Windows policy/registry deployment, security
  baselines, firewall policies, and compliance evidence.
- **Software, patch, and vulnerability operations** — application library,
  controlled installer deployment, software inventory, executable paths,
  patch status and rollout controls, advisory synchronization, and findings
  with remediation workflow.
- **Secure remote operations** — attended approval, capability-scoped remote
  desktop sessions, keyboard and special-key support, process and service
  operations, command jobs, file operations, session claims, leases, timeouts,
  and auditable results.
- **Endpoint experience** — managed wallpaper and lock-screen assets,
  announcements, restart and shutdown workflows, job retention, and bulk
  deployment with endpoint status feedback.
- **Network controls and topology** — application/IP/domain firewall rules,
  network-flow collection, optional packet capture, local-address inventory,
  interactive floors and rooms, device placement, infrastructure assets,
  links, and live endpoint state.
- **Windows security controls** — BitLocker enablement and recovery-key escrow,
  local administrator management, Windows-only enrollment lockdown, firewall
  self-protection, tamper resistance, and signed self-update. These controls
  are intentionally not presented as Linux or macOS features.
- **Warden Home storage (alpha)** — organization-owned Windows or Linux storage
  nodes, per-user home folders and shared drives, quotas, read-only/read-write
  grants, offline cache, primary/replica selection, failover and shared-storage
  active-active modes, encrypted node data, and direct peer-to-peer file
  transfer without routing file contents through the control plane.
- **Security and operations** — MFA, role and branch scoping, dual approval for
  sensitive actions, signed commands, TLS pinning, short-lived device
  certificates, per-device credentials, envelope encryption, audit-chain
  verification, alerts, scheduling, backup/restore verification, and SBOM and
  security-release tooling.

Windows currently has the broadest management coverage. Linux, macOS, Warden
Home, and zero-touch integrations are alpha and should be validated against the
target OS, network, and identity environment before wider deployment. Optional
Microsoft Entra/Autopilot integration extends enrollment but is not required.

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
python -m pytest server/tests
go test ./agent-go/...
go test ./agent-posix/...
go test ./home-node/...
```

Self-hosting under another domain or organization name is supported; see
[Branding and public URLs](docs/BRANDING.md). The community edition enforces a
single organization and contains no SaaS organization-management control plane.
The enforced boundary and retained compatibility identifiers are documented in
[Single-organization boundary](docs/SINGLE_ORGANIZATION.md).

The included Compose configuration is a development starting point, not a hardened production deployment.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security vulnerabilities must be reported privately according to [SECURITY.md](SECURITY.md), not in public issues.

## Trademark

The source licenses do not grant permission to imply that modified deployments are official Warden services. See [TRADEMARKS.md](TRADEMARKS.md).
