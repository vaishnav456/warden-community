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

Generate endpoint and Warden Home installers from your own instance so they use its URL, trust configuration and enrollment settings. Community manages one organization and opens directly into the login/application flow, with no landing page. Hosted Warden is separate.

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

## Optional agent modules

See [Optional agent modules](docs/AGENT_MODULES.md) for separate Core and Helpdesk build targets and organization controls. The new Windows module installation path still needs a native pilot before release. Community remains application-only, with no landing page or hosted subscriptions.

## Third party software

Warden uses third-party Go and Python libraries, browser assets, fonts and Unicode data. See [Third party notices](THIRD_PARTY_NOTICES.md), the [dependency inventory](third_party/inventory.json) and the collected [upstream license texts](third_party/licenses). These components retain their own licenses; their notices do not change Warden's edition-specific licensing in [LICENSING.md](LICENSING.md).

Run `python tools/check_third_party.py` when dependencies change. Release packages also need the relevant notices; repository credits alone are not a compliance certification.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Security vulnerabilities must be reported privately according to [SECURITY.md](SECURITY.md), not in public issues.

## Trademark

The source licenses do not grant permission to imply that modified deployments are official Warden services. See [TRADEMARKS.md](TRADEMARKS.md).
