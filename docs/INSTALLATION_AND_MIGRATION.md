# Installation, upgrades, agent connection, and data migration

Warden Community is a single-organization deployment. A normal installation
has one Linux server running Docker Compose and any number of Windows, Linux,
or macOS endpoints making outbound connections to one stable HTTPS origin.

Warden Community does **not** require or use Supabase Cloud. It runs its own
PostgreSQL and PostgREST containers. The environment names `SUPABASE_URL`,
`SUPABASE_SERVICE_KEY`, and `SUPABASE_KEY` are retained compatibility names;
they point to the private `http://postgrest:3000` service and a locally
generated PostgREST JWT.

## 1. Server requirements

- A supported Linux server or VM with Docker Engine and Docker Compose v2.
- A stable DNS name controlled by the operator, such as
  `warden.example.com`, pointing at the server or its HTTPS reverse proxy.
- A publicly trusted TLS certificate. Caddy or Let's Encrypt is sufficient;
  purchasing a certificate is not required.
- Inbound TCP 443 to the reverse proxy. TCP 80 is needed only when the chosen
  ACME challenge uses it. PostgreSQL and PostgREST must never be published.
- Encrypted backup storage separate from the Warden host.

The supplied `docker-compose.yml` intentionally exposes no public port. Attach
`warden-server:35020` on the `warden-ingress` network to Caddy, nginx, a load
balancer, or a tunnel that terminates HTTPS. Forward the original host and
client address headers. Set `TRUST_CLOUDFLARE=true` only when Cloudflare is the
sole ingress and its client-certificate forwarding is enabled.

## 2. Fresh installation

Clone a tagged release, not a moving development branch. From the repository
root, build the server image and run the interactive configuration generator:

```bash
docker compose build warden-server
docker compose run --rm --no-deps -it \
  -v "$PWD:/workspace" -w /workspace --entrypoint python \
  warden-server tools/configure_install.py \
  --server-url https://warden.example.com \
  --organization-name "Example Ltd" \
  --organization-slug example \
  --admin-email admin@example.com \
  --admin-name "Warden Administrator"
```

The command creates five gitignored files: `.env`, `server/.env`,
`build-service/.env`, `db-init/01-roles.sql`, and
`db-init/04-bootstrap-admin.sql`. It generates independent database, session,
JWT, encryption, signing, and build-service secrets plus a bcrypt administrator
password hash. It refuses to overwrite an existing configuration by default.

Before starting, configure the HTTPS reverse proxy and verify that
`SERVER_URL` resolves to it. Then start and check the stack:

```bash
docker compose up -d --build
docker compose ps
curl --fail https://warden.example.com/health
```

On first start the server creates its private device CA in the
`warden-device-ca` volume. Immediately copy that volume and all generated
configuration to encrypted backup storage. Then set
`DEVICE_CA_AUTO_BOOTSTRAP=false` in `server/.env` and restart
`warden-server`. This makes loss of the CA fail loudly instead of silently
creating a new trust domain.

The SQL files in `db-init/` run only for an empty PostgreSQL volume. The
consolidated `02-schema.sql` is authoritative for a fresh installation. Do not
replay the historical `migrations/` directory on a fresh database.

## 3. How endpoint agents connect

1. Sign in as the organization administrator, create at least one branch, and
   open **Settings → Enrollment and zero touch**.
2. Create an enrollment profile. It controls the branch, device matching,
   initial policy, and optional post-enrollment actions.
3. Generate an installer for the required OS/architecture. Use a single-use
   token for one device. Use a bounded, short-lived reusable token only for a
   controlled GPO/SCCM/other mass deployment.
4. The build service embeds the public Warden URL, server command-signing
   public key, current HTTPS certificate fingerprint, branch/profile, and
   enrollment token. The download remains administrator-authenticated because
   that token is live.
5. Run the Windows MSI/installer as Administrator, or use the matching Linux
   or macOS package. The service starts automatically at boot.
6. The agent opens outbound HTTPS to the Warden origin. It validates the normal
   public certificate chain and hostname **and** the embedded fingerprint,
   generates its private device key locally, and posts its CSR and token to
   `/enroll`. The private key never leaves the endpoint.
7. The server consumes the token atomically, returns a per-device API secret
   and short-lived device certificate, and the agent stores secrets in
   operating-system protected storage. Heartbeats, inventory, jobs, updates,
   remote sessions, and certificate renewal use outbound HTTPS/WebSocket.

No inbound endpoint port, static endpoint IP, VPN, or port-forwarding is
required for control-plane management. Warden Home file transfers use their
separate direct peer-to-peer path.

If an endpoint was removed from the console, its credentials are revoked. Run
a newly generated installer to reconnect it. The installer retains the stable
installation identity and re-enrolls the protected service instead of placing
a second agent beside it.

## 4. What must be backed up

A recoverable installation needs all of the following as one versioned backup
set:

- a PostgreSQL custom-format dump of database `warden`;
- the `warden-device-ca` volume (root/issuing certificates and private keys);
- the `warden-uploads` volume (applications and branding);
- the `warden-agent-dist` volume if existing downloads must remain available;
- `.env`, `server/.env`, `build-service/.env`, and reverse-proxy TLS/config;
- Home Node configurations, node encryption keys, and each node's data root;
- signing certificate/private key when Authenticode signing is configured.

`warden-build-output` can be rebuilt and is not identity-bearing. Backups must
be encrypted, access controlled, integrity checked, and restore-tested. Never
place a dump, CA key, Home Node key, or environment file in Git.

The database alone is insufficient. In particular, losing
`TENANT_MASTER_KEK_B64` makes wrapped organization data unreadable, and losing
the device CA breaks device-certificate continuity.

## 5. In-place upgrade

1. Read the target release notes and confirm that the release supports a
   direct upgrade from the installed version.
2. Record the current Git tag/image digests and take a verified backup of every
   item above.
3. Put the console in a maintenance window and stop job-producing services.
4. Fetch the target tag and apply only the migrations named by that release,
   in order, with `psql -v ON_ERROR_STOP=1`. Never run all historical files.
5. Rebuild/start Compose, verify `/health`, login, one heartbeat, one signed
   read-only job, remote-session negotiation, and Home Node status.
6. Keep the old images and backup until the acceptance checks pass. Database
   rollback means restoring the complete matching backup set, not running SQL
   files backward.

Agent updates are independent. Existing agents continue on their current
version until a signed update job or enabled automatic-update policy upgrades
them.

### Expandable topology and endpoint names (2026-09-30)

Before deploying this update on an existing database, apply
`migrations/2026-09-30-expandable-topology.sql` and
`migrations/2026-09-30-endpoint-nickname.sql` with `psql -v ON_ERROR_STOP=1`.
Fresh installations apply these through `db-init/14-topology-and-endpoint-names.sql`.
Existing floor coordinates are preserved; rooms and devices can extend beyond
the old floor in all directions. Pan or zoom out to add space; **Fit all** shows
the whole layout. A safety limit of ±9,000 map units remains.

Use **Endpoints → device → Edit names** to set a nickname. The visible name
defaults to the hostname; clearing the nickname restores that default.
Nicknames are tenant-encrypted and do not rename or restart the device.
Windows hostname changes require Agent 2.6.43 or later. Restart is unchecked
by default; selecting it follows the configured restart approval process.
The operating-system hostname takes effect after the next restart.

## 6. Move to another server without re-enrolling agents

Use the same public `SERVER_URL`. Restore the database, environment secrets,
device CA, uploads, and (where applicable) the same reverse-proxy certificate
and private key before switching DNS. Existing agents then retain all four
parts of their identity: endpoint row/API-key hash, local protected API secret,
client certificate/private key, and server signing/TLS trust.

Agents pin the HTTPS leaf certificate in addition to normal Web PKI. Before a
certificate change, deploy a signed `ROTATE_TLS_PINS` job containing an
overlapping old+new pin, confirm fleet uptake, change the certificate, and then
remove the old pin with another signed job. If the hostname or certificate is
changed without that overlap, agents correctly fail closed. DNS TTL should be
lowered before the cutover, but an IP-address change alone does not require
re-enrollment.

## 7. Import an existing Warden database

Community conversion supports a database at the same application release with
exactly one organization. It never guesses which customer to retain and never
silently merges organizations or deletes platform accounts.

Create a portable database dump on the source host and move it through an
encrypted channel:

```bash
docker exec warden-postgres pg_dump -U warden_admin -d warden \
  --format=custom --file=/tmp/warden-community-import.dump
docker cp warden-postgres:/tmp/warden-community-import.dump ./warden-community-import.dump
sha256sum ./warden-community-import.dump
```

Restore that dump into an isolated database first and run the checks below
there. A restore/import must also carry the matching environment secrets,
device CA, uploads, Home Node keys/data, and TLS/signing material described in
section 4. Do not point production agents at the imported server until its
acceptance checks pass.

On a restored copy, not the only production database, copy and run the
read-only preflight:

```bash
docker cp tools/community_migration_preflight.sql warden-postgres:/tmp/preflight.sql
docker exec -it warden-postgres psql -v ON_ERROR_STOP=1 \
  -U warden_admin -d warden -f /tmp/preflight.sql
```

The report must show one organization and zero unsupported administrator
accounts. If it does not, export the intended organization through a reviewed,
release-specific migration; do not delete other organizations merely to make
the check pass. Resolve platform-admin accounts explicitly by creating a
company-scoped administrator or excluding obsolete control-plane accounts in
the reviewed copy.

Then apply the boundary transaction:

```bash
docker cp migrations/2026-09-28-community-single-organization.sql \
  warden-postgres:/tmp/community.sql
docker exec -it warden-postgres psql -v ON_ERROR_STOP=1 \
  -U warden_admin -d warden -f /tmp/community.sql
```

Legacy SaaS/subscription tables are ignored but not automatically destroyed.
Remove them only after validation and the retention period, using a separately
reviewed cleanup migration. Preserve the original encrypted backup.

After import, run the same health, login, heartbeat, signed-job, remote, and
storage acceptance checks as an upgrade. If the public URL/signing key/device
CA/database identities were preserved, endpoints reconnect normally; otherwise
use fresh installers and tokens to re-enroll them deliberately.

## 8. Acceptance checklist

- HTTPS health succeeds externally and HTTP redirects only to the same host.
- PostgreSQL/PostgREST have no host-published ports.
- Administrator login, MFA setup, audit logging, and backup restore work.
- A disposable endpoint enrolls, reports inventory, runs a safe signed job,
  renews its device certificate, and survives a reboot.
- A revoked endpoint cannot authenticate and a fresh token reconnects it.
- Certificate-pin rotation is tested before the first real TLS renewal.
- Home Node registration, direct transfer, failover behavior, key recovery,
  and service auto-start are tested when storage is enabled.
