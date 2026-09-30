# Warden Home Node

`warden-home-node` is the separate storage-server executable for Warden Home.
It runs on designated Windows or Linux file servers; ordinary endpoints keep
using the normal Warden Agent.

## Incremental sync and folders

Agent 2.6.45 and Home Node 1.1.5 compare file contents using SHA-256, including
edits that retain the same size and timestamp. Each scan reads local file
contents, but only new or changed files are transferred, as whole files rather
than changed blocks. Existing encrypted files remain readable; older metadata
is hashed from authenticated plaintext until those files are rewritten.

Nested folders and empty folders are preserved in both directions. Directory
entries are opt-in so older agents continue to receive a file-only listing.
Update the Home Node before the agent to enable folder sync. With an older node,
content comparison can require downloading remote bytes to calculate a hash;
unsupported folder creation is reported as incomplete, never as success.

Downloads and replica writes check available hashes before replacing existing
copies. Uploads check the new node's content-hash receipt. Equal-timestamp edits
follow the configured conflict policy: the default retains/uploads local edits,
server-wins restores the server copy, and keep-both preserves both versions.
Folder counts appear in sync job results and completion notifications. This
does not introduce endpoint-side deletion propagation or block-level transfer.

## Security model

- File contents are encrypted end-to-end between endpoints and organization-owned nodes.
- Every request requires a short-lived Ed25519 grant scoped to one organization,
  node, space, folder prefix and permission set.
- Warden automatically issues short-lived server/client certificates to the
  node. Required mTLS protects endpoint and node-to-node traffic, and the
  verified certificate identity must match the organization and device in the
  signed access grant. Public mode refuses to start without this material.
- Files are encrypted at rest with AES-256-GCM in independently authenticated
  chunks. The encryption key and node bootstrap key are never stored in the
  Warden database in plaintext.
- Warden introduces peers and signs access grants. File traffic prefers direct
  endpoint-to-node or node-to-node connections. Its HTTPS relay can forward the
  encrypted stream when direct ICE connectivity is unavailable.
- P2P VPN mode embeds WebRTC/ICE in both executables. Both peers make outbound
  connections; rendezvous offers/answers expire after two minutes and are
  purged by the control plane. The
  established direct data channel carries the existing mTLS HTTPS connection.
  STUN discovers addresses but cannot decrypt or relay files. The HTTPS relay
  fallback preserves the same inner mTLS authentication and signed grants.
- A replica pulls only from the currently authorized writer for the same
  organization space. There is no cross-organization discovery or unrestricted mesh.
- Independent-disk failover waits out the previous 15-minute grant lifetime
  before promotion, preventing two separated servers from accepting writes.
- Shared-storage active-active nodes coordinate quota checks and file changes
  with renewable locks stored on the common filesystem. Warden also compares
  a one-way encryption-key identifier and refuses active-active writers when
  their storage keys do not match.

Create a node in **Warden Home** in the organization console, copy the one-time node
ID/key and signing public key into `warden-home.json`, then install the binary
as a restricted service account. On first start the executable creates its
private key locally and obtains its certificate and CA bundle from Warden.
`warden-home.example.json` documents all settings.

## What to install where

- Employee Windows endpoints use the normal Warden Agent. Do not install the
  Home Node executable on every endpoint.
- A designated Windows or Linux file server runs `warden-home-node`. A small
  pilot can use an always-on PC, but production should use a backed-up server
  with stable DNS/IP and restricted inbound access.
- LAN/VPN-only nodes use the **Local network** mode and a private HTTPS URL.
  Internet-facing nodes use **Public server** mode. Both modes receive their
  private certificate automatically and enforce mTLS.
- A public node can use any domain or subdomain the organization controls, such as
  `home.example.com` or `files.example.com`. Its DNS record must point to the
  Home Node. Warden includes that registered name in the issued certificate.
- Local-only nodes do not need a public domain. A stable private IP or private
  hostname is sufficient. Warden derives certificate names from the registered
  HTTPS URLs; names requested by the node itself are ignored.
- Certificates renew automatically before expiry. Do not pin a rotating leaf
  fingerprint. Endpoints validate the Warden CA chain, hostname and signed
  organization/node identity instead.
- Private nodes serving roaming endpoints can use **P2P VPN** without a public
  DNS record. Both Windows executables automatically allow only their own
  direct-transport sockets: UDP `55000–55099` on the Home Node and UDP
  `55100–55199` on endpoints. The first port is shared by local host
  candidates; ICE/STUN candidates use the remaining ports in that executable's
  firewall allowance. Both sides use ICE/STUN hole punching and request an
  opportunistic PCP, NAT-PMP, or UPnP mapping for the shared port when supported.
  No manual port-forward rule is required. Outbound UDP to STUN and outbound
  HTTPS to Warden must remain allowed. When no direct path is available,
  the existing HTTPS WebSocket relay carries the same end-to-end encrypted
  TLS/mTLS stream. Warden's relay cannot decrypt file contents or grants.

## Availability and scaling

- **Single primary:** one writable node and any number of direct-pull backup
  replicas.
- **Automatic failover:** one active writer and ordered candidates on
  independent disks. Promotion is deliberately fenced to avoid split-brain.
- **Shared-storage active-active:** two or more Home Node front ends mount the
  exact same root, use the same encryption key, and set the same non-empty
  `storage_cluster_id`. Endpoints are distributed deterministically across
  healthy writers and fall back directly to another writer.
- Every node may be P2P, Local, Public, or Hybrid. P2P endpoints connect
  directly to every eligible writer, and P2P backup nodes pull directly from
  the active writer without a public address. Hybrid clients try the private
  address before the public address.
- Vertical scaling requires no special mode: expand the server CPU, memory,
  network, filesystem, RAID, or underlying shared storage normally.

Never give independent filesystems the same `storage_cluster_id`. That value
asserts that all participating front ends see one shared root; mislabeling
separate disks as shared storage can lose updates.

## Disaster recovery and migration

Back up the encrypted data root together with `warden-home.json`, the TLS/mTLS
material, and the encryption key. To recover a single-node installation,
restore those files on a new Windows or Linux server, install the Home Node,
and update the existing node's local/public address in Warden. Reuse the same
Node ID; creating a new node is unnecessary.

If only the node authentication key was lost, rotate it from **Warden Home →
Server recovery or migration** and replace `node_key` in the restored config.
Warden deliberately cannot recover the AES encryption key. Encrypted files
without that key are unrecoverable, so keep an offline copy in a secret
manager separate from the storage server.

## Setup order

1. In the organization portal, open **Warden Home**, create the node, and immediately
   save the one-time Node key and encryption key in a secret manager.
2. Copy `warden-home.example.json`, fill in the displayed values, leave the five
   certificate path fields blank, and install the service. The executable
   creates the key and fills those paths after successful bootstrap:
   - Windows (Administrator): `warden-home-node-windows-amd64.exe install -config warden-home.json`
   - Linux (root): `./warden-home-node-linux-amd64 install -config warden-home.json`
3. Confirm the portal shows the node as **Online**.
4. Create a home/shared space and assign it to the organization, branch, endpoint
   tag, or identity. Online agents sync immediately; offline agents sync after
   their next connection.

The encryption key cannot be recovered from Warden. Back it up separately
from the encrypted file data; both are required for disaster recovery.

To remove the service, run the installed/downloaded executable with
`uninstall` as Administrator/root. Uninstall stops and removes the service and
program binary but deliberately preserves the configuration, encryption keys,
certificates, and encrypted data root for recovery or migration. Delete those
materials separately only after a verified backup and an intentional data
retirement decision.

To upgrade without replacing the node identity, configuration, keys, or data,
download the current executable and run it from a different folder:

- Windows (Administrator): `warden-home-node-windows-amd64.exe upgrade`
- Linux (root): `sudo ./warden-home-node-linux-amd64 upgrade`

The command stops the installed service, replaces only its program binary,
repairs the direct-P2P firewall rule on Windows, and starts the service again.
That one-time upgrade installs managed updates. Later releases are offered in
the authenticated heartbeat, signed with Warden's Ed25519 control-plane key,
downloaded with the node credential, verified by SHA-256, and applied by an
independent helper. Windows and Linux retain the previous executable and
automatically restore it if the replacement service cannot start.

On Linux the installer creates a dedicated unprivileged `warden-home` account,
copies TLS material into `/etc/warden-home/tls` with restricted permissions,
and runs the service with a read-only system plus a narrowly writable data
root. If a public certificate is renewed externally, deploy the renewed leaf
and key to `server-cert.pem` and `server-key.pem` in that directory; the node
reloads the serving certificate without exposing the original ACME account or
private directories to the service.

Build both binaries from a machine with Go installed:

```powershell
.\build.ps1
```
