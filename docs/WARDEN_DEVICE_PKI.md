# Warden device PKI operations

Warden uses two independent certificate systems:

- Cloudflare, Let's Encrypt, or another trusted CA protects the configured public Warden HTTPS endpoint, such as `warden.example.com`.
- The private Warden device PKI identifies endpoint agents and Warden Home Nodes.

The private PKI has no per-device quota. It is suitable for fleets larger than
Cloudflare's managed-client-certificate allowance.

## Certificate lifecycle

1. A device generates its private key locally.
2. It sends only a signed certificate request through its authenticated
   enrollment or renewal API.
3. Warden ignores CSR-requested names and derives the organization, endpoint/node ID,
   DNS names and IP addresses from server-side registration data.
4. Warden returns a seven-day certificate plus its issuing chain.
5. The device renews when less than 48 hours remain.

Leaf certificates are backdated by up to 24 hours so a machine restored from a
snapshot or returning from long sleep can establish Warden Home TLS before its
clock service catches up. Their expiry remains seven days after issuance. Set
`DEVICE_CERT_CLOCK_SKEW_HOURS` lower only when fleet time synchronization is
strictly enforced.

Endpoint private keys are DPAPI protected on Windows. Home Node keys are stored
beside `warden-home.json` with service-account-only permissions. A certificate
contains a SPIFFE-style URI:

```text
spiffe://warden/endpoint/<organization-id>/<endpoint-id>
spiffe://warden/home-node/<organization-id>/<node-id>
```

Warden Home requires both a CA-valid client certificate and a signed, short-lived
grant. It rejects a valid certificate when its organization/device URI does not match
the grant.

## CA files and backups

The online issuing material is stored in the `warden-device-ca` Docker volume at
`/var/lib/warden/device-ca`. The first bootstrap creates a root and issuing CA.
Normal leaf issuance needs the issuing key but not the root key.

The root key was exported to the gitignored, ACL-restricted recovery directory:

```text
certs/device-ca-backup/root-ca.key.pem
```

Keep an additional encrypted offline copy. Never put CA private keys in Git,
container images, support bundles, logs, or organization downloads. Restoring the
existing CA files preserves trust after control-plane recovery. Creating a new
CA requires re-enrolling every endpoint and Home Node.

## Revocation

- Removing an endpoint immediately invalidates its API key and prevents Warden
  from issuing new Home grants.
- Removing or disabling a Home Node prevents heartbeats, renewal and new peer
  introductions.
- Leaf certificates expire after seven days, limiting offline credential life.
- Suspected key compromise requires removing the record and re-enrolling the
  device with a new local key.

## Rotation and recovery

- Leaf rotation is automatic and does not require a new enrollment token.
- Restore all four CA backup files only for disaster recovery or issuing-CA
  replacement. Remove the root key from the online volume again afterward.
- Before an issuing-CA rotation, distribute an overlapping trust bundle to every
  online device. Do not replace the CA abruptly.
- Back up the CA independently from PostgreSQL and test restoration at least
  annually.

## Capacity

Certificate signing is inexpensive relative to heartbeat and inventory traffic.
One issuing CA is sufficient for 500 agents. At larger scale, run one controlled
issuance service with a protected key or HSM/KMS and multiple stateless Warden
API workers; do not copy the issuing key into every arbitrary application host.
