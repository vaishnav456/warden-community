# Warden organization data encryption

Warden Community uses one AES-256-GCM data-encryption key (DEK) for its single
organization. In managed mode the DEK is wrapped by
`TENANT_MASTER_KEK_B64`; the legacy environment-variable name is retained so
existing installations can upgrade without rotating secrets. BYOK can re-wrap
the same DEK later without re-encrypting every row.

## Encrypted endpoint data

The following values are ciphertext in PostgreSQL and are decrypted only in
the Warden application process:

- hostname, hardware ID, installation ID, public/private IP addresses;
- operating-system identity, CPU model and interactive username;
- notes, tags, asset tag, assignee and custom asset metadata;
- device identity, topology telemetry and capability details;
- endpoint event details;
- alert title, message, detail and resolution notes;
- organization audit details.

Each ciphertext is authenticated with the internal organization ID and field
purpose as AES-GCM additional authenticated data. Moving ciphertext to another
record owner or field causes decryption to fail.

Hardware and installation lookups use purpose-scoped HMAC-SHA256 blind
indexes derived from the organization DEK. The database can perform exact
lookups but cannot recover their plaintext.

## Intentionally queryable

The database retains only the minimum control-plane fields needed for routing
and fleet operation: opaque UUIDs, organization/branch relationships, API-key
hashes, status flags, timestamps, numeric health metrics, platform category,
job/action types and approval state. Passwords remain one-way hashes.

This is application-level encryption, not zero knowledge. In managed-key
mode, the running Warden server can decrypt organization data to serve
authorized users and agents. Organization-held BYOK custody prevents the
server from unwrapping the organization DEK while the vault is locked.

Full-disk encryption and encrypted backups remain required because PostgreSQL
WAL, indexes, temporary data and intentionally queryable control-plane fields
are outside application field encryption.

## Migration order

1. Back up PostgreSQL and verify the archive.
2. Apply 2026-09-28-endpoint-private-data-encryption.sql.
3. Deploy compatible server code.
4. Run python tools/encrypt_endpoint_private_data.py.
5. Verify raw rows contain v2 ciphertext and no legacy JSON content.
6. Apply 2026-09-28-endpoint-private-data-encryption-finalize.sql.
7. Run endpt.verify_audit_chain() and retain the result as evidence.

The data tool is restartable and never logs plaintext or keys.
