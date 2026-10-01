# Warden organization data encryption

Warden Community uses one AES-256-GCM data-encryption key (DEK) for its single
organization. In managed mode the DEK is wrapped by
`TENANT_MASTER_KEK_B64`; the legacy environment-variable name is retained so
existing installations can upgrade without rotating secrets. BYOK can re-wrap
the same DEK later without re-encrypting every row.

## BYOK restart and recovery

Switching managed mode to BYOK re-wraps the existing DEK; existing ciphertext
does not change. The current process remains unlocked after the switch.
The unwrapped DEK is held only in process memory and is lost on restart or
explicit vault lock. An ordinary HTTP 500 does not itself clear this cache.

While locked, protected console requests lead to
`/settings/security/vault`, a standalone page that never reads encrypted
endpoint records. An organization administrator can enter the existing
passphrase there. Other roles see administrator-contact guidance. Unlocking
is CSRF-protected, rate-limited and audited, and unlocks the organization for
the running process rather than just one browser session.

API/fetch requests receive HTTP 423 with `error: tenant_vault_locked` and
`unlock_url`; HTMX responses also provide an `HX-Redirect` to the unlock page.
Protected operations fail closed while locked, with no plaintext fallback.
Failed mutations are not automatically replayed after unlock. No passphrase
or derived wrapping key is persisted; losing the passphrase makes encrypted
data unrecoverable. BYOK does not hide plaintext from an authorized running
server once unlocked.

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
