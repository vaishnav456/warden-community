# Warden key service

The key service keeps Warden's existing database encryption master key and
unlocked organization keys in a separate application. Warden requests encryption,
decryption and blind indexes through an authenticated Unix socket. Keys are never
returned by the API. Hosted and Community use the same service without changing
their organization model or entry routes.

This reduces direct key exposure inside the Warden application. An attacker who
controls Warden can still submit operations using its credential and obtain
authorized plaintext. An attacker who controls the host or Docker daemon can
also compromise the key service. This is not end-to-end encryption or a guarantee
against a full server compromise. See [Docker's security model](https://docs.docker.com/engine/security/)
and [OWASP's encryption guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).

## Installation

Use a different private directory, client credential and socket volume for each
deployment. Keep these directories outside Git and outside application mounts.

1. Back up the existing database and its encryption keys in a restricted recovery
   location. The key service does not create backups or rotate existing keys.
2. Place the **existing** `TENANT_MASTER_KEK_B64` value in a file named `master-key`
   in the private directory. It must be base64 for exactly 32 bytes. Replacing it
   with a new random key would make existing records unreadable.
3. Generate a separate random client credential of at least 32 ASCII characters
   into `client-token`, without printing it into logs. On Linux, own `master-key`
   by UID 10003 and set mode 0400. Own `client-token` by UID 10003/GID 10001 and
   set mode 0440. Restrict the parent directory to its administrator.
4. Set `WARDEN_KEY_DIRECTORY` to that absolute directory. Build and initialize:

   ```sh
   docker compose -f docker-compose.yml -f docker-compose.keys.yml build key-service
   docker compose -f docker-compose.yml -f docker-compose.keys.yml run --rm key-storage-init
   docker compose -f docker-compose.yml -f docker-compose.keys.yml up -d --no-deps key-service
   ```

5. Build the updated Warden server, retain the complete deployment-specific
   Compose file list, append `docker-compose.keys.yml` last, and recreate only the
   application after the key service is healthy. The override clears the master
   key from the application environment. Remove it from active application
   environment files as well, preserving a restricted recovery copy.
6. Verify existing encrypted records, MFA, blind indexes and an encrypt/decrypt
   round trip. Inspect the application environment and mounts to confirm that
   it contains no master key and cannot read the master key file.

The example uses the repository's `warden-server` service name. A deployment
using another name must adapt that one stanza. Never remove earlier release or
host-specific Compose overrides. The service has no network interfaces, public
ports, database connection or Docker socket. It runs as UID 10003 with a read-only
filesystem and no Linux capabilities. Warden mounts only the socket directory
and its client credential, both read-only.

## Operations and failure handling

The allowlist supports organization key provisioning, wrapping changes, BYOK
unlock and lock, encryption, decryption, blind indexes, MFA secrets, retained
platform fields and recovery-code verification. It excludes raw key export,
arbitrary function calls and code execution. Requests and responses are limited
to 16 MiB. Logs contain operation names and outcomes, not arguments, plaintext,
credentials or cryptographic exception details.

When enabled, Warden fails the operation if custody is unavailable. It does not
fall back to the local master key. Keep one key-service worker: threads share the
organization cache. A key-service restart locks BYOK organizations; an application
restart alone no longer locks them. Existing AES-GCM v2 data, older authenticated
unversioned data, MFA ciphertext and HMAC lookup tokens remain compatible.

Each successful BYOK unlock receives a fixed period randomly chosen **on the
server from 7 through 30 days**. The key service checks both its monotonic deadline
and UTC expiry on every key use, and sweeps expired memory without needing a
browser request. Reading or writing never extends the period. The web security
page displays the expiry; **Lock workspace** immediately removes the cached key
and expiry for that organization. Clients cannot supply or override a duration.
The usual login, tenant authorization, CSRF and unlock rate limits still apply.

Use the existing HTTPS Warden webpage at `/settings/security/vault`; no desktop
unlock application or installer is required. This is server-side BYOK: unlocking
permits the trusted server to decrypt for dashboards and agents. A malicious
server or host root could capture a phrase or plaintext while unlocked; this
deployment is not end-to-end encryption. A browser offline cannot fetch data or
issue a server lock; downloaded plaintext cannot be revoked remotely.

## Database coverage and recovery

Moving key custody does not encrypt previously readable database columns.
Database coverage must be audited and migrated separately, including historical
records and every write path. Do not describe this service as complete table
encryption. Identifiers, status fields and other values used for joins or queries
need an application and schema design that supports ciphertext storage.

`tools/audit_table_encryption.py` inventories all physical application tables in a
read-only transaction. Supply the database connection through `DATABASE_URL`.
Its JSON report contains only schema metadata and aggregate counts. Prefixes do
not prove successful authentication, and unversioned values can be valid older
ciphertext. Exit status 2 indicates that the strict all-values ciphertext
requirement is not established. Empty tables cannot certify future writes.

Keep the original master key until all records and recovery procedures have been
verified. Restore the same key when restoring the database. For rollback, stop
new writes during the transition, restore the prior application image and its
restricted key configuration, and retain the current database: this change does
not rotate keys or change the database schema. Never commit recovery files,
credentials, keys or deployment backups.
