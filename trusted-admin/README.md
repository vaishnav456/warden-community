# Warden trusted admin application

This is a separate, portable application for inspecting and verifying an
encrypted copy of **every application table**. It runs independently of the
public Warden website, starts locked, and binds only to localhost. Its keys are
fresh client-owned keys, unrelated to the legacy Warden master key. The public
Warden application does not receive its keys or a decryption API.

**Current scope:** a read-only migration workspace and ciphertext installer.
It is not yet the live Warden dashboard, endpoint gateway or automation runner.
Capturing or installing a copy does **not** encrypt the existing live tables,
switch database connections, disable legacy decryption, or update agents.
Do not describe the live application as end-to-end encrypted after running it.

## Protection and hosting

Run the app on a trusted computer or a separate trusted server for protection
against compromise of the public Warden host. Hosting both applications on one
machine is a transitional arrangement: host root can inspect unlocked keys and
plaintext in memory. Separate containers do not prevent this. The legacy key
service still permits authorized Warden decryption and cannot provide this
client-only trust boundary.

Install reviewed admin application code independently of Warden. Never load its
scripts from the public Warden website or automatically update it from that
host. Access a server installation through an authenticated SSH tunnel to
localhost port 35750. Do not publish that port, put the app behind Warden's
public reverse proxy, or mount its directory into Warden/build/key containers.

Database users see random table and row IDs plus `wa1:` ciphertext in the
encrypted copy. Original table/column names, source IDs, timestamps, numbers,
booleans, nulls, row content, captured functions, constraints and view definitions
are inside authenticated ciphertext. PostgreSQL system catalogs, ciphertext
sizes, table counts and traffic timing remain observable; no usable database
can hide every structural or operational fact from its host.

## Create and verify a copy

Use Python 3.12 or later in an isolated environment. Install
`trusted-admin/requirements.txt`, then run these commands **from trusted-admin**.
Choose a private directory outside the checkout. Commands prompt for an unlock
phrase of at least 16 characters; do not put it in arguments or environment
variables. Back up the phrase and encrypted vault separately. Losing either
means losing access to these new encrypted copies.

```text
python -m warden_admin.cli --vault /private/vault.json create-vault
python -m warden_admin.cli --vault /private/vault.json capture --archive /private/database.sqlite --checkpoint /private/checkpoint.enc
python -m warden_admin.cli --vault /private/vault.json verify --archive /private/database.sqlite --checkpoint /private/checkpoint.enc
python -m warden_admin.cli --vault /private/vault.json serve --archive /private/database.sqlite --checkpoint /private/checkpoint.enc
```

Configure `WARDEN_ADMIN_SOURCE_DSN` privately before `capture`. Capture uses a
read-only, repeatable-read transaction and discovers all physical tables in
non-system schemas. It preserves empty tables and encrypts complete raw JSON
rows without converting numeric precision. Partitions are captured once per
physical partition. Materialized views are also included. Foreign tables cause
a failure rather than an unverifiable partial capture. This is a data migration
copy, not a complete PostgreSQL disaster-recovery dump.

The encrypted SQLite archive contains only opaque IDs and ciphertext, including
its manifest. No clear temporary export is written. Files are created
exclusively; existing archives, vaults and checkpoints are never overwritten.
Verification authenticates every row and checks table membership, row counts
and encrypted row-set digests. A trusted checkpoint also binds the exact archive
file. Keep an independent checkpoint and vault backup on the controller: an
attacker who can replace both an old archive and its matching old checkpoint
can otherwise replay them. Recovery after suspected compromise needs fresh
independently generated keys; old backups and previously stolen data cannot be
made private retroactively.

The private web UI unlocks through its own session, rejects cross-site form
requests and unrecognized hosts, escapes data, avoids response caching and locks
after ten minutes of inactivity. Restarting discards unlocked state. Python does
not guarantee secure erasure of old memory allocations.

## Install the ciphertext copy in PostgreSQL

Configure `WARDEN_ADMIN_TARGET_DSN` privately for a **separate staging database**.
Never point a trial migration at an unrelated database.

```text
python -m warden_admin.cli --vault /private/vault.json install-ciphertext --archive /private/database.sqlite --checkpoint /private/checkpoint.enc
```

The installer creates a new `warden_cipher` schema. Each source table has one
opaque table containing random `id` and encrypted `payload` columns. One additional
table holds the encrypted manifest. The installer verifies every destination
ciphertext byte before committing; any error rolls back the schema. It refuses
to overwrite an existing schema and never drops or changes source tables. Empty
tables remain represented. The target receives no key and executes no decryption.

## Same-host installation and moving later

Build with `docker build -f trusted-admin/Dockerfile -t warden-trusted-admin .`.
Use `docker-compose.admin.yml` as a standalone project, setting
`WARDEN_ADMIN_DIRECTORY` to the external private directory containing
`vault.json`, `database.sqlite` and `checkpoint.enc`. Files must be readable by
UID/GID 10004; directory mode 0700 and file mode 0600 are suitable on Linux.
The app mounts the directory read-only, starts locked, drops capabilities and
binds localhost using host networking. Its directory contains **no unlock phrase**.
The Docker image packages Python dependency distributions and their notices.

To move: stop the old app, copy the three encrypted files securely, install the
reviewed app independently on the new machine, and compare the archive with the
controller's checkpoint before unlocking. The directory and connection settings
are external to the image; rebuilding Warden is unnecessary. Remove the old app
and its unlocked processes after verification. If the old host may have been
compromised while unlocked, copying files is insufficient: generate fresh keys
on the new trusted host and re-encrypt from a verified trusted copy.

## Required before live cutover

The existing server still performs SQL joins, account authentication, reporting,
policy scheduling, notifications, command signing, builds, Home control and
device enrollment. Those features cannot operate on these opaque tables through
the existing PostgREST interface. Switching the database now would break them.

The replacement must move queries and automation to the trusted app; encrypt
device reports before upload; pin admin/device identities independently of the
relay; approve and sign commands and updates outside the public server; keep a
durable local anti-replay history; and queue work while the trusted app is locked
or offline. `warden_admin/messages.py` provides tested X25519/HKDF/AES-GCM
envelopes with independently pinned Ed25519 senders. It deliberately has no
plaintext or legacy fallback. Replay/expiry enforcement and agent integration
remain separate required work; this primitive alone does not enable them.

Cutover also needs authenticated verification of every old row, a final
write-quiesced snapshot, working new clients, a recovery rehearsal, removal of
old database copies and old master/signing keys, and an explicit development
pilot. Clearing live tables does not erase old WAL, replicas, dumps, backups or
storage snapshots. Record their retention and destruction separately. Hosted
and Community must keep their edition boundaries throughout that conversion.

## Tests

```text
python -m unittest discover -s trusted-admin/tests -v
```

Set `WARDEN_ADMIN_TEST_DSN` only to a disposable database named
`warden_admin_test` to include consistent capture, partition handling and
transactional ciphertext installation checks. Native tests run on Windows and
Linux; PostgreSQL integration uses a disposable Linux database. Test credentials
and fixtures are synthetic.
