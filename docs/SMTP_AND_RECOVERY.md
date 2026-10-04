# SMTP and email notifications

## Ownership

Community organization administrators configure their organization's SMTP under Settings → SMTP delivery. Community remains application-only, with no hosted platform administration or landing page.

All console users can manage their own choices under Settings → Email notifications.
Critical alerts and all failed jobs are enabled by default. Other categories
(approvals, completed jobs, Home sync completion, agent update/build results and
other notifications) are opt-in. Explicit opt-outs override defaults.

Branch administrators receive only events for their assigned branch. Approvals
remain subject to existing permissions. Email does not authorize any action.

## Installation and configuration

Apply `migrations/2026-10-02-mail-and-password-recovery.sql` before running this
application version on an existing database. Fresh installations use
`db-init/21-mail-and-password-recovery.sql`.
The worker needs the same persisted 32-byte `TENANT_MASTER_KEK_B64` used for
platform authentication secrets, and a correct public HTTPS `SERVER_URL`
(localhost HTTP is allowed for development). Never regenerate the key on restart.
Recovery URLs come from configuration, not incoming Host headers.

Configure host, port, username, password/app password, sender address/name and
enable delivery. Required STARTTLS (typically 587) and implicit TLS (typically
465) are supported with certificate verification. Unencrypted SMTP and TLS
fallback are not supported. Permit outbound SMTP/DNS and configure your mail
provider's sender verification, SPF/DKIM/DMARC and applicable sending limits.
Do not share credentials in chat or commit them.
A blank password retains the saved secret only when host and username match;
changing either requires re-entering it. Disable delivery to stop new sends.

Use “Send test to my email” after saving. The test is queued only to the current
administrator's registered email. The recent-deliveries table displays sanitized
status and retry metadata; “sent” means SMTP acceptance, not inbox delivery.
Bounces and provider webhooks are not implemented.

For Google Workspace/Gmail, use smtp.gmail.com, port 587, required STARTTLS,
the complete mailbox address as username, and a Google app password. Four-group
display spaces in a Google app password are normalized only for this hostname.
Sender identity must be the authenticated mailbox or a Google-authorized alias.
See [Google's application SMTP guide](https://support.google.com/a/answer/176600).

## Branded templates and triggers

Every message has mobile-friendly HTML and a plain-text alternative. Templates
are in `server/templates/email/`. They use no tracking pixels or remote assets.

- Administrator welcome: new account creation while SMTP is configured;
  organization administrators can also use “Send welcome” for an existing user.
- Administrator recovery: public “Forgot password?” and the tenant-scoped
  “Email reset link” action; passwords are never emailed.
- Identity password setup: existing directory creation/reset workflow, with
  its 24-hour, single-use setup link and manual-link fallback.
- Account security: administrator password, email and MFA changes.
- Operational notifications: alert creation, approval transitions, completed
  or failed jobs, installer build results and new in-app notification rows.


Operational mail contains generic status plus a Warden link, not decrypted
endpoint names, sensitive job logs or filenames. “Home sync completed” follows a
device-reported SYNC_WARDEN_HOME job result; it is not a receipt for every
background file transfer. Email preference changes do not change in-app settings.
Automatic welcome mail is not sent retroactively when SMTP is first enabled.

## Secure administrator recovery

Recovery responses do not disclose whether an email exists. Requests are
rate-limited and there is an account-level one-minute issuance cooldown.
A tenant subdomain cannot initiate recovery for another tenant.

The 32-byte random recovery token is stored as SHA-256, expires in 30 minutes
and is single-use. A new issuance invalidates older unconsumed tokens.
The emailed URL uses a fragment; the browser places the token into the CSRF-
protected POST form and removes the fragment from the address bar. GET never
consumes the token. Completion is transactional, locks the account before the
token, checks active status, current email hash and session generation, updates
the bcrypt password, increments access-token generation and revokes refresh
tokens. It does not disable MFA, change roles or sign the user in automatically.
Creating a link does not invalidate the current password or active sessions.

Passwords must contain at least 12 characters and no more than 72 UTF-8 bytes.
Recovery pages and SMTP responses are no-store/no-referrer. Identity setup
uses the pre-existing separate directory identity recovery flow.

## Encryption, reliability and retention

SMTP credentials and all queued recipient/body content (including HTML and
recovery links) are encrypted using AES-256-GCM with record/purpose-bound
authenticated data. The persisted platform key, not a temporarily unlocked
tenant BYOK key, protects this authentication infrastructure so recovery works
when tenant data is locked. This is server-readable encryption, not end-to-end
email encryption. The server decrypts content to deliver to your TLS-protected
SMTP provider; recipients and their mail provider retain ordinary email copies.
Auth email addresses remain in the existing identity tables.

Durable events and message rows are leased atomically with SKIP LOCKED so
parallel workers/restarts can resume delivery. Per-event/recipient unique keys
prevent duplicate fan-out. Recipient status, current email, branch and optional
preferences are rechecked before sending; superseded reset links are skipped.
Disabling SMTP or changing an address does not redirect queued recovery emails.
Temporary transport failures retry with bounded backoff, at most six attempts,
before the one-day operational deadline (reset mail has a 30-minute deadline).
Authentication, certificate and recipient rejection failures are terminal.
Provider exception text is never stored or logged.

Delivery is at least once: a crash after SMTP accepts a message but before its
status is persisted can cause a duplicate. Stable Message-ID helps correlation
but does not guarantee provider deduplication. There is no exact-once or inbox-
receipt claim. Terminal message bodies are cleared. Metadata is retained seven
days, and expired reset/event rows are purged hourly. Tenant mail events/outbox
are tenant-owned database records.

## Verification

Run `python -m unittest tests.test_mail` from `server/` and the full regression
suite. For database contracts, concatenate the migration without its final
COMMIT, `tools/test_mail_transaction.sql`, then ROLLBACK and run with
`psql -v ON_ERROR_STOP=1` only on an isolated test/development database.
The SQL test creates temporary synthetic fixtures and expects no existing
platform mail settings or pending mail queue. Never execute its fixtures on a
live configured mail service.
