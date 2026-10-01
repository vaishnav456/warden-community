# Module correction release

These changes require a database migration before the matching server code is deployed:
`migrations/2026-10-01-module-corrections.sql`. Fresh installations use
`db-init/19-module-corrections.sql`. Back up the database first. The migration is
transactional and repeatable; it does not send commands to devices.

## Corrected behavior

- Revoking an administrator's sessions invalidates access tokens as well as refresh tokens.
- Software inventory replacement is atomic and retains stable software IDs and vulnerability review decisions.
  Removing software keeps finding history instead of cascading deletion.
- Windows patch jobs fail on incomplete downloads or any unsuccessful update result.
- Broad patch rings recheck current ownership, scope, policy and administrator authorization before dispatch.
  Failed pilots pause promotion; failed campaign targets cannot produce a successful campaign.
- Patch restart choices are Never and Notify. Neither automatically restarts the system.
  Existing forced-deadline policies are rejected/paused, not silently converted.
- Conditional sign-in requires compliant evidence no older than 24 hours for the current policy.
  Results are bound to a running scan issued for that tenant and endpoint.
- Branch exports use the branch recorded at event creation, not today's endpoint membership.
- Home backups pin immutable files briefly under the storage lock, then copy and verify after releasing it.
- Future timestamps no longer count as fresh inventory, compliance or successful rollout evidence.

## Compatibility and release checks

Existing agents can submit compliance results using their job ID; they need not send
the new fingerprint field. The server retrieves it from the issued scan.
Pre-migration evidence has no policy fingerprint: tenants requiring compliance must
run a fresh scan before using conditional sign-in. This is intentionally fail-closed.

Legacy remote sessions lack historical branch evidence and are excluded from
branch-scoped exports; organization-wide exports retain them. Already deleted
vulnerability history cannot be reconstructed by this migration.

Home snapshot capture requires filesystem hard-link support (for example NTFS or
ext4). Unsupported filesystems return a backup error without blocking storage for
a full copy. Copying or verification failure does not publish a completed backup.
An interrupted process may leave an internal `.warden-backup-source-*` directory;
do not remove it while a backup is running.

Server and SQL tests do not establish a successful live rollout. Test Windows Update
installation and reboot notifications on a pilot Windows device before publishing
agent updates. Keep a database backup and the previous server/device artifacts for
recovery. Do not roll back to a server that stops enforcing token revocation after
sessions have been revoked.

Community remains application-only, without a landing page or hosted billing flows.
