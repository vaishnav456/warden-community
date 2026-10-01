# Fleet tools

Implemented in the main application and Community. Community remains a single-organization console with no marketing landing page, uses its configured server URL, and does not gain hosted-plan quotas.

## Safe release order

Server schema and application screens can be deployed independently of agent and Home releases. Back up the database and Home recovery keys before release. Apply the existing package-storage and reliability migrations first, then `migrations/2026-10-01-fleet-tools.sql`. Fresh databases use the corresponding `db-init` scripts. Deploy the server before new agents/Home Nodes. Existing agents remain compatible, but do not provide the new support shortcut, traffic enforcement or transport receipts. Pilot the Windows support UI and one Home Node before broad agent rollout; local tests cannot establish live-device behavior.

All automatic application rules begin disabled unless an administrator explicitly enables them during approval. Creating a policy preset does not deploy it. Backups and package caching are opt-in. Installing the server schema and screens does not itself enable patch rules or publish new agent/Home binaries. Existing authorized schedules and update settings remain in effect.

## Application patches and policies

Operations → Fleet tools compares exact product/publisher inventory matches against numeric target versions. Missing, ambiguous, unsupported or stale inventory is not automatically installed. Administrators approve a reviewed App Library installer, pin its SHA-256 and arguments, select scope and a UTC window, and optionally enable dispatch. Changes to the installer require a new approval. In-flight installs and active remote sessions are skipped. Receipts prevent repeating the same rule/inventory attempt, including after job retention deletes the original job. Failed installs need operator review; refreshed inventory, not merely exit code zero, establishes the resulting version.

Device policies provides catalog-validated presets for firewall, screen lock and USB storage. Existing effective-policy assignment/deployment handles branch/device exceptions. Existing Directory actions handle reviewed local-admin membership changes; presets do not silently change account privileges.

## Support and connection evidence

The Windows agent creates a Warden Support Start-menu shortcut. Users can also run the installed agent with `--request-support`. Its bounded, local-only named pipe derives the caller from a Windows process token. Only a help message is accepted; it cannot execute commands or reveal credentials. Request bodies are encrypted with the organization vault before persistence. Administrators claim/resolve requests in their scope, then request normal attended remote-access consent separately.

Home receipts distinguish observed direct HTTPS, direct WebRTC and encrypted relay transport. Unknown transport remains unknown. Remote quality records server-to-agent WebSocket ping RTT and bytes sent to the browser. Viewer browser-to-relay RTT is separate; neither frame age nor ping guarantees interactive responsiveness.

## Independent encrypted Home backups

Set these fields in the protected Home Node JSON configuration (paths must be absolute, real directories without symlink ancestors):

```json
{
  "backup_root": "D:\\WardenBackups",
  "backup_max_bytes": 107374182400,
  "backup_interval_hours": 24,
  "package_cache_max_bytes": 5368709120
}
```

Each field is optional; backups require both a separate destination and positive quota. Cache quota is independent of Home-space quotas. Linux uses an absolute path such as `/mnt/backup/warden`. Do not put backups inside the active root or vice versa. Use a separate failure domain, not merely another folder on the same disk. Shared active-active stores require a coordinated offline/external backup and are intentionally refused by this local snapshot feature.

Snapshots preserve encrypted files, deletion markers, retained encrypted history and empty directories. Node configuration/credentials/keys and disposable package cache are excluded. The manifest and every backup object are authenticated/encrypted with the existing Home encryption key. Every object is verified before publication; tampered content is rejected. Keep that original key in protected offline escrow: the server cannot recover a lost key. Backups are not incremental and briefly serialize Home storage work while copying/verifying; pilot duration and disk headroom for large stores. No automatic snapshot deletion occurs: quota exhaustion stops new backups and reports failure while preserving the previous verified snapshot information.

```text
warden-home backup --config warden-home.json
warden-home verify-backup --config warden-home.json --snapshot SNAPSHOT_ID
warden-home restore-backup --config warden-home.json --snapshot SNAPSHOT_ID --restore-root NEW_DIRECTORY
```

Restore validates first and only accepts a new destination disjoint from active data/backups. It writes encrypted originals, never plaintext. An interrupted restore leaves a marker which prevents starting the service on that root. Review and verify the restored copy before explicitly changing the service configuration. Keep the service stopped during operator recovery. Home recovery displays reports and a checklist, not keys; key fingerprints do not prove offline escrow exists.

## Branch bandwidth and package reuse

Operations → Branch traffic sets per-device Home/installer transfer ceilings and optional business-hour update deferral. UTC windows wrap midnight; equal start/end means all day. This is not an aggregate branch bandwidth cap. New requests pick up changes; existing running jobs are not forcibly interrupted. Long-running jobs renew an endpoint-owned lease through heartbeat, bounded to 24 hours.

Transfers retain bounded request timeouts: 30 minutes on the Windows agent and 10 minutes for Home responses. Select a ceiling sufficient for the expected file size within those bounds. Transfers are whole-file, not resumable block downloads.

An updated LAN/public-HTTPS Home Node can be selected as a package cache after configuring a positive `package_cache_max_bytes`. P2P-only package caching is not supported. Cache grants are signed, short-lived and bound to the endpoint, node, installer hash and expected size; device certificate matching remains enforced. The node fetches only from its configured HTTPS Warden server and stores authenticated encrypted blobs. Both node and agent verify content; cache errors fall back to the verified server download. LRU eviction removes only recognized internal cache blobs, never App Library originals or Home files. Unexpected/corrupt cache objects fail closed; inspect/quarantine them as an operator rather than treating them as user data.

## Read-only reports

Audit, remote approval/session, job result and storage/Home activity CSV exports use retained records only, tenant/current-branch scope, 1–90 days and a 10,000-row scan limit. Oversized exports require a shorter period instead of silent truncation. Formula-like cells are escaped. Payloads, request bodies, log output, grants and keys are excluded. Storage activity means audited operations, not a complete filesystem access ledger.
