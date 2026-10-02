# Endpoint fleet workspace

Device cards show nickname and hostname, CPU/RAM/free disk, branch, contact
freshness, reported check warnings and expandable investigation links.
An online label requires an online status and a heartbeat within three minutes.
Missing or stale encryption evidence is unknown, never an all-healthy claim.
Pending patches are reported inventory, not a complete patch-compliance assertion.
Resource readings on disconnected devices are explicitly not live.
Failed-job and update-job summaries cover jobs created in the last 24 hours.

Filters include OS, reported encryption failure, pending patches, outdated agent,
low disk (under 10 GB), failed jobs and drift. Sorting and 25/50/100-row page
rendering happen on the server. Explicit database reads paginate past default
PostgREST row limits. Friendly names remain encrypted at rest: filtering/sorting
requires tenant-scoped decryption in memory. This is not an indexed plaintext
search engine or a database-only filtered page query; very large fleets still
need a separate benchmark and indexing design.

Saved views are browser-local and partitioned by organization and administrator.
Selection is limited to the current page. Refresh requests transfer only cards,
pagination and summary metadata, not the full page or sensitive job outputs.
Refresh pauses for hidden tabs, dialogs, selected devices, focus and open details,
checks interaction again after the network response, and retains data on failure.

Bulk operations require a read-only server recipient preview followed by explicit
dispatch. Reviewed IDs remain fixed, with tenant/branch ownership rechecked before
dispatch. A branch administrator's selected IDs are no longer discarded.
Empty selections and changed/foreign audiences fail without dispatch.
Supported offline devices queue normally; unsupported devices are skipped.
Existing authorization, capability, entitlement, signing and audit gates remain.
No endpoint action is sent by merely opening or refreshing the page.
# Local drive capacity

Agent 2.6.55 reports each accessible fixed Windows volume (C:, D:, H:, etc.)
on heartbeat. Cards and endpoint details show used, total and free GiB (labeled
GB consistently with existing telemetry). The low-disk filter checks every
reported drive. Drive data remains inside encrypted capability details; no
schema migration. Network shares/removable media and unreadable volumes are
not probed for usage. Older agents show per-drive capacity not reported.
Reports are snapshots, not live disk activity. Source changes alone do not
update installed agents.
