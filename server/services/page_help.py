"""Tenant-facing, contextual documentation for every authenticated console page."""


def _guide(title, overview, workflow, safety, troubleshooting):
    return {
        "title": title, "overview": overview,
        "sections": (
            {"title": "Recommended workflow", "items": workflow},
            {"title": "What changes and who can do it", "items": safety},
            {"title": "If something does not work", "items": troubleshooting},
        ),
    }


GUIDES = {
    "/": _guide("Dashboard guide", "A tenant-wide operational summary. Counts reflect the current tenant only and link to the underlying records.",
        ("Start with critical alerts and offline endpoints.", "Review recent jobs before making broad changes.", "Use status and audit pages to confirm control-plane health and administrator activity."),
        ("This page is read-only.", "Tenant and branch restrictions still apply to every linked page.", "A healthy dashboard does not replace endpoint compliance review."),
        ("Refresh after an agent heartbeat interval.", "Check Platform status when several unrelated cards stop updating.", "Check enrollment and firewall settings when only one endpoint is missing.")),
    "/endpoints": _guide("Endpoints guide", "Inventory and operate managed Windows, macOS, and Linux devices. Online means the control plane recently received an authenticated heartbeat.",
        ("Filter or select the intended devices.", "Review platform, branch, agent version, and last-seen time.", "Run a small pilot before bulk actions or policy deployment.", "Remove from Warden only when you intend to free its license and revoke its identity."),
        ("Actions execute as the privileged Warden Agent and are audited.", "A portal removal does not erase the physical device.", "Offline devices receive queued work after reconnecting unless the job expires or is cancelled."),
        ("Confirm the Agent service is running and outbound HTTPS is allowed.", "Read the job error rather than repeatedly dispatching the same action.", "Use a fresh enrollment profile after a device was reformatted or retired.")),
    "/topology": _guide("Computer topology guide", "Maps managed devices to tenant-defined buildings, floors, and rooms while showing live reachability, signed-in users, network identity, and health.",
        ("Create a floor for the correct branch.", "Draw rooms and set optional capacities.", "Place switches, firewalls, routers, servers, access points, printers, and other assets.", "Drag endpoints onto the floor, then use Connect to draw Ethernet, fiber, Wi-Fi, VPN, or logical paths.", "Switch the heatmap to reveal offline, CPU, or memory hotspots.", "Select a device to inspect it, open its workspace, or start approved remote support."),
        ("Company and branch administrators can edit layouts; technicians can inspect them.", "Lock a completed floor to prevent accidental moves.", "A map position is operational metadata and does not track a person or device using GPS.", "Remote support retains the tenant's consent and approval rules."),
        ("An endpoint must enroll and heartbeat before it appears.", "Agent 2.6.24 or newer reports its LAN IP and device form factor; older agents fall back to the observed connection IP and an inferred outline.", "Signed-in user data requires an active desktop session.", "Check branch assignment when an endpoint is absent from a branch-scoped floor.", "Unlock the layout before adding rooms, assets, links, or moving devices.")),
    "/assets": _guide("Asset inventory guide", "Adds ownership, purchase, warranty, and lifecycle context to endpoint inventory.",
        ("Link each asset to the correct endpoint.", "Record identifiers and dates from authoritative purchase records.", "Review expiring warranties and unassigned hardware regularly."),
        ("Asset edits do not change the endpoint itself.", "Administrators with asset permissions can update ownership and lifecycle data.", "Deleting an endpoint and retiring an asset are separate decisions."),
        ("If an endpoint is missing, confirm it is enrolled and visible to your branch.", "Avoid duplicate serial numbers.", "Export or audit changes when reconciling with finance records.")),
    "/users": _guide("Tenant administrators guide", "Controls people who can sign in to the Warden tenant console; these are not endpoint login accounts.",
        ("Create the administrator with the smallest suitable role.", "Limit branch access where possible.", "Require MFA and rotate temporary passwords.", "Disable access immediately when responsibilities change."),
        ("Company administrators can perform tenant-wide operations.", "Disabling a console administrator does not delete endpoint users.", "Password resets and role changes are recorded in the audit log."),
        ("Check tenant domain, account state, MFA, and assigned branches.", "Use password reset rather than creating a duplicate account.", "A platform administrator and tenant administrator have different scopes.")),
    "/directory": _guide("Central directory guide", "Manages Warden identities and local endpoint accounts without requiring Active Directory or Microsoft Entra.",
        ("Create or import the identity.", "Set its password and conditional-access rules.", "Assign it to one or more endpoints.", "Verify provisioning jobs before asking the user to sign in.", "Disable or reassign deliberately; choose whether old local accounts should remain."),
        ("One Warden password can authorize the identity on assigned devices while each endpoint keeps a unique protected local secret.", "An unassigned device must reject the identity.", "Disabling an identity blocks Warden login; deletion of local accounts is a separate explicit action."),
        ("Check assignment state, endpoint online state, and provisioning job output.", "A reformatted endpoint must enroll again before assignment.", "If a profile photo is absent, verify the image format and completed sync.")),
    "/storage": _guide("Warden Home guide", "Delivers personal and shared folders directly between endpoints and tenant-owned storage nodes; file bytes never transit the Warden control plane.",
        ("Register each node and save its one-time keys.", "Choose single-primary, failover, or shared-storage active-active.", "Create spaces with quota and file-size limits.", "Assign read-only or read-write access by tenant, branch, tag, endpoint, or identity.", "Test recovery before production use."),
        ("Automatic failover waits out old grants and requires a recently synchronized replica.", "Active-active requires the exact same shared storage and encryption key.", "Uninstall preserves configuration and encrypted data; losing the AES key makes recovery impossible."),
        ("Check node heartbeat, HTTPS hostname, mTLS, and storage-cluster identity.", "For recovery, reuse the node ID and rotate only a lost node authentication key.", "Use the job result to distinguish connectivity, quota, permission, and certificate errors.")),
    "/apps": _guide("Application library guide", "Stores approved application packages and deploys them through authenticated Agent jobs.",
        ("Upload a versioned package with a clear name and install arguments.", "Pilot on a test endpoint.", "Review job output and detection results.", "Expand deployment only after the pilot succeeds."),
        ("Packages run with elevated Agent privileges.", "Only trusted, verified installers should be uploaded.", "Updating a library item does not silently redeploy it unless a deployment is created."),
        ("Verify platform, hash, silent-install flags, and endpoint disk space.", "Check application-control or firewall policy blocks.", "Do not retry a partially installed package until its vendor rollback guidance is understood.")),
    "/jobs": _guide("Jobs guide", "Tracks every endpoint command from queueing through execution and result processing.",
        ("Filter by status or operation.", "Open a failed job and read its structured error and log.", "Cancel pending work that is no longer wanted.", "Retry only after correcting the cause."),
        ("Pending work has not executed; running work may already have changed the endpoint.", "Cancellation is best-effort after execution starts.", "Commands and results are tenant-scoped and audited."),
        ("Confirm endpoint connectivity and capability support.", "Check approval requirements for privileged actions.", "A timeout can mean the endpoint disconnected; inspect endpoint state before retrying.")),
    "/escalations": _guide("Privilege approvals guide", "Reviews temporary local-administrator requests raised by managed endpoints.",
        ("Confirm requester, endpoint, reason, requested operation, and duration.", "Approve only the minimum required scope.", "Use dual approval for high-risk operations.", "Revoke saved approvals when no longer justified."),
        ("Approval grants temporary elevation, not permanent tenant administration.", "Approvers must not approve their own request when dual approval is enabled.", "Every decision and token use is audited."),
        ("Check the endpoint clock and connectivity when an approved token is rejected.", "Expired or already-used grants require a new request.", "Review policy precedence if requests are unexpectedly automatic or blocked.")),
    "/alerts": _guide("Alerts guide", "Collects endpoint, policy, security, enrollment, and platform conditions that need attention.",
        ("Handle critical active alerts first.", "Assign an owner and investigate supporting endpoint/job data.", "Resolve only after verifying remediation.", "Use snooze for a known temporary condition, not permanent suppression."),
        ("Resolving an alert records workflow state; it does not automatically fix the underlying device.", "Reopened alerts retain history.", "Threshold changes affect future evaluations."),
        ("Check the originating rule and raw timestamps.", "If alerts are absent, verify collection jobs and thresholds.", "If alerts repeat, inspect whether remediation actually reached the endpoint.")),
    "/compliance": _guide("Compliance guide", "Evaluates endpoint state against tenant policies and benchmark controls.",
        ("Choose or clone a baseline.", "Customize only documented exceptions.", "Deploy to a pilot scope.", "Run scans and inspect control-level evidence.", "Expand after measuring impact."),
        ("A scan reports state; remediation policies can change device configuration.", "More-specific assignments override broader scopes.", "CIS and other benchmarks still require organizational review."),
        ("Check agent capability and policy deployment status.", "A Not applicable control is different from Pass.", "Review platform-specific support before expecting identical Windows, macOS, and Linux results.")),
    "/patches": _guide("Patch management guide", "Inventories operating-system updates and controls staged deployment.",
        ("Refresh patch inventory.", "Define pilot and broad rings with maintenance windows.", "Deploy to the pilot first.", "Monitor failures and reboot requirements.", "Promote or pause based on results."),
        ("Patching can restart endpoints and interrupt users.", "Offline devices execute within the next eligible window.", "A superseded update may disappear from later scans."),
        ("Check vendor applicability, free disk space, reboot state, and update service health.", "Use job logs for error codes.", "Do not repeatedly force an update that the OS marks incompatible.")),
    "/effective-policy": _guide("Effective policy guide", "Explains the final policy calculated for a device after tenant, branch, tag, endpoint, and identity precedence.",
        ("Select the endpoint.", "Review every setting and its source.", "Resolve unintended overrides.", "Deploy and confirm the resulting job."),
        ("Endpoint scope is more specific than branch or tenant scope.", "Removing an override reveals the next applicable value; it does not necessarily disable the setting.", "Policy changes are audited."),
        ("Check tags and branch membership.", "Confirm template version and deployment status.", "Use the provenance field to find the rule that supplied an unexpected value.")),
    "/network": _guide("Network control guide", "Analyzes endpoint flows and manages Warden firewall policy at application, protocol, address, and port level.",
        ("Collect recent flows.", "Create narrow allow rules for required traffic.", "Add explicit blocks with clear scope.", "Pilot and inspect analysis before broad deployment."),
        ("Endpoint rules are evaluated by documented priority and specificity.", "Warden control traffic is protected from tenant rules.", "A broad wildcard can affect many applications and should require careful review."),
        ("Verify executable path, resolved IP, protocol, direction, and rule priority.", "Remember DNS/CDN addresses can change.", "Use packet capture only with authorization and retain captures securely.")),
    "/vulnerabilities": _guide("Vulnerability guide", "Correlates collected software with vulnerability and exploited-vulnerability intelligence.",
        ("Refresh software inventory and intelligence feeds.", "Prioritize known-exploited and internet-facing findings.", "Patch, remove, or mitigate the software.", "Rescan before marking remediated."),
        ("A match is evidence for investigation, not proof of exploit.", "False-positive decisions should include a reason.", "Feed age and inventory age affect accuracy."),
        ("Check product, vendor, and version normalization.", "Verify the endpoint has completed software collection.", "If a finding persists, confirm the patched binary version actually changed.")),
    "/schedule": _guide("Scheduled operations guide", "Runs repeatable endpoint jobs at controlled times.",
        ("Choose the narrowest target scope.", "Set an interval and maintenance window.", "Validate the command manually on a pilot.", "Monitor the first scheduled occurrence."),
        ("Schedules create endpoint jobs; they do not guarantee an offline endpoint runs at the original wall-clock time.", "Disabling a schedule stops future occurrences, not already-running jobs.", "Privileged operations retain normal approval and audit rules."),
        ("Check next-run time and tenant timezone.", "Look for an existing in-flight duplicate.", "Inspect the generated job when the schedule ran but the endpoint did not change.")),
    "/status": _guide("Platform status guide", "Shows tenant-visible control-plane, relay, database, scheduler, and service health.",
        ("Confirm whether an issue affects one endpoint or a shared service.", "Correlate degraded components with recent failures.", "Retry user operations only after the dependency recovers."),
        ("This page is diagnostic and does not restart services.", "Tenant users see operational status, not infrastructure secrets.", "A green control plane does not guarantee a remote endpoint network is healthy."),
        ("Check timestamps to avoid acting on stale status.", "Use endpoint last-seen for device-specific issues.", "Escalate persistent shared-service degradation with the affected time window.")),
    "/audit": _guide("Audit log guide", "Records administrator and security-sensitive tenant actions for investigation and accountability.",
        ("Filter by time, actor, and action.", "Open related endpoint, job, or policy records.", "Export only for an approved audit purpose.", "Retain according to company policy."),
        ("Audit events are read-only.", "Sensitive values such as passwords and raw keys must not appear.", "Company and branch boundaries remain enforced."),
        ("Use UTC timestamps when correlating systems.", "An absent event can mean the action never reached Warden.", "Compare job and endpoint logs for actions executed asynchronously.")),
    "/settings": _guide("Settings guide", "Entry point for tenant configuration, enrollment, policies, integrations, notifications, and security controls.",
        ("Configure organization and branches first.", "Set security and approval controls.", "Create enrollment profiles and policy templates.", "Test integrations before production sync."),
        ("Settings can affect every endpoint in the tenant.", "Use company-admin access sparingly.", "Review the audit log after high-impact changes."),
        ("Check entitlements when a feature is unavailable.", "Confirm tenant context before editing.", "Use page-specific help on each settings screen for prerequisites.")),
}


PREFIX_GUIDES = (
    ("/endpoints/", "/endpoints"), ("/jobs/", "/jobs"),
    ("/escalations/", "/escalations"), ("/settings/", "/settings"),
)


DETAIL_GUIDES = {
    "endpoint": _guide("Endpoint workspace guide", "A complete device record with live health, assigned users, effective policy, firewall, software, jobs, notes, remote support, and lifecycle actions.",
        ("Confirm hostname, platform, assigned branch, and last-seen time.", "Use Overview to understand health before taking action.", "Review the relevant tab, run one action, then follow its Job result.", "Use remote access only with an approved reason and the required user consent."),
        ("Actions execute with Agent privileges and can affect the signed-in user.", "Run action opens the supported operation menu; it does not execute anything until an operation is selected and confirmed.", "Notes are tenant records shown on this endpoint and retained in Warden, not on the device.", "Remove from Warden revokes the device identity and frees its license without proving that local software was removed."),
        ("If a tab is empty, check platform support, Agent version, and the last completed collection job.", "If an action remains queued, confirm the endpoint is online.", "Use the effective-policy source labels to explain unexpected configuration.")),
    "remote": _guide("Remote support guide", "A time-limited, audited session relayed between this browser and one managed endpoint. Available controls depend on the granted session capabilities.",
        ("Verify the device and user before interacting.", "Explain the session and obtain consent when policy requires it.", "Use the special-key toolbar for Ctrl, Alt, Windows, Ctrl+Alt+Delete, clipboard, and display selection.", "End the session as soon as support is complete."),
        ("View-only sessions cannot send input.", "File transfer, clipboard, and unattended access are independent permissions.", "The login/secure desktop may use a different Windows capture path; reconnect once if the display changes."),
        ("Connection failed usually means relay pairing, Agent connectivity, consent, or an expired session.", "A black or flickering login screen should be reported with the endpoint, time, and selected display.", "If a special key fails, use the toolbar button rather than the browser keyboard shortcut.")),
    "job": _guide("Job detail guide", "The authoritative record of one requested endpoint operation, including its target, payload summary, state transitions, output, and error details.",
        ("Read the operation and target first.", "Check timestamps to see whether it queued, started, and finished.", "Use output and error details to correct the cause.", "Return to the endpoint before retrying."),
        ("Payload secrets and binary bodies are redacted from this view.", "Cancel is reliable while pending and best-effort once execution begins.", "A successful process exit does not always prove the intended business outcome; verify endpoint state."),
        ("Queued means the endpoint has not accepted it.", "Timed out can indicate disconnect during execution.", "Use Agent and Windows/Linux logs when the job error points to a local dependency.")),
    "saved_escalations": _guide("Saved privilege rules guide", "Lists reusable privilege decisions that can automatically handle matching elevation requests.",
        ("Review the endpoint, requester, executable, arguments, and expiry.", "Keep matching criteria narrow.", "Revoke a rule as soon as its operational need ends."),
        ("A saved approval can grant elevation without a new administrator decision each time.", "Changing a policy affects future matches, not completed elevation events.", "All matches remain audited."),
        ("If a request does not match, compare path, hash, signer, arguments, user, and endpoint.", "Create a new request instead of broadening a rule unnecessarily.", "Check endpoint clock if expiry behaves unexpectedly.")),
}


SETTINGS_GUIDES = {
    "tokens": ("Enrollment and zero-touch guide", "Create scoped, expiring enrollment profiles; download only the intended platform build; revoke exposed tokens; and use device binding for zero-touch deployments."),
    "builds": ("Agent builds guide", "Track immutable platform installers, versions, hashes, signing state, and build failures. Deploy newer versions through authenticated self-update jobs."),
    "branches": ("Branches guide", "Model offices or administrative boundaries used for access, enrollment, policy assignment, reporting, and delegated tenant administration."),
    "policy-templates": ("Policy templates guide", "Create reusable GPO-style baselines, clone benchmarks, customize documented exceptions, then deploy through scoped and auditable assignments."),
    "firewall-policies": ("Firewall policy guide", "Build ordered application, protocol, IP, port, and wildcard rules; test analysis first; then assign at tenant, branch, tag, or endpoint scope."),
    "integrations": ("Cloud integrations guide", "Tenant-provided credentials remain tenant scoped. Test permissions, start with read-only synchronization, and disconnect credentials that are no longer required."),
    "thresholds": ("Alert thresholds guide", "Define when endpoint and platform observations become alerts. Pilot threshold changes to avoid missed incidents or alert fatigue."),
    "security": ("Tenant security guide", "Manage encryption, vault state, MFA, dual approval, agent updates, and temporary platform-support access. Treat changes here as tenant-wide security decisions."),
}


def page_help_for(path):
    normalized = (path or "/").rstrip("/") or "/"
    if normalized.startswith("/admin"):
        return _guide(
            "Platform administration guide",
            "Operates the Warden SaaS control plane across tenants while keeping tenant payloads inaccessible unless a tenant grants time-limited support access.",
            ("Start with Operations and Platform Health.", "Open Tenant 360 for customer-specific context.", "Use staged rollouts and explicit reasons for every exceptional change.", "Record recovery evidence after testing, not merely after a backup job runs."),
            ("Platform actions are globally sensitive and audited.", "Tenant support access requires tenant approval and expires automatically.", "Deletion pending uses a recoverable 30-day window; final data erasure is a separate controlled process."),
            ("Check incident, build and failed-job timelines together.", "Verify the operator has 2FA and the correct role.", "Pause a rollout before retrying when failures affect more than one tenant."),
        )
    if "/remote-view/" in normalized or normalized.startswith("/support/"):
        return DETAIL_GUIDES["remote"]
    if normalized == "/escalations/saved":
        return DETAIL_GUIDES["saved_escalations"]
    if normalized.startswith("/jobs/"):
        return DETAIL_GUIDES["job"]
    if normalized.startswith("/endpoints/"):
        return DETAIL_GUIDES["endpoint"]
    if normalized.startswith("/settings/"):
        key = normalized.split("/")[2]
        if key in SETTINGS_GUIDES:
            title, overview = SETTINGS_GUIDES[key]
            return _guide(title, overview,
                ("Read the prerequisites shown on the page.", "Apply the smallest safe scope.", "Test on a pilot or non-production object.", "Confirm the resulting audit event and endpoint job."),
                ("Company-admin permission is normally required.", "Secrets and one-time credentials must be stored outside Warden when instructed.", "Existing queued work may retain the previous configuration until refreshed."),
                ("Check validation messages and required keys.", "Confirm licensing and tenant ownership.", "Review job/build logs before retrying."))
    for prefix, key in PREFIX_GUIDES:
        if normalized.startswith(prefix):
            return GUIDES[key]
    return GUIDES.get(normalized) or _guide(
        "Page guide", "This page is part of the authenticated Warden console and operates only within the current tenant context.",
        ("Review the page purpose and current filters.", "Start with the smallest safe scope.", "Confirm results in jobs and audit history."),
        ("Available actions depend on your role and branch access.", "Endpoint changes may execute asynchronously.", "Never paste passwords, private keys, or recovery secrets into notes."),
        ("Check validation messages, endpoint connectivity, and related job logs.", "Refresh once before repeating an action.", "Contact a tenant company administrator when permission is missing."))
