# Optional agent modules

Core and Helpdesk have separate Windows build targets. Helpdesk is a normal-user application under `agent-go/cmd/helpdesk`; it communicates with the SYSTEM service through the bounded local support pipe. It does not carry enrollment credentials, device keys, an updater or remote-control code.

This is a development candidate, not a verified Windows rollout. Core, Helpdesk and the Windows test binaries cross-compile. Server regressions pass, but the new directory ACLs, installation, restart recovery and actual tray-to-Helpdesk launch still require native testing on the designated laptop. Do not enable Core builds for a production fleet before that pilot passes.

## Organization controls

Apply `migrations/2026-10-03-agent-modules.sql` before deploying these server routes. Fresh installations include the equivalent `db-init/25-agent-modules.sql`. Organization admins control Helpdesk under Settings, Agent modules. Downloads are disabled until an explicit enabled policy exists.

Community uses its organization policy, not hosted subscriptions. It retains its configured local server URL and application-only entry flow, with no marketing landing page.

Existing bundled agents retain access when no policy has been saved. Saving Disabled blocks their ticket API actions too. Revocation does not kill an open form or interrupt a remote session; subsequent actions and launches are denied. This compatibility path is not authorization to download an optional module.

## Building separately

The legacy agent target remains the default while the migration is staged. `go build -tags warden_core .` builds Core 2.7.0 without the ticket form implementation. `go build ./cmd/helpdesk` builds only Helpdesk. Go must target Windows AMD64 with CGO disabled; use the existing Windows GUI subsystem flags when packaging.

The build service supports an operator-selected `config_json.agent_core_modules=true` and records the correct Core version. Setting server environment `AGENT_CORE_MODULES_ENABLED=true` selects Core for newly requested Windows installers; this setting defaults to false. Core installers do not contain the Helpdesk executable.

An operator builds an optional release with `build-service/module_builder.py --output <private-release-directory> --sequence <increasing-number> --version <three-part-version>`. This uses the existing Authenticode signing pipeline and includes third-party notice files. Configure `AGENT_MODULE_PACKAGE_DIR` on the server to the same protected published directory. Copy releases atomically and retain earlier blobs for recovery; never expose that directory as public static storage. Development unsigned artifacts must not be published as production releases.

## Verification and storage

The server issues five-minute Ed25519 grants bound to one tenant and endpoint, a fixed Helpdesk capability set and an exact HTTPS package URL. Manifest and package requests also require the endpoint's existing device-certificate signing key, fresh timestamps and single-use nonces. Package download rechecks current organization and subscription permission.

Core uses its pinned TLS transport, rejects redirects, bounds size and duration, verifies the signed SHA-256, and requires Authenticode when its update-signing policy is enabled. It stages under the protected agent data directory, rejects reparse points in path ancestors, and installs into a fixed directory under Program Files with SYSTEM write and Users read/execute permissions. It never loads downloaded DLLs into the service.

The highest installed sequence and hash are persisted with an atomic, flushed Windows replacement. The same sequence cannot substitute a different hash, and lower sequences are rejected. Every launch checks fresh server permission and the installed file hash. An offline server or expired grant does not permit a new launch. Corrupt state fails closed; do not delete its sequence record to work around an error.

Software signatures and ACLs do not make an endpoint tamper-proof against a local administrator or SYSTEM compromise. Keep the existing identity, transport, signing and update protections, and perform native pilot and recovery tests before promotion.
