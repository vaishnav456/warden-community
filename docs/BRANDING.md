# Branding and public URLs

Self-hosted operators can change the human-facing product name, tagline, logo,
public control-plane URL, and Windows service display label without editing
source code.

## Web console

Set these values in `server/.env`:

```dotenv
SERVER_URL=https://manage.example.com
BRAND_NAME=Example Control
BRAND_TAGLINE=Secure endpoint operations.
BRAND_LOGO_PATH=/static/example-control.svg
```

Copy the logo into `server/static/`. `BRAND_LOGO_PATH` deliberately accepts
only a same-origin `/static/...` path: loading arbitrary remote images would
weaken the Content Security Policy and disclose operator visits to a third
party. Restart the server after changing environment values.

`SERVER_URL` is the HTTPS origin embedded into new agent enrollment packages.
Existing agents retain their enrolled server URL; migrate them with a signed
configuration/update workflow rather than changing DNS underneath them.

## Windows agent

Set this in `build-service/.env` before generating installers:

```dotenv
AGENT_DISPLAY_NAME=Example Control Endpoint Agent
AGENT_MANUFACTURER=Example Organization
```

These change the human-readable Windows Services label and MSI metadata in
newly built agents. The display name is also used as the Authenticode signing
description; the verified publisher still comes from the signing certificate.
The internal service identifier (`WardenAgent`), filesystem locations,
executable names, API paths, database schema names, and cryptographic protocol
labels remain stable. Renaming those identifiers would break upgrades,
tamper-protected uninstall, firewall self-protection, or enrolled-device
compatibility and is therefore intentionally unsupported.

Code-signing publisher text comes from the subject on the operator's own
signing certificate; it cannot be safely replaced by a display-name setting.
