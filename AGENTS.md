# Community edition rules

- Warden Community must never include or serve a marketing landing page.
- Anonymous requests to `/` open the local login flow; authenticated requests open the application dashboard.
- Do not copy hosted marketing/trial routes, landing templates, preview showcases or landing-only assets into this repository when synchronizing features or styling from the main repository.
- Keep Community single-organization and use the deployment's configured server URL for agent/Home communication and updates. Do not replace it with the hosted service URL.
- Shared application features and application styling belong here; hosted subscriptions, trial quotas and platform administration do not.
- Preserve these boundaries with `server/tests/test_community_entry.py` and `server/tests/test_frontend_contracts.py` when changing routes, templates or shared UI.
- Never treat a local test pass as proof of a successful live rollout. Keep source implementation, published artifacts and deployed versions distinct in status reports.

# Local development infrastructure

- For this workspace's server/laptop setup, read the private inventory `../Documents/warden-development/INFRASTRUCTURE.md` before infrastructure work, if present.
- Keep private infrastructure credentials, keys, environment files and deployment backups out of Git.
- Enroll Community tests against their own configured Community server, not the hosted development server. Never reuse production enrollment or update credentials.
- Recheck current connectivity, Git state and deployed versions before relying on recorded setup status.
- The designated development laptop is only for Windows agent development/testing. Keep this repository and all other application/server/Home development on the controller; do not transfer full repositories there.
