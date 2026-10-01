# Community edition rules

- Warden Community must never include or serve a marketing landing page.
- Anonymous requests to `/` open the local login flow; authenticated requests open the application dashboard.
- Do not copy hosted marketing/trial routes, landing templates, preview showcases or landing-only assets into this repository when synchronizing features or styling from the main repository.
- Keep Community single-organization and use the deployment's configured server URL for agent/Home communication and updates. Do not replace it with the hosted service URL.
- Shared application features and application styling belong here; hosted subscriptions, trial quotas and platform administration do not.
- Preserve these boundaries with `server/tests/test_community_entry.py` and `server/tests/test_frontend_contracts.py` when changing routes, templates or shared UI.
- Never treat a local test pass as proof of a successful live rollout. Keep source implementation, published artifacts and deployed versions distinct in status reports.
