# Windows Administrative Template catalog

Warden Community includes its policy engine and a reviewed set of Warden-native Windows settings. It does not redistribute generated Microsoft ADMX/ADML policy data.

The checked-in `server/policy_catalog.json` and `agent-go/policy_catalog.json` files are intentionally empty arrays so the server and agent build reproducibly without third-party policy text.

Organizations that are licensed to use their installed Windows Administrative Templates can generate a catalog locally:

1. On the Windows system containing the desired `PolicyDefinitions` set, run `scripts/extract-admx-catalog.ps1`. The script reads the local ADMX/ADML files and produces `admx-catalog.json`.
2. Review the source and generated data for the organization's licensing and security requirements.
3. Run `python scripts/filter_admx_catalog.py admx-catalog.json` to create `policy_catalog_normalized.json`.
4. Review every permitted registry path, value type, scope, range, and option.
5. Copy the reviewed result to both `server/policy_catalog.json` and `agent-go/policy_catalog.json` before building.
6. Re-run the server tests and the Windows agent build. Server and agent catalogs must be identical for that release.

Generated catalogs must not be committed to the upstream Warden Community repository. A deployment operator is responsible for its right to use and distribute any generated policy definitions.
