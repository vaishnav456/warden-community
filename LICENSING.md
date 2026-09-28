# Licensing

Warden Community uses explicit component-level licensing.

## Control plane

Unless a file or directory states otherwise, the repository is licensed under the GNU Affero General Public License version 3 only (`AGPL-3.0-only`). This includes the server, web interface, build service, database schema, migrations, deployment configuration, and control-plane tools.

## Endpoint components

The following directories are licensed under the Apache License 2.0 (`Apache-2.0`) and contain their own `LICENSE` files:

- `agent-go/`
- `agent-posix/`
- `home-node/`
- `windows-credential-provider/`

Files copied from one licensing boundary to another remain governed by their original license. New files should include an SPDX identifier where practical.

## Documentation and assets

Original documentation is licensed under Creative Commons Attribution 4.0 International (`CC-BY-4.0`) unless a file says otherwise. Third-party fonts, JavaScript libraries, icons, specifications, and other assets retain their original licenses; see `docs/THIRD_PARTY_ASSETS.md` and `THIRD_PARTY_NOTICES.md`.

The Warden name, logo, and product marks are not licensed as software. See `TRADEMARKS.md`.

This file describes the intended licensing boundary and is not legal advice. Review third-party compatibility before public distribution.
