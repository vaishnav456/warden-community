# Third-party notices

Warden includes and depends on third-party software. Copyright and license terms for those works remain with their respective owners.

The initial asset inventory is in `docs/THIRD_PARTY_ASSETS.md`. Before the first public binary release, maintainers must generate and review complete dependency inventories for:

- Python packages in `server/` and `build-service/`
- Go modules in all agent and Home Node modules
- Vendored JavaScript and fonts in `server/static/`
- Container base images and operating-system packages
- Windows SDK, credential-provider, remote-access, packet-capture, and networking dependencies

Release artifacts must include the applicable notices and an SPDX or CycloneDX SBOM. This placeholder is not a substitute for that release review.
