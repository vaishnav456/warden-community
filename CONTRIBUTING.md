# Contributing to Warden

Thank you for helping improve Warden.

## Before starting

For a substantial feature, protocol change, database migration, security-boundary change, or new dependency, open a design issue before implementation. Security reports belong in the private channel described in `SECURITY.md`.

## Development rules

1. Keep tenant isolation explicit in every query and authorization decision.
2. Never weaken TLS verification, command signatures, update hashes, certificate validation, or audit logging to make development easier.
3. Never commit credentials, keys, tokens, customer data, generated installers, database dumps, or recovery material.
4. Add tests for new behavior and failure paths.
5. Document new environment variables and migration requirements.
6. Keep Windows, Linux, and macOS behavior explicit rather than silently treating one platform as another.
7. Avoid telemetry unless it is documented, minimized, tenant-visible, and configurable.

## Pull requests

- Keep a pull request focused on one logical change.
- Explain the user-visible behavior and security impact.
- Include tests and documentation.
- Identify migrations, rollback behavior, and agent/server compatibility.
- Confirm that formatted code, tests, secret scanning, and dependency checks pass.

By contributing, you agree that your contribution is licensed under the license governing the component you modify. Contributions must include a Developer Certificate of Origin sign-off:

```text
Signed-off-by: Your Name <you@example.com>
```

Use `git commit -s` to add it. The sign-off certifies the [Developer Certificate of Origin](https://developercertificate.org/).
