# Public release checklist

Complete this checklist before making the repository public or publishing binaries.

## Ownership and licensing

- [ ] Confirm copyright ownership or written permission for every contributed component.
- [ ] Review compatibility of Python, Go, JavaScript, font, container, Windows, and networking dependencies.
- [ ] Confirm that CIS, STIG, Microsoft policy metadata, and other benchmark content may be redistributed.
- [ ] Confirm the AGPL/Apache/CC BY licensing boundary with counsel.
- [ ] Replace provisional security and conduct contact channels with monitored addresses.

## Secrets and private information

- [ ] Scan the complete candidate tree with Gitleaks and another independent scanner.
- [ ] Confirm there is no inherited production Git history.
- [ ] Rotate production database, application, signing, CA, encryption, Cloudflare, enrollment, and build-service credentials.
- [ ] Search for customer names, email addresses, endpoint identifiers, public IPs, internal hostnames, and production domains.
- [ ] Confirm that `.env`, certificates, binaries, dumps, uploads, and recovery evidence are ignored.

## Build and security

- [ ] Run server and agent tests on clean Windows and Linux runners.
- [ ] Validate Docker Compose from example configuration.
- [ ] Run SAST, dependency auditing, container scanning, and protocol fuzzing.
- [ ] Produce SPDX or CycloneDX SBOMs.
- [ ] Build artifacts only in the release pipeline.
- [ ] Sign tags, checksums, Windows binaries, installers, and release attestations.
- [ ] Test installation, upgrade, rollback, uninstallation, disaster recovery, and key rotation.

## GitHub configuration

- [ ] Enable branch protection and required review.
- [ ] Enable secret scanning and push protection.
- [ ] Enable private vulnerability reporting.
- [ ] Enable Dependabot and code scanning.
- [ ] Restrict Actions token permissions and approve third-party actions.
- [ ] Publish the supported-version and release policy.

Passing the automated tests is necessary but does not by itself approve a release.
