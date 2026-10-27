# Security policy

## Supported versions

Security fixes go into the latest release. Older releases do not get backports; upgrade notes for every version are in [docs/operations.md](docs/operations.md#upgrades-and-rollbacks).

## Reporting a vulnerability

Report vulnerabilities privately at https://github.com/privacyfence/peek/security/advisories/new. Please do not open a public issue or pull request for a security problem.

Include the affected version (from `peekd --version`), the deployment shape (storage, sign-in providers, page backends on or off), reproduction steps and the impact you expect.

## What to expect

This is a best-effort process: an acknowledgement within 7 days, a fix or mitigation plan agreed in the advisory, and credit in the advisory unless you prefer otherwise.

## How fixes are announced

Fixes are announced in a GitHub Security Advisory and in the release notes and `CHANGELOG.md` of the release that contains the fix.

## Past audits

The latest internal audit is [docs/audits/2026-10-security-and-coverage-audit.md](docs/audits/2026-10-security-and-coverage-audit.md).
