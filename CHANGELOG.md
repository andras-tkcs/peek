# Changelog

All notable user-visible changes to Peek are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and Peek uses [Semantic Versioning](https://semver.org/). Earlier releases are described in their [GitHub release notes](https://github.com/privacyfence/peek/releases); upgrade-relevant changes per version are in [docs/operations.md](docs/operations.md#upgrades-and-rollbacks).

## [Unreleased]

### Added

- Build provenance attestations for release archives and container images; check an archive with `gh attestation verify <archive> -R privacyfence/peek`.
- `SECURITY.md` with the security policy and private vulnerability reporting.
- Documentation for `peek.params` / `peek.setParams`, which keep a page's filters in the viewer's address bar.
- `peek <command> --help` and `peekd --help`, which list the subcommands and the `PEEK_*` environment variables.

### Changed

- Peek moved to the privacyfence GitHub organization. The Go module path is now `github.com/privacyfence/peek` (`go install github.com/privacyfence/peek/cmd/peekd@latest` works from the first release after the move), the container image is `ghcr.io/privacyfence/peek`, and the docs are at https://privacyfence.github.io/peek/. `ghcr.io/andras-tkcs/peek` gets no new images; switch image references to the new name. Old GitHub URLs redirect.
- A new logo and UI theme: the logo's navy, teal-blue and mint palette on PrivacyFence's design rules (colours only as tokens, WCAG AA contrast, 44 px controls, larger radii), with a dark theme that follows the system setting.
- The README, LICENSE and docs footer say that Peek was originally created by Shy Alter (puemos) and is improved and maintained in this repository by Andras Takacs.
- `peekd` refuses to start when `secret.key` is shorter than 32 bytes instead of replacing it, and writes new keys atomically.
- The startup log field `metrics_auth` is now `metrics_token_set`.
- A release tag must point at a commit on `main` and pass vet, race tests and govulncheck before anything is published, and pre-release tags no longer move the `:latest` image.
- The `:main` image is published only after CI passes on `main`.
- Popups opened by uploaded pages are no longer sandboxed (`allow-popups-to-escape-sandbox`).

### Fixed

- The contact-form example and the README backend commands.
- Slug examples in the README and the agent skills.
- The `--metrics-token` help text.
