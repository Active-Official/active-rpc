# Maturity release runbook — dual remote + crates.io

The program ships to two organizations (Active-Official and RatioArtificiosa)
and two crates (the kernel and its CLI). This runbook is executed for every
maturity release; the executed record lives in `STATUS.md`.

## Preconditions

1. Every CI job is green on both remotes at the candidate commit.
2. Versions are bumped in `Cargo.toml` (library and CLI) and the lockfiles are
   refreshed; `CHANGELOG.md` has a dated section; `REGISTRY.md` lists the
   versions.
3. `cargo publish --dry-run` succeeds for the library, and for the CLI once the
   library version is resolvable.
4. `STATUS.md` reflects the candidate state and its residual risks.

## Order

1. **Commit and push both remotes.**
   ```text
   git push official HEAD
   git push ratio HEAD
   git ls-remote official refs/heads/main
   git ls-remote ratio refs/heads/main
   ```
   Both SHAs must equal the local `HEAD`.
2. **Tag and push the tag.**
   ```text
   git tag -a vX.Y.Z -m "active-rpc X.Y.Z"
   git push official vX.Y.Z
   git push ratio vX.Y.Z
   ```
   Tag pushes run the full CI, including the audit, deny and SBOM release gates.
   A signed tag is produced when a signing key is available
   (`git tag -s`).
3. **Publish the kernel.** `cargo publish`, waiting for the registry to report
   the version available.
4. **Publish the CLI.** It pins the kernel version, so it must follow:
   `cd cli/active-rpc-cli && cargo publish`.
5. **Verify from the registry.**
   ```text
   cargo install active-rpc-cli --locked --root <temporary-root>
   <temporary-root>/bin/active-rpc-cli doctor
   <temporary-root>/bin/active-rpc-cli replay dump --output /tmp/session.arrp
   <temporary-root>/bin/active-rpc-cli replay run /tmp/session.arrp
   ```
6. **Record.** Append the version, the two remote SHAs and the date to
   `STATUS.md`.

## Rollback

- A published version cannot be replaced: `cargo yank --version X.Y.Z` stops new
  resolutions while existing lockfiles keep working, then publish a fixed patch.
- Tags are immutable; a bad tag is superseded by a new patch release, and the
  release notes point at the replacement.

## Executed record

| Date | Kernel | CLI | Commit | Tag (both remotes) | crates.io |
|------|--------|-----|--------|--------------------|-----------|
| 2026-10-31 | 2.2.0 | 0.3.0 | `9f1348c` (`v2.2.0^{}`) | `c27ee6b` on Active-Official and RatioArtificiosa, identical peeled SHA | `active-rpc` 2.2.0, `active-rpc-cli` 0.3.0 |
| 2026-10-31 | 2.1.0 | 0.2.0 | `69f2d92` (`v2.1.0^{}`) | backfilled tag for the published 2.1.0 | `active-rpc` 2.1.0 |

Release commit `9f1348c` resolves `active-infinity` 2.3.0 from crates.io in the
lock; CI 41203912741 (Active-Official) and 41203915377 (RatioArtificiosa), both
green. Tag object `c27ee6b8eec2ef0be807a80299464cf7fba01d44` on both remotes,
peeled to `9f1348cc7b270ad7165b43545dfeaf69d19ff9bc`.

Install verification: `cargo install active-rpc-cli --version 0.3.0 --locked`
then `doctor` and a real `peer`/`call` round trip from the registry build.

### Release objects

| Tag | Active-Official | RatioArtificiosa | Assets |
|-----|-----------------|------------------|--------|
| `v2.2.0` | https://github.com/Active-Official/active-rpc/releases/tag/v2.2.0 | https://github.com/RatioArtificiosa/active-rpc/releases/tag/v2.2.0 | `active-rpc-2.2.0.cdx.json` (197 components) |

Both are marked **Latest** (`gh api repos/<owner>/active-rpc/releases/latest`
returns `v2.2.0`). The notes summarise the release, the hardening and the
verification; the tag is verified with `--verify-tag` at creation.

A CLI-only patch release is recorded here with its commit and does not move the
library tag: the tag names the library version, and the CLI has its own.

| 2026-10-31 | 2.2.0 | 0.3.1 | `3aba8e3` | CLI-only patch; the library tag stays `v2.2.0` | `active-rpc-cli` 0.3.1 |

Registry verification: `cargo install active-rpc-cli --version 0.3.1 --locked`
replaced 0.3.0 and `active-rpc-cli -V` prints `active-rpc-cli 0.3.1 (active-rpc
2.2.0)`. A consumer crate with `active-rpc = "2.2.0"` mints a capability and
gets an in-process echo response. `active-rpc 2.2.0` on crates.io is yanked
`false`; the SBOM for the release lists 197 components.
