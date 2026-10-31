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

| Date | Kernel | CLI | Remotes |
|------|--------|-----|---------|
| 2026-10-31 | 2.2.0 | 0.3.0 | Active-Official + RatioArtificiosa, same SHA |
