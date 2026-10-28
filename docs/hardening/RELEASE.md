# Release runbook

Mechanical checklist for a release. It implements H6.1, H6.3, H6.5, H6.6 and
the per-release review requirement in H9.4.

## 0. Preconditions

- `main` is clean and CI is green on the exact commit.
- `docs/hardening/STATUS.md` is regenerated and every row is `done` or an ADR
  accepts the gap.
- The hardening checklist was reviewed for new attack classes (H9.4).
- A review round against the release candidate reports no new findings.

## 1. Version and lockfile

1. Bump `version` in `Cargo.toml` and add a `CHANGELOG.md` entry.
2. Run `cargo check` so `Cargo.lock` records the new version.
3. Confirm the MSRV job still passes on the declared toolchain.
4. `cargo package --locked` must build the tarball on its own.

## 2. Gates

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked --all-features
cargo test --locked --no-default-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
cargo audit
cargo deny check
python scripts/hardening_status.py --check
python scripts/negative_controls.py --check
```

Fuzz every target for the release budget (20k runs per target in Docker or on
Linux). A crash blocks the release.

## 3. SBOM

Generate a CycloneDX SBOM from the committed lockfile:

```bash
python scripts/sbom.py --output dist/<crate>-<version>.cdx.json
python -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['bomFormat']=='CycloneDX'" dist/<crate>-<version>.cdx.json
```

Attach the SBOM to the GitHub release. Do not commit it (`*.cdx.json` is
ignored).

## 4. Signed tag

```bash
git tag -s v<version> -m "<crate> <version>"
git -c gpg.ssh.allowedSignersFile=release-signing.allowed_signers tag -v v<version>
```

The tag must be an annotated, SSH-signed object. The allowed-signers file is
committed; `scripts/verify_tag.sh v<version>` performs the same check.

## 5. Dual publish

Both organisations receive the same commit and the same tag object.

| Step | Active-Official | RatioArtificiosa |
|---|---|---|
| push `main` | `git push official main` | `git push ratio main` |
| push tag | `git push official v<version>` | `git push ratio v<version>` |
| compare tag object | `git ls-remote official refs/tags/v<version>` | `git ls-remote ratio refs/tags/v<version>` |
| create release + SBOM | `gh release create v<version> --repo Active-Official/<crate> ...` | `gh release create v<version> --repo RatioArtificiosa/<crate> ...` |

The two `ls-remote` hashes must be identical, including the peeled `^{}` line.

## 6. crates.io

```bash
cargo publish --locked
curl -s https://crates.io/api/v1/crates/<crate>/<version> \
  -H 'User-Agent: active-release' | python -c "import json,sys;assert not json.load(sys.stdin)['version']['yanked']"
```

Reserve companion names before publishing a CLI or an adapter crate.

## 7. Consumer smoke

In a fresh directory outside the repository:

```bash
cargo new consumer && cd consumer
cargo add <crate>@<version>
# round-trip a real value and assert it, not just that it links
cargo run --locked
```

For `active-infinity`, encode a module, validate it, decode it and compare the
value. For `active-rpc`, run an in-process call and assert the response.

## 8. Yank and advisory dry run

Exercise the process without publishing a bad release:

1. Pick a reserved, unpublished patch version (for example `0.0.1`).
2. Walk through the crates.io owner page and the `cargo yank --version` command
   on paper, including who has the token and who can re-publish.
3. Record the tabletop in the release notes.
4. If a release is actually yanked, publish the advisory text from
   `SECURITY.md`, open a GitHub security advisory, and note the replacement
   version.

`cargo yank` has no dry-run flag; never run it against a live version as a test.

## 9. Post-release

- Confirm the docs.rs build for the new version.
- Confirm the CI run for the tag SHA is green.
- Update `docs/hardening/STATUS.md` with the release version and evidence.
- Open the next review window in `REVIEWS.md`.

## Reproducibility limits

`cargo package --locked` with a committed lockfile and a pinned toolchain is
reproducible for the crate sources. The following are not bit-reproducible and
are documented rather than claimed:

- absolute paths embedded in debug info (release builds strip them);
- the exact `rustc` build when the toolchain is resolved by `stable`;
- native dependencies built by `cc` (Blake3's assembly choice depends on the
  host CPU features unless `RUSTFLAGS` pins the target features);
- crates.io resolution for a consumer that does not use this lockfile.

Pin the toolchain (`rust-toolchain.toml`) and the target features when a
byte-for-byte artifact is required.
