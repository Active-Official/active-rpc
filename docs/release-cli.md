# `active-rpc-cli` crates.io release checklist

The CLI is a binary crate that depends on the published `active-rpc` library.
Release it only after the library version it pins is live.

## Preconditions

1. `Cargo.toml` `version` is higher than the reserved crate on crates.io
   (`cargo info active-rpc-cli`).
2. `active-rpc = { version = "X.Y.Z" }` names a published library version, and
   the `quic` and `http2` features exist in that release.
3. `Cargo.lock` is committed (CI runs `cargo test --locked`).
4. `README.md`, description, keywords, categories and both license files are in
   the package.

## Gates

```text
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo publish --dry-run
```

The CLI test suite spawns the binary and drives a real kernel peer over tcp,
connect and http2, including the refusal paths. The repository `cli` CI job
runs the same gates on every push.

## Release

1. Tag the library release that the CLI pins.
2. `cargo publish` from `cli/active-rpc-cli`.
3. Verify: `cargo info active-rpc-cli` shows the new version and description,
   and `cargo install active-rpc-cli --locked` builds.
4. Smoke test the installed binary:

   ```text
   active-rpc-cli doctor
   active-rpc-cli peer --limit 1        # prints transport, addr and cap
   ```

5. Record the version and publish date in the release notes.

## Rollback

A published version cannot be replaced. `cargo yank --version X.Y.Z` stops new
resolutions while existing lockfiles keep working; publish a fixed version and
yank the bad one.

## Manual and install docs

- `docs/man/active-rpc-cli.1` (also linked from the top-level README).
- `cli/active-rpc-cli/README.md` carries the full command reference and
  examples; `--help` prints the same set.
