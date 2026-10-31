# Release attestation and the SBOM

What protects a release artifact today, what the Sigstore/cosign spike measured,
and what a deployment should verify. The runbook (`docs/release-runbook.md`) is
the procedure; this file is the evidence and the reasoning.

## What exists today

| Layer | Mechanism | Where |
|---|---|---|
| Source | SSH-signed git tags (`git tag -s`), identical object on both remotes | runbook step 2 |
| Build inputs | `Cargo.lock` committed; every CI job uses `--locked` | `.github/workflows/ci.yml` |
| Bill of materials | CycloneDX 1.5 SBOM generated from `cargo metadata --locked`, attached to the GitHub Release | `scripts/sbom.py`, `.github/workflows/release.yml` |
| Supply-chain policy | `cargo audit --deny warnings` + `cargo deny check` (licenses, bans, sources) | `supply-chain` job, `audit.toml`, `deny.toml` |
| Registry | crates.io publish by a human with a scoped token, then install-and-verify from the registry | runbook steps 3–5 |

The tag signature proves who wrote the commit; the SBOM proves what the locked
graph contained; neither proves that the bytes on a release page were built from
that commit. That gap is what a Sigstore attestation closes.

## Spike: cosign with a key (2026-10-31)

Run in Docker, `ghcr.io/sigstore/cosign/cosign:v2.4.1`, on the SBOM of a real
tagged release, so the artifact is the one the runbook attaches:

```text
docker run --rm -v "$PWD:/w" -w /w -e COSIGN_PASSWORD=... \
  ghcr.io/sigstore/cosign/cosign:v2.4.1 generate-key-pair
# Private key written to cosign.key
# Public key written to cosign.pub

docker run --rm -v "$PWD:/w" -w /w -e COSIGN_PASSWORD=... \
  ghcr.io/sigstore/cosign/cosign:v2.4.1 \
  sign-blob --key cosign.key --tlog-upload=false \
    --output-signature sbom.cdx.json.sig sbom.cdx.json
# Wrote signature to file sbom.cdx.json.sig

docker run --rm -v "$PWD:/w" -w /w \
  ghcr.io/sigstore/cosign/cosign:v2.4.1 \
  verify-blob --key cosign.pub --insecure-ignore-tlog \
    --signature sbom.cdx.json.sig sbom.cdx.json
# WARNING: Skipping tlog verification is an insecure practice ...
# Verified OK

# One byte changed in the SBOM, same signature:
# Error: invalid signature when validating ASN.1 encoded signature
```

Findings that matter for a release process:

1. **Key-based signing defaults to uploading to the public Rekor log.** Without
   `--tlog-upload=false` the command prompts for consent to publish the signer
   identity to an immutable public log and, in a non-interactive job, fails
   ("user declined the prompt"). A CI job must choose explicitly.
2. **Verification mirrors that choice.** A signature made without a transparency
   log entry verifies only with `--insecure-ignore-tlog`, and cosign says so in
   one line. That warning is the honest description: the signature proves the
   key holder signed these bytes, not *when* or *in what order*.
3. **A private key in CI is another secret to protect.** The alternative,
   keyless signing, removes it.
4. **Keyless is the better fit for GitHub Actions.** With
   `permissions: id-token: write`, cosign requests a short-lived certificate from
   Fulcio bound to the workflow identity and records the signature in Rekor, so a
   verifier needs no key at all:

   ```text
   cosign sign-blob --yes --bundle sbom.cdx.json.bundle sbom.cdx.json
   cosign verify-blob --bundle sbom.cdx.json.bundle \
     --certificate-identity-regexp '^https://github\.com/Active-Official/active-rpc/' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     sbom.cdx.json
   ```

   That requires network access to Fulcio and Rekor at release time and an OIDC
   token, neither of which this spike could exercise offline. It is recorded as
   the intended path, not as a measured one.

## Decision

- **Keep SSH-signed tags as the root of trust** for "who released this".
- **Keep the SBOM as the artifact inventory**, now attached automatically by
  `release.yml` and verified by the job itself (`gh release view --json assets`).
- **Do not ship a signing key in CI.** Key-based cosign would add a long-lived
  secret whose compromise is indistinguishable from a legitimate release, which
  is worse than the status quo.
- **Enable keyless attestation when the org has a release environment**: add
  `id-token: write` and a `cosign sign-blob --yes --bundle` step to
  `release.yml`, then upload `*.bundle` next to the SBOM. Until then,
  `docs/release-runbook.md` records the manual key-based procedure above for a
  release that needs an offline signature.

## Reproducible-build notes

The build is reproducible in the weak sense that matters for review: the exact
inputs are pinned (`Cargo.lock`, `--locked` everywhere, `rust-version` in
`Cargo.toml`, toolchain from `dtolnay/rust-toolchain@stable`). Strong
reproducibility (bit-identical binaries) is not claimed: rustc embeds paths and
the standard library build, and the crate builds no binaries at all — it is a
library, and the CLI crate is the only artifact. A verifier reconstructs the
release by checking out the tag, running `cargo build --locked --release` and
comparing behavior, not hashes.

The SBOM records the dependency graph, not the toolchain. `cargo --version` and
`rustc --version` are printed by the release job's logs, which are retained with
the run.

## Trusted publishing (crates.io)

crates.io supports trusted publishing from GitHub Actions over OIDC, so the
registry token can be removed from the process entirely:

1. On crates.io, crate → Settings → Trusted Publishing: add a GitHub Actions
   publisher for `Active-Official/active-rpc` (and separately
   `RatioArtificiosa/active-rpc`), workflow `release.yml`, environment
   `release`.
2. In `release.yml`, add a `publish` job with
   `permissions: { id-token: write, contents: read }` and
   `environment: release`, running `cargo publish` on the library and then the
   CLI.

This is a registry-side setting plus a short job; it is not enabled here because
it needs the crates.io account to register the publisher first, and the current
runbook publishes by hand with a scoped token that is never stored in the
repository.


