# Status — Active RPC

Honest state of the Active Maturity Program for this repository. A claim here
has a test or a CI job behind it; residual risks are listed, not hidden.

## Release

| Item | Value |
|------|-------|
| Library | `active-rpc` 2.2.0 |
| CLI | `active-rpc-cli` 0.3.1 |
| ARP1 envelope | unchanged through the maturity program |
| CI | every job green on both `Active-Official` and `RatioArtificiosa` at the release commit |
| Tag | signed `v2.2.0`, identical object on both orgs |
| GitHub Release | [Active-Official](https://github.com/Active-Official/active-rpc/releases/tag/v2.2.0) and [RatioArtificiosa](https://github.com/RatioArtificiosa/active-rpc/releases/tag/v2.2.0), marked Latest, with `active-rpc-2.2.0.cdx.json` |
| Authenticity | `ReceiptLog` (`ARRL`) for durable receipts; `CapabilityRecord` for durable capabilities; WASM ABI v2 host policy |

## Absolute Max program (AMAX-PROP-2026-10-31)

| Phase | State | Evidence |
|---|---|---|
| M-0 baseline | complete | baseline SHAs and residual import in the program register |
| M-1 capability maximum | complete | `tests/dispatch_authority_matrix.rs`, full-attribute attenuation properties, QUIC binding, H2.47, `docs/spec/security.md` §8 |
| M-3 RPC residuals | complete | M-3.1 receipts (`ARRL`), M-3.2 durable profile, M-3.3 WASM ABI v2, M-3.4 clock ADR, M-3.5 deployment identity, M-3.6 bridge doc gate |
| M-4 speed and transport | in progress | M-4.1 hot path: no per-call module clone, cached canonical hash, `benches/domain.rs`, numbers in `docs/spec/performance.md` |
| M-5..M-8 | pending | supply chain, Copilot marathon, innovations, release |

## Phase status

| Phase | State | Evidence |
|-------|-------|----------|
| C-0 baseline / C-1 invariants / C-2 strategy | complete | inventories, ADRs and gates in the repository |
| C-5 kernel: deltas, cancellation, backpressure, idempotency, persistence | complete | ADR-0009/0010, test suites |
| C-6 transports: identity, HTTP/2, bulk, observability | complete | ADR-0011..0014 |
| C-7 speed and bakeoffs | complete | `docs/spec/performance.md`, `perf-gate` |
| C-8 polyglot thin clients | complete | `active-infinity/polyglot/rpc`, encoder conformance |
| C-9 CLI | complete | `active-rpc-cli` 0.3.1 on crates.io, man page, 16 CLI tests |
| C-10 hardening | complete | nightly fuzz (twelve targets), multi-tenant stress, malicious MCP, transport × cap matrix, review rounds 17-21 |
| C-11 innovations | complete | TTL caps (0015), receipts (0016), intro modules (0017), replay (0018), WASM tools (0019), topics (0020) |
| C-12 interop | complete | `docs/spec/interop.md` + bridge tests |
| C-13 release | complete | this file, `docs/release-runbook.md`, dual-remote push, crates.io |

## Verification

- `cargo fmt --all --check`, `cargo clippy --locked --all-targets --all-features`
  and `--no-default-features` with `-D warnings`.
- `cargo test --locked --all-features` and `--no-default-features`.
- `cli/active-rpc-cli`: `cargo test --locked` (15 end-to-end tests) and clippy.
- `control-plane`: 25 tests plus the two-launch smoke check.
- Fuzz: twelve targets on every push, ten minutes per target nightly. The
  committed corpus is curated; grown inputs travel as CI artifacts.
- Security: `cargo audit` and `cargo deny check` are clean; the SBOM job runs
  on every push.

## Residual risks

1. **Replay packages are integrity checks, not signatures.** The checksum
   detects corruption and naive edits; authenticity needs a signature.
2. **WASM ABI v2 grants only a clock, CSPRNG bytes and a bounded log.**
   Filesystem and network imports need a capability-scoped allow-list and their
   own ADR.
3. **QUIC production identity is documented, not enforced by the kernel.**
   `start_with_identity` takes a deployment CA and chain; issuing and rotating
   certificates stays the deployment's job (`docs/deployment/identity.md`).
4. **TTL is virtual by default.** `use_wall_clock(true)` follows real time and
   never moves backwards, but a lease must be minted after the mode is chosen
   (ADR-0022).
5. **The Connect/gRPC bridge presents no peer identity**, so bound capabilities
   are refused through it; bridge-level authentication is the gateway's job.
6. **Receipts are durable only when exported.** `ReceiptLog` is append-only and
   chain-verified, but the kernel writes nothing to disk by itself and rotation
   is manual (ADR-0021).
7. **Facade crates** (`active-rpc-*` 0.1.x) pin the kernel with a caret range and
   are released separately.
8. **Benchmarks are single-host**; the tables record the methodology.
