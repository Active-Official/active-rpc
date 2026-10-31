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
2. **WASM guest tools have no host imports in ABI v1.** A host-call ABI requires
   a capability policy and a new ADR.
3. **QUIC demos use a self-signed certificate**; mutual TLS and identity binding
   are covered by tests, but a deployment supplies its own CA.
4. **TTL uses the kernel's virtual clock.** A wall-clock policy needs an ADR.
5. **The Connect/gRPC bridge presents no peer identity**, so bound capabilities
   are refused through it; bridge-level authentication is the gateway's job.
6. **Receipts are in-memory and per kernel.** Durable receipts belong with the
   persistence work.
7. **Facade crates** (`active-rpc-*` 0.1.x) pin the kernel with a caret range and
   are released separately.
8. **Benchmarks are single-host**; the tables record the methodology.
