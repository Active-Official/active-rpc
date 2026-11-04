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
| M-4 speed and transport | complete | M-4.1 hot path (no per-call clone, cached canonical hash), M-4.2 ADR-0023 (no io_uring; 8→4 syscalls/call), M-4.3 H2/QUIC budgets, M-4.4 cap-delta load, M-4.5 measured performance.md |
| M-5 supply chain | complete | `release.yml` attaches and asserts the CycloneDX SBOM, `audit.toml` + `cargo audit --deny warnings`, `cargo deny check` clean, `docs/release-attestation.md` records the cosign spike and trusted-publishing path |
| M-6..M-8 | pending | Copilot marathon, innovations, release |

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
9. **Windows process trees are killed leader-first.** The cleanup path no longer
   spawns `taskkill` (whose path came from the mutable `SystemRoot`), so a
   descendant that outlives its leader survives the kill. A job object is the
   complete fix and needs `unsafe` FFI, which the crate forbids; the Unix path
   still kills the whole process group.
10. **Dropping the last handle of an exported durable capability does not
    tombstone its record.** The sealed record stays restorable by design (an
    operator may export for later restore) and the record now pins its object,
    so the provider keeps the module until the record is restored;
    `Event::CapRecordOrphaned` reports the window, and a deployment that treats
    drop as revocation must tombstone.
11. **A durable record names a provider-local object id.** Restoring after a
    provider rebuild can bind the record to a different logical object. The fix
    needs a record-format version plus a provider epoch/stable-key callback
    (audit ARPC-009); the seal and peer binding are enforced, semantic object
    identity is not.
12. **HTTP and process adapter limits are public and mutable after
    construction.** `HttpTool::{max_body,max_request}` and
    `LocalProcess::{allow_args,env,max_output,timeout}` can be widened by code
    inside the host process. A peer has no path to them, so this is an operator
    footgun rather than an escalation; moving them behind setters is a breaking
    change scheduled with the next minor release.
13. **A shell as the process `program` with a `*` rule is a command-line
    grant.** `LocalProcess` refuses shell syntax in a prefix-matched argument,
    but a metacharacter-free payload with a space still runs an arbitrary simple
    command (`sh -c curl …`), which is what a prefix grant on a shell means.
    Operators must not configure `sh`/`cmd` with prefix rules; `wire.md` and
    `security.md` say prefix rules are unconfined, and the metacharacter refusal
    is defense in depth only.
14. **An idempotency key does not cover a cancelled in-flight call or an evicted
    key.** A settled `provider/reply-withheld` reply is reused by its key, so a
    retry does not write twice. Cancelling an in-flight mutating call leaves a
    cancelled promise, which is deliberately retryable, and eviction at
    `MAX_IDEMPOTENCY` starts a fresh call: at-most-once holds for a settled
    withheld reply, not across a cancel or an eviction (round 34, L-6).

