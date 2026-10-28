# Hardening status — active-rpc

Program: `ACTIVE-HARDENING-GUIDE-AND-CHECKLIST.md` v1.0.0, phases H0–H9 plus
Addendum A (research) and Addendum B (fix-and-test loop).

This file is the public status surface required by H0.6 and H9.3. The matrix at
the bottom is generated from `docs/hardening/invariant-map.toml` by
`scripts/hardening_status.py`; editing the matrix by hand is a check failure.

## Baseline

| Field | Value |
|---|---|
| Crate | `active-rpc` 1.1.9 |
| Baseline commit | `69acea89bd03a9a69ff88cdd6dd8d12560a2d210` |
| Baseline tag | `hardening-baseline` (annotated, SSH-signed) |
| Released tag | `v1.1.9` |
| MSRV | 1.88 (ADR-0007) |
| Wire format | ARP1 v1 |

## H0 findings

### H0.1 Test inventory

76 test functions across 6 integration-test binaries plus one doctest:

| Suite | Tests | What it proves |
|---|---|---|
| `tests/unit_tests.rs` | 22 | capability ids, attenuation, lane budgets, path scope, drop notification, revocation, promises, channels, wire round-trip, tool policy, events |
| `tests/integration_tests.rs` | 15 | domain operations, in-process/shm/Connect/QUIC/TCP transports, cross-process peer, redaction, budgeted evaluation |
| `tests/concurrency_tests.rs` | 5 | lane interleaving, budget isolation, channel isolation, concurrent tools, two agents over TCP |
| `tests/conformance_tests.rs` | 8 | golden envelope, re-encode stability, capability table shape, truncated prefixes, header attacks, error catalog, wire limits |
| `tests/redteam_tests.rs` | 23 | forgery/transplant, confused deputy, escalation, secret leakage, budget bypass, promise abuse, malformed frames, revocation edges, plus thirteen review regressions |
| `tests/property_tests.rs` | 3 | envelope round-trip, arbitrary bytes never panic, attenuation monotonicity |

There is **no** `doc_gate.rs` in this crate; the Infinity crate has one. CI does
run `cargo doc` with `-D warnings`, so rustdoc defects are gated, but spec/code
agreement is not.

The machine-readable mapping is `docs/hardening/invariant-map.toml`.

### H0.2 Fuzz, corpus and coverage

- One fuzz target (`framing`, 52 lines) covers envelope decode, capability table
  decode and the gRPC framing helper.
- No committed corpus. CI writes one 28-byte ping envelope at run time.
- Conformance cases are inline Rust, not files.
- Coverage (all features, Windows x86_64): 67.53% regions, 68.52% lines,
  58.62% functions. Full table in `docs/hardening/CORPUS.md`.
- Weakest surfaces: `tool.rs` 17.61% regions / 16.02% lines (MCP, HTTP, process
  adapters), `security.rs` 48.89%, `value.rs` 60.00%, `src/bin/peer.rs` 0%.

### H0.3 Documentation inventory

- 7 ADRs plus index: purpose, deterministic kernel, transports, capability ids,
  promises, versioning, MSRV.
- Specs: `wire.md`, `security.md`, `performance.md`.
- `SECURITY.md`, `REVIEWS.md` (rounds 1–N, final round NO NEW FINDINGS),
  `CHANGELOG.md`, `CHECKLIST.md`, `PROPOSAL.md`.

### H0.4 Supply chain and release

- Dual license MIT OR Apache-2.0, both license files present.
- MSRV 1.88 verified by the CI `msrv` job on both feature sets.
- `cargo audit`: pass; one allowed unmaintained warning (`unsafe-libyaml`,
  RUSTSEC-2024-0449, via `active-core` → `serde_yaml`; ADR-0007 and the
  Infinity ADR-0008 record the acceptance).
- `cargo deny check`: advisories, bans, licenses, sources all ok.
- Tags are SSH-signed and the public key is committed in
  `release-signing.allowed_signers`; `v1.1.9` verifies.
- crates.io 1.1.9 is published and not yanked.
- Tags are identical on `Active-Official` and `RatioArtificiosa`.

**Finding fixed during H0:** the committed lockfile resolved `active-infinity`
2.0.1, which predates the 2.0.5–2.0.7 secret-surface hardening. The requirement
`active-infinity = "2.0.1"` is semver-compatible with 2.0.7, so the lockfile was
updated to 2.0.7 and the full suite re-run. The manifest minimum still says
`2.0.1`; raising it is a release decision for the next version (tracked in the
residual risks and H6).

### H0.5 Baseline tag

`hardening-baseline` is an annotated, SSH-signed tag at the baseline commit.

### H0.6 This file

The matrix below is validated by `scripts/hardening_status.py --check`.

## Gate results (baseline)

| Gate | Result | Evidence |
|---|---|---|
| `cargo fmt --all -- --check` | pass | local run 2026-10-27 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | pass | local run 2026-10-27 |
| `cargo clippy --locked --all-targets --no-default-features -- -D warnings` | pass | local run 2026-10-27 |
| `cargo test --locked --all-features` | pass (76 tests + doctest) | local run + CI |
| `cargo test --locked --no-default-features` | pass (75 tests + doctest) | local run + CI |
| `cargo doc` with `RUSTDOCFLAGS=-D warnings` | pass | local run 2026-10-27 |
| `cargo package --locked` | pass | local run 2026-10-27 |
| `cargo audit` | pass (1 allowed warning) | local run 2026-10-27 |
| `cargo deny check` | pass | local run 2026-10-27 |
| Fuzz smoke (20k runs) | pass | CI run 40559854293 |
| GitHub Actions on `69acea8` | success | run 40559854293 |

## Ordered next steps

1. **H1** Split `framing` into the nine required RPC targets, commit a seed
   corpus in `tests/vectors/`, and add the research-derived targets (capability
   lifecycle, promise graph, budget matrix, tool policy, transport framing).
2. **H2** Build the table-driven red-team battery, including the
   cross-kernel transplant, path canonicalization, event-redaction and tool
   timeout cases, and script the negative controls.
3. **H6** Raise the `active-infinity` minimum to the security release, add the
   reproducible-build note, and exercise the yank dry run.
4. **H7** Prove events and metrics redact payloads and hash capability ids.
5. **H9** Wire the new suites into CI and add the clean-clone gate.

## Residual risks (baseline)

- **Tool adapters are the least covered code** (16% lines) and have no fuzz
  target. They are the most likely place for a confused-deputy or injection
  escape.
- **Manifest minimum `active-infinity = "2.0.1"`.** A consumer with an old
  lockfile can resolve 2.0.1, which predates the secret-surface fixes. The next
  release should raise the minimum to 2.0.7.
- **No documentation gate test.** `cargo doc` proves the rustdoc builds; it does
  not prove the wire spec and the error catalog agree with the code.
- **No committed fuzz corpus.** A crash seed cannot be reviewed or replayed.
- **QUIC evidence is loopback only** with a self-signed certificate; hostile
  peer behavior beyond malformed frames is not tested.
- **`unsafe-libyaml` advisory.** Accepted, unreachable from the parsing path.
- **Windows-native test host.** CI runs Linux; QUIC and shared memory can differ
  by platform, so both are exercised in CI and locally.
- **Event payload content.** `events_record_the_dispatch_batches` proves events
  exist, not that they are free of secret material.

## Maturity sign-off

Not signed. H0 is complete; H1–H9 remain.

<!-- BEGIN GENERATED: hardening matrix (scripts/hardening_status.py) -->

**Repository:** `active-rpc` **version:** `1.1.9` **baseline commit:** `69acea89bd03a9a69ff88cdd6dd8d12560a2d210` **baseline tag:** `hardening-baseline` **measured:** 2026-10-27

Invariants: 12 covered, 0 partial, 0 gap, 1 not applicable. Checklist items: 22 done, 55 partial, 62 gap, 20 not applicable. Criticals with an implemented negative control: 0/7. Distinct automated checks resolved: 73.

| Invariant | Meaning | Status | Checks | Negative control |
|---|---|---|---|---|
| **I-1** | Structural secret taint | `covered` | 3 | - |
| **I-2** | Anti-oracle equality | `n/a` | 0 | - |
| **I-3** | Secret non-leakage | `covered` | 5 | documented |
| **I-4** | Capability unforgeability | `covered` | 4 | documented |
| **I-5** | Attenuation only narrows | `covered` | 7 | documented |
| **I-6** | Revocation at dispatch | `covered` | 5 | documented |
| **I-7** | Drop notification | `covered` | 2 | - |
| **I-8** | Hard budgets | `covered` | 9 | documented |
| **I-9** | Deterministic canonicalization | `covered` | 4 | - |
| **I-10** | Fail-closed validation | `covered` | 8 | documented |
| **I-11** | No ambient authority | `covered` | 4 | - |
| **I-12** | Domain operations under capability and budget | `covered` | 7 | - |
| **C-1** | Derived control: promise single settlement | `covered` | 3 | documented |

| Item | Checklist item | Status | Evidence |
|---|---|---|---|
| **H0.1** | Inventory all existing tests as an invariant-to-test matrix | `done` | `script:scripts/hardening_status.py` |
| **H0.2** | Inventory fuzz targets, corpus sizes and coverage snapshots | `done` | `doc:docs/hardening/CORPUS.md`, `fuzz:framing` |
| **H0.3** | Inventory ADRs, SECURITY, REVIEWS, security and performance specs | `done` | `doc:docs/hardening/STATUS.md` |
| **H0.4** | Confirm license, MSRV, advisories, signing and publish status | `done` | `gate:audit`, `gate:deny` |
| **H0.5** | Tag a hardening baseline | `done` | `gate:baseline-tag` |
| **H0.6** | Create docs/hardening/STATUS.md | `done` | `script:scripts/hardening_status.py` |
| **H1.1** | fuzz_decode_infinity | `n/a` | - |
| **H1.2** | fuzz_stream_reassembly | `n/a` | - |
| **H1.3** | fuzz_canonical_roundtrip | `n/a` | - |
| **H1.4** | fuzz_layout_sections | `n/a` | - |
| **H1.5** | fuzz_graph_cycles | `n/a` | - |
| **H1.6** | fuzz_secret_positions | `n/a` | - |
| **H1.7** | fuzz_unit_discriminants | `n/a` | - |
| **H1.8** | fuzz_projection_agreement | `n/a` | - |
| **H1.9** | fuzz_arp1_frame: envelope and capability table malformations | `partial` | `fuzz:framing` |
| **H1.10** | fuzz_capability_lifecycle | `gap` | - |
| **H1.11** | fuzz_promise_graph | `gap` | - |
| **H1.12** | fuzz_budget_matrix | `gap` | - |
| **H1.13** | fuzz_tool_mcp | `gap` | - |
| **H1.14** | fuzz_tool_http | `gap` | - |
| **H1.15** | fuzz_tool_process | `gap` | - |
| **H1.16** | fuzz_channel_cap_transfer | `gap` | - |
| **H1.17** | fuzz_transport_framing | `gap` | - |
| **H1.18** | Seed corpus = vectors, examples, almost-valid frames; document classes | `gap` | - |
| **H1.19** | Every fixed bug adds a minimized seed | `gap` | - |
| **H1.20** | CI fuzz budget on PRs, longer on main/nightly, fail on regression | `partial` | `fuzz:framing` |
| **H1.21** | Optional public sanitized corpus | `gap` | - |
| **H1.22** | 32-bit target build and test lane | `gap` | - |
| **H1.23** | Differential canonicalization oracle | `n/a` | - |
| **H1.24** | fuzz_tool_policy: adversarial policy descriptors and tool calls | `gap` | - |
| **H2.1** | Integer overflow and underflow in length and offset arithmetic | `partial` | `test:tests/conformance_tests.rs::header_field_attacks_are_rejected`, `test:tests/conformance_tests.rs::truncated_prefixes_are_always_rejected` |
| **H2.2** | Overlapping and out-of-bounds sections | `n/a` | - |
| **H2.3** | Deep nesting aimed at stack overflow | `partial` | `test:tests/redteam_tests.rs::review_wire_rejects_deep_value_nesting` |
| **H2.4** | Billion-laughs expansion via references | `n/a` | - |
| **H2.5** | Huge sparse claims with tiny actual buffers | `partial` | `test:tests/redteam_tests.rs::review_capability_table_count_is_capped_before_allocating`, `test:tests/redteam_tests.rs::threat_malformed_frames_and_bombs` |
| **H2.6** | Invalid UTF-8 and encoding confusion | `partial` | `test:tests/unit_tests.rs::wire_rejects_malformed_envelopes` |
| **H2.7** | Streaming slowloris and oversize total declarations | `gap` | - |
| **H2.8** | Forge capability IDs (random, bit-flip, replay, cross-agent) | `done` | `test:tests/unit_tests.rs::capability_ids_are_unforgeable`, `test:tests/redteam_tests.rs::threat_forgery_and_transplant`, `test:tests/redteam_tests.rs::review_agent_secrets_are_random` |
| **H2.9** | Attenuate then widen (methods, budget, path, tool policy) | `done` | `test:tests/unit_tests.rs::attenuation_narrows_and_never_widens`, `test:tests/property_tests.rs::attenuation_is_monotone`, `test:tests/redteam_tests.rs::threat_escalation_through_metadata` |
| **H2.10** | Use after revoke or drop; borrowed channel lifetime | `partial` | `test:tests/redteam_tests.rs::threat_revocation_and_lifetime_edges`, `test:tests/unit_tests.rs::dropping_the_last_handle_notifies_the_provider` |
| **H2.11** | Confused deputy provider | `partial` | `test:tests/redteam_tests.rs::threat_confused_deputy` |
| **H2.12** | Tool adapter confused deputy | `partial` | `test:tests/redteam_tests.rs::review_tool_policy_predicate_matches_the_enforcer`, `test:tests/unit_tests.rs::tool_policy_is_enforced_on_tool_calls` |
| **H2.13** | Revocation racing with dispatch | `done` | `test:tests/redteam_tests.rs::review_revocation_after_queueing_prevents_invocation`, `test:tests/redteam_tests.rs::review_cancelled_and_destroyed_work_never_runs` |
| **H2.14** | Secrets in every legal position; scan all export paths | `partial` | `test:tests/redteam_tests.rs::threat_secret_material_never_reaches_the_wire`, `test:tests/redteam_tests.rs::review_module_payloads_are_redacted` |
| **H2.15** | Force secrets into error messages | `partial` | `test:tests/redteam_tests.rs::threat_secret_material_never_reaches_the_wire` |
| **H2.16** | Equality and ordering oracle attempts | `n/a` | - |
| **H2.17** | Smuggle secrets via extensions, annotations, provenance, projections | `partial` | `test:tests/redteam_tests.rs::review_module_payloads_are_redacted` |
| **H2.18** | Logging and metrics carry no secrets or raw capability bits | `partial` | `test:tests/unit_tests.rs::events_record_the_dispatch_batches` |
| **H2.19** | Queue storms under a low call budget | `partial` | `test:tests/redteam_tests.rs::review_lane_capacity_counts_queued_calls` |
| **H2.20** | Nested value byte bombs under a low byte budget | `partial` | `test:tests/redteam_tests.rs::threat_argument_bombs_in_memory_budget` |
| **H2.21** | Many lanes, channels and promises to finite limits | `gap` | - |
| **H2.22** | Enormous tool payloads and tools that never return | `gap` | - |
| **H2.23** | Zero or near-zero ceilings refused where policy needs finite limits | `done` | `test:tests/redteam_tests.rs::review_zero_ceilings_are_refused_in_every_budget_field` |
| **H2.24** | Single-bit mutation fails validation or changes the hash | `n/a` | - |
| **H2.25** | Large-corpus hash collision search | `n/a` | - |
| **H2.26** | Pipelined vs sequential preserves the authorization side-effect set | `gap` | - |
| **H2.27** | Projection hash and redaction agreement | `n/a` | - |
| **H2.28** | Overlapping write capabilities detected or prevented | `gap` | - |
| **H2.29** | Audit-only capability cannot write | `done` | `test:tests/unit_tests.rs::read_only_capability_refuses_mutation` |
| **H2.30** | Stale capability after ownership change refused | `gap` | - |
| **H2.31** | Another worker's secret-bearing subgraph denied or fully redacted | `gap` | - |
| **H2.32** | Public errors do not enable secret or capability oracles | `partial` | `test:tests/conformance_tests.rs::every_error_code_is_unique_and_documented` |
| **H2.33** | No debug unlock or test ambient authority in release builds | `gap` | - |
| **H2.34** | Fuzz corpus treated as permanently hostile input | `gap` | - |
| **H2.35** | Docs and examples do not teach insecure patterns without warnings | `partial` | `doc:SECURITY.md`, `doc:README.md` |
| **H2.36** | Allocation ceiling for untrusted counts | `partial` | `test:tests/redteam_tests.rs::review_capability_table_count_is_capped_before_allocating` |
| **H2.37** | Length arithmetic checked on 32-bit and 64-bit widths | `gap` | - |
| **H2.38** | Strings and blobs that end exactly at EOF | `partial` | `test:tests/conformance_tests.rs::truncated_prefixes_are_always_rejected` |
| **H2.39** | Extension skip and duplicate-tag arithmetic | `n/a` | - |
| **H2.40** | Abort-free lane under panic=abort | `gap` | - |
| **H2.41** | Linear-time validation | `gap` | - |
| **H2.42** | Cross-kernel and cross-connection capability transplant or replay | `gap` | - |
| **H2.43** | Event and log redaction oracle (no secret bytes, hashed capability ids) | `gap` | - |
| **H2.44** | Tool timeout and payload ceiling | `gap` | - |
| **H2.45** | Shared-memory frame TOCTOU under concurrent mutation | `gap` | - |
| **H2.46** | URL and path allow-list canonicalization bypass | `gap` | - |
| **H2.47** | Promise settlement count under concurrent cancel and resolve | `partial` | `test:tests/unit_tests.rs::promise_can_be_cancelled_or_resolved_once` |
| **H3.1** | Freeze a review scope document | `gap` | - |
| **H3.2** | Independent review with recorded findings | `partial` | `doc:REVIEWS.md` |
| **H3.3** | Triage findings; critical and high fixed before maturity | `partial` | `doc:REVIEWS.md` |
| **H3.4** | Re-test after fixes with evidence | `partial` | `doc:REVIEWS.md` |
| **H3.5** | Schedule delta reviews after model or wire changes | `gap` | - |
| **H3.6** | Annual revisit in maintenance | `gap` | - |
| **H4.1** | Checked-in benchmark matrix | `partial` | `script:benches/transport.rs` |
| **H4.2** | Infinity encode/decode throughput and latency | `n/a` | - |
| **H4.3** | RPC call latency, pipelining and concurrency | `gap` | - |
| **H4.4** | Sustained load with RSS, allocations, FDs, threads | `gap` | - |
| **H4.5** | CI regression gates on the benchmark matrix | `gap` | - |
| **H4.6** | Publish docs/performance.md with methodology and numbers | `partial` | `doc:docs/spec/performance.md` |
| **H4.7** | Explicit DoS scenarios prove budgets cap CPU and memory | `partial` | `test:tests/redteam_tests.rs::threat_budget_bypass_attempts`, `test:tests/redteam_tests.rs::threat_argument_bombs_in_memory_budget` |
| **H4.8** | RSS, FD and thread stability over repeated cycles | `gap` | - |
| **H4.9** | FD and thread stability under connection churn | `gap` | - |
| **H5.1** | Runnable examples: round-trip, two-agent channel, tools, attenuation | `partial` | `script:examples/loopback.rs` |
| **H5.2** | Migration from JSON/YAML guide | `gap` | - |
| **H5.3** | Why not only Cap'n Proto, FlatBuffers or gRPC | `gap` | - |
| **H5.4** | Stable machine-readable error code catalog | `partial` | `test:tests/conformance_tests.rs::every_error_code_is_unique_and_documented` |
| **H5.5** | Explicit what-is-safe-to-log rules | `partial` | `doc:docs/spec/security.md` |
| **H5.6** | Misuse documentation | `partial` | `doc:SECURITY.md` |
| **H5.7** | Optional active-habitat demo | `gap` | - |
| **H6.1** | SBOM on every release | `partial` | `doc:docs/release-signing.md` |
| **H6.2** | cargo deny and advisory audit strict in CI | `done` | `gate:audit`, `gate:deny` |
| **H6.3** | Reproducible builds where feasible, limits documented | `gap` | - |
| **H6.4** | Signed tags with allowed_signers enforced | `partial` | `script:release-signing.allowed_signers` |
| **H6.5** | Dual publish checklist mechanical and reviewed | `partial` | `doc:docs/release-signing.md` |
| **H6.6** | Yank and advisory process exercised in a dry run | `gap` | - |
| **H6.7** | Property tests for attenuation monotonicity | `done` | `test:tests/property_tests.rs::attenuation_is_monotone` |
| **H6.8** | Bounded or exhaustive capability lifecycle model | `gap` | - |
| **H6.9** | Public statement of tested vs fuzzed vs reviewed vs proven | `partial` | `doc:SECURITY.md` |
| **H6.10** | Exhaustive small-state capability lifecycle model | `gap` | - |
| **H7.1** | Structured events for call, settle, revoke, budget, refusal | `partial` | `test:tests/unit_tests.rs::events_record_the_dispatch_batches` |
| **H7.2** | Default logs carry no secrets or raw capability bits | `gap` | - |
| **H7.3** | Metrics without sensitive payloads | `gap` | - |
| **H7.4** | Tests that force sensitive data into events fail CI | `gap` | - |
| **H8.1** | Written wire and format compatibility policy | `partial` | `doc:docs/spec/wire.md` |
| **H8.2** | Old Infinity images still validate | `n/a` | - |
| **H8.3** | Unknown flags and fields behavior specified and tested | `partial` | `test:tests/conformance_tests.rs::header_field_attacks_are_rejected`, `test:tests/conformance_tests.rs::every_encoding_is_stable_under_re_encoding` |
| **H8.4** | Versioned public conformance suite | `partial` | `test:tests/conformance_tests.rs::capability_table_golden_shape` |
| **H8.5** | Deprecation windows for shipped behavior | `gap` | - |
| **H9.1** | Nightly continuous fuzz with growing corpus | `partial` | `gate:fuzz` |
| **H9.2** | Periodic independent review cadence | `partial` | `doc:REVIEWS.md` |
| **H9.3** | Public status section: performance, security posture, residual risks | `gap` | - |
| **H9.4** | Hardening checklist reviewed every release | `gap` | - |
| **H9.5** | Maturity claim only after H0-H8 complete and H9 sustained | `gap` | - |
| **R-0** | Research sprint before each phase | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-1** | Research sibling components after every critical fix | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-2** | Full multi-domain pass once per release cycle | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-3** | Log every finding in RESEARCH-LOG.md | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **R-4** | Every finding becomes a test, item, ADR or n/a note | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.1** | At least 15 historical parser bugs with identifiers | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.2** | Map each historical bug to the wire decoder | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D1.3** | Add a test or fuzz oracle per mapped class | `partial` | `fuzz:framing` |
| **D1.4** | Differential parsing and second checker | `gap` | - |
| **D2.1** | At least 10 capability or RPC authz failure patterns | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D2.2** | Map authz patterns to kernel, cap, channel, tool, transport | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D2.3** | Monotonicity, revoke-at-dispatch and confused-deputy tests | `partial` | `test:tests/property_tests.rs::attenuation_is_monotone`, `test:tests/redteam_tests.rs::threat_confused_deputy` |
| **D2.4** | Rights amplification and caretaker patterns | `gap` | - |
| **D3.1** | Enumerate every export path | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D3.2** | Attempt redaction bypass techniques | `partial` | `test:tests/redteam_tests.rs::review_module_payloads_are_redacted` |
| **D3.3** | Anti-oracle equality in debug and optimized builds | `n/a` | - |
| **D3.4** | Stable error codes do not branch on secret-dependent data | `gap` | - |
| **D4.1** | Compare fuzz targets to structure-aware state of the art | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D4.2** | Semantic oracles, not only crash oracles | `partial` | `fuzz:framing` |
| **D4.3** | Directed seeds for cold paths | `gap` | - |
| **D4.4** | Corpus growth and minimize-and-commit policy | `partial` | `doc:docs/hardening/CORPUS.md` |
| **D5.1** | Map classic DoS classes to budget dimensions | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D5.2** | Prove hostile input hits budget before host OOM | `partial` | `test:tests/redteam_tests.rs::review_capability_table_count_is_capped_before_allocating` |
| **D5.3** | Compression bombs at transport edges | `n/a` | - |
| **D6.1** | Escape catalog for HTTP, process and MCP tools | `done` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D6.2** | Automate escape attempts as red-team tests | `partial` | `test:tests/unit_tests.rs::tool_policy_is_enforced_on_tool_calls` |
| **D6.3** | Runtime sandbox escape claims | `gap` | - |
| **D7.1** | Audit dependencies for unnecessary privilege | `partial` | `doc:docs/hardening/RESEARCH-LOG.md` |
| **D7.2** | cargo deny and advisories gate merges | `done` | `gate:audit`, `gate:deny` |
| **D7.3** | Document residual non-reproducibility sources | `partial` | `doc:docs/release-signing.md` |
| **D8.1** | Capability patterns for writer, auditor, orchestrator | `gap` | - |
| **D8.2** | Overlapping, stale and exfiltration grants | `gap` | - |
| **D8.3** | Import applicable multi-agent security tests | `gap` | - |
| **D9.1** | Secret- or capability-dependent timing in hot paths | `gap` | - |
| **D9.2** | Docs do not reveal privileged test-only behavior | `partial` | `doc:docs/spec/security.md` |
| **D9.3** | Standing question: what would an infinite-input agent try next | `gap` | - |

### Check index

<details><summary><strong>I-1</strong> (3 checks)</summary>

- `test:tests/redteam_tests.rs::threat_secret_material_never_reaches_the_wire`
- `test:tests/redteam_tests.rs::review_module_payloads_are_redacted`
- `test:tests/integration_tests.rs::redaction_hides_the_secret_cone`

</details>

<details><summary><strong>I-3</strong> (5 checks)</summary>

- `test:tests/redteam_tests.rs::threat_secret_material_never_reaches_the_wire`
- `test:tests/redteam_tests.rs::review_module_payloads_are_redacted`
- `test:tests/integration_tests.rs::redaction_hides_the_secret_cone`
- `test:tests/unit_tests.rs::response_and_error_envelopes_carry_no_payload`
- `fuzz:framing` — fuzz/fuzz_targets/framing.rs

Negative control (documented): Make Kernel::redact_module_payload a no-op and run the redaction tests → expected: threat_secret_material_never_reaches_the_wire must fail with the canary bytes present in the encoded envelope

</details>

<details><summary><strong>I-4</strong> (4 checks)</summary>

- `test:tests/unit_tests.rs::capability_ids_are_unforgeable`
- `test:tests/redteam_tests.rs::threat_forgery_and_transplant`
- `test:tests/redteam_tests.rs::review_agent_secrets_are_random`
- `test:tests/unit_tests.rs::unknown_method_is_refused`

Negative control (documented): Replace the OS CSPRNG in Agent::new with a fixed seed and mint two agents → expected: review_agent_secrets_are_random must fail because both agents produce the same capability ids

</details>

<details><summary><strong>I-5</strong> (7 checks)</summary>

- `test:tests/unit_tests.rs::attenuation_narrows_and_never_widens`
- `test:tests/unit_tests.rs::attenuated_budget_is_enforced_on_the_real_call_path`
- `test:tests/unit_tests.rs::read_only_capability_refuses_mutation`
- `test:tests/unit_tests.rs::path_scope_is_enforced_before_the_provider`
- `test:tests/property_tests.rs::attenuation_is_monotone`
- `test:tests/redteam_tests.rs::threat_escalation_through_metadata`
- `test:tests/redteam_tests.rs::review_attenuation_validates_the_budget`

Negative control (documented): Allow attenuation to union parent and child method lists and run the monotonicity property and the escalation test → expected: attenuation_is_monotone and threat_escalation_through_metadata must fail on a child that widens the parent

</details>

<details><summary><strong>I-6</strong> (5 checks)</summary>

- `test:tests/redteam_tests.rs::review_revocation_after_queueing_prevents_invocation`
- `test:tests/redteam_tests.rs::review_cancelled_and_destroyed_work_never_runs`
- `test:tests/redteam_tests.rs::threat_revocation_and_lifetime_edges`
- `test:tests/unit_tests.rs::revocation_kills_the_capability_and_its_children`
- `test:tests/unit_tests.rs::destroyed_lane_refuses_further_calls`

Negative control (documented): Remove the revocation re-check from the dispatch loop and run review_revocation_after_queueing_prevents_invocation → expected: the queued call must reach the provider after revoke, so the test fails with the provider call count at 1

</details>

<details><summary><strong>I-7</strong> (2 checks)</summary>

- `test:tests/unit_tests.rs::dropping_the_last_handle_notifies_the_provider`
- `test:tests/redteam_tests.rs::review_channel_shares_capabilities_without_holding_them_alive`

</details>

<details><summary><strong>I-8</strong> (9 checks)</summary>

- `test:tests/unit_tests.rs::lane_budget_is_independent_and_enforced`
- `test:tests/redteam_tests.rs::threat_budget_bypass_attempts`
- `test:tests/redteam_tests.rs::threat_argument_bombs_in_memory_budget`
- `test:tests/redteam_tests.rs::review_lane_capacity_counts_queued_calls`
- `test:tests/redteam_tests.rs::review_byte_budget_is_charged`
- `test:tests/redteam_tests.rs::review_wire_rejects_deep_value_nesting`
- `test:tests/redteam_tests.rs::review_zero_ceilings_are_refused_in_every_budget_field`
- `test:tests/redteam_tests.rs::review_capability_table_count_is_capped_before_allocating`
- `test:tests/conformance_tests.rs::wire_limits_are_enforced`

Negative control (documented): Charge one byte instead of the recursive wire size in Kernel::call and run review_byte_budget_is_charged → expected: the byte budget no longer fires, so the test fails when the large nested argument is accepted

</details>

<details><summary><strong>I-9</strong> (4 checks)</summary>

- `test:tests/conformance_tests.rs::minimal_request_is_a_stable_golden_vector`
- `test:tests/conformance_tests.rs::every_encoding_is_stable_under_re_encoding`
- `test:tests/conformance_tests.rs::capability_table_golden_shape`
- `test:tests/property_tests.rs::envelope_round_trips`

</details>

<details><summary><strong>I-10</strong> (8 checks)</summary>

- `test:tests/conformance_tests.rs::truncated_prefixes_are_always_rejected`
- `test:tests/conformance_tests.rs::header_field_attacks_are_rejected`
- `test:tests/conformance_tests.rs::every_error_code_is_unique_and_documented`
- `test:tests/unit_tests.rs::wire_rejects_malformed_envelopes`
- `test:tests/unit_tests.rs::unknown_method_is_refused`
- `test:tests/property_tests.rs::arbitrary_bytes_never_panic`
- `test:tests/redteam_tests.rs::threat_malformed_frames_and_bombs`
- `fuzz:framing` — fuzz/fuzz_targets/framing.rs

Negative control (documented): Skip the trailing-bytes check in Envelope::decode and run the malformed-envelope tests → expected: the trailing-bytes case must be accepted, so wire_rejects_malformed_envelopes fails and names the case

</details>

<details><summary><strong>I-11</strong> (4 checks)</summary>

- `test:tests/redteam_tests.rs::threat_confused_deputy`
- `test:tests/redteam_tests.rs::review_tool_policy_predicate_matches_the_enforcer`
- `test:tests/unit_tests.rs::tool_policy_is_enforced_on_tool_calls`
- `test:tests/unit_tests.rs::read_only_capability_refuses_mutation`

</details>

<details><summary><strong>I-12</strong> (7 checks)</summary>

- `test:tests/integration_tests.rs::evaluate_honors_the_capability_budget`
- `test:tests/integration_tests.rs::evaluate_runs_the_active_engine_over_the_binary_module`
- `test:tests/integration_tests.rs::stats_hash_and_metadata_are_served_through_capabilities`
- `test:tests/integration_tests.rs::why_and_impact_answer_with_paths`
- `test:tests/integration_tests.rs::subgraph_returns_a_valid_module`
- `test:tests/integration_tests.rs::patch_creates_a_new_module_version`
- `test:tests/unit_tests.rs::path_scope_is_enforced_before_the_provider`

</details>

<details><summary><strong>C-1</strong> (3 checks)</summary>

- `test:tests/unit_tests.rs::promise_can_be_cancelled_or_resolved_once`
- `test:tests/redteam_tests.rs::threat_promise_abuse`
- `test:tests/concurrency_tests.rs::lanes_interleave_in_one_batch`

Negative control (documented): Remove the settled flag check in Promise::settle and run the promise tests → expected: promise_can_be_cancelled_or_resolved_once must fail on the second settlement attempt

</details>

### Gates referenced by the matrix

| Gate | Command |
|---|---|
| `audit` | `cargo audit` |
| `baseline-tag` | `git rev-parse --verify hardening-baseline^{commit}` |
| `clippy` | `cargo clippy --locked --all-targets --all-features -- -D warnings` |
| `clippy-nodefault` | `cargo clippy --locked --all-targets --no-default-features -- -D warnings` |
| `deny` | `cargo deny check` |
| `doc` | `RUSTDOCFLAGS=-D warnings cargo doc --locked --no-deps --all-features` |
| `fmt` | `cargo fmt --all -- --check` |
| `fuzz` | `cargo +nightly fuzz run framing -- -runs=20000` |
| `msrv` | `cargo +1.88.0 check --locked --all-targets --all-features` |
| `package` | `cargo package --locked` |
| `test` | `cargo test --locked --all-features` |
| `test-nodefault` | `cargo test --locked --no-default-features` |

<!-- END GENERATED: hardening matrix -->
