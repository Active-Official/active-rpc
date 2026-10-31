# Review record

Independent reviews and the disposition of every finding. Transcripts are kept
with the release evidence (`review-rpc-*.log`).

Serve path: the Copilot subscription returned a monthly quota error, so every
round ran through the Copilot CLI routed at the Meta Muse proxy
(`muse-spark-1.3-contributor`), which reads the repository directly.

## Round 1 — 2026-10-27

| Finding | Severity | Disposition |
|---|---|---|
| `subgraph`/`patch` returned modules with secret nodes | high | fixed in 1.1.0 (redacted payloads); `review_module_payloads_are_redacted` |
| Revocation checked only when queueing | high | fixed in 1.1.0 (re-checked at dispatch); `review_revocation_after_queueing_prevents_invocation` |
| Byte budget never charged | high | fixed in 1.1.0 (recursive wire size); `review_byte_budget_is_charged` |
| Lane capacity ignored queued calls | high | fixed in 1.1.0; `review_lane_capacity_counts_queued_calls` |
| Unbounded value recursion in `wire` | high | fixed in 1.1.0 (depth 64 + size ceilings); `review_wire_rejects_deep_value_nesting` |
| `Budget::check` accepted zero ceilings in two fields | high | fixed in 1.1.0; `review_zero_ceilings_are_refused_in_every_budget_field` |
| Tool-policy predicate disagreed with the enforcer | medium | fixed in 1.1.0; `review_tool_policy_predicate_matches_the_enforcer` |
| Cancel / lane destruction left work queued | medium | fixed in 1.1.0; `review_cancelled_and_destroyed_work_never_runs` |
| `fail_job` reported `rpc/provider` for a pipelined cycle | medium | fixed in 1.1.0 (errors carry their class) |
| Borrowed-handle clone leaked a reference | medium | fixed in 1.1.0 (clone retains only owning handles) |
| Predictable agent secret | medium | fixed in 1.1.0 (OS CSPRNG); `review_agent_secrets_are_random` |
| Kernel borrow held across provider calls | medium | fixed in 1.1.0; `review_provider_may_call_back_into_the_agent` |
| Annotation redaction heuristic | low | fixed in 1.1.0 (taint-based) |
| Non-atomic shared-memory consume | low | fixed in 1.1.0 (`pop_frame`) |

## Round 2 — 2026-10-27

(a) no authority survives revocation, cancellation or lane destruction,
(b) no budget bypass through queueing or attenuation, (c) no secret bytes on the
wire. One new finding:

| Finding | Severity | Disposition |
|---|---|---|
| Tool payload ceiling counted only top-level text and modules | medium | fixed in 1.1.1 (recursive wire size); nested-list case added to `threat_argument_bombs_in_memory_budget` |

## Round 3 — 2026-10-27

Six new findings, all fixed in 1.1.2:

| Finding | Severity | Disposition |
|---|---|---|
| List/map values preallocated from an untrusted count | high | fixed; `review_capability_table_count_is_capped_before_allocating` covers the table decoder, the list path is covered by the arbitrary-bytes property |
| Standalone capability-table decoder allowed a million descriptors | high | fixed (capped by `WireLimits::max_caps`) |
| Connect bridge died on a malformed request | medium | fixed; `connect_bridge_survives_a_request_without_content_length` |
| Channel send retained capability references | medium | fixed (share, not retain); `review_channel_shares_capabilities_without_holding_them_alive` |
| Destroyed lane could still send | medium | fixed; `review_closed_lane_cannot_send` |
| Attenuation skipped budget validation | medium | fixed; `review_attenuation_validates_the_budget` |

## Round 4 — 2026-10-27

Verification round: **NO NEW FINDINGS**.

## Round 5 — 2026-10-27 (1.1.4)

Review of `v1.1.2..HEAD` (releases 1.1.3 and 1.1.4). No `src/` or `tests/` code
changed in the range; the review covered dependencies, feature wiring, CI and the
documents those releases claim. Five findings, all fixed:

| Finding | Severity | Disposition |
|---|---|---|
| `CHANGELOG.md` claimed `cargo deny check` passes with no advisory ignores, while `deny.toml` carries one | medium | fixed: the text names RUSTSEC-2024-0449 (`unsafe-libyaml` via `active-core`'s `serde_yaml`, outside every parsing path) |
| `fuzz/README.md` container example pinned `rust:1.85-bookworm`, below the declared 1.88 MSRV | low | fixed: `rust:1.88-bookworm` |
| `CONTRIBUTING.md` patch example closed a fence with a mangled `` ``n `` | low | fixed |
| CI: the fuzz job's toolchain and graph were unpinned, and the MSRV job skipped `--no-default-features` | low | fixed: the fuzz graph is the committed `fuzz/Cargo.lock` (documented rolling nightly), and the MSRV job checks both feature sets |
| `docs/release-signing.md` verify example still named `v1.1.3`, and one sentence read "a `allowed_signers`" | low | fixed: `v1.1.4`, grammar corrected |

Verified in the same round: `rustls-pemfile` removal is safe (no code reference;
the QUIC transport uses quinn/rustls/rcgen directly), the feature list is complete,
the MSRV claim holds for the committed lockfile, no public API or wire behavior
changed (empty `src` diff), and the signing instructions match the keys and
commands that actually verify.

## Round 6 — 2026-10-27 (1.1.5)

Verification of round 5, plus a whole-repository pass. Six findings, all fixed:

| Finding | Severity | Disposition |
|---|---|---|
| `#![deny(missing_docs)]` was cancelled by `#![allow(missing_docs)]`, so the documentation gate was off | medium | fixed: the allow is gone and all 27 hidden items are documented; `cargo doc` is part of the gates |
| ADR-0007 said `cargo deny` must pass with no advisory ignores while `deny.toml` carries one | medium | fixed: the ADR names RUSTSEC-2024-0449 and why it is out of the parsing path |
| The MSRV job's no-default-features check skipped `--all-targets` | low | fixed |
| README did not state the 1.88 MSRV | low | fixed (new section, links ADR-0007) |
| The framing fuzz target asserted `caps.len() <= 1 << 20` while the decoder caps at 256 | low | fixed: the assertion uses `WireLimits::default().max_caps` |
| The signing example still named `v1.1.3` | low | fixed: `v1.1.4`; the doc now tracks the current release |

No capability-forgery, secret-leak or budget-bypass path was found in `src/`;
the reviewer ran `cargo fmt --check`, `cargo deny check`, `cargo test --locked`
and confirmed the workflow parses.

## Round 7 — 2026-10-27 (1.1.6)

Final verification of round 6. The reviewer confirmed every prior fix, the doc
gate, the MSRV, the ADR, the CI checks and the fuzz assertion, and found no
security or correctness issue in `src/`. Five documentation defects, all fixed:

| Finding | Severity | Disposition |
|---|---|---|
| Signing example pinned `v1.1.4` while the doc implied it tracks the current release | low | fixed: `v1.1.5`, with a note to substitute the tag being verified |
| `CHECKLIST.md` still said `1.1.2` and "tags are annotated" | low | fixed: `1.1.5`, SSH-signed |
| `Channel::close` claimed receives fail; queued messages stay receivable | low | fixed doc; behavior unchanged |
| Duplicate doc line on `Channel::len` | low | fixed |
| `McpSession::calls` did not say the handshake is excluded | low | fixed |

Verified in the same round: `fmt`, `clippy -D warnings`, `deny`, `test --locked`
and `doc` all pass; no `unsafe` and no `TODO` in `src/`.

## Round 8 — 2026-10-27 (1.1.7)

Verification of round 7 found four low items; all fixed in 1.1.7:

| Finding | Severity | Disposition |
|---|---|---|
| ADR-0006 stated MSRV 1.85 with no pointer to its successor | low | fixed: points at ADR-0007 |
| The new `Channel::close` doc had no test | low | fixed: `close_stops_sends_but_queued_messages_remain_receivable` |
| `McpSession::calls` semantics had no test | low | fixed: `mcp_handshake_is_not_counted_as_a_tool_call` |
| `examples/` was empty while the checklist claimed runnable examples | low | fixed: `examples/loopback.rs`, checklist repointed |

## Round 9 — 2026-10-27 (1.1.7)

Verification round: **NO NEW FINDINGS**.

## Round 10 - 2026-10-27 (hardening H2-H9 delta)

Serve path: Muse-routed Copilot CLI (`muse-spark-1.3-contributor`).

| Finding | Severity | Disposition |
|---|---|---|
| Shared-memory compaction copied the wrapped front piece after overwriting its source | critical | fixed: compaction copies through a temporary buffer; desync check moved before the capacity check |
| Settled jobs and promises were never reclaimed; no job ceiling; `destroy_lane` did not purge them | high | fixed: `destroy_lane` removes the lane, its jobs and its promises; `MAX_PROMISES` also bounds jobs |
| Destroyed lanes and channels counted toward their registry ceilings forever | high | fixed: ceilings count open lanes, lanes are removed on destroy, `destroy_channel` added; churn test |
| `MAX_PROMISES` was checked after `meter.charge`, burning budget on a refused call | high | fixed: ceilings checked before charging; promise-ceiling test |
| `LocalProcess` ignored `Call.budget.max_wall_ms` | high | fixed: effective deadline is `min(tool timeout, wall budget)`; test |
| `Display for CapId` still printed raw authority bits; `Error::UnknownCapability`/`Revoked` printed the raw u128 | high | fixed: `Display` prints the correlation id; `CapToken` wraps the raw bits and formats only a correlation id; regression |
| Channel queue was unbounded | high | fixed: `MAX_QUEUED_PER_CHANNEL` with `rpc/budget-exceeded`; test |
| `with_timeout` could overflow / zero made calls flaky | medium | fixed: clamp 1..=300_000 ms and checked deadline |
| `decode_capability_table` ignored caller `WireLimits` | medium | fixed: `decode_capability_table_with`; the convenience form delegates with defaults |
| Lanes/channels and promises used different ceiling codes | medium | fixed: both are `rpc/budget-exceeded` with a dimension |
| Dispatch comment claimed a budget re-check it did not perform | medium | corrected; tool wall budget is enforced in the adapter |
| Dispatch fabricated `UnknownCapability(0)` | medium | fixed: the job's real capability travels in the error |
| cfg audit missed `#[cfg(debug_assertions)]` | medium | fixed: both spellings are scanned |
| Double settlement was silently swallowed | low | fixed: `Metrics::promises_double_settled`; test |
| New ceilings and events lacked failing-first tests | medium | fixed: channel ceiling, promise ceiling, registry reclaim, wall budget, Display/error redaction, double settle |

Verification after fixes: full suite, `fmt`, `clippy` (both feature sets),
`doc`, `package`, battery and negative controls pass. A follow-up verification
round is recorded below.

## Round 11 - 2026-10-27 (verification of round 10)

| Finding | Severity | Disposition |
|---|---|---|
| Dispatch fabricated `UnknownCapability(CapToken(0))` | medium | fixed: the job's real capability travels in the error |
| A vanished head capability failed as `PipelinedCycle` | medium | fixed: the stuck path maps to `UnknownCapability(cap_token(job.cap))` |
| `destroy_lane` removed settled promises, so an await saw `UnknownPromise` | medium | fixed: promise records survive lane destruction (the promise ceiling bounds them); jobs are reclaimed |

Regression tests: `dropped_capability_fails_queued_work_with_unknown_capability`,
`destroyed_lane_keeps_a_settled_promise_readable`.

Verification: full suite, `fmt`, `clippy` (both feature sets), `doc`, the
negative controls and the red-team battery pass.

## Round 12 - 2026-10-27 (convergence)

Focused convergence review of the three fixes and the surrounding lifecycle,
registry and `CapToken` paths.

**NO NEW FINDINGS.**

## Round 13 - 2026-10-27 (API gate and reclamation)

| Finding | Severity | Disposition |
|---|---|---|
| `api_surface.py` treated a renamed `impl.items` key as an empty list, so the gate stayed green while blind to every inherent method (including `CapId::hex`) | high | fixed: a missing or non-list `items` array is a schema-drift finding; inherent methods now count toward the `<10` tripwire |
| The allowlist could rot silently if `CapId::hex` disappeared | medium | fixed: the gate requires exactly one documented `hex` accessor; mutation test exits 1 with `found 0` |
| Double settlement could add a duplicate retention entry | low | fixed: a promise is recorded for retention only when it newly settles |

Mutation evidence: renaming `impl.items` exits 1 with "inherent impl has no `items` array"; renaming `hex` exits 1 with "found 0".

Verification: full suite, API gate, clippy, docs, 32-bit lane and the red-team battery pass.

## Round 14 - 2026-10-27 (convergence of the gate hardening)

**NO NEW FINDINGS.** The reviewer confirmed the `impl.items` drift finding, the
inherent-method counting, the single-`hex` allowlist check and the reclamation
interactions.

## Round 15 - 2026-10-27 (handle-pinned retention)

| Finding | Severity | Disposition |
|---|---|---|
| `trim_settled` evicted the oldest settled records without regard for live `PromiseHandle`s. A 2,000-call batch drained by the first await lost 976 results to `rpc/unknown-promise`, including the handle being awaited. | high | fixed: `PromiseRecord` carries a handle refcount; `PromiseHandle::clone`/`Drop` maintain it; trimming only evicts records with `handles == 0`. The limits are targets for unreferenced records, not a reason to drop readable results. |
| The previous reclamation test awaited each promise inside the loop, so it never had more than one live handle and could not catch the batch bug. | gap | fixed: `a_large_pipelined_batch_keeps_every_handle_readable` queues 2,000 calls, drains once, then reads every handle. With pinning disabled it fails on handle 0 with `rpc/unknown-promise`; with pinning it passes. |
| Residual-risk text told callers to "copy it out", which a pending pipeline cannot do before the drain. | gap | fixed: STATUS now states the real rule (handle-pinned; unreferenced records are trimmed). |

Verification: 115 tests, clippy both feature sets, doc gate, 32-bit lane and the
red-team battery pass.

## Round 16 - 2026-10-27 (convergence of handle-pinned retention)

**NO NEW FINDINGS.** The reviewer confirmed the refcount, clone/drop balance,
trim's pinned-record skip, the late handle-reference assignment, and the
interactions with pipelined dependencies, cancel, failure, destroy and cloning.
The 2,000-call batch test drives the shipped drain/read path.

## Round 17 - 2026-10-31 (C-6..C-10 delta: transports, CLI, hardening)

Scope: `git diff 8415a61..HEAD` - identity/HTTP2/bulk/observability, the new
`active-rpc-cli`, MCP hardening and the new test matrices. Serve path: Copilot
CLI routed at the Meta Muse proxy (`muse-spark-1.3-contributor`, xhigh).

| Finding | Severity | Disposition |
|---|---|---|
| HTTP/2 called a blocking kernel handler inside async stream tasks, stalling the runtime under concurrent streams | high | fixed: `handle_stream` runs the handler under `tokio::task::block_in_place`; the transport matrix test exercises concurrent streams |
| A call charged only its arguments; an envelope payload moved bytes for free and could be amplified by the echo | high | fixed: `Agent::call_with_payload` / `call_as_with_payload` add the payload to `max_bytes`; `tests/payload_budget.rs` proves the refusal and the spend |
| CLI `events` buffered an unbounded control-plane response; `--payload` read any file size | high | fixed: 8 MiB event ceiling and 64 MiB payload ceiling, `--payload` and `--text` are mutually exclusive |
| CLI QUIC peer slept 200 ms and then force-closed, racing the last response | medium | fixed: `QuicServer::wait()` waits for the serving task, which drains before closing; manual QUIC round trip passes |
| `loadgen` ids could collide past 1,000 requests per worker and a failed connection miscounted | medium | fixed: shared atomic id counter; a failed connection reports its whole assignment as errors |
| `fuzz_bulk_plan` only exercised error paths | low | fixed: decodes a generated plan, asserts structural invariants, verifies its own bytes and re-decodes the encoding |
| `McpSession::next_id` could overflow in debug builds | low | fixed: wrapping increment that skips the reserved zero id |

Also hardened in this delta and confirmed by the reviewer: bounded MCP line
reads (1 MiB), response-id matching (`mcp/id-mismatch`), refusal of responses
without `result`/`error`, and the per-tenant tests (foreign caps, budgets,
events, revocation).

Verification: `cargo fmt --all --check`, clippy `-D warnings` on both feature
sets, `cargo test --locked --all-features`, `cargo test --locked`, CLI tests and
lint, fuzz crate check.

## Round 18 - 2026-10-31 (verification of round 17)

| Finding | Severity | Disposition |
|---|---|---|
| `src/bin/peer.rs` TCP dispatch still used `Agent::call`, bypassing the new payload charge | high | fixed: `call_with_payload` with the envelope length (same as the examples) |
| The CLI payload ceiling checked file metadata first; pipes report zero and a growing file bypassed it | high | fixed: read through `File::take(MAX_PAYLOAD_BYTES + 1)` and reject on overflow |

The other round-17 fixes were confirmed: `block_in_place` holds no lock across an
await, the kernel charge is a single saturating add, `QuicServer::wait` drains
before closing, MCP ids wrap past zero, and `payload_budget` fails without the
charge.

## Round 19 - 2026-10-31 (convergence)

**NO NEW FINDINGS.** The reviewer verified that every dispatch path now charges
the envelope payload (the CLI, `examples/thin_peer.rs` and `src/bin/peer.rs`),
that the CLI reads payloads through a bounded reader, and that format, clippy,
the full suite and the CLI suite are green.

## Round 20 - 2026-10-31 (C-11 and C-12 delta)

Scope: `637e962..HEAD` (TTL bounds, receipts, intro modules, replay packages,
WASM tools, pub/sub topics, bridge specification) plus the working tree.
Path: Copilot CLI via the Meta Muse proxy, `--reasoning-effort xhigh`.

| Finding | Severity | Disposition |
|---|---|---|
| TTL checked only when queueing: a call that expires during its round trip still ran | high | fixed: dispatch re-checks `expires_at`, settles `rpc/revoked` and emits `CapExpired`; `a_call_that_expires_while_queued_never_reaches_the_provider` (provider panics if reached) |
| `publish` ignored the identity binding and charged no budget | high | fixed: `publish` delegates to `publish_as`, which checks `bound_to` and charges the payload against cap x lane bytes; `a_capability_bound_to_a_peer_publishes_only_through_that_peer`, `a_publish_charges_the_capability_byte_budget` |
| `attenuate`, `introduce_to`, `send_as` checked revocation but not expiry | high | fixed in all three, with `CapExpired`; `every_authority_path_refuses_an_expired_capability` |
| Replay had no total body ceiling (100k x 1 MiB transient) | high | fixed: `MAX_PACKAGE_BYTES` (64 MiB) and `MAX_ARG_TOTAL_BYTES` (16 MiB); two ceiling tests |
| WASM compiled an unbounded module and had no recursion or stack ceiling | high | fixed: 1 MiB module cap, `set_max_recursion_depth(1024)`, `set_max_stack_height(1 MiB)`, fail-open limit validation; three tests |
| Bridge aborted `serve` on a truncated body and both sides allocated the announced length | high | fixed: 400 + continue, incremental reads; `a_truncated_body_gets_a_400_and_the_bridge_keeps_serving`, `a_short_response_body_is_a_transport_error` |
| `cap.expired` was emitted but missing from `EVENT_NAMES` | medium | fixed; the projection test now requires the closed set and the projected events to match exactly |
| MCP tool descriptions were unbounded and could carry ANSI/bidi text | medium | fixed: 4 KiB cap, control and bidi characters replaced; `a_tool_description_is_capped_and_stripped_of_control_characters` |
| Tool names could spoof another entry in an operator allow-list | medium | fixed: `[A-Za-z0-9_.-]{1,128}` and unique (`mcp/tool-name`); six tests |
| Missing `tools/call` id-mismatch test | low | added |
| `fuzz_docker.py --all` skipped `fuzz_bulk_plan` | low | fixed |
| Nightly `fuzz_capability_lifecycle` asserted against a locally minted capability because the "other" seed expanded to the same secret | low | harness fixed (flip seed byte 0); crash input committed as a seed; `tests/fuzz_regression_tests.rs` pins both halves |
| `Recorder` recorded an attenuation only on success, so the parent clone's retain/release events were unreproducible | high | found by the new `fuzz_replay_package` target; fixed by recording every attempt; two regression tests |

Verified and rejected: a property-test generator for `topics`/`ttl_ms` (the
fuzz targets already drive both), and an "id is authority" note (already in
`cap.rs` and `SECURITY.md`).

## Round 21 - 2026-10-31 (verification)

All twelve dispositions VERIFIED at `7805a8e`, with the suites named in round
20 passing. One new finding:

| Finding | Severity | Disposition |
|---|---|---|
| `bounded_description` could overshoot the 4 KiB cap by up to three bytes when a multi-byte character straddled it | low | fixed: reserve `len_utf8()`; `a_multibyte_character_cannot_straddle_the_description_ceiling` |

No authority over-refusals, no test bypassing the shipped path, no other bound
bypass. Gates after the fix: clippy both feature sets, 283 tests with all
features, 256 without, CLI 15, control-plane 25.
