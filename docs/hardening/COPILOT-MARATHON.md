# Copilot deep audit marathon — Active RPC

Program: `C:\Users\Usuario\Downloads\Active-Absolute-Max-Program`, phase M-6,
procedure `COPILOT-DEEP-AUDIT-LOOP.md`. Reviewer: GitHub Copilot CLI routed to the
Muse proxy (`muse-spark-1.3-contributor`, `--reasoning-effort xhigh`), which reads
the repository through its own tool access, so findings carry file:line
references rather than pasted guesses.

Loop per section: prepare context → hostile review → triage every finding against
the code → regression test first → minimal fix → targeted tests + clippy → re-audit
→ CLEAN twice or ADR-accepted residual.

## Status

| ID | Section | Paths | State | Findings (fixed / rejected / open) | Commits |
|----|---------|-------|-------|------------------------------------|---------|
| R-01 | wire ARP1 | `src/wire.rs` | CLEAN | 6 fixed, 2 rejected, 0 open | this commit |
| R-02 | kernel dispatch | `src/kernel.rs` | CLEAN (rounds 1-3) | 24 fixed / 2 rejected / 2 low open (contract) | this commit |
| R-03 | capabilities | `src/cap.rs` | CLEAN (rounds 1-3) | 36 fixed / 0 rejected / 0 open | this commit |
| R-04 | promises / pipeline | `src/promise.rs` | CLEAN (rounds 1-2) | 24 fixed / 0 rejected / 3 low open (logged) | this commit |
| R-05 | lanes / channels | `src/lane.rs`, `src/channel.rs` | round 1: 9 fixed, 1 carried | 9 fixed / 0 rejected / 1 open (ADR) | this commit |
| R-06 | budget | `src/budget.rs` | CLEAN (rounds 1-2) | 8 fixed / 0 rejected / 5 open (logged) | this commit |
| R-07 | domain ops | `src/domain.rs` | round 1: 12 fixed, 0 open | 12 fixed / 0 rejected / 0 open | this commit |
| R-08 | tools / MCP | `src/tool.rs` | round 1: 10 fixed, 5 carried; round 2: 5 carried closed, 3 highs + 6 mediums + 7 lows fixed | 24 fixed / 0 rejected / 0 open | this commit |
| R-09 | transports | `src/transport/**` | round 1: 4 highs + 11 mediums + 3 lows fixed | 18 fixed / 0 rejected / 0 open (1 documented residual) | this commit |
| R-10 | bulk | `src/bulk.rs` | round 1: 3 highs + 4 mediums + 5 lows fixed | 12 fixed / 0 rejected / 0 open | this commit |
| R-11 | identity | `src/identity.rs` | round 1: 3 highs + 2 mediums + 3 lows fixed | 8 fixed / 0 rejected / 0 open | this commit |
| R-12 | replay | `src/replay.rs` | pending | — | — |
| R-13 | receipts | `src/receipts.rs` | pending | — | — |
| R-14 | wasm tools | `src/wasm_tool.rs` | pending | — | — |
| R-15 | observability | `src/observability.rs` | pending | — | — |
| R-16 | security helpers | `src/security.rs`, `src/persistence.rs` | pending | — | — |
| R-17 | intro / topics | `src/intro.rs`, `src/channel.rs` | pending | — | — |
| R-18 | CLI | `cli/active-rpc-cli/**` | pending | — | — |
| R-19 | control-plane | `control-plane/**` | pending | — | — |
| R-20 | fuzz | `fuzz/**` | pending | — | — |

## Cross-cutting passes (after the sections)

| Pass | State | Notes |
|---|---|---|
| Concurrency / multi-tenant | pending | — |
| Oracle and secret paths (Display/Debug/Serialize) | pending | — |
| Wire confusion (ARP1 vs bridge framing) | pending | — |
| Resource bombs (depth, counts, WASM fuel, headers) | pending | — |
| Polyglot encoder golden | pending | — |
| Second pass over changed sections | pending | — |

## Log

Entries are appended per section: date, reviewer path, findings, disposition.

### R-02 kernel dispatch - 2026-11-01 (round 3)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, repository tool
access. Tests: `tests/marathon_round2_fixes_tests.rs`; twelve of its thirteen
tests fail on the pre-fix tree (one of them hangs, which the reviewer predicted:
"control-flow certain; not executed"). The thirteenth exercises API that only
exists after the fix and passes with an accessor shim, so it is evidence for the
API and not for the defect.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| H-1 | high | export stamped the export-time clock mode, not the deadline's domain | **fixed**: `CapRecord.wall_clock` is set at mint and inherited by attenuation; export writes it and attenuation refuses a parent whose deadline is in another domain; `a_record_keeps_the_clock_mode_its_deadline_was_taken_in`, `attenuation_refuses_a_clock_mode_change` |
| H-2 | high | dropping the parent handle freed the ancestor meters, so every child spent the grant again | **fixed**: `CapRecord.descendants` keeps an ancestor's record and meter alive while any derived capability can call through it, and removal cascades up the lineage; `dropping_the_parent_handle_keeps_the_subtree_bound` |
| H-3 | high | a provider that awaited a promise spun forever (regression from round 2) | **fixed**: `await_promise` refuses with `rpc/provider` while a dispatch owns the kernel; `a_provider_awaiting_its_own_call_is_refused` (hangs pre-fix) |
| M-4 | medium | a provider unwind left `dispatching` set and the provider removed, wedging the kernel | **fixed**: `DispatchGuard` restores both on unwind; `a_panicking_provider_does_not_wedge_the_kernel` |
| M-5 | medium | `on_drop` ran with the kernel mutably borrowed, so any agent call panicked | **fixed**: every notification is queued and delivered by `deliver_pending_drops` with no borrow held; a provider that is already being notified queues the nested drop; `a_provider_may_use_the_agent_inside_on_drop` |
| M-6 | medium | revoking one restored copy left its siblings alive | **fixed**: restore refuses a second live copy of a credential and revoke dooms every live capability carrying a tombstoned record id; `restoring_the_same_record_twice_is_refused` |
| M-7 | medium | `send` charged nothing and needed no capability | **fixed**: a send charges the lane's bytes (payload plus one id per transfer) and one lane call, and a channel has a queued-byte ceiling; `a_send_consumes_the_lane_byte_budget`, `a_channel_accounts_for_queued_bytes` |
| L-8 | low | a vanished provider was `rpc/invalid-argument` at call time and `rpc/provider` at dispatch | **fixed**: both are `rpc/provider` |

### R-04 promises / pipeline - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `09704cc`.
Twelve findings; the round-1 table above stays valid for the parts it verified.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | the envelope guard was per method: `active-rpc-cli peer` served every connection through `call_with_payload` and accepted a decoded `Arg::Promise` | **fixed**: the refusal moved to the kernel boundary (`call_with_origin(.., from_peer)`), and the CLI uses `call_from_envelope`; `an_envelope_cannot_carry_authority_arguments` |
| F2 | high | `await_promise` from `on_drop` spun: the delivering provider is not `dispatching`, so the round-1 guard did not fire | **fixed**: the loop now requires a round trip to have happened, else `rpc/unresolvable-promise`; `awaiting_from_on_drop_returns_instead_of_spinning` (hangs pre-fix) |
| F3 | medium | phase 3 and `fail_job` emitted `PromiseResolved`/`PromiseRejected` and advanced the counters after a *failed* transition | **fixed**: both are inside `settled_now` |
| F4 | medium | an in-batch cancelled promise never became trim-eligible, so repeated cancellations leak records until the promise ceiling wedges the kernel | **fixed**: `cancel` records the terminal state for an in-batch job too |
| F5 | medium | the empty-batch arm trimmed settled records while the queue still held a consumer for them (spurious `rpc/pipelined-cycle`) | **fixed**: no trim while the queue is non-empty |
| F6 | medium | `cancel_tree`'s queue filter was O(jobs × queue): 10 000 jobs = 658 ms (measured) | **fixed**: one `BTreeSet` of queued ids |
| F7 | medium | `order_candidates` scanned `ordered` per dependency: a 2 000-link chain = 808 ms (measured) | **fixed**: a `BTreeSet` of promises produced in the batch |
| F8 | medium | the idempotency key ignored the arguments: the same key with different arguments returned the first result | **fixed**: the cache stores an argument fingerprint (shape and content, secrets by marker only) and refuses a mismatch; `an_idempotency_key_refuses_different_arguments` |
| F9 | low | a cached replay was refused at the lane call ceiling, exactly when a retry is needed | **fixed**: the capacity check is on the miss path; `a_cached_replay_is_served_at_the_lane_ceiling` |
| F12 | low | settlement walks a provider-controlled value with no depth bound: a 200 000-deep response aborted the process | **fixed**: dispatch refuses a value deeper than the wire limit as `rpc/provider`; `a_provider_value_deeper_than_the_wire_limit_is_refused` |

Carried (documented, not fixed here):

| # | Sev | Reason |
|---|-----|--------|
| F10 | low | a `PromiseHandle` is not bound to its kernel, so two agents in one process can mix ids; the fix is a kernel nonce in every handle-accepting method, which changes the handle type |
| F11 | low | idempotent refusals skip `CallRefused`/metrics; the accounting helper exists (`note_refusal`) and the wiring is a follow-up |
| F13 | note | `JobState::Done` is vestigial; the invariant "a job leaves `jobs` only at settlement" should be asserted or the enum removed |

Gate: `cargo test --all-features` 444 passed, 0 failed; the CLI suite 17 passed;
clippy clean on both feature sets and the CLI; fmt clean.

### R-06 budgets - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `64ea410`.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | a sealed record was never consumed: export → restore → spend → drop → restore refilled the same grant without bound, so a record stored in a config system was an unlimited credential | **fixed**: `Kernel.consumed_records` marks a record on export and `Kernel.restored_records` marks it on restore; a second export or restore is `rpc/persistence`; `an_exported_record_is_consumed`, `a_record_restores_once_per_kernel` |
| 2 | high | export recorded only the capability's own remainder and restore minted an unlineaged capability, so a restored child escaped the parent's grant | **fixed**: export clamps the record to the minimum remaining of the capability *and* every ancestor, then **reserves** that grant on every meter (`BudgetMeter::check_reserve`/`reserve`), so the local subtree cannot spend it twice; `a_restored_child_cannot_outspend_its_parent` |
| 3 | medium | response bytes are not a budget dimension: a 32-byte grant can return 1 MiB | **fixed**: dispatch charges the response's wire size against the capability, its ancestors and the lane before settlement, so a response that does not fit settles as `rpc/budget-exceeded`; `a_response_larger_than_the_remaining_grant_is_refused`, and `budget.rs` says the ceiling covers both directions |
| 4 | medium | `max_wall_ms` is enforced only by `LocalProcess`; MCP has no deadline and HTTP uses a fixed 10 s | **carried**: threading the ceiling into the adapters is mechanical but changes three adapters' timeouts; logged for R-08 (tools) where the adapters are audited |
| 5 | low | send/publish refusals advance `budget_exhaustions` without an `Event::BudgetExhausted`, and the dimension vocabulary has more values than the spec lists | **carried** with #3/#4; the event and the spec list are one change |

Gate: `cargo test --all-features` 448 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-06 budgets - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `22c3d66`
plus `d801371`. Tests: `tests/promise_tests.rs` (4 new, failing-first;
`tests/r06_audit_probe*.rs` were the scratch probes and are removed).

Verified clean, by probe rather than by reading: export → restore → re-export →
restore across three kernels carries the grant once (3 calls in, 3 calls out,
0 in the exporting kernels); a child attenuated *after* an export cannot see the
reserved grant (the chain is charged, not the child's ceiling); a restore whose
`mint_restored` fails does **not** consume the record; a dropped parent handle
still binds its child; two sibling exports cannot each carry the ancestor's
whole remainder; and an export of a spent, revoked or expired capability still
refuses.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a refused export still burned the grant and the record: the empty-path-scope check ran *after* `reserve` and after `consumed_records.insert`, so one malformed field destroyed the authority and made the record unexportable | **fixed**: the check moved above the reserve; `a_refused_export_keeps_the_grant_and_the_record` |
| 2 | high | a tombstone did not reach a live capability: `tombstone_record` only filled the set, and dispatch never consults it, so a credential restored before the kill list was replayed kept serving its whole lease | **fixed**: `tombstone_record` revokes every live capability carrying the id (shared `revoke_subtree` with `revoke`); `a_tombstone_revokes_the_live_capability_it_names` |
| 3 | medium | `consumed_records` and `restored_records` had no ceiling and are not covered by `durable_ceiling_reached`: 70 000 export/drop cycles grew the set forever (measured) | **fixed**: `MAX_RECORD_IDS` (65 536) with `set_record_id_ceiling`; a new export or restore past it is `rpc/budget-exceeded`; `the_record_id_sets_are_bounded` |
| 4 | low | a sealed record whose budget disables a ceiling was refused as `rpc/invalid-argument`, outside the durable vocabulary | **fixed**: restore reports `rpc/persistence`; `a_record_that_disables_a_ceiling_is_a_durable_refusal` |
| 5 | low | ADR-0010 still said "one live capability per credential", while the code restores once per kernel and consumes on export | **fixed**: the ADR addendum states consumption, the lineage reserve, the bounded sets, the kill-switch semantics and the startup order |
| 6 | low | an export and a restore emit no event (`CapMinted` is reused), so authority leaving the process is not on the trace | **carried**: the event names are a schema change with `docs/spec/observability.md` and the ADR-0014 list; one change |
| 7 | low | the lineage clamp skips an ancestor whose meter is missing (`if let Some`), so the clamp degrades fail-open if the "an ancestor outlives its descendants" invariant is ever broken | **carried**: today unreachable (`drop_record` refuses an ancestor with `descendants > 0`); the fail-closed form needs an error path no test can reach |
| 8 | low | `object` is a provider-local id: a restart with a different registration order re-mints a credential against a different object | **documented** in ADR-0010 as a provider contract; a name-based object identity is a record format change |

Gate: `cargo test --all-features` 456 passed, 0 failed; `cargo test
--no-default-features` 0 failed; clippy clean on both feature sets; fmt clean.

### R-06 budgets - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`. All five round-1
claims were verified with fresh probes (lineage clamp = capability ∩ every
ancestor and the same grant reserved on that chain; a three-kernel
export→restore→re-export→restore carries 3 calls in, 3 out, 0 left behind; a
child attenuated *after* an export cannot spend the reserved grant; a failed
`mint_restored` does not mark the record; spent/revoked/expired exports still
refuse; a hostile record cannot insert into either set). Two new highs:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a *refused* export burned the grant and marked the record consumed: the empty-path-scope check ran after `reserve` and the consumed insert, so one mistyped field destroyed a durable credential | **fixed**: every "the record cannot be built" refusal now happens before the reserve; `a_refused_export_keeps_the_grant_and_the_record` |
| 2 | high | `tombstone_record` filled the set but never reached a live capability: a record restored before the kill list was replayed (or tombstoned at runtime) kept spending for its whole lease | **fixed**: `tombstone_record` revokes every live capability carrying the id through a shared `revoke_subtree`; `a_tombstone_revokes_the_live_capability_it_names` |
| 3 | medium | the consumed/restored mark sets had no ceiling | **fixed**: `MAX_RECORD_IDS` (65 536) with `set_record_id_ceiling`, refused as `rpc/budget-exceeded`; `the_record_id_sets_are_bounded` |
| 4 | low | a record with a zero budget answered `rpc/invalid-argument` | **fixed**: restore maps it to `rpc/persistence` |
| 5-8 | low | export/restore emit no event; the clamp is fail-open on a missing ancestor meter; `object` is a provider-local id; provider error text is delivered unbilled | carried in the reviewer's table with reasons |

The reviewer applied its fixes directly to the working tree; they are in commit
`da59ba9` together with the R-07 D-1 fix and the removal of the scratch probes.

Gate after the D-2..D-12 work: `cargo test --all-features` 466 passed, 0 failed
(and the `--no-default-features` suite green); clippy clean on both feature sets;
fmt clean.

### R-08 tools / MCP - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `0953e7a`
(probes compiled against an isolated `git archive` snapshot because this
worktree was being edited). Five highs, four mediums, six lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `LocalProcess` joined its pipe readers with no deadline: a descendant that inherited the pipe kept the call alive past the ceiling (measured 8.2 s on a 300 ms grant) | **fixed**: the readers report over a channel and the wait is bounded; `taskkill /T` ends the tree on Windows; `capability_wall_budget_caps_a_slow_tool` (19 s child, 120 ms ceiling, returns < 5 s) |
| 2 | high | MCP had no deadline: a silent server held the dispatch thread forever | **fixed**: the transport trait has a deadline-aware read, `StdioTransport` reads on a thread and abandons the wait; `a_silent_stdio_server_times_out` (real silent child at 400 ms) |
| 3 | high | `HttpTool` ignored the wall ceiling (fixed 10 s, no write timeout) | **fixed**: read and write timeouts are `min(10 s, ceiling)` |
| 4 | high | HTTP connect was unbounded (21.15 s measured to a blackhole) | **fixed**: resolve, then `connect_timeout` per address under the ceiling |
| 5 | high | the response status and header lines were unbounded (a 64 MiB line accepted; a header stream aborts the allocator) | **fixed**: `read_line_bounded` per line plus a 64 KiB / 128-field block budget |
| 6 | medium | after an over-long MCP line the session resynchronised on the tail, so one stream answered two calls | **fixed**: the reader thread stops on a framing error, so the tail can never answer a later request |
| 7 | medium | the tool-list duplicate check was a scan (32 000 tools: 12.7 s) | **fixed**: a `BTreeSet` |
| 8 | medium | a bare program name resolves through the ambient `PATH`; `cwd` is inherited | **carried**: requiring an absolute program path is a contract change (the control plane spawns `cmd`/`sh` by name); logged for the R-19 control-plane pass |
| 9 | medium | a timeout kills the child, not its descendants, and the readers were detached | **partly fixed**: the tree is ended on Windows and the reader wait is bounded everywhere; a Unix process group needs a `libc`-level `setsid`, carried |
| 10 | low | `Transfer-Encoding: chunked` was returned as a body | **fixed**: anything but `identity` is refused, as are 1xx and non-`HTTP/1.x` status lines |
| 11 | low | a GET always sent `content-length: 4` | carried with #8 (the request shape belongs to the same pass) |
| 12 | low | the outbound MCP line was uncapped | **fixed**: refused before send |
| 13 | low | non-text process arguments were silently dropped | **fixed**: `rpc/invalid-argument` |
| 14 | low | an MCP notification desynchronised the session | carried: fail-closed today (an unexpected frame is fatal), a skip-up-to-N rule is a protocol decision |
| 15 | low | `bounded_description` missed U+2028/U+2029 and invisible formatters | carried with #8 (same small edit) |

Gate: `cargo test --all-features` 469 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-11 identity - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `2361b7d`.
No critical. Three highs were fail-open binding paths, two mediums were contract
and availability, three lows defence-in-depth. All fixed here.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the all-zero (anonymous) fingerprint is a wildcard: `bound_to([0;32])` matched an anonymous peer, contradicting I-13 and the API docs | **fixed**: `identity::presented_fingerprint` models "no identity" as `None`; `identity::matches` is a constant-time compare; the kernel uses both at all five enforcement sites, and `mint`/`attenuate`/`restore`/`from_json` refuse a zero binding; `a_zero_fingerprint_binding_is_refused` |
| 2 | high | every loopback peer shares one *bindable* fingerprint, so a capability bound to `admit(None, true)` was usable by any local process (and by a co-hosted TLS terminator) | **fixed**: `AdmittedIdentity::can_bind` requires `TrustLevel::Authenticated`; `mint_bound`/`introduce_to` refuse a loopback peer; the deployment guide and ADR-0011 say so; `a_loopback_peer_cannot_hold_a_binding`, and the policy test now asserts the refusal |
| 3 | high | the verification contract was honour-system: `PeerIdentity::from_certificate` accepts any bytes and `admit` returns `Authenticated` without touching them | **fixed in documentation and types**: `from_certificate` states it is record-keeping, not proof; `Agent::call_peer` takes the `AdmittedIdentity` the policy returned, so mint and dispatch share one gate; `call_peer_uses_the_admitted_identity` |
| 4 | medium | `with_subject` re-hashed the fingerprint, so attaching a SAN broke every binding and the "digest of the certificate" claim | **fixed**: the subject is a label and the fingerprint is untouched; the identity value still includes the label. `certificate_identities_are_stable_and_subject_sensitive` now pins that |
| 5 | medium | `introduce_to` bound only the root; children minted earlier stayed usable by another peer and transferable | **fixed**: introduction binds the live subtree (validated first: a descendant bound to another peer refuses the introduction); `introduction_binds_the_existing_subtree` |
| 6 | low | the default `cert:` label was 8 bytes of the fingerprint, and the subject length was framed as `u32` | **fixed**: 16 bytes; the length is `u32::try_from` with a saturated fallback rather than a truncating cast |
| 7 | low | `bound_to` accepted zeros and rebinding; the record parser accepted a zero binding while rejecting a zero record id | **fixed** with #1: the kernel validates every path that sets a binding, and `CapabilityRecord::from_json` refuses an unbindable fingerprint |
| 8 | low | five fingerprint comparisons short-circuited | **fixed**: `identity::matches` folds the difference; the value is a public label, so this is defence in depth |

Documented residual: a caller that fabricates a `PeerIdentity` in-process can bind
to it. No wire path reaches that — the QUIC transport reads only the leaf rustls
verified, HTTP/2 and the bridge present no identity, and an envelope has no
identity field — and the kernel treats the value as the caller's claim about its
own connection.

Gate: `cargo test --all-features` 518 passed, 0 failed; `--no-default-features`
469 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the identity and bulk suites pass in `rust:1.88-bookworm`.

### R-10 bulk transfer - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `dd50c0d`.
No critical. The chunk codec was fail-closed (nothing stored before length and
hash validation), but the section was a library with no consumer, and the two
properties that make a transfer safe — charging the budget and binding the plan
to the authority that opened it — were absent from the API. Three highs, four
mediums, five lows; all fixed here.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | bulk bytes were never charged: a 1 GiB receiver ceiling against a 64 MiB grant, with no meter anywhere | **fixed**: `BulkReceiver::with_budget` charges every accepted frame's wire size before it is stored (`rpc/budget-exceeded`, nothing retained), `accept_charged` takes a caller callback, and the ceiling defaults to the grant; the provider path is charged by the kernel on ingress. `a_receiver_charges_every_chunk_and_stores_nothing_refused`, `the_kernel_grant_and_byte_budget_bound_a_bulk_transfer` |
| 2 | high | a plan was self-authenticating only: no binding to the envelope, capability, peer or an expected root, so plan substitution and whole-transfer replay were accepted | **fixed**: the root now folds a transfer context (request id + capability id), `BulkPlan::new_with_context`/`decode_with_context` implement it, and `BulkReceiver::with_expected_root` plus `BulkProvider::with_expected_root` refuse a substituted plan; `a_substituted_plan_is_refused_by_the_pinned_root`, `a_plan_is_bound_to_its_transfer_context` |
| 3 | high | `frames_for` materialised an unbounded, duplicate-laden peer list (25 GiB from a 100 000-index request) | **fixed**: deduplicated, bounded by the plan, one frame at a time via `frame_at`, and `frames_from` refuses a resume point past the plan; `a_resume_request_is_deduplicated_and_bounded` |
| 4 | medium | the response envelope payload was never charged on egress; `max_bytes` ("both directions") was bypassed by the reference dispatcher's echo | **fixed**: `Agent::charge_egress_bytes`, called by the CLI dispatcher before attaching the echoed payload; `egress_payload_bytes_are_charged` |
| 5 | medium | no consumer of `ARBL`/`ARBC`, no encoding for the missing list or the finish marker, no credit window; `frames()` re-materialised the body and `encode` re-hashed | **fixed**: `BulkProvider` (`plan`, `put`, `missing`, `finish`) receives the frames as ARP1 envelope payloads through a capability, so authority and the ingress charge apply; `ARBM`/`ARBF` complete the protocol; `frame_at` streams, and a chunk frame carries the hash it was built with. `a_bulk_transfer_through_the_kernel_assembles_the_body`, `a_request_frame_round_trips_and_refuses_an_off_plan_index`, `a_finish_marker_names_the_transfer` |
| 6 | medium | `finish` peaked at 2-3x the advertised ceiling and hashed every byte three times | **fixed**: chunks are removed from the map as they are appended (peak = body + one chunk) and the accept path uses the hash `decode` already verified, so a byte is hashed twice (decode + final verify) |
| 7 | medium | `decode` accepted a 16 TiB claim from a 64 MiB frame and allocated the hash vector before any ceiling check | **fixed**: the declared total and the chunk count (65 536) are checked before `Vec::with_capacity`; `a_plan_counts_are_bounded_before_allocation` |
| 8 | low | the idempotent call path had no payload parameter, a free-payload path for any future dispatcher | **fixed**: `call_idempotent_as_with_payload` charges the payload and includes its size in the fingerprint; `an_idempotent_call_with_a_payload_is_charged_and_fingerprinted` |
| 9 | low | `BulkPlan::new` truncated the chunk count to `u32` instead of using `expected_chunks` | **fixed**: `new` goes through `expected_chunks` (which now also enforces `MAX_CHUNKS`), with a `debug_assert` on the hash count |
| 10 | low | `BulkChunk::new` accepted >8 MiB and `encode` truncated the length to `u32` | **fixed**: `BulkChunk::try_new` refuses an oversized chunk and a zero chunk size; `a_chunk_cannot_exceed_the_frame_ceiling` |
| 11 | low | `frames_from` silently accepted an impossible resume point (a stall) while `frames_for` errored | **fixed**: `frames_from` returns `Result` and refuses `from > chunks` |
| 12 | low | `Debug` dumped raw body bytes (log exfiltration, log bomb) | **fixed**: manual `Debug` for plan, chunk, sender, receiver and provider prints shape only; `debug_does_not_print_the_body` |

Also fixed while triaging: `Call` gained `payload` (the kernel now hands the
envelope payload to a provider instead of discarding it after the charge), and
the fuzz target `fuzz_bulk_plan` now drives `BulkReceiver`/`finish`/`BulkRequest`
instead of only the decoders.

Spec corrections: `docs/spec/wire.md` §9 (frames travel as envelope payloads,
`ARBM`/`ARBF`, bounded counts, the context in the root, the 1 MiB strict-profile
note) and ADR-0013 (the root is integrity, not authority; `finish` verifies the
body against the plan rather than "recomputing the root"; the ceiling language).
`tests/doc_gate.rs` now lists `rpc/bulk`.

Gate: `cargo test --all-features` 514 passed, 0 failed; `--no-default-features`
465 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the bulk, transport and frame suites pass in `rust:1.88-bookworm`.
`tests/bulk_hardening_tests.rs` (14) is new.

### R-09 transports - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `c89cf3b`.
No critical. Four highs, eleven mediums and three lows; it proved the highs with
temporary probes and deleted them, leaving the tree clean. Every finding below is
fixed here with a test; the two frame oracles were shown to fail pre-fix with a
targeted mutation (`read_frame` reserved **67 109 933 bytes** from a four-byte
header, and `serve_connection` returned `Err` after a bad frame).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a non-UTF-8 request head killed the bridge: `read_line` returns `InvalidData` and `serve` propagated it, so one packet ended `active-rpc peer --transport connect` | **fixed**: the head is read as bytes under the remaining budget and decoded lossily; a head fault answers `400 rpc/wire` for that connection; `a_non_utf8_request_head_is_a_400_and_the_bridge_keeps_serving` |
| 2 | high | the bridge had no read deadline and accepts serially: one `POST …` without a newline blocked every later peer indefinitely | **fixed**: `CONNECTION_WAIT` (2 s) on every accepted stream, and a stalled connection answers 400 and returns; `a_stalled_head_does_not_block_the_next_connection` |
| 3 | high | `serve_connection` returned the peer's error after replying, and `peer.rs` plus the CLI use `?`, so one bad frame ended the process | **fixed**: a frame error ends the connection and returns `Ok(served)`; the mutation that restores `Err` makes the test fail; `a_malformed_frame_ends_the_connection_not_the_server` |
| 4 | high | QUIC read streams serially with no deadline: a stream that sent four bytes and stopped parked every later stream forever | **fixed**: each stream runs on its own task with `STREAM_WAIT` (10 s), so a stalled stream cannot block the others; `a_stalled_stream_does_not_block_another_stream` |
| 5 | medium | `read_frame` allocated the announced body immediately: a four-byte header forged a 64 MiB zeroed buffer per connection | **fixed**: the body grows with the bytes that arrive (`take(len).read_to_end`), verified against the announced length; `a_maximum_length_header_does_not_reserve_the_body` (tracking allocator, measured) |
| 6 | medium | QUIC `read_to_end(64 MiB)` per stream meant 256 connections could pin 16 GiB, and the window constants did not bound it | **fixed**: the frame prefix is read and validated first, the body is read to exactly that length, and a server-wide `MAX_INFLIGHT_BODY` (256 MiB) budget refuses the excess with `rpc/backpressure` |
| 7 | medium | QUIC ignored bytes after the frame, while the bridge refused them | **fixed**: the stream is read to exactly the announced length, and quinn reports `TooLong` for a longer stream (`rpc/wire`); `trailing_bytes_after_a_quic_frame_are_refused` |
| 8 | medium | QUIC hardcoded `WireLimits::default()`, so a server could not apply `strict()` | **fixed**: `QuicServer::with_limits` writes through a shared lock that the serve task reads per stream, and the client has `with_limits`; `quic_applies_the_server_wire_limits` |
| 9 | medium | 256 QUIC slots with a 5 s keep-alive: keep-alive defeats the idle timeout, and a full table dropped newcomers | **fixed**: keep-alive is gone (the 30 s idle timeout frees slots), a full table waits up to `HANDSHAKE_WAIT` for a slot, and a handshake that outlives it is abandoned |
| 10 | medium | a one-to-three-byte header at end of stream was reported as a clean close | **fixed**: a partial header is `rpc/transport`; `a_partial_header_at_end_of_stream_is_refused` |
| 11 | medium | `SharedSegment::advance(len)` trusted its argument: a wrong length left `tail` inside a payload, and `advance(usize::MAX)` overflowed | **fixed**: `advance()` reads the length from the frame header, bounds-checks it and returns `Result`; `shared_memory_write_is_total_after_a_desynchronised_advance` |
| 12 | medium | the "zero-copy" claim was false: the frame is borrowed but the decoded envelope owns a copy of the payload | **fixed**: the claim is corrected in the module docs, ADR-0003 and `wire.md`, and `recv_zero_copy` is renamed `recv_in_segment` with the cost stated |
| 13 | medium | a duplicate `content-length` or any `transfer-encoding` was accepted by the bridge (request smuggling behind a proxy) | **fixed**: exactly one length, no transfer coding; `conflicting_framing_headers_are_refused` |
| 14 | medium | `MAX_HEAD` was checked only after `read_line` had buffered the whole line | **fixed** with the byte-bounded head read; `a_head_line_without_a_newline_is_refused_at_the_ceiling` |
| 15 | medium | an HTTP/2 peer's `rpc/...` refusal collapsed to `rpc/provider` and its body could be carried into the error | **fixed**: `Error::provider_code` exposes the class, the body is read as a bounded token and anything else becomes `rpc/provider`; `the_client_preserves_a_peer_refusal_code` |
| 16 | medium | one HTTP/2 `accept` error aborted the server | **fixed**: transient accept errors are retried, and only `MAX_ACCEPT_FAILURES` in a row is fatal |
| 17 | medium | HTTP/2 has no identity parameter, although `docs/deployment/identity.md` told deployers to pass one | **fixed**: the deployment doc now states that the shipped HTTP/2 transport is plaintext, carries no identity, and that a bound capability needs QUIC mutual TLS. Documented residual: there is no identity channel on this transport |
| 18 | medium | no transport checked `Envelope::kind`, so a response envelope carrying a capability and a method was dispatched | **fixed** on TCP, the bridge, HTTP/2, QUIC and the CLI dispatcher; `a_response_envelope_is_refused_on_the_framed_and_bridge_transports` |
| 19 | medium | the bridge's served-count assertion in `tests/integration_tests.rs` was swallowed by a mangled comment (`\n` escapes) | **fixed**: the assertion is restored, with the count corrected to mean "calls that reached the handler" |
| 20 | low | the QUIC client hardcoded SNI `localhost`, so a certificate for `rpc.internal` could never verify | **fixed**: `QuicClient::connect_with_name` |
| 21 | low | `MAX_FRAME_BYTES` was documented as the transport ceiling but `read_frame` honoured only `WireLimits`; a partially written frame left the TCP stream reusable | **fixed**: the ceiling is `min(limits.max_bytes, MAX_FRAME_BYTES)`, and a failed write poisons the connection |
| 22 | low | shared-memory counters went backwards on drain, compaction allocated a full copy, and the inspection closure ran under the lock | **fixed**: lifetime byte and frame totals, `copy_within` for a contiguous unread region, and the re-entrancy contract documented |

Also updated: `docs/spec/wire.md` (transport table, error-class note) and
`docs/adr/0003-transports.md` (the borrowed-read claim).

Gate: `cargo test --all-features` 500 passed, 0 failed; `--no-default-features`
451 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the 10 transport tests, 3 frame tests and 11 tool tests pass in
`rust:1.88-bookworm`. `tests/transport_hardening_tests.rs` and
`tests/transport_frame_tests.rs` are new.

### R-08 tools / MCP - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `db3af5a`.
It reproduced the gates itself and probed each carried fix. Verdicts: #11
(HTTP framing) and #14 (notification skip) verified; #8, #9, #15 verified with
caveats; three new highs and six mediums came out of the same pass, all fixed
here. Every fix carries a test, and each test was shown to fail against the
tree before it.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 8 | medium | a bare program name resolved from the ambient `PATH`, and `cwd` was inherited (carried from round 1) | **fixed**: `pin_program` refuses a non-absolute path and pins the canonical one; `LocalProcess::with_current_dir` pins the directory (refusing a relative one), `StdioTransport` pins it at spawn; `taskkill.exe` comes from `SystemRoot`; `a_bare_program_name_is_refused` |
| 9 | medium | a timeout killed the direct child only; the readers were detached (carried) | **fixed**: the child leads its own process group on Unix and the group gets SIGKILL (`/bin/kill`, then `/usr/bin/kill`); Windows keeps `taskkill /T`; `a_timeout_kills_the_descendant_tree` (proved on Linux) |
| 11 | low | a GET carried `content-length: 4` and a `"null"` body (carried) | **fixed**: only POST, PUT and PATCH send content; `a_get_request_has_no_body`, `a_post_carries_its_body_and_length` |
| 14 | low | an MCP notification desynchronized the session (carried) | **fixed**: a frame without an `id` that has a `method` is skipped up to `MAX_MCP_NOTIFICATIONS` (16), then the session is poisoned; `a_notification_before_the_response_is_skipped`, `exactly_the_notification_ceiling_is_skipped` |
| 15 | low | `bounded_description` missed U+2028/U+2029 and invisible formatters (carried) | **fixed**: separators, bidi controls, zero-width joiners, tag characters, invisible operators and variation selectors become spaces; `a_description_cannot_inject_a_line_separator` |
| N1 | high | the reader-wait timeout returned `rpc/timeout` without killing the tree: a leader that exits at once leaves a descendant holding the pipes and acting after the grant was refunded | **fixed**: `kill_process_tree` runs on both timeout paths and on a wait error; `a_timeout_after_the_leader_exits_kills_the_tree` (the mutation that removes only this call makes it fail) |
| N2 | high | the HTTP ceiling was a per-read socket timeout, not a wall deadline: a server dripping a byte per 35 ms held a 60 ms grant for 2.07 s and the call succeeded | **fixed**: one deadline for the exchange, threaded through `DeadlineReader` (connect, every read, body) and re-checked after each read; a timed-out read is `rpc/timeout`; `a_dripping_server_cannot_stretch_the_wall_ceiling` |
| N3 | high | `McpSession::handshake` had no deadline at all: a silent server blocked the caller forever | **fixed**: `DEFAULT_MCP_HANDSHAKE_TIMEOUT_MS` (5 s) covers `initialize` and `tools/list`; `handshake_within` takes an explicit one; `an_mcp_request_carries_a_deadline`, `an_expired_deadline_sends_no_frame` |
| N4 | medium | the duplicate-name check was still a linear scan (round-1 #7's `seen` set was dead code): 8 000 tools took 1 007 ms | **fixed**: one `BTreeSet` insert decides duplicates, and `MAX_MCP_TOOLS` (4 096) bounds the table |
| N5 | medium | stdout and stderr were labelled by channel arrival order (8 of 20 runs swapped) | **fixed**: each reader sends its tag; `stdout_and_stderr_are_not_swapped` (20 runs) |
| N6 | medium | every dispatch rebuilt the MCP method table through the default `has_method` (1.19 ms and ~1 MB per call at 7 000 tools) | **fixed**: `McpSession` and `ModuleProvider` answer from their own tables; `has_method_does_not_rebuild_the_method_table` |
| N7 | medium | HEAD, 204 and 304 responses were read as if they carried a body, so an allowlisted HEAD endpoint stalled until the ceiling | **fixed**: those replies return an empty body; `a_head_response_has_no_body` |
| N8 | medium | a `*` allowlist rule is a command-line prefix: with `cmd /C` and `echo*`, `echo ok & del …` was arbitrary command execution | **fixed**: an argument admitted only by a prefix rule may not contain shell syntax (command separators, redirection, `^`, parentheses, quotes, `$`, backtick, `%`, newline, NUL); `a_prefix_argument_cannot_smuggle_a_command` |
| N9 | low | tag characters, U+2061-U+2064, U+180E and variation selectors survived the description scrub | **fixed** with the carried #15 |
| N10 | low | a repeated or unparsable `content-length` silently switched framing | **fixed**: `http/headers`; `a_repeated_content_length_is_refused` |
| N11 | low | `Value::Path` and the `request` method text reached the request line unsanitised | **fixed**: a control character in either is `rpc/tool-policy`; `a_path_with_a_control_character_is_refused` |
| N12 | low | the MCP deadline was checked after `send_line`, so an expired call still mutated the server | **fixed**: the check runs before the frame leaves; `an_expired_deadline_sends_no_frame` |
| N13 | low | `StdioTransport` children had no process group and `Drop` killed the leader only | **fixed**: `process_group(0)` at spawn and `kill_process_tree` on drop |
| N14 | low | test gaps: the notification boundary, a server-initiated request, a framing fault, and the fuzz target still passing a text path | **fixed**: four tests plus `fuzz_tool_http` now sends `Value::Path` |
| N15 | low | `lane_queue_depth` walked the queue per lane on every dashboard snapshot | **fixed**: `Agent::lane_queue_depths` is one pass; the control plane uses it; `lane_queue_depths_count_the_undispatched_calls` |
| N16 | low | two wall-ceiling tests flaked under a saturated parallel run (5 s bound) | **fixed**: the bound is 10 s, and the comment says why the margin exists |
| N17 | low | the control plane is a separate workspace, so root `cargo test` never builds it (it did not compile at `fd64122`) | **fixed**: it was repaired and CI's `control-plane` job (format + tests) is green; the root workspace is unchanged on purpose, because the crate has its own dependency set |

Residual risks recorded, not defects: the `poisoned` flag is provider-wide, so
one desync ends every capability on that MCP provider; a transient MCP timeout
poisons the session on the next call (the abandoned answer is an id mismatch);
`SystemRoot` is trusted to locate `taskkill.exe`; a distroless image with
neither `/bin/kill` nor `/usr/bin/kill` falls back to the leader only; Windows
children inherit every inheritable handle (no `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).

Gate: `cargo test --all-features` 487 passed, 0 failed; `--no-default-features`
441 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the 11 tool tests and the fuzz crate build in
`rust:1.88-bookworm`, where both process-group tests run.

### R-07 domain operations - 2026-11-01 (round 1, in progress)
Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `22c3d66`.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| D-1 | critical | `Call.path_scope` was never enforced by the domain provider: a capability confined to `app` returned the whole module (pathless `evaluate`, `patch` outside the scope, `stats`/`annotations`/`provenance`/`content_hash`, and dependents labels) | **fixed**: `ModuleProvider::serve` refuses a path outside the scope and refuses a pathless form under a scope (`rpc/path-not-granted`); `tests/domain_scope_tests.rs` (4) |
| D-2 | high | metadata queries ignore `Budget` and are quadratic: `why`/`impact` took 2.5 s at 3 000 nodes and 10.7 s at 6 000 (measured) | **fixed**: one adjacency and one path map per call, `max_nodes` refused as `rpc/budget-exceeded`, and a walk past `max_wall_ms` refused; `why_is_linear_in_module_size`, `metadata_queries_respect_max_nodes` |
| D-3 | high | an unchecked index in the taint walk, a quadratic taint fixpoint, and a panicking call that destroyed the module object | **fixed**: one Kahn pass over a checked adjacency, `invoke` re-inserts the slot through `catch_unwind` and resumes the unwind, and `install` validates a module as canonical before storing it; `a_deep_chain_redacts_quickly` (4 000 links, 4.9 s measured before), `install_refuses_a_dangling_locator` |
| D-4 | high | `restrict`/`subgraph` dropped annotations, so a projection lost `@ai_immutable` and a constraint whose expression was outside the cone | **fixed**: the cone grows to include every in-cone constraint expression, annotations are remapped, and bindings plus provenance travel with it; `subgraph_preserves_annotations` |
| D-5 | medium | `patch` ignored `@ai_immutable` and replaced the provenance with an empty one | **fixed**: a target or ancestor under `@ai_immutable` is `rpc/read-only`, and the new provenance keeps the producer chain with the old content address as `parent`; `patch_refuses_an_ai_immutable_node`, `patch_preserves_the_parent_provenance` |
| D-6 | medium | provenance/annotation text left a copy of a secret literal as ordinary text | **fixed**: the provenance map is built from `interop::provenance_lines` (a copy becomes the marker), and `install` refuses a non-canonical arena that could carry one; `provenance_redacts_secret_literals` |
| D-7 | medium | a scoped `patch` changed a value outside the scope through a shared node | **fixed**: a scoped write is refused (`rpc/path-not-granted`) when any named dependent of the target lies outside the scope; `a_scoped_patch_cannot_change_a_value_outside_its_scope` |
| D-8..D-12 | low | redacting `stats` disclosed the secret count and hidden annotations their node id; lowering faults used `rpc/payload`; the drop log was unbounded; `timestamp_ms as i64` wrapped; a refused call counted as served | **fixed**: the count is omitted under `redact`, a hidden annotation names no node, encode/lower faults are `rpc/domain` (`active/lower`), `MAX_DROP_LOG` bounds the log, `i64::try_from` clamps, and `calls` advances only after the slot is taken |

Gate after the D-2..D-12 work: `cargo test --all-features` 466 passed, 0 failed
(and the `--no-default-features` suite green); clippy clean on both feature sets;
fmt clean.

### R-05 lanes / channels - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`. Tests:
`tests/lane_tests.rs` (10, the file the section map named); six fail on the
pre-fix tree, four are coverage of behaviour that already worked (the lane
charge from R-02 round 2, per-channel byte accounting, and the documented
"a lane is not an authority boundary").

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `destroy_lane` scrubbed the queue with a linear `Vec::contains` per job: 40 000 jobs blocked the kernel for 10.6 s (measured) | **fixed**: a `BTreeSet` of doomed ids; `destroying_a_full_lane_does_not_block_the_kernel` asserts a 5 s ceiling on 40 000 jobs |
| 2 | medium | a publish checked the message count but not the channel's byte ceiling, charged every meter, and then the channel refused: the grant was gone and nothing was queued | **fixed**: capacity is checked before any charge and answers `rpc/backpressure`; `a_publish_refused_on_a_full_channel_charges_nothing` |
| 3 | medium | no aggregate queued-byte ceiling: 4 096 channels × 64 MiB is 256 GiB | **fixed**: `MAX_QUEUED_CHANNEL_BYTES` (256 MiB) is tracked by the kernel and released on receive and on channel destroy |
| 4 | medium | `Channel::close()` was unreachable: `Agent::channel` returns a snapshot | **fixed**: `Agent::close_channel`; `closing_a_channel_stops_sends` |
| 5 | low | `Lane.caps` and `Lane.ready` were never written and the module doc described a scheduler that does not exist | **fixed**: both fields and the stale doc are gone; the module now states that a lane is a budget and lifecycle scope, not an authority boundary; `a_lane_is_not_an_authority_boundary` |
| 6 | low | send/publish refusals were not counted and a duplicated capability id double-counted a transfer | **fixed**: `note_refusal` counts and logs them, and a duplicate id is `rpc/invalid-argument`; `refusals_are_counted`, `a_message_cannot_transfer_the_same_capability_twice` |
| 7 | low | `attenuate_lane` does not invalidate work already reserved under the old ceiling | **documented**: reservations are final (the call was charged against the old grant); the doc now says so |
| 8 | low | names were unbounded and subscriptions had no per-lane cap | **fixed**: `MAX_OBJECT_NAME_BYTES` (256) and `MAX_CHANNELS_PER_LANE` (1 024); `names_and_subscriptions_are_bounded` |
| 9 | low | every send cloned the payload although only the sequence was used | **fixed**: `Channel::send_sequence`; the kernel uses it |
| 10 | low | `recv` is ambient: a provider holding the agent can drain any channel | **carried**: this is the documented residual (R-02 #8b/#17) and needs an ADR for subscription-based receive |

Gate: `cargo test --all-features` 440 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-04 promises / pipeline - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`. Tests:
`tests/promise_tests.rs` (15), the file the section map named and that did not
exist; fourteen of them fail on the pre-fix tree. The fifteenth covers the
phase-3 settlement gating, which this scenario cannot reach, so it is coverage
and not proof.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | promise ids were accepted from any lane and from envelopes: cross-tenant disclosure plus a membership oracle | **fixed**: a dependency must have been minted on the calling lane, and `Agent::call_from_envelope` refuses promise and capability arguments for transports (used by `peer.rs` and `thin_peer`); `promise_from_another_lane_is_refused`, `an_envelope_cannot_carry_authority_arguments` |
| 2 | high | the idempotency key outlived its promise, so a replay silently re-executed a mutating call | **fixed**: `trim_settled` pins a record an idempotency key still names; `an_idempotent_replay_survives_the_retention_window` |
| 3 | medium | an idempotent replay skipped lane existence, closure and capacity and was not lane-scoped | **fixed**: the lane is validated before the cache lookup and the key includes it; `an_idempotent_replay_needs_a_live_lane`, `an_idempotent_key_is_lane_scoped` |
| 4 | medium | cancelling a promise in the current batch completed its lane twice and logged a settlement that never happened | **fixed**: only a job still in the queue is dequeued, and phase 3 emits the event and the metric only when the transition succeeded; `cancelling_inside_dispatch_counts_once` |
| 5 | medium | `resolve` left the producing job queued: the provider ran anyway and the settlement was counted twice | **fixed**: a successful out-of-band resolve dequeues its job; `resolving_a_queued_promise_prevents_the_provider_call` |
| 6 | medium | a promise retain/release was dropped when the kernel was borrowed, so a live handle lost its record | **fixed**: promise reference operations queue in FIFO order and are drained by `run`; `a_clone_under_a_borrow_keeps_the_handle` |
| 7 | medium | `cancel_tree` was O(targets × jobs): a 4 000-link chain blocked the kernel for 3.1 s (measured) | **fixed**: one reverse index and a `BTreeSet` of targets |
| 8 | medium | `run`/`await_promise` from `on_drop` failed that provider's queued work as `rpc/provider` | **fixed**: `next_batch` skips a provider that is being notified and `run` returns when nothing is runnable; `run_from_on_drop_does_not_kill_queued_jobs` |
| 9 | low | a re-entrant `run` silently succeeded while a re-entrant await returned `rpc/provider` | **fixed**: both are now "no progress"; the await reports `rpc/unresolvable-promise`, which does not invite a retry |
| 10 | low | `PromiseRecord.waiters` was incremented and never released | **fixed**: every job removal releases its dependencies; `waiters_return_to_zero` |
| 11 | low | `Arg::Cap` from an envelope was forwarded unvalidated | **fixed** with finding 1 |
| 12 | low | rejected error text did not count toward the retention ceiling | **fixed**: `record_settled` charges the error text |
| 13 | low | `peek` on a pending promise returned the terminal `rpc/unresolvable-promise` | **fixed**: a pending peek is `rpc/invalid-argument`; `peek_on_a_pending_promise_is_not_unresolvable` |
| 14 | low | the section's test file did not exist | **fixed**: `tests/promise_tests.rs` |

### R-03 capabilities - 2026-11-01 (round 3)

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| H-1 | high | a virtual deadline is not comparable across kernels (unrelated epochs), and attenuation stamped a child with the parent's domain | **fixed**: a child is stamped with the clock that produced its deadline, attenuation refuses a bounded parent from the other domain, and the record carries a sealed `lease_ms` that restore uses as the ceiling; `a_child_after_a_clock_switch_is_stamped_with_the_new_domain`, `a_virtual_deadline_does_not_inflate_across_a_restart` |
| M-3 | medium | export wrote the grant, not the remainder, so export/drop/restore refilled a spent budget | **fixed**: the record carries the remaining calls and bytes, and a spent grant is refused; `a_restored_copy_cannot_refill_a_spent_grant` |
| L-1 | low | restore accepted an unbound record and bound it to any admitted peer | **fixed**: `rpc/identity`; `an_unbound_record_is_refused_by_restore` |
| L-2 | low | the tombstone ceiling was soft | **fixed**: the ceiling counts live durable grants as well, so revoke cannot pass it |
| L-3 | low | a full tombstone set turned a valid restore into `rpc/budget-exceeded` | **fixed**: `mint_restored` bypasses the tombstone ceiling |
| L-4 | low | export emitted `path_scope: ""`, which `from_json` refuses | **fixed**: an empty scope is refused at export |
| L-5 | low | a borrow failure mid-delivery discarded already-taken notifications | **fixed**: entries are pushed back before returning |

Gate: `cargo test --all-features` 430 passed, 0 failed; clippy clean on both
feature sets; fmt clean; the nine negative controls pass.

### R-03 capabilities - 2026-11-01 (round 2)

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | a derived capability freed its ancestors' meters when the parent handle dropped | **fixed** with the same `descendants` accounting as R-02 H-2 |
| F2 | high | tombstones were memory-only, so a restart resurrected a revoked durable record, and `revoke` on a dropped record was a silent no-op | **fixed**: `Agent::tombstone_record` / `record_is_tombstoned` / `record_tombstone_count` let a deployment replay its kill list, and `revoke` returns `Result` with `rpc/unknown-capability` for an id that is not live; `a_tombstone_replayed_at_startup_refuses_the_record` (API-addition test) |
| F3 | medium | one record restored into N independent grants | **fixed**: `restoring_the_same_record_twice_is_refused` |
| F4 | low | every revocation tombstoned an ephemeral record id, forever | **fixed**: only durable records are tombstoned, and the set has a ceiling (`MAX_TOMBSTONES`) that refuses a new durable mint instead of evicting; `a_revocation_tombstones_only_durable_records` |
| F5 | low | the deferred ref-op drain was one-shot, so a retain queued during the drain could be overtaken | **fixed**: `enqueue_or_apply` keeps FIFO across both paths and the drain loops (bounded); exercised by `a_drop_raised_inside_on_drop_is_delivered_once` |
| F6 | medium | `on_drop` ran under a borrow | **fixed** with R-02 M-5 |
| F7 | low | `revoke` rebuilt the whole ancestor index per call | **fixed**: `Kernel.children` is maintained on attenuation and drop, so a revocation walks only its subtree. Event volume stays one `CapRevoked` per record (the honest record of the action); the aggregate event is not worth a contract change |
| F8 | medium | `await_promise` livelocked inside a provider | **fixed** with R-02 H-3 |
| F9 | low | an unbound record exported before `introduce_to` restored for any peer | **fixed**: export refuses an unbound durable capability (`rpc/identity`); `an_unbound_durable_capability_cannot_be_exported` |

Carried as accepted residuals (documented, not defects): `max_bytes` bounds
ingress, not egress; `Value::wire_size` recurses under the decoder's nesting
limit; a revoked capability keeps its registry slot while a handle exists;
rotating the seal key invalidates earlier records (by design, documented in
ADR-0010).

Gate: `cargo test --all-features` 414 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-02 kernel dispatch - 2026-11-01 (round 2)

Reviewer: same DeepSeek V4.1 Flash channel, `xhigh`, repository tool access.
Tests: `tests/marathon_kernel_round2_tests.rs` (9); eight of them fail against
the pre-fix tree (the ninth is a guard that must pass on both trees). The
pre-fix run also exposed the livelock the round-1 note called a "cycle": the old
selector returned an empty batch for a blocked head provider and the queue never
advanced, so the test binary spun for 17 minutes of CPU before it was killed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 4 | medium | cross-provider pipeline failed as a cycle | **fixed**: `next_batch` scans providers in queue order and dispatches the first one with a runnable job; `order_candidates` only returns jobs whose dependencies are settled or produced earlier in the same batch; `a_cross_provider_pipeline_settles` |
| 6 | medium | a wall-clock record restored into a virtual kernel kept a deadline from another clock domain | **fixed**: `CapabilityRecord.wall_clock` travels in the JSON and `restore_capability` refuses a mismatch with `rpc/persistence`; `a_record_carries_its_clock_mode`, `a_wall_clock_record_does_not_restore_unbounded_in_virtual_mode` |
| 8 | medium | `publish` ignored `read_only` | **fixed**: a read-only grant cannot publish (`rpc/read-only`); `a_read_only_capability_cannot_publish` |
| 9 | medium | lane byte ceilings were per call and `publish` skipped the lane call budget | **fixed**: `Lane.bytes` accumulates both, and `publish` consumes lane calls and bytes; `a_lane_byte_budget_is_cumulative`, `publish_counts_against_the_lane_budget` |
| 10 | medium | `on_drop` was lost when the last reference died during dispatch | **fixed**: `Kernel.deferred_drops` holds the notification until the provider is re-inserted, then delivers it; `on_drop_is_delivered_when_a_provider_releases_during_its_own_call` |
| 11 | low | a nested `run()` inside a provider failed unrelated queued work | **fixed**: `Kernel.dispatching` makes the nested call return the current round-trip count while the outer dispatch continues |
| 18 | low | `restore_capability` took the first provider whose name matched | **fixed**: exactly one match is required (`rpc/persistence`); `restore_refuses_an_ambiguous_provider_name` |

Gate: `cargo test --all-features` 384 passed, 0 failed; clippy clean on the
default and all-features sets; fmt clean.

Carried (contract decisions, logged rather than half-fixed):

| # | Sev | Reason |
|---|-----|--------|
| 8b | low | `topics: None` means "any topic" and a grant with no publish method can publish; channel authority is ambient by design, so changing it needs an ADR |
| 17 | low | `recv`/`recv_topic` ignore lane subscription; subscription is advisory today and the contract needs an ADR |

### R-03 capabilities - 2026-11-01 (round 1)

Reviewer: Copilot CLI routed to CommandCode DeepSeek V4.1 Flash, `xhigh`, with
repository tool access. Tests: `tests/marathon_cap_tests.rs` (17); all 17 fail
against the pre-fix tree, proved by stashing `src/` and adding only the API
surface the tests name (no behavioural shim).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | path scope was checked only against the queued arguments, so a promise argument delivered a `Path` the scope never saw | **fixed**: dispatch re-walks the resolved arguments; `a_pipelined_argument_cannot_carry_a_path_outside_the_scope` (asserts the provider never runs) |
| 2 | critical | the byte budget and the tool argument ceiling counted a promise as its 8-byte placeholder | **fixed**: dispatch measures the resolved arguments, refuses over the effective budget and the policy ceiling, and charges the difference to the capability, every ancestor and the lane before the provider runs; `a_pipelined_argument_is_charged_at_dispatch` |
| 3 | critical | a policy-less parent accepted any child `ToolPolicy`, so attenuation could grant `allow_process` | **fixed**: `CapAttrs::effective_tool_policy` (own methods, own byte budget, no process) is the parent for the comparison, in the predicate and in `attenuate`; `attenuation_cannot_add_process_execution` |
| 4 | high | a durable record revived a revoked capability | **fixed**: `CapRecord::record_id` (secret-derived, carried in the record) is tombstoned by `revoke` and refused by `restore_capability` with `rpc/revoked`; `a_revoked_durable_capability_cannot_be_restored` |
| 5 | high | records were unauthenticated authority: whoever wrote the JSON could mint what it described | **fixed**: `Agent::set_record_seal_key` + keyed Blake3 seal over every field, constant-time check before any field is read; a kernel without a key exports and restores nothing; `an_edited_or_unsealed_record_is_refused` |
| 6 | high | a child call did not consume the parent's budget, so delegation multiplied the grant | **fixed**: a call charges its whole lineage, checked first and then charged; publish does the same; `a_child_call_consumes_the_parent_budget` |
| 7 | high | `parse_hex32` sliced a 64-**byte** string of multi-byte characters and panicked | **fixed**: ASCII is required before slicing; `a_non_ascii_record_field_is_refused_without_panicking` |
| 8 | medium | `BudgetMeter::charge` compared with `saturating_add` and then added, so a byte count at the ceiling panicked in debug and wrapped in release | **fixed**: `checked_add` through `check`/`charge`, plus `check_bytes`/`charge_bytes` for dispatch; `a_meter_at_the_ceiling_never_wraps` |
| 9 | medium | `HttpTool` took a path from `Value::Text` that starts with `/`, so the kernel's path scope never saw it | **fixed**: the adapter reads `Value::Path` only; `a_text_argument_is_not_an_http_path` |
| 10 | medium | `to_active_budget` derived ceilings larger than the grant (`max_value_size * 4`) | **fixed**: derived ceilings are clamped to the grant; `evaluator_ceilings_never_exceed_the_grant` |
| 11 | medium | `CapTableDelta::apply_to` had no table ceiling | **fixed**: `MAX_CAP_TABLE` (4096) with `rpc/capability-table`; `a_delta_cannot_grow_the_table_past_its_ceiling` |
| 12 | medium | `retain`/`release` returned silently when the kernel was borrowed, so a handle dropped inside a provider notification lost its release | **fixed**: the operation is queued on a shared `Rc<RefCell<Vec<(CapId, bool)>>>` and applied at the next kernel borrow; `a_drop_inside_a_provider_notification_is_applied` |
| 13 | low | `CapabilityRecord::attrs` dropped `bound_to`, so the natural restore path minted an unbound capability | **fixed**: the binding is carried; `record_attrs_preserves_the_binding` |
| 14 | low | `export_capability` accepted an id-only (imported) handle | **fixed**: `CapHandle::is_owning` gates export; `export_from_an_imported_handle_is_refused` |
| 15 | low | duplicate method names decoded to a smaller set and re-encoded differently | **fixed**: a duplicate is `rpc/capability-table`; `a_descriptor_is_canonical_or_refused` |
| 16 | low | a descriptor with no methods was accepted by the wire and by `apply_to` | **fixed**: refused in both; `a_descriptor_is_canonical_or_refused` |
| 17 | low | durable-policy refusals used `rpc/capability-table` (a hostile-peer fault) while export/restore used `rpc/persistence` | **fixed**: both are `rpc/persistence`; `tests/persistence_tests.rs` and the round-1 kernel test updated |
| 18 | low | `CapHandle::into_id` leaked a reference and had no caller | **fixed**: removed |
| 19 | low | the registry and the attenuation chain were unbounded, and `revoke` was quadratic | **fixed**: `MAX_CAPS` (65536), `MAX_LINEAGE_DEPTH` (64), and a single parent/lineage index per revoke; `the_registry_and_the_lineage_are_bounded` |
| 20 | low | `cap_table_hash` asserted the encoding succeeded | **fixed**: it returns `Result`, so an unencodable table has no hash |

Also closed in this round (found while fixing): `publish` charged only the
payload, so a 1 KiB topic name rode through a 32-byte grant; it now charges
topic bytes and the lineage (`tests/topic_tests.rs`,
`a_publish_charges_the_capability_byte_budget`).

Documented residual (the predicate is honest, the operation is strict): a child
that omits the identity binding reports monotone because `attenuate` inherits
the parent's binding. `CapAttrs::is_attenuation_of` now says so, and a caller
validating foreign attributes must apply the binding itself.

Gate: `cargo test --all-features` 401 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-01 wire ARP1 — 2026-10-31

Reviewer: Copilot CLI → Muse proxy, `xhigh`, repo tool access. Tests:
`tests/marathon_wire_tests.rs` (5); three of them fail against the pre-fix tree.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | list/map counts are checked against the frame budget, not the remaining bytes | **rejected**: every iteration consumes at least one byte and fails when the input ends, so the loop is bounded by the frame; the preallocation is capped at 1024. The check is coarse, not an amplification |
| 2 | medium | `Value::Bool` accepted any non-zero byte and re-encoded as 1 (§8.5 re-encode stability) | **fixed**: only 0 and 1 decode; `a_boolean_that_is_not_zero_or_one_is_refused` |
| 3 | medium | faults inside a capability descriptor leaked `rpc/wire` instead of `rpc/capability-table` | **fixed**: `read_cap` translates scalar-reader faults and keeps descriptor-level reasons; `a_zero_capability_id_is_refused` |
| 4 | medium | duplicate map keys collapsed on decode and re-encoded shorter | **fixed**: a duplicate key is `rpc/wire`; `a_duplicate_map_key_is_refused` |
| 5 | low | `len as u32` casts in the encoder | **rejected**: every count is bounded by `WireLimits` before it can reach `u32::MAX`, and the payload path checks explicitly |
| 6 | low | `cap_table_hash` hashed the empty table on an encode error (fail-open) | **fixed**: the encoder's invariant is asserted, so two tables can never share the fallback hash |
| 7 | low | a zero capability id was accepted | **fixed** on both the wire path and the programmatic delta path; the id is not a capability |
| 8 | low | `CapTableDelta::apply_to` skipped the budget check the wire path applies | **fixed**: added descriptors are checked for a disabling budget; `a_delta_addition_with_a_zero_budget_is_refused` |

Gate: clippy clean; `cargo test --all-features` 365 passed, 0 failed.

### R-02 kernel dispatch - 2026-11-01 (round 1)

Reviewer: Copilot CLI routed to CommandCode DeepSeek V4.1 Flash, `xhigh`, with
repository tool access. Tests: `tests/marathon_kernel_tests.rs` (10); all ten
fail against the pre-fix tree (verified by stashing `kernel.rs`/`cap.rs`/
`wire.rs`).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | revocation missed descendants of a dropped intermediate (the record removal broke the parent chain) | **fixed**: `CapRecord::lineage` records every ancestor; `revoke` marks any record whose lineage contains the target; `revocation_reaches_a_grandchild_through_a_dropped_intermediate` |
| 2 | high | a call with an unknown promise dependency charged the meter, inserted a promise and sealed a receipt before refusing | **fixed**: dependencies are validated before any ceiling, charge, receipt or record; waiters increment only after a successful charge; `a_refused_promise_dependency_charges_nothing_and_leaves_no_record` |
| 3 | high | an idempotent cache hit returned a stored promise without re-checking revoke, expiry or the identity binding | **fixed**: `call_idempotent_as` re-checks liveness and binding on a hit; `an_idempotent_replay_is_refused_after_revoke` |
| 5 | medium | durable policy was bypassable through attenuation and export | **fixed**: both check `allow_durable`; `disabling_durable_refuses_attenuation_and_export` |
| 7 | medium | path scope only inspected top-level `Value::Path`; a nested list/map path escaped | **fixed**: the scope walk is recursive; `a_nested_path_argument_is_outside_the_scope` |
| 12 | low | a cap-table delta could remove an id and re-add it with wider authority | **fixed**: an added id that exists in the base table is refused; `a_delta_cannot_replace_an_id_with_a_wider_descriptor` |
| 13 | low | `send_as` reported `rpc/invalid-argument` for an unknown capability | **fixed**: `rpc/unknown-capability`; `send_reports_an_unknown_capability` |
| 15 | low | `mint_bound` silently overwrote a caller-supplied `bound_to` | **fixed**: a conflicting binding is `rpc/identity`; `mint_bound_refuses_a_conflicting_binding` |
| 16 | low | `subscribe` was refused with `rpc/backpressure` when the queue was full although it enqueues nothing | **fixed**: the check is gone; `subscribe_is_not_refused_by_a_full_queue` |
| 14 | low | idempotency keys were unbounded and the order deque grew on stale keys | **partly fixed**: keys are capped at `MAX_IDEMPOTENCY_KEY_BYTES` (256) and stale keys are removed from the deque; `an_oversized_idempotency_key_is_refused` |

Carried to round 2 (triaged, not yet fixed):

| # | Sev | Reason |
|---|-----|--------|
| 4 | medium | cross-provider pipeline: `next_batch` fails jobs whose producer is queued on another provider and mislabels the code as `rpc/unknown-capability`; needs a rework of the batch selector plus a scheduler test |
| 6 | medium | durable restore treats a wall-clock absolute deadline as the importing kernel's domain; needs a clock-mode field on `CapabilityRecord` (format change) and an ADR note |
| 8 | medium | `publish` is authorized by possession alone (no method grant, `read_only` ignored, `topics: None` means any topic); the design intent needs a decision before changing the contract |
| 9 | medium | lane byte budgets are per-call, and `publish` does not consume the lane call budget; needs a lane meter shared by call and publish |
| 10 | medium | `on_drop` is lost when the last reference dies during dispatch (the provider is removed for the call); needs a deferred-drop queue |
| 11 | low | a nested `run()` inside a provider fails unrelated work with `rpc/provider` |
| 17 | low | `recv`/`recv_topic` ignore lane subscription; subscription is currently advisory and the contract needs a decision |
| 18 | low | `restore_capability` resolves a provider by `name()`, first match wins when two share a name |

Gate: `cargo test --all-features` 375 passed, 0 failed; clippy clean on the
default and all-features sets; fmt clean.
