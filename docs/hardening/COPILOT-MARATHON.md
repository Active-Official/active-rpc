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
| R-02 | kernel dispatch | `src/kernel.rs` | round 1: 9 fixed, 9 open | 9 fixed / 0 rejected / 9 open | this commit |
| R-03 | capabilities | `src/cap.rs` | pending | — | — |
| R-04 | promises / pipeline | `src/promise.rs` | pending | — | — |
| R-05 | lanes / channels | `src/lane.rs`, `src/channel.rs` | pending | — | — |
| R-06 | budget | `src/budget.rs` | pending | — | — |
| R-07 | domain ops | `src/domain.rs` | pending | — | — |
| R-08 | tools / MCP | `src/tool.rs` | pending | — | — |
| R-09 | transports | `src/transport/**` | pending | — | — |
| R-10 | bulk | `src/bulk.rs` | pending | — | — |
| R-11 | identity | `src/identity.rs` | pending | — | — |
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
