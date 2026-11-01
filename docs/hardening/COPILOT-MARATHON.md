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
| R-03 | capabilities | `src/cap.rs` | CLEAN (rounds 1-2) | 29 fixed / 0 rejected / 0 open | this commit |
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
