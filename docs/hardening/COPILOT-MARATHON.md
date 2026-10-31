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
| R-02 | kernel dispatch | `src/kernel.rs` | pending | — | — |
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
