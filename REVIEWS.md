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
