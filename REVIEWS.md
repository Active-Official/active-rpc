# Review record

Independent reviews and the disposition of every finding. Evidence transcripts
are stored with the release (not in the repository): `review-rpc-*.log`.

## Round 1 — 2026-10-27 (serve path: muse proxy, `muse-spark-1.3-contributor`)

The Copilot subscription path returned a monthly quota error; the review ran on
the Meta Muse proxy through the Copilot CLI (BYOK routing), which reads the
repository directly.

| Finding | Severity | Disposition |
|---|---|---|
| `subgraph`/`patch` returned modules with secret nodes | high | fixed in 1.1.0: payloads are redacted projections; `review_module_payloads_are_redacted` |
| Revocation checked only when queueing | high | fixed in 1.1.0: re-checked at dispatch; `review_revocation_after_queueing_prevents_invocation` |
| Byte budget never charged | high | fixed in 1.1.0: recursive `Arg::wire_size` charged and capped; `review_byte_budget_is_charged` |
| Lane capacity ignored queued calls | high | fixed in 1.1.0; `review_lane_capacity_counts_queued_calls` |
| Unbounded value recursion in `wire` | high | fixed in 1.1.0 (depth 64 + size ceilings); `review_wire_rejects_deep_value_nesting` |
| `Budget::check` accepted a zero ceiling for two fields | high | fixed in 1.1.0; `review_zero_ceilings_are_refused_in_every_budget_field` |
| Tool-policy predicate disagreed with the enforcer | medium | fixed in 1.1.0; `review_tool_policy_predicate_matches_the_enforcer` |
| Cancel / lane destruction left work queued | medium | fixed in 1.1.0; `review_cancelled_and_destroyed_work_never_runs` |
| `fail_job` reported `rpc/provider` for a pipelined cycle | medium | fixed in 1.1.0 (errors carry their class) |
| Borrowed-handle clone leaked a reference | medium | fixed in 1.1.0 (clone retains only owning handles) |
| Predictable agent secret | medium | fixed in 1.1.0 (OS CSPRNG); `review_agent_secrets_are_random` |
| Kernel borrow held across provider calls | medium | fixed in 1.1.0; `review_provider_may_call_back_into_the_agent` |
| Annotation redaction heuristic | low | fixed in 1.1.0 (taint-based) |
| Non-atomic shared-memory consume | low | fixed in 1.1.0 (`pop_frame`) |

## Round 2 — 2026-10-27 (same path)

Verification of round 1: (a) no authority survives revocation, cancellation or
lane destruction, (b) no budget bypass through queueing or attenuation, (c) no
secret bytes on the wire. One new finding:

| Finding | Severity | Disposition |
|---|---|---|
| Tool payload ceiling counted only top-level text and modules | medium | fixed in 1.1.1 (recursive wire size); nested-list case added to `threat_argument_bombs_in_memory_budget` |

Round 3 (final): no new findings.
