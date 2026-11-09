# ADR-0025 - Fail-closed idempotency ceiling

**Status:** accepted (2026-11-09). Behaviour change to `call_idempotent*`:
a new key past `MAX_IDEMPOTENCY` (1,024) is refused instead of evicting the
oldest live claim.

## Context

An idempotency key is an exactly-once promise: replaying a key must return
the original promise, never run the mutating provider a second time. The
kernel kept at most `MAX_IDEMPOTENCY` (1,024) claims in `Kernel::idempotency`,
and past the ceiling it silently evicted the oldest claim
(`idempotency_order.pop_front`). A caller that could issue 1,024 fresh keys
— no privilege beyond the ability to call — evicted a victim's claim, and
replaying the victim's key re-executed the mutating call (RPC-06; audit
probe `probe_sec_f5_idempotency_eviction_double_apply` measured 1,026
provider invocations becoming 1,027 on replay). The rest of the idempotency
path is careful — a replay re-checks revocation, expiry, binding and budget
— which made the eviction the single hole. Claims are also in-memory only:
a restart loses them entirely (audit Part E, P6).

## Decision

1. **Fail-closed at the ceiling.** `call_idempotent_inner` refuses a new
   key with `Error::BudgetExceeded("idempotency")`
   (`rpc/budget-exceeded`) once `idempotency.len() >= MAX_IDEMPOTENCY`.
   The check runs **before** `call_with_origin_payload`: refusing after
   the provider ran would be worse than eviction, because the side effect
   would have happened while the caller was told it had not. It also runs
   after the stale-entry removal in the hit path, so a key replayed
   against a dead promise has already freed its own slot when the check
   runs.
2. **Dead claims are reclaimed, live claims never are.** Before refusing,
   the ceiling path sweeps out claims whose promise can no longer answer a
   replay and retries the check. A table full of live claims still refuses;
   a table padded with dead claims admits the new key. Without this, a
   kernel that had served 1,024 failed or cancelled idempotent calls would
   refuse every further idempotent call for the rest of its life — a naive
   fail-closed fix would have traded silent double-apply for permanent
   self-denial. The sweep is bounded by `MAX_IDEMPOTENCY` and runs only at
   the ceiling, so it costs nothing on the ordinary path.
3. **One predicate for "live".** `idempotency_claim_reusable` is shared by
   the hit path and the reclaimer: pending or resolved promises replay; a
   rejection replays only when the provider withheld its reply
   (`provider/reply-withheld` — the write landed, so the key must keep
   returning that outcome, round 33 F2); every other terminal state (an
   ordinary rejection, a cancellation) and a missing promise make the claim
   dead. The two sites can never disagree about which claims are live.
4. **The FIFO is gone.** `Kernel::idempotency_order` existed only to
   implement eviction, so it is removed — field, initialiser, stale-entry
   `retain` and the eviction loop — rather than left as dead machinery a
   later reader could "restore".

## Consequences

- The failure mode under flood changes from "old calls silently re-execute"
  to "new idempotent calls are refused". That is the correct trade for
  exactly-once semantics, but operators must know the refusal exists: a
  flood is now visible as `rpc/budget-exceeded` on new keys instead of
  silent corruption of old ones. Replays of already-accepted keys are
  never refused at the ceiling — a cached replay makes no call, and
  refusing it would defeat the retry idempotency exists for.
- No format change, no new API: the only new observable behaviour is the
  refusal, documented on `Agent::call_idempotent`. The ceiling itself is
  now the public constant `MAX_IDEMPOTENCY` (`src/kernel.rs`), next to
  `MAX_IDEMPOTENCY_KEY_BYTES`.
- **Residual, not closed here:** claims are still in-memory only, so a
  restart loses them and a key can legitimately re-execute after one. That
  is the durable-persistence design (audit Part E, P6), a larger change
  than this ceiling fix; it is not claimed by this ADR. The per-call sweep
  at a full table is O(1,024) per refused call — bounded, and only under
  flood or a full table.
