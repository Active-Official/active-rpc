# ADR-0027 - Charge envelope descriptor bytes to the call budget

**Status:** accepted (2026-11-09). Behaviour change to `call_from_envelope`
and `call_idempotent_from_envelope`: a call's byte charge now covers the
envelope's method name and any capability descriptors or table delta, not
just the arguments and the payload. A call whose descriptor table alone
exceeds the grant is refused with `rpc/budget-exceeded` before the provider
runs.

## Context

The kernel charged a call as `call_bytes = Σ Arg::wire_size(arg) +
payload_bytes`. The envelope method name (up to 1,024 B), every capability
descriptor in `envelope.caps` (up to 256 descriptors × 64 methods × 1,024 B)
and the whole `cap_delta` (removed ids plus added descriptors) were charged
zero — `Call` does not even carry the descriptors, so dispatch had nothing
to charge (RPC-52; audit probe `r01_descriptor_bytes_are_not_charged_to_
the_call_budget` measured a 1,249,536-byte frame running against a 100-byte
grant, provider running once). A peer with a 100-byte grant could push
~1.3 MiB of descriptor bytes per call — up to ~16 MiB at the ceilings,
frame-bound only — forever, without ever tripping `rpc/budget-exceeded`.
It defeats the "budget is charged before work and never exceeds capability
∩ lane" invariant for any deployment that prices by `max_bytes`, and lets a
peer smuggle arbitrarily large capability tables past a meter an operator
believes is closed. The `Budget::max_bytes` doc says "payload bytes moved
through this capability" — descriptors are bytes moved through the
capability and were not in that sum.

## Decision

1. **Charge the three unbounded sections, in the two envelope entry
   points.** `call_from_envelope` and `call_idempotent_from_envelope` add
   `Envelope::non_argument_wire_size()` to the `payload_bytes` they pass
   down. The existing `call_bytes` accounting — capability ∩ lane, then the
   lane cumulative, checked across the whole lineage chain before anything
   is charged — enforces the new charge with no new machinery. The charge
   lands at queue time, before the provider runs, so a refused call costs
   nothing and leaves no trace, like every other queue-time refusal.
2. **Compute the size from the decoded envelope, never by re-encoding.**
   `Envelope::non_argument_wire_size()` sums the sections arithmetically
   from the decoded values: the method name (4 plus its length), the
   capability table (4 for the count plus each descriptor's
   `CapDescriptor::wire_size()`), and the delta when present (32 for the
   base hash, 4 plus 16 per removed id, 4 plus each added descriptor). The
   size function lives in the wire module next to the encoder and mirrors
   it field for field, so the two cannot drift silently — a test pins the
   size against `encode()` exactly. No allocation happens on the hot path,
   and the sum saturates instead of overflowing, so a hand-built envelope
   with absurd counts charges the maximum and is refused rather than
   wrapping to a small charge.
3. **Do not charge it in `call`/`call_as`.** In-process callers have no
   envelope, so there is nothing to charge — the asymmetry is exactly why
   the charge belongs in the envelope entry points. A fix that charged
   descriptors inside `call_inner_payload` itself would double-charge
   in-process callers that pass descriptors by other means and would break
   the `call_bytes` accounting the budget tests pin.
4. **The idempotent fingerprint covers the charge.** `payload_bytes` is an
   input to `fingerprint_with_payload`, so a retry with a changed
   descriptor table is a different call (`rpc/invalid-argument`), not a
   replay of the first one. A retry of the same envelope replays exactly
   as before — and a replay is never re-charged, by the existing RPC-06
   design: a cached replay makes no call, and refusing it would defeat the
   retry idempotency exists for.
5. **The fixed 24-byte frame overhead is deliberately not charged.** The
   16-byte header, the argument-count prefix and the payload-length prefix
   are constant per frame and cannot be used to smuggle arbitrary bytes;
   charging them would buy nothing and would move the boundary for every
   tight-budget caller. The charge is exactly the three sections that can
   grow: method, descriptors, delta. (Verified against the probe frame:
   1,249,536 total = 24 fixed + 8 method + 1,249,504 descriptors.)

## Consequences

- A call whose envelope carries more descriptor bytes than the grant allows
  is refused with `rpc/budget-exceeded` and the provider never runs. Calls
  inside the budget are unaffected: the charge is added to bytes the
  caller already paid for, and the boundary is exact — one byte under the
  descriptor size refuses, the size plus the response admits.
- **Blast radius:** any deployment whose peers attach descriptor tables or
  deltas to calls, and whose grants are sized only for arguments and
  payload, will see refusals until the grants grow to cover the tables.
  That is the fix working as intended — the grants were under-priced — but
  operators must know the meter now counts the tables. In-process callers
  see no change at all.
- No format change, no new API: `non_argument_wire_size()` and
  `CapDescriptor::wire_size()` are new public helpers on existing types;
  the only new observable behaviour is the refusal. The `Budget::max_bytes`
  doc now names the descriptor half of the charge.
- **Residual, not closed here:** the response side is charged separately
  at egress (`charge_egress`), and the two charges stack — a call admitted
  at exactly its budget still needs headroom for its response. That
  stacking is pre-existing behaviour, not introduced by this fix.
