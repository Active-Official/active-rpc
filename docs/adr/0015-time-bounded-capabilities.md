# ADR-0015 — Time-bounded capabilities

**Status:** accepted (2026-10-31). Additive: no wire change.

## Context

A capability that is never revoked lives for the lifetime of the kernel, even
when the work it authorizes is short-lived (a single negotiation, a batch job, a
delegated tool run). Operators asked for a bound that does not depend on a
supervisor remembering to revoke.

## Decision

`CapAttrs` gains `ttl_ms: Option<u64>`. `Agent::mint` resolves it against the
kernel's monotonic clock into an absolute `CapRecord::expires_at`. At dispatch,
`now >= expires_at` refuses the call with the same `rpc/revoked` code as an
explicit revocation, and emits `Event::CapExpired` so the two are distinguishable
in the event stream and the control plane.

Rules:

1. **Expired ≡ revoked.** The refusal code is the same; only the event differs.
2. **Attenuation only shortens.** A child of a bounded parent must carry a TTL
   and it may not exceed the parent's nominal TTL. The kernel additionally
   clamps the child's absolute expiry to the parent's, so elapsed time cannot
   be used to extend a child past its parent.
3. **No wire change.** The TTL is local authority, like persistence and the
   identity binding. A `CapDescriptor` never advertises it, and a descriptor
   grants nothing regardless.
4. **Deterministic.** The clock is the kernel's virtual `now_ms`, advanced per
   dispatch batch by the configured latency. Tests reproduce expiry exactly.

## Consequences

- Long-lived grants keep working: `ttl_ms: None` is the default.
- Durable capabilities may carry a TTL; restore must preserve `expires_at` when
  persistence lands, or the capability must be re-minted.
- The event vocabulary grows by one name (`cap.expired`); the control plane maps
  it to the `caps` category.
- A future wall-clock policy (for example, TTL from a signed timestamp) needs a
  new ADR; this one deliberately uses kernel time only.
