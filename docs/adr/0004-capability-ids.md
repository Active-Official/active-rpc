# ADR-0004 — Capability identity, attenuation and lifetime

**Status:** accepted (2026-10-27)

## Context

"Unforgeable reference" in a single-address-space library has no hardware
boundary to lean on: any caller can construct any integer. The property has to
come from the design, not from memory protection.

## Decision

1. **Identity is derived, not chosen.** A capability id is
   `Blake3(kernel secret ‖ serial ‖ parent id)[..16]`. The kernel secret is
   random per agent (or fixed for deterministic replays) and never leaves the
   kernel. A peer can guess, but a guess is only useful if it is in the
   receiver's registry — and the receiver only mints through `mint`/`attenuate`.
2. **The registry is the authority.** `Agent::import` reconstructs a handle from
   a wire id without granting anything: every call looks the id up, and an
   unknown id is `rpc/unknown-capability`. The capability table in an envelope is
   a description; the registry is the proof.
3. **Attenuation is monotone by construction.** `CapAttrs::attenuate` refuses a
   wider method set, budget, path scope or tool policy, and refuses to lift
   read-only or redaction. Budget is intersected, so a child cannot exceed either
   parent or lane.
4. **Lifetime is reference counting.** Handles are `Clone` (retains) and `Drop`
   (releases); the last release removes the record and calls the provider's
   `on_drop`. Revocation walks the parent/child tree and marks every descendant,
   so revoking a parent kills what was derived from it.
5. **No ambient authority.** There is no "current user", no implicit capability,
   no method on the kernel that acts without an id.

## Consequences

- An id is also a bearer token: whoever holds it can use it. That is the point,
  and why attenuation and revocation exist — transfer is explicit
  (`Arg::Cap`, channel transfers) and auditable (`Event::CapTransferred`).
- Ids are stable for a kernel's lifetime; a restarted kernel mints new ones, so a
  stale id fails closed instead of silently resolving to something else.
- Deterministic tests use `Agent::with_secret`; production uses `Agent::new`.
