# ADR 0009 — Capability-table deltas

Status: accepted for AIM-PROP-2026-10 C-5.1.

## Decision

An envelope may carry a negotiated **capability-table delta** instead of a full
table. The delta is:

```
base_hash[32] | removed_count u32 | removed ids[16]... | added_count u32 | descriptors...
```

The envelope sets flag bit 2 (`FLAG_CAP_DELTA`). A peer applies the delta only
when the Blake3 hash of its current canonical capability table equals
`base_hash`; an unknown base, an unknown removal, a duplicate addition or a
malformed delta is `rpc/capability-table`. The result is sorted by capability id
so table identity is deterministic.

Negotiation is explicit: a peer advertises support in its hello/feature policy;
an implementation that does not understand the flag rejects the envelope at the
flag check. Full tables remain valid and are the default. The flag is additive
within ARP1 v1; no existing byte layout changes when the flag is clear.

## Why

Full tables repeat every descriptor on every frame. A capability-delta path
reduces bytes and copy work for long-lived agents, while the base hash prevents
a confused-deputy table substitution. Identity of the table is the hash, not the
descriptor order.

## Consequences

- A peer must retain the base table to apply a delta.
- A delta cannot widen authority by itself; descriptors still pass the same
  attenuation checks when imported.
- A lost/reordered base is a hard error, not a silent full-table fallback.
- A later ADR may add an explicit reset delta; the current format always
  requires the base hash.
