# ADR-0017 - Peer introduction modules

**Status:** accepted (2026-10-31). Additive: no wire change.

## Context

Two peers that meet over a transport know each other's capability ids, not each
other's shape: which providers exist, which methods they grant, and what budget
ceilings a caller should plan for. Negotiation currently happens out of band.
Active Infinity already provides a canonical, hashable module format, so the
description can travel as AINF bytes instead of a bespoke handshake.

## Decision

`Agent::intro()` builds a canonical AINF module:

```text
Table {
  default_budget: Table { seven ceilings },
  peer:           Str("active-rpc/<version>"),
  providers:      Array [ Table { methods: Array[Str], name: Str } ],
}
```

- Provider order is the kernel's provider-table order, so the bytes are
  deterministic and hashable.
- The module carries names, methods and default ceilings only. Capability ids,
  arguments, values and secrets never enter it.
- It is plain AINF: any language binding validates, hashes and decodes it with
  the shared conformance pack.
- This ADR defines the description, not a transport. A peer may serve it as the
  payload of a normal call, ship it at connection setup, or hand it to an agent
  out of band; none of those choices change the bytes.

## Consequences

- `intro` joins the public surface and depends on the `active-infinity` crate
  already used by domain operations.
- A future revision may add units or capability *classes* to the description;
  that changes the module shape and needs a new ADR plus a schema class.
- The introduction is not authority: presenting it grants nothing.

## Amendment (R-17, hostile review round 1)

- **Canonical by construction.** `build` sorts the providers and sorts and
  deduplicates each method list, so the same surface produces the same bytes
  whatever order the caller used. A peer's fingerprint is derived from those
  bytes, and a `HashSet`-ordered plugin used to change the digest without
  changing the surface. Duplicates are dropped for the same reason.
- **Names are validated.** A peer, provider or method name is 1..=1024 bytes and
  free of control characters, at the same boundary as a capability method name:
  every one of them reaches a module, a fingerprint and a log line.
- **The binding is one-way for the recipient, and revocable by the owner.**
  `introduce_to` writes `bound_to` into the live records of the subtree,
  including the root, so after an introduction the local kernel can no longer
  use the capability it handed over. That is the intent — the capability now
  belongs to that peer — and the recipient can never rebind it: a second
  `introduce_to` to a different peer is refused. The owning handle can end the
  binding: `reintroduce_to` rotates the capability to a peer the owner names,
  tombstones the old peer's unrestored records and carries its queued work to
  the new peer. That is a rotation, not a second introduction, and it needs the
  owner's handle plus knowledge of the old fingerprint. `introduce_to`'s
  "authority never moves between principals" is therefore about peers acting
  on each other; the owner remains the principal that may withdraw and
  re-place its own grant. An embedder that wants to keep its own authority
  should attenuate a child and introduce that. A future revision may return a
  bound child instead; it is a breaking change to the call's semantics.
