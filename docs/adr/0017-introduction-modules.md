# ADR-0017 — Peer introduction modules

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
