# ADR-0001 — Purpose of Active RPC

**Status:** accepted (2026-10-27)

## Context

Agents call tools, modules and each other. Today that traffic is JSON-RPC or
gRPC: a request/response shape with no notion of *who may call what*, no notion
of a result that is not ready yet but is already useful, and no unit of
concurrency an agent can actually reason about.

The Active ecosystem already has a value model with units, secrets and a
dependency graph (Active Infinity). What it lacks is the layer that moves those
modules between processes and agents with authority, budgets and low-latency
chaining.

## Decision

Active RPC is that layer:

- **Capabilities** are unforgeable ids minted by the receiving kernel. Holding
  one is the permission; attenuation narrows; revocation is transitive.
- **Promises** can be arguments, so dependent calls pipeline.
- **Lanes and channels** give an agent many independent contexts and streams,
  with capability transfer over channels.
- **Domain operations** (`evaluate`, `why`, `impact`, `subgraph`, `patch`) run on
  Infinity modules under the capability's budget.
- **Transports are adapters** over one envelope; capability semantics never
  depend on the wire.

## Consequences

- The kernel is a state machine, not an async runtime: determinism and
  testability over raw throughput.
- Authority is explicit everywhere. There is no "default allow" path and no
  ambient identity to inherit.
- The wire format is small enough to implement in another language
  (`docs/spec/wire.md`).
