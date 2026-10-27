# PROPOSAL — Active RPC

**Crate / repo:** `active-rpc`  
**Print name:** Active RPC  
**Status:** Normative specification for implementation  
**Cross-references:** `CHECKLIST.md` (this folder), `../MASTER-PROPOSAL.md`, `../MASTER-CHECKLIST.md`, `../active-infinity/PROPOSAL.md`

---

## 1. Purpose and scope

Active RPC is a capability-based, promise-pipelined, multi-lane / multi-channel RPC system optimized for Active Infinity payloads and multi-agent concurrent workloads. It is designed to be strictly superior to gRPC for Active-centric and agent-to-agent scenarios while offering an interop path (gRPC bridge) for the broader ecosystem.

**Checklist mapping:** R-0.*, R-1.*.

---

## 2. Relationship to Active Infinity and active-core

- Payloads are Active Infinity (ABF) bytes or zero-copy views.
- Domain operations (`evaluate`, `why`, `impact`, …) ultimately invoke Active evaluation semantics and must respect all Active invariants.
- Capabilities may reference modules, subgraphs, tools, lanes, or channels.
- `active-rpc` depends on `active-infinity` and, where needed, `active-core`.

**Checklist mapping:** R-1.1; MASTER-PROPOSAL §2, §5.

---

## 3. Capability model

- A capability is an unforgeable, opaque reference.
- Possession of the capability is the only authority needed to invoke its methods.
- Dropping the last reference (or connection loss) notifies the provider (automatic lifetime).
- Capabilities can be attenuated: budget reduction, read-only, secret redaction, path restriction, tool policy narrowing.
- No ambient authority.

**Checklist mapping:** R-2.1–R-2.4; PROPOSAL §3.

---

## 4. Domain operations (first-class)

Minimum required surface (all return Promises where asynchronous):

- `evaluate(path) → Value`
- `why(path) → WhyTrace`
- `impact(change) → ImpactReport`
- `subgraph(roots) → ModuleCap`
- `patch(ops) → ModuleCap`
- `with_budget(Budget) → Self`
- `redact() → Self`
- Graph navigation: `dependents`, `dependencies`
- Lane / channel management (see §6–7)
- Tool invocation (see §8)

**Checklist mapping:** R-6.*; PROPOSAL §4.

---

## 5. Promise pipelining

- A Promise represents a future result that can be passed as an argument to further calls *before* it resolves.
- The runtime tracks dependencies and can start dependent work as soon as intermediate results are available.
- Critical for low-latency multi-step agent reasoning (`evaluate` → `why` → `impact` without serial round-trips).

**Checklist mapping:** R-3.1–R-3.4; PROPOSAL §5.

---

## 6. Lanes

- A Lane is an independent concurrent execution context belonging to an agent.
- Each Lane has its own budget, local state, and set of open channels / held capabilities.
- An agent may own many Lanes simultaneously.
- The protocol provides creation, attenuation, and destruction; scheduling policy is left to the agent runtime.

**Checklist mapping:** R-4.1–R-4.3; PROPOSAL §6.

---

## 7. Channels

- Named, typed streams (bidirectional or unidirectional) that carry Infinity messages and capability transfers.
- A Lane can listen on and speak to many Channels at once.
- Used for agent-to-agent conversations, event streams, watch/notify patterns, and tool result streams.

**Checklist mapping:** R-4.4–R-4.6; PROPOSAL §7.

---

## 8. Tool handles

- Tools are capabilities.
- Adapters required:
  - MCP session → set of tool capabilities
  - OpenAPI / HTTP description → typed API capabilities
  - Local / VPS process (heavily sandboxed and attenuated)
- All tool calls are Promises and participate in pipelining.

**Checklist mapping:** R-5.*; PROPOSAL §8.

---

## 9. Transports

| Transport        | Priority | Notes |
|------------------|----------|-------|
| In-process       | Highest for same binary | Direct calls, zero serialization |
| Shared memory    | High (same host) | Zero-copy Infinity + capability table |
| QUIC / HTTP/3    | Preferred cross-host | Multiplexing, 0-RTT |
| gRPC / Connect bridge | Interop | Carry Infinity + capability descriptors |
| Custom framing   | Optional max-performance | Length-prefixed segments |

Capability table is transmitted as a side-channel (Cap’n Proto style).

**Checklist mapping:** R-7.*; PROPOSAL §9.

---

## 10. Security and invariants

- Capability unforgeability and attenuation.
- Structural secret taint preserved across the wire; redaction on all export paths.
- Budgets enforced before and during work.
- Units checked at boundaries.
- No unlock API for secrets in the base design.
- Deserialization and framing must resist bombs and malformed input.

**Checklist mapping:** R-8.*; PROPOSAL §10; MASTER-CHECKLIST M-5.1.

---

## 11. Multi-agent concurrency model (future-proof)

The protocol must support an agent that simultaneously:

- Runs many Lanes.
- Listens and responds on many Channels.
- Issues many concurrent tool calls (MCP, API, local, VPS).
- Holds conversations with many peer agents.
- Pipelines dependent calls across all of the above.

Current models may not fully utilize this; the protocol must not prevent future models from doing so.

**Checklist mapping:** R-9.*; PROPOSAL §11; MASTER-PROPOSAL §4.3.

---

## 12. Integration with Active Infinity

- All heavy payloads are Infinity.
- Domain operations decode / view Infinity, then invoke Active evaluation semantics.
- Streaming Infinity frames can be mapped to Channel messages.

**Checklist mapping:** R-6.5, M-4.1; MASTER-PROPOSAL §5.

---

## 13. Interop and bridging

- gRPC gateway that accepts ordinary gRPC clients and translates to/from Active RPC + Infinity.
- Optional projections of results to JSON (redacted) or other formats.

**Checklist mapping:** R-10.*; M-4.3.

---

## 14. Testing and hardening

- Unit tests for capability, promise, lane, channel, each transport.
- Concurrency and pipelining stress tests.
- Red-team: capability forgery attempts, secret leakage, budget bypass, resource exhaustion.
- Fuzz framing and capability table parsing.
- Multi-agent integration scenarios.

**Checklist mapping:** R-11.*, R-12.*; MASTER-CHECKLIST Phase 5.

---

## 15. Documentation and ADRs

- ADRs for every major protocol decision.
- Public README that positions Active RPC against gRPC and Cap’n Proto RPC for agent workloads.
- Examples: simple evaluate/why, pipelined chain, multi-lane tool use, agent-to-agent capability exchange.

**Checklist mapping:** R-0.5, R-13.*.