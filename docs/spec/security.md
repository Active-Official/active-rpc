# Security model (Active RPC)

Companions: `docs/spec/wire.md` (normative protocol), Active Infinity's
`docs/spec/security.md` (codec and secret model).

## 0. Invariants (never weaken)

These are the non-negotiable properties the hardening program defends. A change
that would violate one stops and needs an ADR.

| ID | Invariant |
|---|---|
| I-1 | Structural secret taint: a secret is a kind, not a removable flag. |
| I-2 | Anti-oracle equality: a secret never equals anything, including itself. |
| I-3 | Secret non-leakage: secrets never appear in Debug, Display, JSON, Protobuf, diagnostics, logs, errors, annotations, provenance or wire tags. |
| I-4 | Capability unforgeability: capability ids are unguessable and possession is authority. |
| I-5 | Attenuation only narrows: no operation may widen methods, budgets, paths or tool policy. |
| I-6 | Revocation at dispatch: a capability revoked after queue but before the provider runs is refused. |
| I-7 | Drop notification: the last handle drop notifies the provider. |
| I-8 | Hard budgets: nodes, depth, bytes, calls, arrays, values and tool payloads fail closed. |
| I-9 | Deterministic canonicalization: the same logical module maps to the same bytes and hash. |
| I-10 | Fail-closed validation: malformed, truncated, overlapping, cyclic or over-budget input is rejected with a stable code. |
| I-11 | No ambient authority: no hidden global permission in the kernel, tools or transports. |
| I-12 | Domain operations run only under a valid capability and within budget. |

## 1. Assets

1. **Authority**: the set of actions a caller may take. A capability is the unit.
2. **Secret material** inside modules and evaluation results.
3. **Provider state**: module versions, tool side effects, channel queues.
4. **Budgets**: CPU, bytes, wall time, call counts.
5. **Agent isolation**: one agent's lanes and channels must not affect another's.

## 2. Adversaries

- **Hostile peer**: sends forged capability ids, escalated descriptors,
  malformed frames or bombs.
- **Confused deputy**: a legitimate capability holder is tricked into acting
  outside its grant.
- **Curious caller**: reads values, traces, annotations, provenance or errors.
- **Runaway caller**: exhausts budgets or floods a channel.
- **Provider bug**: a tool or module provider returns more than it should.

## 3. Threats and controls

| Threat | Control | Where |
|---|---|---|
| Forged / guessed capability id | registry lookup on every call; ids derived from a per-kernel secret | `Kernel::call`, `CapId::derive` |
| Capability transplanted from another kernel | ids are kernel-specific; unknown ids fail closed | `Agent::import`, `call` |
| Escalation by attenuation | monotone check on methods, budget, read-only, redaction, path, tool policy | `CapAttrs::attenuate` |
| Capability-table lie on the wire | descriptors are informational; only the registry grants | `wire`, `Kernel::call` |
| Budget bypass | capability budget ∩ lane budget; charged per call; domain ops map the budget into the Active evaluator | `Budget`, `BudgetMeter`, `domain` |
| Read-only bypass | mutating methods refused before the provider sees the call | `Kernel::call` |
| Path escape | path arguments checked against the capability scope before dispatch | `Kernel::call` |
| Confused deputy across providers | a capability names one provider and one object; method sets do not travel between them | `CapRecord`, `Provider` |
| Secret leakage | values carry `Value::Secret` markers; evaluation, annotations and provenance never carry secret bytes; envelope has no secret-bytes tag | `security`, `wire`, `domain` |
| Revoked capability still usable | revocation marks the record and every descendant; the check runs at queue time **and again at dispatch** | `Agent::revoke`, `Kernel::dispatch` |
| Cancelled / destroyed work still runs | a queued job is removed on cancel or lane destruction | `Agent::cancel`, `Agent::destroy_lane` |
| Secret bytes in a module result | `subgraph`/`patch` return a **redacted** module: every secret node becomes the marker before encoding | `domain::redacted_module_bytes` |
| Guessable capability ids | the kernel secret comes from the OS CSPRNG | `Agent::new` |
| Byte budget bypass | arguments and payload are measured and charged per call, then intersected with the lane budget | `Arg::wire_size`, `Kernel::call` |
| Lane budget bypass by queueing | capacity counts pending calls as well as completed ones | `Lane::has_capacity` |
| Dropped capability still usable | last release removes the record | `HandleControl::release` |
| Promise abuse (double resolve, cycle, unknown id) | single settlement, cycle detection before dispatch, id validation | `promise`, `Kernel::next_batch` |
| Malformed frame | magic, version, flags, every length and count checked before allocation; value nesting capped at 64 | `wire` |
| Re-entrant provider | the kernel holds no borrow while a provider runs | `Kernel::dispatch` |
| Frame bombs | `WireLimits` ceilings on bytes, args, payload, descriptors, methods | `wire` |
| Shared-memory overwrite | frames are refused rather than wrapping over unread data | `shm` |
| Stream splicing (QUIC / bridge) | one stream per call, framed length, per-frame gRPC prefix | `quic`, `connect` |
| Resource exhaustion via lanes | per-lane call budget and lane destruction | `lane`, `Kernel::call` |

## 4. Non-goals

- **Network authentication of peers.** QUIC uses a self-signed certificate on
  loopback; a deployment terminates TLS with its own identity. Capabilities, not
  network identity, carry authority.
- **Confidentiality of a capability id at rest.** An id is a bearer token; store
  it like a key.
- **Side channels.** Batch composition is observable by design (it is the
  performance property); secret *contents* never influence a batch.
- **Protection from a malicious provider.** A provider runs in the agent's own
  process and can do anything the process can. Tools are sandboxed at the
  adapter level (no shell, scrubbed environment, allowlists), not by the kernel.

## 5. Verification

`tests/redteam_tests.rs` covers every row above that has a testable control:
forgery, transplant, escalation, confused deputy, secret leakage through values
and envelopes, budget bypass (capability, lane, tool policy), promise abuse,
malformed frames, frame bombs and revocation. `tests/property_tests.rs` asserts
that arbitrary bytes never panic the decoder and that attenuation is monotone.

## 6. Multi-agent patterns (writer, auditor, orchestrator)

A habitat composes agents from capabilities, not from roles baked into the
kernel. Three patterns are supported and tested:

- **Writer** — a capability granting mutating methods plus a finite budget. It
  can change one object and nothing else.
- **Auditor** — a read-only capability (`read_only = true`) over the same
  object. `call` refuses any method the provider reports as mutating, so an
  auditor cannot write even if the method list is wide.
- **Orchestrator** — a capability whose methods are the narrow query surface
  plus channel send/receive; it hands attenuated child capabilities to workers
  instead of widening its own.

Rules the tests enforce:

- Overlapping grants do not compose into a wider grant: each capability is
  evaluated on its own record (`attenuation_is_monotone`, `redteam_battery`
  H2.9/H2.10).
- A revoked parent revokes its children; a stale handle is refused with
  `rpc/revoked` (`revocation_kills_the_capability_and_its_children`).
- A capability minted in another kernel is unknown here; ids are derived from a
  per-kernel secret (`capability_ids_are_unforgeable`, H2.42).
- Secret-bearing subgraphs are redacted per capability, so one worker's
  read-only view does not expose another's secret (`redteam_tests`
  secret-export cases, H2.43).

The kernel has no ambient authority: it does not open sockets, spawn processes
or read the environment. A tool adapter does those things only through a
capability whose `ToolPolicy` grants them.

## 7. Timing and side channels

The kernel is a deterministic state machine with a logical clock; it performs no
I/O and takes no wall-clock measurement on the dispatch path. The observable
timing differences that remain are:

- **Budget exhaustion is visible.** A caller learns that a ceiling fired from
  the error code. This is intended: budgets are policy, not secrets.
- **Capability lookup is a `BTreeMap` keyed by id.** Ids are opaque and derived
  from a secret; a probe that does not know the id cannot use lookup timing to
  learn it.
- **Tool adapters and transports do real I/O** and therefore have real timing.
  They are outside the secret boundary; a deployment that needs constant-time
  behaviour at that edge must supply its own padding or fixed-size frames.

No secret value is compared, ordered, hashed for equality, or branched on inside
the kernel. `Value::Secret` has no equality; the anti-oracle test asserts that
comparing a secret with itself, or with another secret, never yields `true`.
