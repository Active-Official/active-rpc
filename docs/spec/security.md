# Security model (Active RPC)

Companions: `docs/spec/wire.md` (normative protocol), Active Infinity's
`docs/spec/security.md` (codec and secret model).

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
