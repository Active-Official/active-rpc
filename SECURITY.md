# Security policy — Active RPC

## Supported versions

| Version | Security fixes |
|---|---|
| 2.2.x | yes |
| 2.1.x | until 2.2.0 + 12 months |
| 1.0.x | no (superseded) |

## Reporting a vulnerability

Report privately to the `Active-Official` organization (or a GitHub private
security advisory on `Active-Official/active-rpc`). Never include a live
capability id or secret material in a report; describe the shape instead.

Please include:

- the transport and the sequence of envelopes that reproduces the issue;
- the code observed (e.g. `rpc/unknown-capability`) and the expected behaviour;
- the class: forgery, escalation, confused deputy, budget bypass, secret leak,
  malformed-frame acceptance, or a crash/hang.

## Response

- Acknowledgement within 3 business days.
- A fix or mitigation plan within 30 days for a confirmed issue.
- A CVE and patched release for anything affecting a released version.
- Credit in the advisory unless you ask otherwise.

## Scope

In scope: capability minting, attenuation, revocation and lifetime; promise
settlement and pipelining; budget accounting; lane and channel isolation; the
envelope codec and capability table; every transport adapter; tool policies.

Out of scope: the security of a provider's own logic (a provider runs in the
agent's process), network authentication (QUIC uses a self-signed certificate on
loopback; deployments terminate their own TLS), and confidentiality of a
capability id at rest (it is a bearer token).

## Hardening expectations

- The registry is the authority: a wire descriptor never grants anything.
- Attenuation is monotone; any widening is `rpc/attenuation-escalation`.
- Budget is charged per call and intersects capability with lane. A call also
  charges every ancestor's meter, so a delegation tree cannot multiply its
  grant, and a promise argument that resolves larger than its placeholder pays
  the difference before the provider runs.
- A capability without an explicit tool policy still bounds the tool surface:
  its own methods, at most its byte budget, and never a local process. A child
  policy is compared against that effective policy, so "adding a policy" cannot
  grant process execution.
- Durable records are credentials: a record is accepted only if its seal
  verifies under the deployment key, it names the peer it was issued to, and it
  is the only live copy of that credential. A revoked capability's record id is
  tombstoned; a deployment replays its kill list at startup, because tombstones
  are memory-only (ADR-0010). The restored set is memory-only too, so a
  deployment that stores records passes a `RecordStore` to
  `restore_capability_with`, which makes a record single-use across kernels and
  restarts; without one the record is single-use per process.
- `CapabilityRecord::from_json` is a parser, not a verifier: it accepts a record
  with no seal. `restore_capability` is the only path that turns a record into
  authority, and it checks the seal, the tombstone, the binding and the clock
  first. The attribute bridge it uses is crate-internal for that reason.
- A capability's budget bounds its whole subtree even after the parent handle is
  dropped: an ancestor's record and meter live while a derived capability can
  still call through it.
- Provider callbacks (`on_drop`) and provider code (`invoke`) run with no kernel
  borrow held, and a provider panic cannot wedge the kernel.
- A lane is a budget and lifecycle scope, not an authority boundary: any lane may
  call any live capability, and a destroyed lane neither revokes nor invalidates
  them. Authority lives on the capability.
- Channel capacity (per channel and in aggregate) is checked before a send or a
  publish is charged, so a refused message spends nothing; a full channel is
  `rpc/backpressure`, not a budget fault.
- Secret material is represented by `Value::Secret`, never by bytes.
- Every frame is bounded and rejected at the boundary; the capability registry,
  the attenuation chain depth and a negotiated capability table have ceilings.
- `#![forbid(unsafe_code)]`.

### Authority domain

A kernel's secret *is* its authority domain. Capability ids are
`Blake3("active-rpc/cap" || secret || serial || parent_id)`, so two kernels that
share a secret derive the same id for the same serial, and an id minted by one
is meaningful to the other. That is the design: unforgeability comes from the
secret, and holding the secret is equivalent to holding every capability the
kernel can mint. Two consequences for deployments:

- Never copy a kernel secret between processes that are not one logical agent.
  Persistent hosts derive the secret once and keep it; `Agent::new()` takes a
  fresh OS seed per process.
- "A capability from another kernel is refused" therefore holds across kernels
  with **different** secrets, which the fuzz target and
  `tests/fuzz_regression_tests.rs` assert explicitly.

An id observed by a peer is a bearer token: with it, and with no binding, the
peer can call while the capability lives. Use `CapAttrs::bound_to` (via
`Kernel::mint_bound`) to tie a capability to an admitted transport identity, and
`CapAttrs::ttl_ms` to bound its life.

## Maturity invariants (AIM-PROP-2026-10 §2)

These are release gates. A change that weakens one is rejected even if it makes
a benchmark faster.

| ID | Invariant | Enforced by |
|---|---|---|
| I-1 | Structural secret kind; redaction on every export path | `tests/invariant_gate.rs`, unit/red-team/protobuf suites |
| I-2 | Anti-oracle equality for secrets | `tests/invariant_gate.rs`, unit tests |
| I-3 | Capability unforgeability; correlation ids in logs | `tests/invariant_gate.rs`, `tests/api_surface.rs` |
| I-4 | Attenuation only narrows | `tests/property_tests.rs`, conformance tests |
| I-5 | Revocation enforced at dispatch | `tests/property_tests.rs`, red-team suite |
| I-6 | Hard budgets fail closed | unit/concurrency/red-team suites |
| I-7 | Canonical bytes ↔ Blake3 identity stable | conformance/property tests |
| I-8 | Fail-closed validation; no partial unsafe views | red-team, fuzz and perf-budget suites |
| I-9 | No ambient authority in kernel/tools/transports | API surface, tool and red-team suites |
| I-10 | Domain operations under capability + budget | domain/integration suites |

## What is tested, fuzzed, reviewed, and proven

| Level | What it covers | Where the evidence lives |
|---|---|---|
| **Tested** | kernel, capability lifecycle, attenuation, revocation, promises, lanes, channels, tools, transports, the red-team battery, negative controls and performance budgets | `tests/`, `docs/hardening/STATUS.md` |
| **Fuzzed** | twelve structure-aware targets: envelope, capability lifecycle, promise graph, budget matrix, MCP/HTTP/process tools, channel transfers, transport framing, bulk plans, replay packages, topic policy | `fuzz/`, committed corpora, nightly campaign per target |
| **Reviewed** | independent review rounds with triaged findings and regression tests for every fix | `REVIEWS.md`, `docs/hardening/REVIEW-SCOPE.md` |
| **Proven** | monotone attenuation, revoke-at-dispatch and single settlement are stated as invariants and property/model-tested; they are **not** machine-checked proofs | `docs/spec/security.md` |

Nothing in this crate is formally verified. The claims are bounded by the
checked-in tests and the documented residual risks; a property that is not in
that table is not claimed.
