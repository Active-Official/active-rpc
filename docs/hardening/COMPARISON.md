# Why Active Infinity and Active RPC

This comparison is written for humans and agents choosing a format. It states
the trade-off, not a universal winner.

| Property | Active Infinity | Cap'n Proto | FlatBuffers | Protobuf | MessagePack |
|---|---|---|---|---|---|
| zero-copy reads | yes (validated borrowed view) | yes | yes | no | no |
| canonical bytes | yes, with a proof (`validate_canonical`) | no general canonical form | no general canonical form | no (field order and unknown fields vary) | no |
| content hash in the image | yes, Blake3-256 | no | no | no | no |
| structural secrets | yes (`Secret` kind, redacted projections) | no | no | no | no |
| units | yes (built-in + named) | schema-defined | schema-defined | schema-defined | no |
| graph with derived edges | yes | pointer graph | offset graph | tree of messages | tree |
| unknown fields preserved | extensions are explicit and tagged | yes | yes | yes | n/a |
| schema required to read | no (self-describing tags) | yes | yes | yes | no |
| hostile-input budgets | first-class (`Limits`, fail closed) | caller-supplied | verifier options | size limits | caller-supplied |
| stable error codes | yes (`infinity/*`, `rpc/*`) | no catalog | no catalog | no catalog | no catalog |

## Agent transport comparison (Active RPC vs common RPC stacks)

This table is about the authorization and agent-model fit. Performance is
measured separately in `docs/spec/performance.md`; no speed claim is made here.

| Property | Active RPC | gRPC | Cap'n Proto RPC | JSON-RPC | MCP |
|---|---|---|---|---|---|
| authority carried with the call | attenuable capability | ambient TLS/service identity | capability (object reference) | none beyond transport | server-defined |
| attenuation before delegation | yes, kernel-enforced | no standard | capability narrowing by reference | no | no |
| revoke at dispatch | yes | no standard | reference lifetime | no | no |
| promise pipelining | yes, dependency graph | no (streams are separate) | yes (promises) | no | no |
| payload identity | canonical AINF + Blake3 | protobuf schema | schema-defined | arbitrary JSON | JSON |
| secrets as a structural kind | yes | no | no | no | no |
| tools under capability + budget | yes | separate auth layer | no standard | no | server policy |
| hard per-call/byte budgets | yes | no standard | no standard | no | no |
| stable error-code catalog | yes (`rpc/*`) | status codes | exception/status | application-defined | JSON-RPC codes |
| transports | in-process, TCP, SHM, QUIC, Connect bridge | HTTP/2 | TCP/QUIC | any | stdio/HTTP |

**Where it fits:** Active RPC is the strongest fit when an agent delegates
authority to another agent, needs a dependent pipeline without a round trip per
hop, or must move a secret-bearing module without letting a projection become
the source of truth. gRPC remains the right bridge for existing HTTP/2 estates;
Cap'n Proto remains attractive for schema-first object graphs; JSON-RPC and MCP
remain simple tool surfaces. Active RPC ships bridges for those ecosystems
rather than asking them to disappear.

## When another format is the better choice

- **Cap'n Proto / FlatBuffers** when you control both ends, already have a
  schema, and need the largest zero-copy ecosystem. Neither gives you a
  canonical content address or a structural secret kind out of the box.
- **Protobuf / gRPC** when interop with the existing gRPC ecosystem matters more
  than canonical identity or capability security. Active RPC ships a
  Connect/gRPC bridge for that case; the bridge is interop, not the core.
- **MessagePack / CBOR** for small, schema-less payloads where canonical
  identity and authorization are not requirements.

## What Active adds

- **One identity.** The image contains its hash; two logically equal modules
  have the same bytes, the same hash and the same projections.
- **Secrets as a kind.** A secret cannot be stripped by re-encoding, cannot be
  compared, and cannot leave through Debug, JSON, Protobuf, errors or logs.
  Other formats require the application to remember to redact.
- **Capabilities as the authorization model.** A capability is unforgeable,
  attenuable and revocable at dispatch. A bearer token is none of those.
- **Budgets as a security control.** Every traversal, count, value and tool call
  has a finite ceiling that fails closed.

## What Active does not claim

- It is not a general-purpose replacement for every gRPC deployment.
- It does not protect a secret from a compromised host kernel or debugger.
- It does not make a non-canonical producer canonical; it refuses the image.
- It does not hide the length of a secret (the length is used by budgets).
