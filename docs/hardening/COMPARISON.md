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
