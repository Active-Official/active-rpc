# Interop: the Connect / gRPC bridge

Active RPC has one native protocol and several adapters.

| Path | Status |
|------|--------|
| ARP1 over TCP, `u32` length + envelope | **Native baseline** |
| QUIC (mutual TLS) | Native, Rust stack |
| HTTP/2 (`application/arp1`) | Native, Rust stack |
| Shared memory, in-process | Native, local |
| Connect / gRPC bridge (`application/connect+active-infinity`, `application/grpc+active-infinity`) | **Interop only** |

The bridge exists so a gateway written for Connect or gRPC can reach an Active
RPC peer without reimplementing the envelope. It is never the default in
examples, quick starts or deployment docs, and it must not become the system of
record.

## Wire

```text
POST /active.rpc.v1.Agent/Call HTTP/1.1
content-type: application/connect+active-infinity   (or application/grpc+active-infinity)
content-length: <n>

<gRPC 5-byte prefix: 0x00, u32 big-endian length>
<bare ARP1 envelope: magic, version, kind, flags, id, method, args, payload, caps>
```

The response repeats the framing with the response or error envelope. Other
content types are `415`; a malformed prefix or envelope is `400` with an
`rpc/...` code in the body; bodies over `MAX_BODY` (64 MiB) are `413`.
`BridgeServer` accepts a fixed number of requests and `ConnectClient` can post
raw bodies (`post_raw`) or a chosen content type (`post_typed`) for negative
tests.

## Authority

The bridge is a pipe. It does not mint, attenuate, widen, rebind or bypass
anything:

1. **Envelopes cross verbatim.** Capability descriptors travel in the envelope;
   the receiving kernel's registry is the authority. A descriptor that claims a
   method the capability does not grant is refused with
   `rpc/method-not-granted` (`a_descriptor_cannot_widen_the_registry`).
2. **Refusals are preserved.** The error envelope carries the same request id
   and the same `rpc/...` code as a native transport
   (`a_refusal_crosses_the_bridge_unchanged`, `a_revoked_capability_is_refused_over_the_bridge`).
3. **No identity, no bound capability.** The bridge presents no peer identity,
   so a capability bound by `introduce_to` is refused with `rpc/identity`
   (`a_bound_capability_is_refused_over_the_bridge`).
4. **No ambient authority.** The bridge has no privileged method, no implicit
   capability and no way to transfer one. A request without a capability is
   `rpc/unknown-capability`.
5. **The AINF payload is bytes.** Infinity content hashes and redaction rules
   are unchanged: see `active-infinity/docs/spec/projection.md`. A projection
   carried through the bridge is a view, never the module's identity.

## Tests

`tests/connect_bridge_tests.rs` drives a real kernel behind a real
`BridgeServer` over loopback: a successful call, an unknown-capability refusal,
a descriptor that tries to widen authority, a bound capability and a revoked
capability. `tests/integration_tests.rs` adds framing abuse: a malformed gRPC
prefix (`400`), a wrong content type (`415`) and a request without
`content-length` (`400`, server keeps serving).

## Migration guidance

- New deployments start on ARP1 over TCP (or QUIC/HTTP2 when the network needs
  them).
- A bridge is added when an existing Connect/gRPC client must be reached. Keep
  it at the edge; do not re-export it as the native API.
- Bridge-level authentication (for example mTLS terminating at a gateway) is the
  gateway's job. The kernel still requires an authenticated identity before it
  honours a bound capability; the bridge alone never provides one.
