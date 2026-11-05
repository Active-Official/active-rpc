# Identity in a deployment

Active RPC's kernel does not open sockets; transports do, and a transport that
claims a peer identity must prove it. This guide covers the only identity source
the shipped transports accept — a mutual-TLS certificate — and how to run it with
a certificate authority you own instead of the in-process test CA.

## What identity buys

A capability bound with `mint_bound` (or `introduce_to`) records a peer
fingerprint. At dispatch the kernel compares that fingerprint with the identity
the transport authenticated:

- right peer → the call runs;
- wrong peer → `rpc/identity`;
- no identity → `rpc/identity`;
- a **loopback** peer → `rpc/identity`.

Only a **certificate** peer can hold a binding. The loopback relaxation admits a
local caller without a certificate, but every local process shares that one
identity, so binding a capability to it would hand the capability to every
process on the host. A loopback caller may use an *unbound* capability; bind one
only to a verified certificate. `introduce_to` binds the capability and every
live capability derived from it, so a child minted before the introduction
cannot be used by another peer or transferred over a channel.

The fingerprint is a Blake3 hash over the peer's DER certificate, domain
separated (`active-rpc/peer-identity/v1`). It is stable across reconnects for the
same certificate and different for every other certificate. `with_subject`
attaches an operator-facing **label**; the fingerprint does not change, because
it is the binding key the transport presents.

Identity is not authority by itself: it only answers *who* may use a capability
that was already introduced to them.

## Trust model

```text
            your CA (offline or HSM-backed)
             /                         \
   server certificate            client certificate
   (QUIC listener)               (each agent)
```

- **One CA per trust domain.** A client trusts the server's CA; the server trusts
  the clients' CA. They may be the same CA.
- **The kernel does not ship a CA.** `QuicServer::start_mutual_tls` generates a
  throwaway CA so tests can run in one process; production uses
  `QuicServer::start_with_identity`.
- **Certificates identify processes, not people.** Issue one leaf per agent
  deployment, with the deployment's name in the subject. Rotation is a new leaf,
  not a new CA, unless you are revoking the domain.

## Server

```rust
use std::net::SocketAddr;
use active_rpc::transport::quic::{QuicServer, ServerIdentity};

let identity = ServerIdentity {
    chain: vec![leaf_der, intermediate_der],   // leaf first, then issuers
    key: leaf_private_key,                     // PKCS#8 DER
};
let bind: SocketAddr = "0.0.0.0:7443".parse()?;
let server = QuicServer::start_with_identity(
    1_000_000,                                  // max calls before shutdown (0 = unlimited)
    handler,                                    // FnMut(Envelope, Option<PeerIdentity>) -> Envelope
    bind,
    identity,
    Some(ca_der),                               // require client certificates
)?;
```

- `Some(ca_der)` turns on client authentication; `None` accepts anonymous clients
  and reports `None` as the peer identity, which makes every bound capability
  unusable (fail closed).
- `start_with_identity` mints nothing: `client_credentials()` and
  `issue_client_credentials()` return `None`/error, because the CA is yours.
- The handler receives the authenticated peer. Dispatch with
  `agent.call_as(peer.as_ref(), …)` or `publish_as`; never with `None` on a path
  that is supposed to be authenticated.

## Client

```rust
use active_rpc::transport::quic::QuicClient;

let client = QuicClient::connect_mutual_tls(
    "rpc.internal:7443",
    &ca_der,          // trust root for the server
    client_leaf_der,  // this agent's certificate
    client_key,       // PKCS#8 DER
)?;
```

A client that presents a certificate from another CA fails the handshake; a
client that presents none fails it as well.

## HTTP/2 and Connect

- **HTTP/2** carries ARP1 over a stream and has no identity of its own: the
  shipped transport is plaintext, and its handler signature has no identity to
  pass. Terminate TLS in front of it (a reverse proxy or a service mesh) and
  have *that* terminator refuse or bind capabilities; do not accept a header
  that claims an identity, and do not bind a capability to a peer when the
  connection is HTTP/2, because the kernel cannot tell two peers apart there.
  Use QUIC with mutual TLS when a bound capability has to be enforced.
- **Connect/gRPC** is interop only and presents no peer identity in this build,
  so a bound capability is refused through the bridge. That is intentional: the
  gateway authenticates, and the kernel still refuses anything it cannot bind.

## Operating rules

1. **One leaf per agent.** Do not share a client certificate between processes:
   the fingerprint is the only identity the kernel sees.
2. **Keep the private key off the wire and out of logs.** The CLI reads
   certificates and keys from files; the kernel never prints key material, and
   should not be given a path it cannot read.
3. **Rotate before expiry.** A new leaf has a new fingerprint, so capabilities
   bound to the old one are moved with `reintroduce_to(cap, &old_peer, &new_peer)`
   (`introduce_to` refuses an already-bound capability). A rotation also
   tombstones the durable records exported for the old peer, and only the live
   subtree is rebound: a revoked or expired child keeps the binding it died
   with. Plan the rotation window.
4. **Revoke at the CA and at the kernel.** Dropping a certificate stops new
   handshakes; `Agent::revoke` stops existing capabilities immediately.
5. **Pin the clock mode.** Mint leases after selecting the clock
   (`use_wall_clock(true)` for real time), or a lease minted under the virtual
   clock is already expired.
6. **The policy is a path, not an attribute.** `IdentityPolicy::admit` returns an
   `AdmittedIdentity`, and `dispatch_envelope` is what enforces
   `require_identity`/`trust_loopback`. `call_as` trusts whatever peer handle the
   embedder passes, so a server that hands a peer straight to `call_as` has
   applied no policy: admit first, then dispatch. A QUIC handler receives the
   peer certificate but not the connection, so it must derive the loopback flag
   from its own connection (`remote_addr().ip().is_loopback()`) before calling
   `admit`.

## Evidence

- `tests/deployment_identity_tests.rs`: a CA issues the server and the client,
  a call succeeds with the expected fingerprint, a client from another CA is
  refused, and 25 further connections keep the same identity.
- `tests/identity_tests.rs`: policy admission, loopback relaxation, wrong and
  missing peers, the in-process test CA, and the QUIC bound-capability case.
- `tests/transport_binding_matrix.rs`: TCP, Connect and HTTP/2 with the right,
  wrong and missing peer.
