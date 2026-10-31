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
- no identity → `rpc/identity`.

The fingerprint is a Blake3 hash over the peer's DER certificate, domain
separated (`active-rpc/peer-identity/v1`). It is stable across reconnects for the
same certificate and different for every other certificate.

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
    1_000_000,                                  // connection budget
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

- **HTTP/2** carries ARP1 over a stream and has no identity of its own. Terminate
  TLS in front of it (a reverse proxy or a service mesh) and pass the verified
  peer to the dispatcher; do not accept a header that claims an identity.
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
   introduced to the old one must be re-introduced (`introduce_to`). Plan the
   rotation window.
4. **Revoke at the CA and at the kernel.** Dropping a certificate stops new
   handshakes; `Agent::revoke` stops existing capabilities immediately.
5. **Pin the clock mode.** Mint leases after selecting the clock
   (`use_wall_clock(true)` for real time), or a lease minted under the virtual
   clock is already expired.

## Evidence

- `tests/deployment_identity_tests.rs`: a CA issues the server and the client,
  a call succeeds with the expected fingerprint, a client from another CA is
  refused, and 25 further connections keep the same identity.
- `tests/identity_tests.rs`: policy admission, loopback relaxation, wrong and
  missing peers, the in-process test CA, and the QUIC bound-capability case.
- `tests/transport_binding_matrix.rs`: TCP, Connect and HTTP/2 with the right,
  wrong and missing peer.
