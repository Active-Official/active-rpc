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

- `Some(ca_der)` turns on client authentication. `None` accepts anonymous
  clients, so it is only accepted when the listener binds a loopback address;
  every other `None` is refused at startup. An anonymous peer is reported as
  `None`, which makes every bound capability unusable (fail closed).
- `start_with_identity` mints nothing: `client_credentials()` and
  `issue_client_credentials()` return `None`/error, because the CA is yours.
- The handler receives the authenticated peer. With `Some(ca_der)` the
  handshake has already refused an anonymous peer, so the policy step is
  done; dispatch the decoded envelope with `dispatch_envelope` (or
  `call_from_envelope`) so its arguments pass the authority-argument guard.
  `call_as` is for arguments this process built: it does not run the
  authority-argument guard, so never decode a peer's body into `Arg` and
  forward it with `call_as`. `call_peer` is a transport entry point and does
  run the guard, so an envelope cannot smuggle a promise or a capability
  through it. On either path a pipelined argument may only name a promise the
  same peer queued. With `None` (loopback only) the peer can be
  anonymous, so run `IdentityPolicy::admit` and `dispatch_envelope`
  (rule 6 below). Never pass `None` on a path that is supposed to be
  authenticated.

## Client

```rust
use active_rpc::transport::quic::QuicClient;

let client = QuicClient::connect_mutual_tls_with_name(
    "rpc.internal:7443",
    "rpc.internal",   // the name the server certificate covers (SNI)
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
2. **Keep the private key off the wire and out of logs.** The CLI reads a
   certificate (`--cert` as a trust root, `--cert-out` to write one); it has no
   mTLS client mode and never takes a private key. A key stays in the
   deployment's own file store, and the kernel never prints key material.
3. **Rotate before expiry.** A new leaf has a new fingerprint, so capabilities
   bound to the old one are moved with `reintroduce_to(cap, &old_peer, &new_peer)`.
   `introduce_to` refuses a capability bound to a *different* peer (re-introducing
   one to the peer that already holds it is a no-op). A rotation also tombstones
   the durable records exported for the old peer, and only the live subtree is
   rebound: a revoked or expired child keeps the binding it died with, and a
   child holding a deadline from the other clock mode refuses the whole
   operation instead of being rebound or left open. The peer's *work* follows the
   binding: queued jobs, pending promises and cached idempotency claims stamped
   with the old fingerprint are moved to the successor, so a retry of a call the
   peer already made returns the same promise instead of `rpc/identity` (and a
   retry with a fresh key would apply the mutation twice). Two consequences to
   plan for. First, the carry is scoped to the capabilities this call rebinds: a
   queued pipeline that spans two capabilities of the same peer needs **both**
   rotated before the next dispatch, or the dependent job is refused
   `rpc/identity` (fail-closed, nothing half-applied). Second, an idempotency
   claim is scoped to `(capability, lane, method, key)` and a rotation cannot
   move a lane: a retry that arrives on a new connection, and therefore a new
   lane, is a new call, so a peer retrying an applied mutation has to retry on
   the lane that holds the claim or accept that the write may apply again. Plan
   the rotation window.
4. **Revoke at the CA and at the kernel.** Dropping a certificate stops new
   handshakes; `Agent::revoke` stops existing capabilities immediately.
5. **Pin the clock mode.** Mint leases after selecting the clock
   (`use_wall_clock(true)` for real time), or a lease minted under the virtual
   clock is already expired.
6. **The policy is a path, not an attribute.** `IdentityPolicy::admit` returns an
   `AdmittedIdentity`, and `dispatch_envelope` is what enforces
   `require_identity`/`trust_loopback`. `call_as` trusts whatever peer handle the
   embedder passes, so a server that hands a peer straight to `call_as` has
   applied no policy: admit first, then dispatch. The `FnMut(Envelope,
   Option<PeerIdentity>)` handler signature carries the certificate, not the
   connection, so the loopback flag has to be derived where the connection is
   available (a `quinn::Connection::remote_address()`, for example) and passed
   into `admit` there; a handler cannot infer it from the envelope.

## Evidence

- `tests/deployment_identity_tests.rs`: a CA issues the server and the client,
  a call succeeds with the expected fingerprint, a client from another CA is
  refused, and 25 further connections keep the same identity.
- `tests/identity_tests.rs`: policy admission, loopback relaxation, wrong and
  missing peers, the in-process test CA, and the QUIC bound-capability case.
- `tests/transport_binding_matrix.rs`: TCP, Connect and HTTP/2 with the right,
  wrong and missing peer.
