# ADR-0011: Transport identity and capability binding

- Status: Accepted
- Date: 2026-10-30
- Context: Maturity Program C-6.1 (PROPOSAL §5.4)

## Problem

A capability is an unforgeable 128-bit id, but "unforgeable" is not "unshareable".
The id travels over a transport. A peer that observes it — in a proxy log, in a
crash dump, in a copied frame, or simply because it was handed the wrong
descriptor — can present it and the kernel will dispatch the call. Promise and
budget semantics stay correct, but the *principal* is wrong: authority moved
without an attenuation.

The missing link is the peer. A transport knows who connected (a certificate, a
TLS exporter), and the kernel does not. Without that link, capability
introduction is a bearer token with no audience.

## Decision

1. A transport may expose a **`PeerIdentity`**: a kind (`mutual-tls`, `loopback`,
   `anonymous`), a subject label, and a 32-byte fingerprint. The fingerprint is
   a domain-separated Blake3 digest of the DER certificate the TLS stack
   verified. It identifies a peer; it never authorises one.
2. **`IdentityPolicy`** decides whether a peer is admitted. The production
   default requires an identity and relaxes loopback only; `strict()` requires a
   certificate even on loopback; `local()` admits anonymous peers for
   development and marks them unbindable. `loopback` must come from connection
   addresses, never from a header.
3. **`CapAttrs::bound_to`** records the fingerprint a capability was introduced
   to. Dispatch (`call_as`) refuses a bound capability when the presented
   identity is missing or different (`rpc/identity`). `send_as` refuses to
   transfer a bound capability over a channel: a channel cannot prove who reads
   the message, so delegation across an identity boundary is an explicit
   `introduce_to`.
4. **Attenuation is monotone for binding.** A child inherits the parent's
   binding; it may add a binding when the parent has none; it may never change
   or drop one. Rebinding is `rpc/attenuation-escalation`.
5. **QUIC mutual TLS is the first implementation.** `QuicServer::start_mutual_tls`
   verifies a client certificate against a CA and hands the identity to the
   handler. `QuicClient::connect_mutual_tls` presents a client certificate.
   `peer_identity()` reads only a certificate the TLS stack verified; an
   unauthenticated session yields `None`.

## Consequences

- The registry remains the authority. Binding narrows *who* may exercise a
  capability that already exists; it never creates authority.
- A capability copied off a connection is useless to another peer, which is the
  audience property a bearer token lacks.
- `Error` gains a variant (`Identity`). The wire code `rpc/identity` is
  permanent. This is an additive change to the envelope's error vocabulary, not
  to the envelope layout: ARP1 v1 bytes are unchanged.
- The fingerprint is not the X.509 SHA-256 thumbprint. Operators who need the
  standard thumbprint compute it from the certificate; using one digest
  everywhere keeps the comparison cheap and domain-separated.
- The test CA in `transport::quic` is single-host scaffolding. A deployment
  supplies its own CA-signed certificates; the verifier API is the seam.

## Alternatives considered

- **Bearer-only capabilities with short TTLs.** Rejected as the primary control:
  a TTL bounds the damage window but does not bind the audience, and C-11 adds
  TTLs as an additional, independent control.
- **Putting the binding on the wire descriptor.** Rejected: the binding is
  enforced where the capability was minted, and a peer never needs our local
  fingerprint map. Keeping it off the wire keeps ARP1 v1 stable.
- **Binding to a connection id instead of a certificate.** Rejected: a
  connection is ephemeral (QUIC migration, reconnects), so a reconnect would
  silently invalidate or, worse, re-bind authority.
