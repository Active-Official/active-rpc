# Security policy — Active RPC

## Supported versions

| Version | Security fixes |
|---|---|
| 1.0.x | yes |

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
- Budget is charged per call and intersects capability with lane.
- Secret material is represented by `Value::Secret`, never by bytes.
- Every frame is bounded and rejected at the boundary.
- `#![forbid(unsafe_code)]`.
