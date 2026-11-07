# ADR-0024 - Subscriptions are not authority

**Status:** accepted (2026-11-02).
**Date:** 2026-11-02
**Context:** R-05 lanes and channels, carried residual (recv is ambient).

## Problem

`Agent::recv` and `Agent::recv_topic` take a lane and a channel id and need
nothing else. The kernel checks that the lane is subscribed, and `subscribe`
needs no capability: any caller that holds the `Agent` can subscribe a lane to
any channel and drain it. Channel ids are a sequential counter, so enumerating
them is trivial. A provider, or any code that clones the `Agent`, can therefore
read every message in the kernel.

The R-05 audit called this out as the section's open finding and asked for an
ADR: either a subscription becomes a capability, or the model says plainly that
it is not one.

## Decision

**A subscription is kernel-local state, not authority.** The kernel keeps the
rule that a receive must come from a subscribed lane, because it makes an
accidental cross-lane read (a mistyped channel id, a lane reused by a scheduler)
a refusal rather than a leak. It does not claim more than that.

1. **Holders of the `Agent` are trusted.** The same trust boundary already lets
   a holder mint capabilities, register providers, export durable records and
   read the event tape. A channel read adds no authority a holder did not
   already have.
2. **Untrusted code never holds the `Agent`.** Providers receive `&mut self` and
   a `Call`; a provider that needs kernel services is constructed with a clone,
   which is an explicit decision by the embedder (the tool adapters do not get
   one). Remote peers reach the kernel through transports, and no transport has
   a "receive from an arbitrary channel" message.
3. **The advisory gate stays.** `recv` from an unsubscribed lane answers
   `rpc/unknown-channel`, the same answer as an id that does not exist, so the
   receive path is not a membership oracle for a lane. The host is a different
   principal: it already holds `&Agent`, and `Agent::channel(id)` returns a
   channel's existence, name, counts and subscriber total for any id, while
   `publish` distinguishes a missing channel from a closed one. That is inside
   the `&Agent` trust boundary (point 1) and no envelope path reaches it.
   `unsubscribe` exists so a lane can withdraw read access from a channel it no
   longer needs, and `destroy_lane` and `destroy_channel` clear the relevant
   halves.
4. **A capability-mediated receive would be a new feature, not a fix.** It would
   need: a receive capability naming (channel, filter), a changed wire surface so
   a remote peer can be granted one, and a story for what a capability means
   when the channel is created and destroyed inside the same kernel. That is a
   design change with its own ADR, and nothing in the program requires it.

## Consequences

- The security model states the boundary: lanes and channels are isolation for
  budgets, ordering and lifecycle, and authority still lives on capabilities.
- An embedder that runs third-party code in-process must not hand it the
  `Agent`; that is the same rule that already applies to providers, durable
  records and the tape.
- A future capability-mediated receive can be added without breaking this ADR:
  it would be an additional check in `check_subscriber`, and the current
  behaviour would become the "ambient mode" of a kernel that opts in.
