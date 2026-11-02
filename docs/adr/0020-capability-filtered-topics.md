# ADR-0020 - Capability-filtered pub/sub topics

**Status:** accepted (2026-10-31). Additive; ARP1 unchanged.

## Context

Channels move values and capabilities between lanes. A publisher that should
only speak on particular subjects (`alerts`, `metrics`, one tenant's stream) had
no way to be restricted: opening a channel grants the whole channel. The
capability model already narrows methods, budgets, paths, tools and lifetimes;
topics are the pub/sub analogue.

## Decision

- `CapAttrs` gains `topics: Option<BTreeSet<String>>`. `None` means no topic
  restriction; `Some(set)` is an allow-list.
- `CapAttrs::restrict_topics(&["a", "b"])` builds the set **and** the publish
  grant; `CapAttrs::allow_publish()` grants any topic. Publishing is an explicit
  grant, not a side effect of holding a capability (see the amendment below).
- `Agent::publish(lane, channel, cap, topic, payload)` requires a live
  capability:
  - revoked or expired → `rpc/revoked` (with `Event::CapExpired` for expiry),
  - topic outside the set → `rpc/topic-not-granted`,
  - channel missing → `rpc/unknown-channel`, queue full → `rpc/backpressure`,
  - receive-only channel → `rpc/invalid-argument`.
  The message is queued with its topic and transfers no capabilities.
- `Agent::recv_topic(channel, topic)` takes the oldest message on that topic;
  later messages on other topics stay queued in order. `recv` still takes the
  oldest message of any topic, and `send` still produces topic-less messages.
- **Attenuation only narrows.** `is_attenuation_of` and `attenuate` refuse a
  child whose topic set is not a subset of its parent's, and refuse a child that
  drops the restriction entirely. An unrestricted parent may be narrowed.

## Consequences

- `rpc/topic-not-granted` joins the error vocabulary.
- `Message` gains a `topic` field; the channel API gains `send_topic`,
  `recv_topic` and the kernel `publish`/`recv_topic` pair.
- Topic strings are part of the local policy, not the wire envelope: a peer
  cannot widen a topic set by editing a descriptor, exactly like paths and
  tool policy.
- Subscriptions are per receive call, not stored per lane. A sticky subscriber
  registry would be a new ADR.

## Amendment (R-17, hostile review round 1)

The review found that the topic set filtered *publishers* while the channel had
no read authorization at all. Three changes:

- **Reading is a subscription.** `recv`/`recv_topic` take the lane and require
  that lane to be in the channel's subscriber set. Channel ids were a sequential
  counter and a receive needed nothing but an id, so any lane in the kernel could
  drain any channel. A lane that may not read a channel gets `rpc/unknown-channel`
  — the same answer as a channel that does not exist — so the ids are not a
  membership oracle.
- **Publishing is a grant.** `CapAttrs::publish` defaults to false and
  attenuation can only drop it, so holding a capability for one provider no
  longer lets a lane speak on a channel under a topic a subscriber trusts. A cap
  without the grant gets `rpc/method-not-granted`; the record persists the flag.
- **A topic is bounded text.** 1..=128 bytes, no control characters, checked at
  the grant and again at publish. An empty topic was publishable and
  indistinguishable from "no topic"; an unbounded one reached an error message
  and an event unclamped; a control character forged a line in a terminal.

Remaining, recorded: a publisher's *identity* is not in the message, so two
capabilities granted the same topic are indistinguishable to a subscriber. A
future revision can record the publishing correlation id on `Message`.
