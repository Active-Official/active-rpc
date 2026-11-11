# Observability schema (Active RPC)

Two versioned JSON documents let a mesh collect telemetry without collecting
authority.

| Schema | Emitted by | Shape |
|--------|-----------|-------|
| `active-rpc/observability/3` | `Agent::trace()`, `Agent::trace_json()` | one object per kernel event |
| `active-rpc/metrics/1` | `Agent::metrics_json()` | counters and gauges |

## Hard rules

1. **Correlation ids only.** A capability is identified by
   `CapId::correlation_id()` — a domain-separated, truncated hash. The raw
   128-bit id is authority and never appears in a metric, a trace, a log line or
   an error. An operator can correlate two records for the same capability
   without being able to call it.
2. **No argument values.** Kernel events carry ids, counts and stable codes. A
   provider error code is reported; the arguments that produced it are not.
3. **No secrets.** Secret material is a marker in the value model and has no
   representation here. Free-form label fields (`code`, `dimension`,
   `detail`) pass through `label()`, which scrubs secret-looking shapes
   (`key=value` assignments, `Bearer`/`Basic` tokens, `sk-`/`ghp_`/`AKIA`
   prefixed tokens, PEM private keys, URL userinfo) to `[redacted]`
   (RPC-48): a refusal reason is provider-controlled text, so the scrubber
   is the second line of defence behind the rule that events carry no
   values. A hash, a correlation id, or a long method name is not a
   secret shape and passes through untouched.
4. **Stable names.** Event names and counter names are part of the schema. Adding
   a field is wire-compatible — a reader ignores fields it does not know — but
   the schema version still moves when the shape changes, so a consumer that
   asserts exact field sets is told to update instead of silently reading the
   old shape. v2 added the optional `method` label on the call-lifecycle
   events and `args_bytes` on `call.queued` (RPC-46). v3 adds the optional `identity` caller prefix on `call.queued` (RPC-56). Renaming a field is a
   schema version bump.

## Event record

```json
{"schema":"active-rpc/observability/3","sequence":42,"event":"call.refused",
 "lane":0,"cap":"9f1c0e2d4b6a8c31","method":"nope","code":"rpc/method-not-granted"}
```

The `method` label is the bounded name the kernel records for the call: a
granted name is carried exactly, and a name longer than 64 bytes (or one
carrying characters the trace cannot hold) is an escaped 64-byte prefix plus
a 128-bit digest tail, so two long names that share a prefix stay distinct.
A refusal that names no call — a send, a publish, or a receive that failed
before any method was selected — carries no `method` field at all. A
`method` is a tool identifier, never an argument value: argument values
have no representation in any event (rule 2), and a name the kernel cannot
represent is labelled, never dropped silently and never refused.

| Field | Type | Present when |
|-------|------|--------------|
| `schema` | string | always |
| `sequence` | u64 | always; monotonic per kernel, survives tape eviction |
| `event` | string | always; one of the names below |
| `lane` | u64 | the event names a lane |
| `cap` | string | the event names a capability (correlation id) |
| `provider` | u64 | the event names a provider |
| `job` | u64 | the event names a queued or completed job |
| `promise` | u64 | the event names a promise |
| `channel` | u64 | the event names a channel |
| `channel_sequence` | u64 | a channel send or receive |
| `code` | string | a refusal or rejection with a stable `rpc/...` code, projected from `Error::code` (a provider-authored code is always `rpc/provider`, never the provider's own text) |
| `method` | string | a call-lifecycle event (`call.queued`, `call.refused`, `job.completed`): the method the call named, as the bounded label the kernel records; absent on a refusal that names no call |
| `args_bytes` | u64 | `call.queued`: the argument bytes the call was charged for (a refused call was never charged, so a refusal carries none; a completed job's bytes are on its queued record) |
| `dimension` | string | a budget exhaustion or ceiling: `call`, `byte`, `lane call`, `lane byte`, `promises`, `jobs`, `caps`, `caps per message`, `lanes`, `channels`, `subscriptions`, `records`, `tombstones`, `nodes`, `keys`, `value`, `wall`, `depth`, `array_len`, `value_size`, `channel queue`, `args`, or `other` for a ceiling added without a label |
| `identity` | string | a capability's peer: one fingerprint (a public label) for `cap.introduced`, `from->to` for `cap.rebound`, which carries the same field twice, or the first 128 bits of the caller's fingerprint (32 lowercase hex characters) for `call.queued` |
| `detail` | string | a short, value-free explanation (`"3 jobs in 2 lanes"`) |

## Event names

| Name | Fields | Meaning |
|------|--------|---------|
| `cap.minted` | `cap`, `provider` | a first-generation or attenuated capability was minted |
| `cap.retained` | `cap` | a handle cloned |
| `cap.released` | `cap` | a handle dropped |
| `cap.dropped` | `cap` | the last reference went away; the provider was notified |
| `cap.revoked` | `cap` | a capability and its descendants were revoked |
| `cap.expired` | `cap` | a capability's TTL elapsed and it was refused like a revocation |
| `cap.exported` | `cap` | a durable capability was exported as a sealed record |
| `cap.restored` | `cap` | a sealed durable record was restored as a live capability (paired with `cap.minted`) |
| `cap.record-orphaned` | `cap` | the last handle of an exported durable capability was dropped: the record is still restorable, and its object stays pinned until the record is restored or tombstoned (by a revoke, a kill switch or a rotation away from the bound peer); when the last pin and live capability are gone, the provider reclaims the object |
| `cap.rebound` | `cap`, `identity` | a capability was rebound from one authenticated peer to another (`from->to` fingerprints) |
| `cap.rotation-carried` | `cap`, `detail` | a rotation carried the peer's own work to the successor certificate; `detail` is `jobs N promises N claims N`, so a rotation that moved a peer's answers is distinguishable from one that moved none |
| `cap.introduced` | `cap`, `identity` | a capability was bound to an authenticated peer |
| `cap.transferred` | `cap`, `channel` | a capability travelled on a channel |
| `lane.created` | `lane` | a lane was created |
| `lane.destroyed` | `lane`, `detail` | a lane was destroyed; `detail` is the number of queued jobs dropped with it (their per-job events are coalesced into this one, receipts still record each refusal) |
| `call.queued` | `job`, `lane`, `cap`, `method`, `args_bytes`, `identity` | a call entered the queue; `identity` is present when the call arrived from an authenticated peer |
| `call.refused` | `lane`, `cap`, `method`, `code` | a call was refused before a provider saw it; `method` is absent when the refusal names no call |
| `batch.dispatched` | `provider`, `detail` | one provider round-trip carrying a batch |
| `job.completed` | `job`, `lane`, `method` | a dispatched job finished; `method` is the same label `call.queued` carried for the job, so the two records join on (`job`, `method`) |
| `promise.resolved` | `promise` | a promise settled with a value |
| `promise.rejected` | `promise`, `code` | a promise settled with an error; the code is an `rpc/...` class, except that a withheld reply is `provider/reply-withheld` (the kernel authors that one, so the tape says what actually happened) |
| `channel.send` | `channel`, `channel_sequence` | a message was sent |
| `channel.created` | `channel` | a channel was created |
| `channel.subscribed` | `lane`, `channel` | a lane gained read access to a channel |
| `channel.unsubscribed` | `lane`, `channel` | a lane withdrew its read access |
| `channel.closed` | `channel` | a channel stopped accepting sends; queued messages stay receivable |
| `channel.destroyed` | `channel`, `detail` | a channel was destroyed; `detail` is the number of messages dropped with it |
| `channel.recv` | `channel`, `channel_sequence` | a message was received |
| `budget.exhausted` | `cap`, `dimension` | a budget ceiling refused work |
| `receipts.dropped` | `detail` | the receipt ring dropped records; `detail` carries the running total (evicted or cleared) |
| `receipts.disabled` | `detail` | receipt recording was turned off; `detail` carries the running dropped total, so a log exported across the interval shows that decisions were not recorded |
| `receipts.enabled` | — | receipt recording was turned on again after a disabled interval; a repeated call is not a transition and emits nothing |
| `provider.panicked` | `provider`, `detail` | a provider panicked; `detail` names the phase, and the panic message never enters a trace |
| `intro.skipped` | `provider`, `detail` | a provider's captured surface cannot go into an introduction module (a name or a method the module cannot carry, or more than 4 096 methods), so `intro` leaves it out; `detail` is the reason |
| `tool.refused` | `cap`, `detail` | a tool policy refused work |

`tests/observability_tests.rs` fails if the code emits a name that is absent
from this table, so the table cannot drift.

## Retention and paging

The kernel keeps a bounded tape (`MAX_EVENTS`, 16 384 records). `sequence` is
monotonic over the whole life of one kernel, including evicted records, so a
collector pages with `last_sequence + 1` and never repeats a record within that
kernel. A restarted kernel starts at zero again and the record carries no epoch:
a collector must read `metrics_json` and reset its cursor when `events_total`
decreases, or it will discard every event below its last seen sequence. Consumers
that need every event export on a cadence shorter than the tape wrap.

## Metrics record

```json
{"schema":"active-rpc/metrics/1",
 "counters":{"calls_queued":12,"calls_refused":1,"budget_exhaustions":0,
             "tool_refusals":0,"revocations":0,"promises_resolved":11,
             "promises_rejected":0,"round_trips":3,"transfers":0,
             "promises_double_settled":0,"backpressure_refusals":0,
             "identity_refusals":0,"receipts_dropped":0,"events_total":57,
             "events_evicted":0},
 "gauges":{"promises":4,"promises_kept":4,"promises_pending":0,
           "events_retained":57,"jobs":0,"lanes":1,"channels":0}}
```

Counters never decrease; gauges are point-in-time. A dashboard that reads a
counter keeps working when a new counter appears, which is why the object is a
map rather than a tuple.

`promises` is the number of retained promise records (the gauge the schema
always had); `promises_kept` is the same number named honestly, and
`promises_pending` is the outstanding work an operator watches. `events_total`
is monotonic; `events_retained` is the bounded tape and `events_evicted` is what
the tape dropped, so a quiet kernel is distinguishable from one whose history
was overwritten.

A **decrease** in `events_total` means a different kernel (or a restart): the
tape is bounded, so `events_retained` may fall while `events_total` cannot. A
collector must treat a decrease as a new epoch and must not merge the two
number spaces.

## Exporting

The JSON is deliberately plain: an exporter maps `event` to a span name,
`sequence` to a record ordinal, and `cap`/`lane`/`promise` to attributes. No
OpenTelemetry dependency is required in the library, and a deployment that
prefers Prometheus reads the counters map directly.
