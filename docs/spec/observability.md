# Observability schema (Active RPC)

Two versioned JSON documents let a mesh collect telemetry without collecting
authority.

| Schema | Emitted by | Shape |
|--------|-----------|-------|
| `active-rpc/observability/1` | `Agent::trace()`, `Agent::trace_json()` | one object per kernel event |
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
   representation here.
4. **Stable names.** Event names and counter names are part of the schema. Adding
   a field is compatible; renaming one is a schema version bump.

## Event record

```json
{"schema":"active-rpc/observability/1","sequence":42,"event":"call.refused",
 "lane":0,"cap":"9f1c0e2d4b6a8c31","code":"rpc/method-not-granted"}
```

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
| `code` | string | a refusal or rejection with a stable `rpc/...` code |
| `dimension` | string | a budget exhaustion (`call`, `byte`, `lane call`, `promises`, `jobs`) |
| `identity` | string | a capability introduction; the peer fingerprint (a public label) |
| `detail` | string | a short, value-free explanation (`"3 jobs in 2 lanes"`) |

## Event names

| Name | Fields | Meaning |
|------|--------|---------|
| `cap.minted` | `cap`, `provider` | a first-generation or attenuated capability was minted |
| `cap.retained` | `cap` | a handle cloned |
| `cap.released` | `cap` | a handle dropped |
| `cap.dropped` | `cap` | the last reference went away; the provider was notified |
| `cap.revoked` | `cap` | a capability and its descendants were revoked |
| `cap.introduced` | `cap`, `identity` | a capability was bound to an authenticated peer |
| `cap.transferred` | `cap`, `channel` | a capability travelled on a channel |
| `lane.created` | `lane` | a lane was created |
| `lane.destroyed` | `lane` | a lane was destroyed |
| `call.queued` | `job`, `lane`, `cap` | a call entered the queue |
| `call.refused` | `lane`, `cap`, `code` | a call was refused before a provider saw it |
| `batch.dispatched` | `provider`, `detail` | one provider round-trip carrying a batch |
| `job.completed` | `job`, `lane` | a dispatched job finished |
| `promise.resolved` | `promise` | a promise settled with a value |
| `promise.rejected` | `promise`, `code` | a promise settled with an error |
| `channel.send` | `channel`, `channel_sequence` | a message was sent |
| `channel.recv` | `channel`, `channel_sequence` | a message was received |
| `budget.exhausted` | `cap`, `dimension` | a budget ceiling refused work |
| `tool.refused` | `cap`, `detail` | a tool policy refused work |

`tests/observability_tests.rs` fails if the code emits a name that is absent
from this table, so the table cannot drift.

## Retention and paging

The kernel keeps a bounded tape (`MAX_EVENTS`, 16 384 records). `sequence` is
monotonic over the whole life of the kernel, including evicted records, so a
collector pages with `last_sequence + 1` and never repeats a record. Consumers
that need every event export on a cadence shorter than the tape wrap.

## Metrics record

```json
{"schema":"active-rpc/metrics/1",
 "counters":{"calls_queued":12,"calls_refused":1,"budget_exhaustions":0,
             "tool_refusals":0,"revocations":0,"promises_resolved":11,
             "promises_rejected":0,"round_trips":3,"transfers":0,
             "promises_double_settled":0,"backpressure_refusals":0,
             "identity_refusals":0},
 "gauges":{"promises":4,"jobs":0,"lanes":1,"channels":0}}
```

Counters never decrease; gauges are point-in-time. A dashboard that reads a
counter keeps working when a new counter appears, which is why the object is a
map rather than a tuple.

## Exporting

The JSON is deliberately plain: an exporter maps `event` to a span name,
`sequence` to a record ordinal, and `cap`/`lane`/`promise` to attributes. No
OpenTelemetry dependency is required in the library, and a deployment that
prefers Prometheus reads the counters map directly.
