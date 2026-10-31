# ADR-0014: An observability schema that carries no authority

- Status: Accepted
- Date: 2026-10-30
- Context: Maturity Program C-6.4 (PROPOSAL §5.9)

## Problem

Operators need to answer "which capability refused which call on which lane" in
a mesh of agents. The obvious implementation — log the event, including the
capability id — turns every log sink, dashboard, error tracker and support
bundle into a credential store. In Active RPC the id *is* the authority, so a log
line that contains one is a capability handout, and `Debug` for `CapId` already
prints a correlation id for exactly this reason.

## Decision

1. **Two versioned documents.** `active-rpc/observability/1` is one JSON object
   per kernel event; `active-rpc/metrics/1` is a counter and gauge snapshot. Both
   are emitted by the kernel (`Agent::trace_json`, `Agent::metrics_json`) and by
   the `observability` module directly.
2. **Correlation only.** Every capability reference is
   `CapId::correlation_id()`, a domain-separated truncated hash. Two records for
   the same capability correlate; neither can be replayed. The raw id never
   appears.
3. **No values.** Events carry ids, counts, stable codes and a short value-free
   `detail`. Argument values, module bytes and secret material have no field.
4. **A closed name set.** `EVENT_NAMES` lists every event the schema can emit.
   The projection covers all of them, and a test fails if the documentation does
   not name each one. Adding an event is a code + doc + test change in one commit.
5. **Monotonic sequences across eviction.** The kernel's event tape is bounded
   (16 384). `sequence` counts every event ever appended, so a collector pages
   with `last_sequence + 1` and observes each record once across a wrap.
6. **Plain JSON, no tracing dependency.** An exporter maps the record to a span or
   a metric; the library does not take an OpenTelemetry dependency, and a
   Prometheus deployment reads the counters map directly.

## Consequences

- A support bundle, a CI log and a dashboard are safe to share by default. That
  is the same posture as the redaction rules in Active Infinity.
- The schema is additive: new fields and counters do not break a reader. Renaming
  a name is a schema version bump, which is why the tests pin the set.
- Correlation ids are stable for the lifetime of an id and differ between
  kernels, so two agents' logs cannot be joined on a capability id — they can be
  joined on a lane, a promise or an application-level id. That is the intended
  trade: cross-agent correlation is an application concern, not a capability
  leak.
- `Metrics` gained `identity_refusals` in the same phase; the observability test
  compares every counter in JSON against the live struct, so a new counter that is
  not exported fails the test.
