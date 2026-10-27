# ADR-0005 — Promises, batching and what "pipelined" measures

**Status:** accepted (2026-10-27)

## Context

The proposal asks that "a promise passed as an argument to a second call resolves
without a serial round-trip (observably fewer provider round-trips than the
non-pipelined sequence under injected latency)".

Elapsed time is a bad oracle: it depends on the machine, the OS scheduler and the
test's timing. The property needs a unit the kernel controls.

## Decision

1. A **batch** is every queued job for one provider, ordered so that a job whose
   promise dependencies are produced in the same batch runs after its producer.
2. **One batch is one provider round-trip.** `Agent::round_trips()` counts batches;
   `Event::BatchDispatched` records the size and the lanes involved.
3. A call whose arguments contain `Arg::Promise` is queued immediately. Two calls
   issued before `Agent::run()` therefore share a batch when they target the same
   provider and the dependency can be ordered.
4. A promise settles exactly once. A cycle among pipelined calls is detected
   before dispatch and fails with `rpc/pipelined-cycle` instead of deadlocking.
5. Rejection preserves the original error object through the promise, so a
   caller sees `rpc/domain` (with the Active class in the message), not a generic
   "provider failed".

## Consequences

- The test asserts `sequential == 2` and `pipelined == 1` with no timing
  dependence; the injected latency only makes the difference visible in a real
  deployment.
- Pipelining is a *provider* property: two calls to different providers cannot
  share a batch, which is correct — they are separate round-trips.
- The same accounting works over every transport, including cross-process: the
  peer binary reports the round-trips it observed
  (`tests/integration_tests.rs::cross_process_peer_pipelines_in_one_round_trip`).
