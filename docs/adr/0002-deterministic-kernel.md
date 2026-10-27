# ADR-0002 — A deterministic kernel with transports as adapters

**Status:** accepted (2026-10-27)

## Context

The obvious implementation of "RPC with pipelining and concurrency" is async:
tokio tasks, channels, timeouts. That makes the properties this crate promises
hard to test: a pipelined chain either wins a race or does not, budget
enforcement depends on when a task got scheduled, and drop notification becomes a
timing question.

## Decision

1. The kernel is a **synchronous deterministic state machine**. Providers are
   `Box<dyn Provider>`; time is a counter (`set_latency`); dispatch is an
   explicit `Agent::run()` loop. A *batch* is every queued job for one provider,
   ordered so promise producers precede consumers.
2. Capability lifetimes are `Rc`-based handles with an `Rc<dyn CapControl>`
   reference counter; the last drop notifies the provider. This is checked, not
   guessed: no garbage collector timing is involved.
3. Transports are adapters over the same `Envelope`. The in-process transport
   moves envelopes by value (no bytes); TCP, shared memory, QUIC and the Connect
   bridge serialize the same bytes.
4. Real concurrency is exercised where it belongs: multiple lanes interleaved by
   the scheduler, and multiple OS threads each owning an agent and a socket
   (tested in `tests/concurrency_tests.rs`).

## Consequences

- Pipelining is measurable as "provider round-trips", not as elapsed time. The
  test asserts 1 versus 2 deterministically.
- Budget exhaustion, revocation and drop notification are reproducible.
- Throughput is bounded by one core per agent kernel. An agent that needs more
  runs more kernels — which is the intended model (one kernel per identity, many
  lanes inside it).
- An async facade can be layered on top without changing semantics: each
  `Agent::run` step is a unit of work an executor can schedule.
