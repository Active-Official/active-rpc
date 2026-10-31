# ADR-0022 — Clock policy: virtual by default, wall clock on request

**Status:** accepted (2026-10-31). No wire change.

## Context

Deadlines (ADR-0015) are absolute kernel milliseconds. The kernel needs a clock
to resolve them, and two consumers want different things:

- a test, a replay, or a benchmark wants **determinism**: the same inputs must
  produce the same decisions;
- a long-running agent in production wants **real time**: a one-hour lease must
  end one hour later, not after N round trips.

The earlier kernel only had the first: `now_ms` advanced by one simulated round
trip (`latency_ms`) per dispatch. That is exact and replayable, but a process
that waits between calls never sees its clock move.

## Decision

One kernel, two modes, selected with `Agent::use_wall_clock(bool)`:

| Mode | Advancement | Used for |
|---|---|---|
| Virtual (default) | `now_ms += latency_ms` at dispatch | tests, replay, benchmarks; fully deterministic |
| Wall | `now_ms = max(now_ms, SystemTime since epoch)` at dispatch | production leases; follows real time |

Rules that hold in both modes:

1. **`now_ms` never decreases.** A backwards system-clock jump cannot extend a
   capability's life; `max` keeps the clock monotonic. A forward jump can end a
   lease early, which is the safe direction.
2. **The deadline is checked at queue time and again at dispatch** (ADR-0015).
   The mode changes how `now_ms` moves, never whether it is checked.
3. **Switching to wall clock jumps forward** to real time; switching back keeps
   the current value. Neither transition rewinds.
4. **Idempotency keys and receipts use the same clock**, so a wall-clock agent
   records real times and a virtual agent records simulated ones. The field is
   documented as "kernel time", not "wall time".
5. **Replay is a virtual-clock feature.** A replay package records the demo
   session, whose clock is simulated. A session that runs with the wall clock is
   not byte-reproducible, and the replay API does not claim it is.

## Why not a pluggable `Clock` trait

A trait would let an embedder supply a clock that jumps backwards or freezes,
which are exactly the failure modes deadlines must resist. Two explicit modes
keep the monotonicity proof local and testable. An embedder that needs a
different time source can drive `use_wall_clock(false)` and call a long-running
agent only when it wants simulated time.

## Consequences

- `Agent::now_ms()` exposes the current kernel time for diagnostics and tests.
- A deployment must decide its mode at start-up: a lease minted under the
  virtual clock and later read under the wall clock was minted with an absolute
  deadline near zero, so it is already expired. Mint after enabling the mode.
- Wall-clock mode is a per-agent switch, not a global; two agents in one process
  may disagree, which is intentional (a test agent and a production agent can
  coexist).
- `latency_ms` still drives promise batching in wall mode; it just no longer
  drives the clock.

## Evidence

`tests/clock_policy_tests.rs`: default advancement, wall tracking, live and
zero-lifetime capabilities, no rewind across mode changes, dispatch-time
refusal under wall time. `tests/cap_ttl_tests.rs` and
`tests/dispatch_authority_matrix.rs` cover the virtual-mode deadline paths.
