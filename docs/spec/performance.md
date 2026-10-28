# Performance baselines (Active RPC)

`cargo bench --locked --bench transport` (criterion). Baseline machine:
Windows 11, x86-64, Rust stable, 20 samples, 1 s warm-up and 2 s measurement
per point, on an idle machine (2026-10-27).

Fixtures: an 868-byte `ARP1` envelope carrying a real Active Infinity module,
the in-process queue transport, a 4 MiB shared-memory segment, and a kernel with
one `ModuleProvider` answering `stats`.

## Matrix

| Operation | Result |
|---|---|
| envelope encode | 273 ns (2.96 GiB/s) |
| envelope decode | 703 ns (1.15 GiB/s) |
| in-process transport round trip | 724 ns |
| shared-memory transport round trip | 1.09 µs (637 MiB/s) |
| kernel call + dispatch (`call-and-run`) | 6.63 µs |
| 8 call-and-wait calls (sequential) | 52.9 µs |
| 8 queued calls, one drain (batched) | 55.1 µs |

The two eight-call numbers are total cost, including eight call setups and eight
promise settlements. Round-trip count is the designed difference and is proved
separately: `pipelining_costs_one_round_trip_and_sequential_costs_two` asserts
`round_trips == 1` for a promise-dependent chain and `2` for the sequential
form, and `cross_process_peer_pipelines_in_one_round_trip` proves the same over
a real TCP peer (16 pipelined calls, 1 round trip).

## Sustained-load and hostile-input budgets

`tests/perf_budget.rs` enforces the bounds; numbers are the current pass:

| Test | Bound | Why |
|---|---|---|
| `envelope_decode_is_linear` | 2,000 args ≤ 60× the 100-arg time + 50 ms | no quadratic argument walk |
| `in_process_call_throughput_is_bounded` | 5,000 calls < 15 s | dispatch stays proportional |
| `shared_memory_frames_are_bounded` | 10,000 round trips < 10 s | ring arithmetic is O(frame) |
| `repeated_calls_do_not_grow_rss` (Linux) | < 64 MiB growth over 20,000 calls | promise/meter cleanup |
| `lane_and_channel_churn_does_not_leak_descriptors_or_threads` (Linux) | FD and thread counts do not grow over 2,000 cycles | no hidden per-lane resource |

The hostile battery adds the fail-closed side: a queue storm under a low call
budget (H2.19), nested byte bombs (H2.20), registry ceilings (H2.21), zero
ceilings (H2.23) and a tool payload that exceeds its policy (H2.22) all return a
stable `rpc/*` error before work is materialised. The event log is capped at
`MAX_EVENTS = 16_384` records with exact counters, so a call storm cannot grow
kernel memory without bound.

## Where the time goes

- **Envelope encode/decode is a tight binary walk.** Capability descriptors,
  arguments and payload are length-prefixed; decode refuses counts that exceed
  the buffer before allocating (`WireLimits`).
- **A call is validation plus metering.** `call` checks capability state,
  method grant, read-only policy, path scope, tool policy, and both budgets
  before a promise record exists. That is why one call costs microseconds even
  when the provider does almost nothing.
- **Dispatch batches per provider.** Jobs for one provider run in one batch,
  ordered by promise dependency. The benchmark's batched case is dominated by
  the eight `call` validations, not by transport; over a real transport the
  round-trip count is what matters.
- **Shared memory copies once per direction.** The ring is atomically advanced
  and the payload is copied into the caller's buffer; there is no deserialize
  step on the transport path.

## Regression policy

A change that moves a benchmark by more than 20% on the same machine needs a
note here and a fresh baseline in the same commit. CI compiles the benchmark
binary (`cargo bench --no-run`) and runs `tests/perf_budget.rs`; it does not gate
on cross-machine absolute time. The 32-bit lane runs the same budget tests under
i686, where `usize` arithmetic is the risk.
