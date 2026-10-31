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

## Domain provider hot path (M-4.1, 2026-10-31)

`cargo bench --bench domain` (criterion, 100 samples, 2 s warm-up, 5 s
measurement). Host: Intel Xeon E5-1650 v4 @ 3.60 GHz, 6 cores / 12 threads,
Windows 10 Pro, `rustc 1.99.1`, machine shared with other work during the run,
so read the intervals, not the third digit. Fixture: a 35-node module
(`benches/domain.rs`) with nested tables, an array, a quantity expression, an
environment default, string interpolation and one secret.

| Arm | Median | 95% interval | What it is |
|---|---|---|---|
| `floor/noop_invoke` | 7 ns | 6.6–7.5 ns | provider trait call, no work |
| `content_hash/shipped_cached` | 476 ns | 439–527 ns | `content_hash` on a warm slot |
| `content_hash/removed_encode_hash` | 53.6 µs | 50.7–57.6 µs | encode + hash on every call (the old path) |
| `stats/shipped` | 3.0 µs | 2.9–3.1 µs | `stats` over the stored module |
| `stats/removed_clone` | 5.0 µs | 4.5–5.7 µs | `module.clone()`, the copy the old path made per call |
| `path/why` | 26.6 µs | 25.0–29.3 µs | `why` on `services.auth_url` |
| `path/subgraph` | 42.4 µs | 37.7–48.1 µs | `subgraph` on `services` (cone + encode) |
| `evaluate/root` | 273 µs | 246–307 µs | Infinity evaluation of the whole module |
| `evaluate/scoped` | 188 µs | 183–195 µs | Infinity evaluation of one subtree |

Components, measured alone:

| Component | Median | Note |
|---|---|---|
| `ir::hash_hex` (published 2.3.0) | 4.1 µs | 32 `format!` allocations per hash |
| local one-allocation formatter | inside the 476 ns `content_hash` arm | same 64 characters, one allocation |
| `Module::edges()` | 2.5 µs | builds, sorts and dedups a `Vec` for a count |
| `Module::node_count()` | 0.65 ns | inline |
| `encode` | 41 µs | canonical image of the fixture |

Two costs were removed from every call to a module capability:

- **The per-call module clone.** `ModuleProvider::invoke` used to start with
  `self.require(object)?.clone()` for every method, including read-only ones.
  The slot is now taken out of the map for the duration of the call and put back
  on every exit path, so a read-only call copies nothing and a refused call
  never drops the object. `stats` measures 3.0 µs including the map round trip,
  below the 5.0 µs the bare clone costs.
- **The per-call canonical re-encode in `content_hash`.** The hash is computed
  once per module version, cached in the slot and cleared by `patch`;
  `install_canonical_image` seeds it from the bytes it was handed so a transport
  that already validated an image never encodes it at all. A warm call is 476 ns
  against 53.6 µs for the re-encode, about 113x.

The remaining cost centres are named rather than hidden. `stats` is dominated by
`Module::edges()`, which materialises, sorts and deduplicates the edge list for a
count that only needs `len`; adding a counted accessor to the codec is the fix and
needs a codec release. `content_hash` still formats 64 hex characters per call
because the published `active_infinity::ir::hash_hex` allocates per byte; the
codec tree carries the one-allocation formatter and this crate formats locally
until the next dependency bump adopts it.

`why`, `subgraph` and `evaluate` are Infinity work: `why` builds a dependency
map and walks the cone, `subgraph` copies the cone and encodes it, and
`evaluate` runs the engine. None of them re-encodes for the answer's sake; the
subgraph encode is the payload.

## Regression policy

A change that moves a benchmark by more than 20% on the same machine needs a
note here and a fresh baseline in the same commit. CI compiles the benchmark
binary (`cargo bench --no-run`) and runs `tests/perf_budget.rs`; it does not gate
on cross-machine absolute time. The 32-bit lane runs the same budget tests under
i686, where `usize` arithmetic is the risk.

## Bakeoff (C-7, 2026-10-30)

Host: Intel Xeon E5-1650 v4 @ 3.60 GHz, Windows 10 Pro, 64 GiB RAM,
`rustc 1.99.1`. Criterion, 20 samples, 1 s warm-up, 2 s measurement, otherwise
idle machine. Run the same commands to reproduce:

```text
cargo bench --all-features --bench bakeoff -- "rpc_protocol"
cargo bench --all-features --bench bakeoff -- "rpc_bakeoff"
cargo run --release --example perf_matrix --all-features
python scripts/perf_gate.py perf-matrix.json
```

### Protocol message path: ARP1 versus gRPC

Same logical call (method, one integer argument, 4 KiB payload). The gRPC
adapter uses `prost` plus the five-byte gRPC prefix; the message is built once
and only encoding and prefix/length validation are timed. HTTP/2 framing and
HPACK headers are excluded, so this isolates the call encoding; the transport
benchmarks cover in-process and shared-memory framing, not HTTP/2.

| Operation | ARP1 | gRPC message | Ratio |
|---|---|---|---|
| encode | 723 ns | 1.37 µs | 0.53x (ARP1 faster) |
| decode | 443 ns | 497 ns | 0.89x (ARP1 faster) |

This is not a claim that ARP1 beats gRPC end to end: gRPC carries HTTP/2
headers, trailers and a richer status model that a deployment may need. It is
the message-path share, which is what the envelope controls.

### Envelope throughput

`examples/perf_matrix` (p50):

| Args | Bytes | encode | decode |
|---|---|---|---|
| 1,000 | 10,036 | 7.9 µs | 24.4 µs |
| 4,000 | 40,036 | 28.0 µs | 98.5 µs |

Decode pays for value-tree allocation; encode writes a flat buffer. The 4x
argument growth costs 3.5x encode and 4.0x decode, inside the gate's linearity
ceiling.

### Kernel throughput and pipelining

| Workload | Wall time | Round trips |
|---|---|---|
| 1,000 sequential `echo` calls | 2.58 ms (2.6 µs/call) | 1,000 |
| 4,000 sequential `echo` calls | 11.0 ms (2.8 µs/call) | 4,000 |
| 100 calls, one dependent promise chain | 372 µs | 1 |
| 100 calls, one at a time | 378 µs | 100 |

Wall time is dominated by per-call work in both shapes; the durable claim is the
round-trip count. A dependency chain does the same work in one dispatch and
therefore one batch, which is what removes the per-hop latency of a real
transport.

### Subgraph materialization

`why` and `impact` already return label lists computed over the cone; they never
build a module, so there is nothing to make lazy there. `subgraph` must return a
module, and the C-7 audit found it cloned every reachable node twice (once into
the destination, once to rewrite its children). It now allocates the destination
ids first, then copies each node once with references rewritten
(`domain::restrict`). The result is byte-identical; the work is one clone per
node instead of two.

### The gate

`scripts/perf_gate.py` enforces tail stability (p95 ≤ 4× p50, or 5x for a
1,000-call batch, plus slack for one scheduler hiccup), linear scaling (4k/1k ≤
10x encode, 12x decode, 12x calls) and the encoded-size sanity check. `--baseline
docs/spec/perf-baseline.json` adds an absolute comparison (p50 ≤ 1.6x, p99 ≤
3.0x) for a release machine. CI runs the ratio gate in the `perf-gate` job; the
matrix is uploaded as an artifact.
