# ADR-0023: No io_uring backend for TCP and QUIC I/O

- **Status:** Accepted
- **Date:** 2026-10-31
- **Phase:** Absolute Max program, M-4.2
- **Supersedes:** nothing
- **Related:** ADR-0003 (transports), ADR-0008 (bakeoff methodology), ADR-0013
  (bulk transfer), `docs/spec/performance.md`

## Context

The Absolute Max proposal asks the Linux transport path to evaluate an
**io_uring** backend for TCP and QUIC "where measured win". The question has
three parts: how much per-call work would batching remove, whether the current
stack can be moved onto io_uring without replacing it, and whether the kind of
latency a call actually pays is the kind io_uring removes.

This ADR answers with measurements from the shipped path and a survey of what
the ecosystem supports as of 2026-10.

## What a call costs today

`examples/tcp_bench.rs` drives the shipped `TcpTransport` over one loopback
connection: 20,064 framed envelopes, one request and one response each, release
build, `strace -f -c` for the syscall census.

Host: Docker Desktop Linux container on a Windows 11 / Hyper-V host, Intel Xeon
E5-1650 v4, `rustc 1.99.1`, kernel 6.x, container otherwise idle.

| Measurement | Before this ADR's transport change | After |
|---|---|---|
| Syscalls per call (2,064 calls) | 8.05 | 4.05 |
| Total syscalls (2,064 calls) | 16,613 | 8,357 |
| Time inside syscalls (strace-instrumented) | 1.64 s | 0.94 s |
| p50 round trip | 95 µs | 86 µs |
| Requests per second, one connection | 8,907 | 10,700 |

The "after" column is the change this evaluation produced: a frame now goes out
in **one** `writev` instead of `write`(header) + `write`(body), and an envelope
comes in with the reader buffered, so a header read and its body read are served
by **one** `recvfrom` instead of two. That halves the syscall count, and it is the
largest syscall-side win available without changing the runtime.

Note what dominates the number that remains:

- ~86 µs per round trip on a container VM, and 94 µs at 4 KiB payloads, so the
  cost is **not** proportional to bytes. It is scheduling: the server thread must
  wake, and the client thread must wake again. io_uring does not remove those
  wake-ups; removing them needs busy-polling (`IORING_SETUP_SQPOLL`, `IORING_POLL`
  with spin), which burns a core per connection and is a different product
  decision.
- 4 syscalls per call is the floor for a strict request/response exchange on
  blocking sockets. Batching on the submission side could collapse it toward
  ~2 per *batch*, but only if the server reads K requests before answering K,
  which is an application-level protocol shape, not an I/O-layer setting.

## What the protocol already provides

`ARBL` bulk transfer (ADR-0013) and capability-table deltas (ADR-0009) already
amortize per-call cost at the layer where it is portable: one envelope carries a
carousel of chunks with per-chunk hashes, and one envelope carries a whole
capability-table delta. A deployment that needs fewer syscalls per unit of work
sends fewer envelopes; that works on TCP, QUIC, HTTP/2, shared memory and the
Connect bridge without a runtime swap.

## What an io_uring backend would require

- **tokio stays on epoll.** Mainline tokio's reactor is `mio`, epoll on Linux.
  There is no io_uring backend and none planned; `tokio-uring` is deprecated and
  unmaintained, and it was never API-compatible with the rest of tokio.
- **quinn's supported path is a conventional async UDP socket.** `quinn-proto` is
  runtime-agnostic, but `quinn::Endpoint` is not: it is built for a tokio-shaped
  reactor. Pointing it at a completion-based runtime is not a supported
  integration. QUIC throughput on Linux comes from UDP GSO/GRO, `sendmmsg`, and
  pacing, which the tokio path already uses; io_uring would not add a batching
  primitive quinn is missing.
- **h2 for the HTTP/2 transport** is likewise a tokio-codec library.
- **Completion-based runtimes are thread-per-core.** `compio` (io_uring on Linux,
  IOCP on Windows) and `monoio` (io_uring first, epoll fallback) are the
  maintained options, and neither runs tokio tasks, `AsyncRead`/`AsyncWrite`, or
  quinn unchanged. Adopting one means rewriting the runtime, the socket types,
  the timers and the `select!` structure of every transport, plus owning buffers
  for the whole operation — a rewrite of the I/O layer, for a saving bounded by
  the syscall share measured above.

Cost of that rewrite: the kernel, capability model, promises, receipts and
codecs are runtime-independent and stay; the TCP, QUIC, HTTP/2 and bridge
adapters, their tests, and the CI matrix would be re-created. That is a program,
not an item, and the expected gain on the measured workload is the syscall share
of ~86 µs, most of which is wake-up latency io_uring does not remove.

## Decision

**No io_uring backend.** The Linux TCP and QUIC transports stay on tokio with the
syscall work already removed (one `writev` per frame, buffered reads). The
syscall census and the loopback numbers live in `docs/spec/performance.md` and
`examples/tcp_bench.rs` so the decision can be re-tested, not re-argued.

## Revisit triggers

Re-open this ADR when **any** of these holds:

1. Mainline tokio ships an io_uring reactor, or quinn ships a completion-based
   socket driver — the integration cost collapses from a rewrite to a flag.
2. A deployment profile shows the transport is the bottleneck at the target rate:
   more than 50% of call wall time in `send`/`recv`/`writev` on a machine where
   the process is otherwise idle, measured by `perf` or `strace -c` on the real
   workload, not on loopback.
3. `compio` or `monoio` gain a quinn-compatible endpoint, making the QUIC half of
   the question a library change.
4. A bulk-free workload (single small calls at very high rate) becomes a product
   requirement that `ARBL` batching cannot serve.

## Consequences

- Portable: the same code runs on Windows, macOS and Linux, including
  environments where io_uring is disabled by seccomp policy — a real constraint
  on container platforms, and one reason io_uring cannot be a hard dependency.
- The measured transport floor is documented and reproducible: `cargo run
  --release --example tcp_bench -- 20000 256`, plus `strace -f -c` for the
  census.
- The syscall reduction this ADR did land (8 → 4 per call, 20% loopback
  throughput) is a property of the shipped code, not of an optional feature, so
  every build gets it.
