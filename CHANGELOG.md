# Changelog — Active RPC

## 1.1.3 — 2026-10-27

- **A fresh clone builds.** The dependency on `active-infinity` is the published
  crate (now 1.2.0) instead of a path into a sibling repository, so `git clone`
  followed by `cargo test` works with no extra checkout. Co-development is
  documented in `CONTRIBUTING.md` with a `[patch.crates-io]` override.
- **Fuzzing runs in CI.** The framing target is built and run on every push, not
  only on a manual dispatch.

## 1.1.2 — 2026-10-27

- **No preallocation from untrusted counts.** List/map values and the standalone
  capability-table decoder grow from a small bound instead of trusting a 4-byte
  count; the table decoder is capped by WireLimits::max_caps.
- **The Connect bridge survives a malformed request.** A missing content length or a
  short body is a 400 for that connection, not a server failure.
- **Channel capability sharing no longer retains references.** A message names a
  capability; it does not keep it alive, matching the documented borrow
  semantics.
- **A destroyed lane cannot send.** send refuses a closed lane like call does.
- **Attenuation validates the budget.** `attenuate`/`attenuate_lane` refuse a zero
  ceiling instead of minting an unbounded grant.

## 1.1.1 — 2026-10-27

- **Tool payload ceiling counts every argument shape.** max_arg_bytes is compared
  against the recursive wire size of the arguments, so a nested list or map can no
  longer hide bytes one level down while the call budget sees them.

## 1.1.0 — 2026-10-27

Security and correctness fixes from the independent review. The wire format
(`ARP1` v1) is unchanged.

- **Revocation at dispatch.** A capability revoked after a call was queued is
  rejected when the batch runs; the provider never sees it.
- **Cancel and destroy really drop work.** A queued job is removed on
  `cancel`/`destroy_lane`, and its promise is rejected; an in-flight job cannot
  be stopped and its result is discarded.
- **Lane budget counts queued calls.** Queueing many calls no longer bypasses a
  lane's call budget.
- **Byte budget is charged.** Arguments and payloads are measured, charged
  against the capability meter and intersected with the lane budget; a call over
  the ceiling fails with `rpc/budget-exceeded` before dispatch.
- **Every budget ceiling must be non-zero**, including array length and value
  size; the wire refuses a descriptor that disables one.
- **Bounded value decoding.** Nesting is capped at 64 levels and every length is
  checked against remaining bytes; deeply nested or oversized values are
  `rpc/wire` instead of a stack overflow or a huge allocation.
- **Redacted module results.** `subgraph` and `patch` return a module with every
  secret replaced by `***SECRET***`; the wire has no tag for secret bytes.
- **CSPRNG capability ids.** `Agent::new` seeds the id secret from the OS random
  source instead of the clock.
- **No borrow across provider code.** The kernel releases its borrow before
  invoking a provider, so a provider that holds an `Agent` and calls back works.
- **Tool-policy predicate fixed.** `CapAttrs::is_attenuation_of` now agrees with
  `attenuate` (adding a policy narrows, dropping one widens).
- **Capability sharing clarified.** Channel messages share (borrow) capability
  ids without inflating reference counts; cloning a borrowed handle no longer
  leaks a reference.
- **Atomic shared-memory consumption.** `SharedSegment::pop_frame` decodes and
  advances under one lock.

## 1.0.0 — 2026-10-27

First release: capability kernel with attenuation and lifetime notification,
promise pipelining with batching, lanes, channels, tool handles (MCP, HTTP,
sandboxed process), domain operations over Active Infinity, and five transports
(in-process, TCP, shared memory, QUIC, Connect/gRPC bridge).
