# Changelog - Active RPC

## Unreleased

Additive work from the hardening and innovation phases. The `ARP1` layout is
unchanged.

### Added

- **Time-bounded capabilities** (`CapAttrs::ttl_ms`, ADR-0015): the kernel
  resolves a TTL against its clock and refuses an expired capability exactly
  like a revoked one (`rpc/revoked`, plus `Event::CapExpired`). Attenuation can
  only shorten a lifetime.
- **Capability receipts** (ADR-0016): `Agent::enable_receipts` records every
  admitted call in a bounded ring as `Receipt { sequence, cap correlation id,
  method, at_ms, mac }`, authenticated with a keyed hash under the kernel
  secret. Arguments and secrets never enter a receipt; `verify_receipt`
  detects edits and foreign kernels.
- **Peer introduction modules** (ADR-0017): `Agent::intro` describes providers,
  granted methods and the default budget ceilings as a canonical AINF module
  that any binding can validate and hash. It carries no capability ids or
  secrets.
- **Deterministic replay packages** (ADR-0018): `replay::Recorder` records a
  session's operations and decision trace into the `ARRP` format;
  `ReplayPackage::replay` re-executes it against a fresh kernel and compares
  every entry. Packages store argument sizes, never values. The CLI gains
  `replay dump` and `replay run`.
- **Payload accounting**: `Agent::call_with_payload` and
  `call_as_with_payload` charge an envelope payload against `max_bytes`; the
  CLI, examples and peer binaries use them.
- **`QuicServer::wait`**: waits for the serving task, which drains the last
  response before closing.

### Security

- MCP sessions bound every inbound line (1 MiB), require the response id to
  match the request (`mcp/id-mismatch`) and refuse responses with neither
  `result` nor `error`; a hostile server can no longer exhaust memory or answer
  a different call.
- HTTP/2 runs a blocking kernel handler under `block_in_place`, so one stream
  cannot stall the runtime.
- New suites: multi-tenant cross-talk, malicious MCP sequences, transport ×
  capability binding, payload budgets, bulk and compressed-frame fuzzing.

## 2.1.0 - 2026-10-31

Additive transport and telemetry work from the Active Maturity Program. The
`ARP1` envelope layout is unchanged; new code strings extend the error
vocabulary.

### Tooling

- **`active-rpc-cli` 0.2.0**: `doctor`, `peer` (tcp, connect, http2, quic),
  `call`, `pipeline`, `loadgen`, `bridge`, `events`, stable exit codes and
  end-to-end tests that spawn a real kernel peer.

### Added

- **Transport identity and capability binding** (`identity`, ADR-0011).
  `PeerIdentity`, `IdentityPolicy`, `AdmittedIdentity`. `CapAttrs::bound_to`,
  `Agent::mint_bound`, `Agent::introduce_to`, `Agent::call_as`, `Agent::send_as`.
  A capability introduced to one peer is refused for every other peer with
  `rpc/identity`. QUIC mutual TLS (`QuicServer::start_mutual_tls`,
  `QuicClient::connect_mutual_tls`) exposes the verified peer identity.
- **Native HTTP/2 transport** (feature `http2`, ADR-0012): bare ARP1 envelopes,
  content type `application/arp1`, one connection with concurrent streams and
  `Http2Client::call_many`.
- **Bulk transfer** (`bulk`, ADR-0013): `ARBL` plan and `ARBC` chunk frames,
  per-chunk and root Blake3 hashes, resume with `frames_for(missing)`, a
  configurable receiver ceiling, and `rpc/bulk` for malformed frames.
- **Observability schema** (ADR-0014): `Agent::trace`, `trace_json`,
  `metrics_json`; `active-rpc/observability/1` and `active-rpc/metrics/1`;
  correlation ids only, with a closed event-name set.
- `Metrics::identity_refusals`, `Agent::lane_count`, `Agent::channel_count`.

### Changed

- Attenuation is monotone for persistence: a durable capability cannot be
  derived from an ephemeral one, and a child no longer inherits a longer
  lifetime than it requested (`rpc/attenuation-escalation`).
- `CapDescriptor` documentation now states which capability fields stay local
  (persistence, tool policy, identity binding).

### Fixed

- HTTP/2 serves connections concurrently, isolates a failed stream from its
  connection, and applies `WireLimits` to request and response bodies.
- A QUIC stream that fails mid-frame receives an `rpc/wire` error envelope when
  the peer is still reachable.
- `BulkSender::frames_for` rejects an index outside the plan instead of silently
  dropping it.

## 2.0.0 - 2026-10-28

Hardening release with one breaking error-type change. The `ARP1` wire format is
unchanged.

### Breaking

- `Error::UnknownCapability` and `Error::Revoked` now carry `CapToken` instead of
  `u128`. `CapToken` keeps the raw bits internally and formats a correlation id;
  the previous variants printed the raw authority into `Display` and `Debug`.
  Migration: match `error.code()` (`rpc/unknown-capability`, `rpc/revoked`) or
  compare a `CapToken`; do not expect a `u128` field.
- `Display for CapId` now prints the correlation id. `CapId::hex()` remains the
  documented raw-authority accessor for a deliberate transfer.
- The dependency floor is `active-infinity = "2.1.0"`, the hardened core
  release; the lockfile and clean-clone gates use it.

### Security

- **Handle-pinned promise retention.** Settled promise records are trimmed to
  1,024 records / 64 MiB only when no live `PromiseHandle` references them. A
  pipelined batch of any size can be drained and then read; the older
  order-window trim lost results above 1,024.
- **Completed jobs are reclaimed immediately**, and promise/job ceilings are
  checked before budget is charged. `MAX_PROMISES` is transient backpressure,
  not a lifetime quota.
- **Capability and lane/channel registries are finite and reclaimable**;
  `destroy_channel` and lane destruction release their slots.
- **`LocalProcess` honours the capability wall budget** and kills a child at the
  deadline; the channel queue is bounded.
- **API-surface gate**: rustdoc-JSON check for raw secret accessors and exactly
  one documented `CapId::hex`, wired into CI.

### Added

- `Metrics`, `Event::CallRefused`, `Event::BudgetExhausted`, `Event::ToolRefused`.
- `Agent::metrics`, `promise_count`, `job_count`, `destroy_channel`.
- `MAX_LANES`, `MAX_CHANNELS`, `MAX_PROMISES`, `MAX_EVENTS`,
  `MAX_SETTLED_PROMISES`, `MAX_SETTLED_BYTES`.
- `decode_capability_table_with`.
- `LocalProcess::with_timeout`.
- `examples/tool_policy.rs`, `examples/two_agents.rs`.

### Fixed

- Shared-memory wrapped-ring compaction copied through a temporary buffer; a
  desynchronised ring is reported before the capacity decision.
- Dispatch uses the job's real capability id in errors; a destroyed lane leaves
  settled results readable.
- Double settlement is counted in `Metrics::promises_double_settled`.
- The CI 32-bit lane and the Linux churn test are stable.

### Verification

- 115 tests, red-team battery (19 cases), nine negative controls, Docker fuzz
  (9 targets), i686 lane, performance budgets, API gate and clean-clone gates.


## 1.1.9 — 2026-10-27

No API or wire-format change in this crate.

- **Tracks `active-infinity` 2.0.1** and the committed lockfile resolves it. The
  previous floor (`2.0.0`) is yanked because it still exposed
  `Validated::secret`; this release makes a fresh clone and a locked build both
  resolve the fixed core.
- Everything else is unchanged: capability, promise, lane, channel, transport and
  tool behavior, MSRV 1.88, and the feature set.

## 1.1.8 — 2026-10-27

No API or wire-format change in this crate.

- **Depends on `active-infinity` 2.0.0**, which removes the public plaintext
  secret accessors (`secret_texts`, `secret_bytes`, `secret_literals`). RPC never
  called them; the floor moves so consumers of the stack resolve the fixed core.
- Everything else is unchanged: capability, promise, lane, channel, transport and
  tool behavior, the MSRV (1.88) and the feature set.

## 1.1.7 — 2026-10-27

No API or wire-format change.

- **A runnable example.** `examples/loopback.rs` (`cargo run --example loopback`)
  mints a capability, opens a lane, calls `stats` and `why`, shows the provider's
  drop notification, and demonstrates a method the capability does not grant
  being refused. The checklist entry for runnable examples now points at it.
- **Documented behavior is pinned by tests.** `Channel::close` (sends stop, queued
  messages stay receivable) and `McpSession::calls` (the handshake is not a tool
  call) each have a test.
- **ADR-0006 points at ADR-0007** for the MSRV change instead of leaving the old
  number unqualified.

## 1.1.6 — 2026-10-27

Documentation-only release: no API, wire-format or behavior change.

- **Documentation corrected against behavior.** `Channel::close` said sends and
  receives fail, but queued messages stay receivable; the doc now says so.
  `McpSession::calls` now states that the handshake is not counted, and a
  duplicated line on `Channel::len` is gone.
- **Release docs track the current release.** The signing example and its
  expected output name `v1.1.5`, with a note to substitute the tag being
  verified.
- **`CHECKLIST.md` no longer claims annotated tags** (they are SSH-signed) and
  names the published line `1.1.5`.

## 1.1.5 — 2026-10-27

Documentation-only release: no API, wire-format or behavior change.

- **The documentation gate is real again.** `#![deny(missing_docs)]` was
  cancelled by an `#![allow(missing_docs)]` left over from earlier scaffolding,
  so the published docs could regress silently. The allow is gone and the 27
  public items it was hiding are documented, so `cargo doc` fails the build on an
  undocumented item.
- **README states the MSRV** (1.88) and points at ADR-0007.
- **ADR-0007 records the one advisory ignore** (RUSTSEC-2024-0449, `unsafe-libyaml`
  via `active-core`'s `serde_yaml`), matching `deny.toml` and the changelog.
- **The framing fuzz target asserts the decoder's own capability ceiling**
  (`WireLimits::default().max_caps`) instead of a looser constant, and the
  release-signing example names the current release tag.

## 1.1.4 — 2026-10-27

- **An unmaintained dependency is gone.** `rustls-pemfile` was declared for the
  QUIC feature but never used; it is removed, which clears advisory
  RUSTSEC-2025-0134.
- **MSRV is 1.88.** The patched `time` (RUSTSEC-2026-0009, stack exhaustion while
  parsing RFC 2822 dates) and `proptest` 1.12 both require rustc 1.88; keeping
  1.85 would mean pinning the vulnerable release. `rust-version` and the CI MSRV
  job now say 1.88, and ADR-0007 records the reasoning. Active Infinity keeps its
  1.85 floor.
- **CI tests the committed dependency graph.** Every job runs with `--locked`,
  the MSRV job builds every feature and every target, the fuzz job runs on
  pushes as well as pull requests, and the package job verifies the tarball.
  `cargo deny check` passes with one documented ignore: RUSTSEC-2024-0449
  (`unsafe-libyaml`, pulled in by `active-core`'s `serde_yaml` and outside every
  parsing path this crate exposes).

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

