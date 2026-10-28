# Hardening research log — active-rpc

Addendum A of `ACTIVE-HARDENING-GUIDE-AND-CHECKLIST.md` requires a dated research
sprint at the start of every phase and a log entry per finding. An entry is only
complete when it produces a test, a fuzz oracle, a checklist item, or an ADR
recording accepted risk (`R-4`).

## 2026-10-27 — H0 research sprint: RPC, capability and tool classes (D1, D2, D6)

Sources: NVD 2.0 records fetched on 2026-10-27 for `grpc`, `wasmtime`,
`protobuf`, `msgpack`, `flatbuffers`; RustSec advisories; object-capability
literature (E language, Cap'n Proto RPC, wasmtime capability model).

### D1.1 historical bug inventory (wire and transport)

| # | Identifier | Class | Source | Mapped item | Status |
|---|---|---|---|---|---|
| 1 | CVE-2017-8359 | gRPC use-after-free in `grpc_call_destroy` | NVD | H2.10, I-7 | partial: `threat_revocation_and_lifetime_edges` |
| 2 | CVE-2017-7860 | gRPC `parse_unix` heap buffer overflow | NVD | H2.12, D6.1 | open: path canonicalization tests |
| 3 | CVE-2017-7861 | gRPC `gpr_free` out-of-bounds write | NVD | H2.1 | n/a: no manual allocator |
| 4 | CVE-2017-9431 | gRPC `iomgr/error.c` out-of-bounds write | NVD | H2.1 | partial: header attacks |
| 5 | CVE-2017-6599 | gRPC request handling leaks memory until the daemon dies | NVD | H4.9, H2.7 | open: connection-churn memory test |
| 6 | CVE-2023-44487 | HTTP/2 Rapid Reset stream churn | vendor advisories | H2.19 | open: stream churn under lane budget |
| 7 | CVE-2021-39219 | Wasmtime cross-`Engine` `Linker` type confusion | NVD | H2.42, I-4 | open: cross-kernel transplant test |
| 8 | CVE-2021-39216 | Wasmtime `externref` use-after-free across GC | NVD | H2.10, I-7 | partial: last-drop notification |
| 9 | CVE-2021-39218 | Wasmtime invalid free through stale GC stack map | NVD | H2.10 | open: handle-lifetime model |
| 10 | CVE-2022-24791 | Wasmtime UAF when safepoints sit in cold blocks | NVD | H2.10 | open: lifecycle state machine |
| 11 | CVE-2022-31146 | Wasmtime missing GC metadata after allocator migration | NVD | H6.10 | open: exhaustive small-state model |
| 12 | CVE-2022-23636 | Wasmtime invalid drop of an uninitialized pointer | NVD | H2.10 | open |
| 13 | CVE-2021-32629 | Cranelift sign-extend instead of zero-extend | NVD | H2.37, H1.22 | open: 32-bit lane |
| 14 | CVE-2026-2454 | Corrupted msgpack frames with wrong array lengths cause OOM | NVD | H2.5, I-8 | covered: `review_capability_table_count_is_capped_before_allocating` |
| 15 | CVE-2026-25899 | Ten-byte cookie triggers an 85 GB allocation | NVD | H2.5, I-8 | covered in spirit: count capped before allocation |
| 16 | CVE-2021-3121 | GoGo protobuf missing index validation in skip logic | NVD | H2.1 | open: length-field skip audit |
| 17 | CVE-2021-22569 | protobuf-java parser kept busy for minutes by interleaving | NVD | H2.41 | open: linear-time assertion |

Extracted classes:

1. **Handle lifetime and GC** (CVE-2021-39216/39218/24791, CVE-2022-23636):
   a handle can be freed while a queued operation still references it. Oracle:
   every dispatch re-resolves the handle from the live table; a stale id is
   refused with `rpc/...`. Existing coverage: revocation and drop tests. Missing:
   a small-state model that enumerates mint/attenuate/clone/drop/revoke/call
   interleavings (H6.10).
2. **Cross-context transplant** (CVE-2021-39219): an object created in context A
   is used in context B. Oracle: a capability minted by kernel A must be refused
   by kernel B even when the 16-byte id collides. New item H2.42.
3. **Unvalidated count drives allocation** (CVE-2026-2454/25899): covered for the
   capability table; extend to lanes/channels/promises (H2.21).
4. **Connection churn leaks** (CVE-2017-6599, CVE-2023-44487): oracle: 10k
   connect/disconnect cycles must leave FD and thread counts flat. New item H4.9.
5. **Path parsing** (CVE-2017-7860): oracle: dot segments, encoded dots,
   userinfo, absolute URLs, redirects and symlinks cannot escape the allowed
   path. New item H2.46.

### D2.1 capability and authorization failure patterns

| # | Pattern | Where it could appear here | Test / item |
|---|---|---|---|
| 1 | Attenuation inversion (union instead of intersection) | `cap.rs` method set merge | `attenuation_narrows_and_never_widens`, `attenuation_is_monotone` |
| 2 | Budget widening on merge (max instead of min) | `budget.rs` | `review_attenuation_validates_the_budget` |
| 3 | Revocation race (authorize at enqueue only) | `kernel.rs` dispatch | `review_revocation_after_queueing_prevents_invocation` |
| 4 | Cross-kernel capability transplant | `cap.rs` lookup keyed only by 16 bytes | H2.42 |
| 5 | Stale handle after drop or destroy | `cap.rs`, `lane.rs` | H6.10, `review_cancelled_and_destroyed_work_never_runs` |
| 6 | Confused deputy (provider uses its own authority) | provider call path | `threat_confused_deputy` |
| 7 | Ambient authority in tool adapters | `tool.rs` | `review_tool_policy_predicate_matches_the_enforcer` |
| 8 | Path scope escape (`..`, absolute, symlink) | `cap.rs` path check | `path_scope_is_enforced_before_the_provider`, H2.46 |
| 9 | Capability replay across a connection | transport session binding | H2.42 |
| 10 | Borrowed channel capability extends lifetime | `channel.rs` | `review_channel_shares_capabilities_without_holding_them_alive` |
| 11 | Numeric handle guessing (lane/channel/promise) | `LaneId`, `ChannelId` | `channels_do_not_cross_talk`; add id-guess cases |
| 12 | Error-channel oracle (distinct errors reveal existence) | `error.rs` | H2.32, D3.4 |
| 13 | Cross-tenant channel cross-talk | `channel.rs` | `channels_do_not_cross_talk` |
| 14 | Overlapping write grants | policy helper (future) | H2.28 |
| 15 | Stale capability after ownership change | kernel ownership model | H2.30 |

### D6.1 tool escape catalog

| Adapter | Attempts | Current coverage |
|---|---|---|
| HTTP | absolute URL overrides the allowlist; `userinfo@host`; `..` and `%2e%2e`; redirect to another host; CRLF in header values; method override; chunked body without length; body over the ceiling | policy predicate and a few method/path cases; no redirect or encoding cases |
| LocalProcess | argv metacharacters; `PATH`/`LD_PRELOAD`/`DYLD_*` env poisoning; cwd escape; symlink race; inherited FDs; shell invocation when a direct exec was intended | policy enforcement test; no escape battery |
| MCP | handshake counted as a tool call; unknown tool; JSON-RPC batch abuse; progress-token spoofing; resource URI traversal | handshake test; no adversarial sequence target |

New items: H1.24 (`fuzz_tool_policy`), H2.43 (event redaction), H2.44 (tool
timeout and payload ceiling), H2.46 (path canonicalization), D6.2.

### D2.4 rights amplification notes

The capability model is attenuate-only, but two amplification paths deserve
explicit tests:

- **Caretaker inversion**: a parent delegates a capability to a caretaker that
  attenuates it and hands back a *different* capability. The caller must never
  receive wider rights than it gave. Oracle: attenuation returns a child whose
  allowed set is a subset of the parent's for every field, and the child's parent
  link is the attenuated cap, not the original.
- **Metadata copy**: a capability descriptor carries methods/budget inline on
  the wire. A peer must not be able to send a descriptor that claims more than
  the local parent. Covered by `review_attenuation_validates_the_budget`; extend
  to path and tool policy (H2.9).

### D7 supply chain

`cargo audit` and `cargo deny` are green; the same accepted `unsafe-libyaml`
advisory as Infinity (via `active-core`). Direct dependencies: `active-infinity`,
`active-core`, `thiserror`, `blake3`, `getrandom`, `serde_json`, optional
`tokio`, `quinn`, `rustls`, `rcgen`. The QUIC stack is the largest dependency
subtree and the largest memory-safety surface; it is pinned by the lockfile and
exercised by an integration test on every feature set. Residual: QUIC tests use
a self-signed loopback certificate; they do not prove behavior against a hostile
peer beyond malformed frames.

### D9 side channels

Capability ids are 16 bytes derived from a 32-byte agent secret. The kernel
compares ids by value; the comparison cost is independent of the secret because
the secret is never compared. Timing can reveal whether an id exists (a refused
call is cheaper than a dispatched one), which is already visible from the
response. Error strings are stable and do not include secret material. Residual:
event payloads currently record values; H7.2 must prove they contain no secrets.

### Research-derived checklist items

- **H1.24** `fuzz_tool_policy`: adversarial policy descriptors and tool calls.
- **H2.42** Cross-kernel and cross-connection capability transplant/replay.
- **H2.43** Event and log redaction oracle (no secret bytes, hashed cap ids).
- **H2.44** Tool timeout and payload ceiling.
- **H2.45** Shared-memory frame TOCTOU under concurrent mutation.
- **H2.46** URL and path allow-list canonicalization bypass.
- **H2.47** Promise settlement count under concurrent cancel/resolve.
- **H4.9** FD and thread stability under connection churn.
- **H6.10** Exhaustive small-state capability lifecycle model.

Status: open. Each item is a gap or partial row until its oracle lands.
