# Copilot deep audit marathon — Active RPC

Program: `C:\Users\Usuario\Downloads\Active-Absolute-Max-Program`, phase M-6,
procedure `COPILOT-DEEP-AUDIT-LOOP.md`. Reviewer: GitHub Copilot CLI routed to the
Muse proxy (`muse-spark-1.3-contributor`, `--reasoning-effort xhigh`), which reads
the repository through its own tool access, so findings carry file:line
references rather than pasted guesses.

Loop per section: prepare context → hostile review → triage every finding against
the code → regression test first → minimal fix → targeted tests + clippy → re-audit
→ CLEAN twice or ADR-accepted residual.

## Status

| ID | Section | Paths | State | Findings (fixed / rejected / open) | Commits |
|----|---------|-------|-------|------------------------------------|---------|
| R-01 | wire ARP1 | `src/wire.rs` | `CLEAN` (rounds 1-5; rounds 4 and 5 clean) | 20 fixed / 0 rejected / 0 open (residuals documented) | this commit |
| R-02 | kernel dispatch | `src/kernel.rs` | `CLEAN` (rounds 1-10; rounds 9 and 10 clean) | 40 fixed / 0 rejected / 0 open (residuals documented) | this commit |
| R-03 | capabilities | `src/cap.rs` | CLEAN (rounds 1-3) | 36 fixed / 0 rejected / 0 open | this commit |
| R-04 | promises / pipeline | `src/promise.rs` | `CLEAN` (rounds 1-6; rounds 5 and 6 clean) | 36 fixed / 0 rejected / 0 open (residuals documented) | this commit |
| R-05 | lanes / channels | `src/lane.rs`, `src/channel.rs` | `CLEAN` (rounds 1-6; rounds 5 and 6 found no critical/high/medium) | 33 fixed / 0 rejected / 0 open (recv ambient settled by ADR-0024) | this commit |
| R-06 | budget | `src/budget.rs` | `CLEAN` (rounds 1-13; rounds 12 and 13 clean) | 50 fixed / 0 rejected / 0 open (4 accepted designs documented) | this commit |
| R-07 | domain ops | `src/domain.rs` | rounds 1-29: 29 found 1 high, fixed; rounds 30-31 must be clean | 177 fixed / 0 rejected / 0 open (residuals documented) | this commit |
| R-08 | tools / MCP | `src/tool.rs` | rounds 1-22: ... + 9 findings; round 23 is the confirmation | 188 fixed / 0 rejected / 0 open | this commit |
| R-09 | transports | `src/transport/**` | rounds 1-7: 22 + 16 + 13 + 6 + 6 + 6 + 4 findings | 73 fixed / 0 rejected / 0 open (QUIC and TCP audited CLEAN) | this commit |
| R-10 | bulk | `src/bulk.rs` | rounds 1-2: 12 + 2 findings | 14 fixed / 0 rejected / 0 open | this commit |
| R-11 | identity | `src/identity.rs` | rounds 1-3: 8 + 7 + 7 findings (2 + 2 dispositions partial) | 22 fixed / 0 rejected / 0 open (1 accepted: a placeholder certificate buffer is a shared principal) | this commit |
| R-12 | replay | `src/replay.rs` | rounds 1-3: 9 + 11 + 8 findings (5 round-1 fixes were partial) | 28 fixed / 0 rejected / 0 open | this commit |
| R-13 | receipts | `src/receipts.rs` | rounds 1-4: 13 + 16 + 19 + 7 findings | 55 fixed / 0 rejected / 0 open | this commit |
| R-14 | wasm tools | `src/wasm_tool.rs` | rounds 1-2: 15 + 7 findings fixed | 22 fixed / 0 rejected / 0 open (1 accepted design: host imports stay per instance) | this commit |
| R-15 | observability | `src/observability.rs` | rounds 1-2: 19 + 7 findings (1 rejected as a false positive) | 25 fixed / 1 rejected / 1 noted | `cb44d07` |
| R-16 | security helpers | `src/security.rs`, `src/persistence.rs` | rounds 1-2: 4 + 11 findings (1 noted) | 14 fixed / 0 rejected / 1 noted (no store wired by default; virtual-epoch deadline) | `cb44d07` |
| R-17 | intro / topics | `src/intro.rs`, `src/channel.rs` | rounds 1-2: 11 + 14 findings fixed (2 design-level documented) | 25 fixed / 0 rejected / 0 open (2 recorded: publisher identity, host authority) | `190e9c9` |
| R-18 | CLI | `cli/active-rpc-cli/**` | rounds 1-2: 19 + 19 findings fixed | 38 fixed / 0 rejected / 0 open | `af12e3a` |
| R-19 | control-plane | `control-plane/**` | rounds 1-2: 16 + 20 findings fixed (1 partly a false positive) | 36 fixed / 0 rejected / 0 open (3 documented) | `4c127c4`, `d2ee809` |
| R-20 | fuzz | `fuzz/**` | rounds 1-2: 21 + 12 findings fixed (1 noted); found 3 kernel defects | 33 fixed / 0 rejected / 1 noted | `09b1c82`, `1c4cb37` |

## Cross-cutting passes (after the sections)

| Pass | State | Notes |
|---|---|---|
| Concurrency / multi-tenant | pending | — |
| Oracle and secret paths (Display/Debug/Serialize) | pending | — |
| Wire confusion (ARP1 vs bridge framing) | pending | — |
| Resource bombs (depth, counts, WASM fuel, headers) | pending | — |
| Polyglot encoder golden | pending | — |
| Second pass over changed sections | pending | — |

## Log

Entries are appended per section: date, reviewer path, findings, disposition.

### Fuzz nightly red - 2026-11-02 (run 41437025560, `fuzz_arp1_frame`)

The nightly fuzz job failed once on `08e49a5` with `libFuzzer: deadly signal` at
`fuzz_targets/fuzz_arp1_frame.rs:28`. The artifact was downloaded and reproduced:
the codec is fine, the **oracle** was not.

- The input decodes to a request carrying `Float(NaN)`. Re-encoding produces the
  same 52 bytes, but the harness asserted `Envelope` equality, and
  `f64::NAN != f64::NAN`, so a byte-stable encoding was reported as a lost fixed
  point.
- Fix: the fixed-point assertion compares the re-encoded **bytes**.
  `tests/marathon_wire_tests.rs::a_nan_argument_re_encodes_to_the_same_bytes`
  pins the artifact as a regression, and the crash input is committed as a corpus
  seed (`fuzz/corpus/fuzz_arp1_frame/nan-fixed-point`) so a future nightly starts
  from it.
- No wire change: a NaN argument was already round-tripping to the same bytes;
  the wire format permits the bit pattern and the decoder is total over it.

### Audit remediation (2026-11-03 auditors) - 2026-11-04

The independent audits (`G:\AUDIT`) and the architect's remediation package
(`G:\AUDIT\audit-remediation`) were checked against this tree. Every P0 and P1
was real here; each is fixed with a regression.

| ID | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| ARPC-004 | P0 | Windows cleanup spawned `%SystemRoot%\System32\taskkill.exe`, and `SystemRoot` is a mutable environment value | **fixed**: no helper is launched; the leader is killed and a descendant that outlives it is a recorded residual (a job object needs `unsafe`, which this crate forbids); `a_poisoned_system_root_does_not_run_a_planted_helper` |
| ARPC-001 | P1 | dispatch re-checked only resolved args, so a payload queued under a wide grant rode in after the lane was narrowed | **fixed**: the complete delivered request is compared; `a_narrowed_lane_refuses_a_queued_payload` fails pre-fix |
| ARPC-010 | P1 | `RecordStore::claim` had a check-then-mark default | **fixed**: `claim` is required, `MemoryRecordStore` claims atomically, and a two-contender test pins one winner |
| AR-02 | P1 | `resolve_as` charged egress before the settle outcome | **fixed**: eligibility is checked first and a settled promise is counted without a charge; `Agent::remaining_bytes` makes the meter observable |
| ARPC-006 | P1 | QUIC `max_calls` counted after the handler | **fixed**: admission reserves the slot by compare-exchange before the handler |
| ARPC-005 | P2 | `workdir` was a public, non-canonical path | **fixed**: private and canonicalised; `working_directory()` is the accessor |
| AR-01 | P2 | `order_candidates` was O(n²) | **fixed**: Kahn waves in candidate order (same output order, linear) |
| AR-03 | P2 | dropping the last handle of an exported durable record was silent | **fixed**: `Event::CapRecordOrphaned` reports it; the restore window is a STATUS residual |
| AR-04 | P2 | a certificate renewal broke every binding | **fixed**: `Agent::reintroduce_to` moves a bound subtree to the rotated peer and emits `CapRebound` |
| ARPC-003 | P2 | the control plane's worker and `/health` held different heartbeat `Arc`s | **fixed**: one Arc is created before the thread and shared |
| ARPC-009 | P2 | a durable object id is provider-local | **deferred**: needs a record format version and a provider epoch callback; recorded in STATUS |
| ARPC-011 | P2 | the wasm clock ADR disagreed with the code | **deferred to the doc batch**: ADR-0019 edit queued with the P3 docs |
| Polyglot P3 | P3 | Fortran/C/Swift/C# endian and Dart EOF | **deferred**: recorded in STATUS with the exact client files |

### R-07 domain operations - 2026-11-03 (round 30)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `dd5ed9f`.
All round-29 fixes verified; **no critical or high**. Two mediums, seven lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `response.encode()` ran outside the handler lock and before the in-flight reservation, so worker threads could materialise many responses first | **fixed**: the handler and the encode share the lock |
| 2 | medium | a response over the in-flight budget answered `429 rpc/backpressure` after the handler ran, inviting a retry of a call that already took effect | **fixed**: `500 rpc/transport` on that path; 429 stays pre-handler |
| 3 | low | `Reservation::reserve(0)` could fail on a concurrent transient overshoot | **fixed**: zero is free, and the counter moves by compare-exchange |
| 4 | low | the client's response `content-length` parse accepted `+N`, a duplicate and an overflow | **fixed**: one value, ASCII digits, at most 20 |
| 5 | low | `serve` never reaped completed connection tasks | **fixed**: `try_join_next` at the top of the accept loop |
| 6 | low | `stats.secrets` reported 0 after a declassifying patch while every other method treated the module as secret-bearing | **fixed**: at least 1 while the install-time redactor is non-empty |
| 7 | low | the five round-29 fixes had no regression tests | **fixed**: forged h2 answer ids/kinds, the four invisible characters, `provider/secret-material` and the exact-ceiling gRPC body are covered |
| 8 | low | the dispatch settlement walked a provider value recursively before the depth ceiling | **fixed**: `shape_refusal` and `value_too_deep` run first |
| 9 | low | the Connect client dialled only the first resolved address, cached forever | **fixed**: every address is tried and a failed connect clears the cache |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 29)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `bbd53c1`.
All round-28 fixes verified except two gaps; one **high**, four lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the HTTP/2 in-flight body reservation was dropped *before* the handler ran, so 128 streams could park 128 bodies plus their decoded copies outside the documented memory bound | **fixed**: the request guard lives until the response is written; the response charges only the excess over what the guard already holds. `a_parked_handler_keeps_its_body_charged` fails pre-fix (the second call is served and the first times out) and gets `rpc/backpressure` after |
| 2 | low | the HTTP/2 client accepted any envelope as the answer | **fixed**: kind and request id checked in `call` and `call_many` |
| 3 | low | the gRPC 5-byte prefix was left out of both size ceilings, so the largest legal envelope could not cross | **fixed**: both directions allow the prefix on top of the envelope ceiling |
| 4 | low | U+034F, U+17B4–U+17B5 and U+180F still passed the invisible-character filter | **fixed** |
| 5 | low | `rpc/secret-material` claimed the closed `rpc/` namespace without being registered | **fixed**: `provider/secret-material`, a provider-namespace code like `wasm/*` |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 28)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `4180196`.
Round-27 fixes verified except two gaps; one **critical**, one medium, six lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | `content_hash` still derived the "redacted" image from the stored bytes, so after a declassifying patch the redacted hash equalled the raw one | **fixed**: redact a clone of the module with the install-time `Redactor`, then encode and hash; the declassify test now reconstructs the stored image *including the provenance a patch records* and asserts the served hash differs — it fails against the pre-fix library (verified by stashing `domain.rs`) |
| 2 | medium | `evaluate` derived redaction placeholders by indexing the cone with the module's node ids, turning a secret field into data and a public one into `Secret` once a subtree was renumbered | **fixed**: placeholders come from a redacted clone of the source arena again; `a_scoped_evaluate_keeps_secret_and_public_fields_apart` |
| 3 | low | HTTP/2 accepted a duplicate or signed/zero-padded `content-length` | **fixed**: one value, ASCII digits, at most 20 |
| 4 | low | the HTTP/2 405 carried no `Allow` | **fixed**: `allow: POST` |
| 5 | low | an idle accept deadline stopped polling a connection with live streams, so a long handler could never flush | **fixed**: an idle timeout with live streams continues; completed tasks are reaped before the emptiness check (the first version looped forever — caught by `http2_round2_tests`) |
| 6 | low | `nodes_within_scope` scanned ids before any wall check | **fixed**: the grant is checked every 64 ids |
| 7 | low | `is_invisible_or_reordering` missed U+180B–U+180D | **fixed**: the range is U+180B..=U+180E |
| 8 | low | `ConnectClient::call` accepted any envelope as the answer | **fixed**: only a response or error for the same request id; `an_answer_for_another_request_is_refused` |
| 9 | low | HTTP/2 responses had no connection-wide in-flight budget | **fixed**: a response holds a `Reservation` for its encoded length (the request reservation is released first, or one stream charged the connection twice) |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 27)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `6e9487f`.
All eight round-26 lows verified. One **critical**, one high, two mediums, six
lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | a patch that removes the last secret node declassified the module: the redactor was rebuilt from the post-write module, so a later `subgraph`/`evaluate` served the plaintext copy and `content_hash` served the raw hash | **fixed**: `ModuleSlot` keeps the install-time `Redactor`; every redaction and every "holds a secret" decision uses it (a patch can only remove secrets, so it is an upper bound); `a_patch_cannot_declassify_an_install_time_secret` (patch the secret away, then assert no cone byte, no evaluated value and no raw hash) |
| 2 | high | the HTTP/2 `JoinSet` retained every completed stream task per connection (~2.2 KB/request, measured), so one long-lived connection grew memory without bound | **fixed**: `try_join_next` reaps inside the accept loop |
| 3 | medium | the patch provenance filter rescanned all nodes per entry, after the last wall check | **fixed**: one `held_secret` per patch |
| 4 | medium | `ConnectClient::call` framed before the size check, so an oversized envelope hit the release invariant as a panic | **fixed**: the bound runs before `grpc_frame` |
| 5 | low | HTTP/2 accepted a duplicate `content-type` and ignored `content-length` | **fixed**: a duplicate is 400; a `content-length` that disagrees with the stream is 400 |
| 6 | low | the request line accepted Unicode whitespace and the header values used Unicode `trim` | **fixed**: the request line must be visible ASCII plus spaces |
| 7 | low | `post_typed` interpolated an unvalidated content type (CRLF injection) | **fixed**: visible ASCII only |
| 8 | low | the spec said 404 for a wrong method and a 405 carried no `Allow` | **fixed**: interop.md says 405, and the refusal carries `allow: POST` |
| 9 | low | `scoped_labels` takes a scope it never enforces | **documented**: callers pre-check; the doc says so |
| 10 | low | `stats` returned `has_provenance` to a redacting caller | **fixed**: withheld when `call.redact` |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 26)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `2615c75`. All six round-25
fixes verified; **no critical, high or medium finding**. Eight lows, all fixed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | low | `grpc_frame` still wrapped a length past 4 GiB for a direct caller | **fixed**: a release-checked invariant (`assert!`) with the rationale; both shipped callers bound first |
| 2 | low | the HTTP/2 server ignored the query string, which the HTTP/1.1 bridge 404s | **fixed**: `PATH?x` is a 404 on both; `http2_rejects_a_query_string_on_the_service_path` |
| 3 | low | the Connect client skipped response head lines the server would refuse | **fixed**: an unparsable or untokenized field is `rpc/wire`; `a_malformed_response_head_line_is_a_wire_fault` |
| 4 | low | `Http2Client` sent an oversized body the server could only 413 | **fixed**: `check_body` before framing; `http2_refuses_an_oversized_request_before_sending` |
| 5 | low | the HTTP/2 server streamed a response past `MAX_BODY` | **fixed**: 413 before writing |
| 6 | low | `scoped_labels` built `value_paths` and `labels_for` rebuilt it | **fixed**: `labels_from` takes the map |
| 7 | low | a transient accept failure consumed one of `serve`'s connections | **fixed**: the loop counts accepted connections, with the failure budget unchanged |
| 8 | low | a wrong method was 404 on the bridge and 405 on HTTP/2 | **fixed**: 405 on both; `a_get_is_405_on_the_bridge` |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 25)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `527b121`.
All eleven round-24 fixes verified. One high, three mediums, two lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `restrict` re-ran `interop::subgraph` per fixpoint round with no wall check; the reviewer read `InfinityModule::edges` (which does list constraint edges) and concluded one pass suffices | **fixed**: one BFS over `domain::adjacency`, which reads `edges`, so a whole constraint chain lands in the cone. The fixpoint existed because `interop::subgraph`'s own adjacency reads only value children — verified by probe (`cone nodes=1` before, `200` after); `a_constraint_chain_is_inside_one_cone` |
| 2 | medium | response writes were bounded per syscall, so a reader taking a byte just inside the timeout held the serial bridge | **fixed**: `write_all_before` re-arms from the time left with a 250 ms hard grace past the deadline (a refusal owed at the deadline still reaches the peer); `a_dripping_reader_cannot_hold_the_bridge_response` |
| 3 | medium | `Http2Client` await of the response headers had no default bound; `with_deadline` could not cover connect | **fixed**: the whole exchange always runs under `wait_for(deadline)` (30 s default), and connect plus the preface share `CONNECT_WAIT`. A probe showed the client preface does not wait for the peer's settings, so the header wait is the real bound; `a_silent_h2_server_fails_the_call_within_the_deadline` |
| 4 | medium | a redacting `annotations` answer still carried the node arena index, the size `stats` hides | **fixed**: the index is omitted for a redacting caller; `a_redacting_annotation_answer_names_no_arena_index` |
| 5 | low | `grpc_frame` cast the payload length with `as u32`, and the client never bounded an outgoing body | **fixed**: both callers bound to `MAX_BODY` (client `rpc/wire` before writing), so the length fits; `an_oversized_post_is_refused_before_framing` |
| 6 | low | a repeated `content-type` and a request line with a fourth token or another version were accepted | **fixed**: both are `400 rpc/wire`; `an_ambiguous_head_is_refused` |

Residuals recorded: `patch` runs one linear encode/hash pass after its last
wall check; `scope_closure`'s final `outside` scan is uncharged per pathless
node; `LIVE_RESOLVERS` is process-global (64 hung lookups disable resolution
until exit); an h2 connection-level accept error aborts sibling streams.

Gate: 86 suites, all green on both feature sets; clippy/fmt clean; negative
controls 9/9; red-team battery green.

### R-07 domain operations - 2026-11-03 (round 24)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `843bbeb`.
The five round-23 fixes held, with three gaps; the reviewer then defeated the
new mid-walk wall check with measurements (8 000 annotations: 9.7 s on a 5 s
grant; patch 18.4 s; 20 000: 60.5 s / 116 s). Two highs, four mediums, five
lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the wall check sat between fixpoint rounds while one round rebuilt the adjacency per annotation, and `effects_within_scope` (patch) had no inner check at all | **fixed**: `transitive_with` walks an adjacency built once, and both loops check the grant every 64 annotations; `a_scoped_walk_over_many_constraints_stays_within_the_wall_ceiling` (4 000 distinct constraints, 400-node expression, 5 ms grant; `why` and `patch` answer wall in < 1 s; fails pre-fix after running a whole round) |
| 2 | high | the HTTP/2 handshake ran outside the connection deadline, so a peer that connected and sent no preface held the serve task forever | **fixed**: `tokio::time::timeout(connection_deadline, handshake)`; `a_silent_connection_is_dropped_at_the_deadline` (50 ms, serve returns) |
| 3 | medium | a folded or whitespace-only head line, and a field name that is not a token, were silently skipped: a gateway that ends the block there sees a different request | **fixed**: both are `400 rpc/wire`; `a_folded_or_untokenized_head_line_is_refused` |
| 4 | medium | a body that ran past the connection budget answered `400 rpc/wire`, contradicting the interop spec and the head path | **fixed**: `408 rpc/transport` on the deadline; `a_stalled_body_is_408_request_timeout` |
| 5 | medium | one detached resolver thread per call, spawned even after the deadline, unbounded | **fixed**: the client caches its first lookup, checks the remaining budget before spawning, and a process-wide cap (64) refuses rather than grows; interop.md documents the 2 s default budget |
| 6 | medium | the annotation charge was a distinguishable size oracle for a scoped/redacting caller | **fixed**: both counts report `nodes`; the `annotations` dimension was withdrawn from observability.md; `an_annotation_flood_is_refused_by_the_node_ceiling` asserts the single kind |
| 7 | low | the client accepted `+200` and `0200` as a status | **fixed**: exactly three digits; `a_non_three_digit_status_is_a_wire_fault` |
| 8 | low | the HTTP/2 in-flight refusal answered `rpc/wire`, which a client treats as fatal | **fixed**: `rpc/backpressure`; `an_inflight_budget_refusal_is_backpressure` |
| 9 | low | without `with_deadline`, the 2 s budget now includes DNS | **documented** in interop.md: 2 s total, resolution included |
| 10 | low | the patch replaced `slot.module` before recomputing `slot.hash`, so a failure between them left a stale hash | **fixed**: both are computed into locals and assigned together |
| 11 | low | the round-23 UTF-8 rule also hit response heads, where obs-text is legal | **fixed**: strict for request lines, lossy for response values |

Residuals recorded: `Http2Client::connect` uses an unbounded TCP connect (OS
SYN timeout); `respond_status` does not drain a refused body (the h2 reset
does); `read_head` refuses a head of exactly `MAX_HEAD` plus its CRLF.

Gate: 86 suites, all green on both feature sets; clippy/fmt clean; negative
controls 9/9.

### R-07 domain operations - 2026-11-03 (round 23 residuals)

Round 23 (reviewer: DeepSeek through the Copilot CLI, `xhigh`) found no
critical, high or medium defect and five lows. All five are closed here.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | low | the bridge's 408 said `Internal Server Error` | **fixed**: `Request Timeout`; `a_stalled_head_is_408_request_timeout` |
| 2 | low | the 404 body `rpc/not-found` is not a class `Error::code` can return, so `refusal()` flattened it to `rpc/provider` | **fixed**: a method or path this service does not serve is `rpc/wire`, a registered class; the HTTP/2 and HTTP/1.1 bridges and their tests agree; `a_wrong_target_is_a_wire_refusal` |
| 3 | low | the Connect client resolved outside its deadline, so a hung resolver held a `with_deadline` call | **fixed**: the lookup runs on a helper thread and waits only the remaining grant; `resolve_within` |
| 4 | low | the head was decoded lossily, so a `transfer-encoding` name with an invalid byte was not the name the peer sent | **fixed**: a head line that is not UTF-8 is `rpc/wire`; `a_non_utf8_head_line_is_a_400` |
| 5 | low | a huge annotation count made the scope closure scan quadratic before the wall check | **fixed**: annotations are charged against `max_nodes`, and the closure checks the wall every round; `an_annotation_flood_is_refused_by_the_node_ceiling` |

Gate: 86 suites, all green on both feature sets; clippy/fmt clean; negative
controls 9/9.

### R-07 domain operations - 2026-11-03 (round 22)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `ffd7920`. Two mediums and
three lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the scoped-evaluate fix from round 21 landed in `resolve()` but not in the evaluate arm, so a scoped caller could tell a missing field from a confined one | **fixed**: one answer; `a_scoped_evaluate_hides_whether_a_name_exists` |
| 2 | medium | the Connect client read a declared body under the per-read timeout, so a byte-per-period drip held it | **fixed**: the body is read in 8 KiB chunks with the deadline re-armed |
| 3 | low | the client's connect was unbounded | **fixed**: `connect_timeout` under the same wait |
| 4 | low | the client accepted `+25`, a repeated length and a `transfer-encoding` the server refuses | **fixed**: the same rules the server applies |
| 5 | low | the egress asserts walked map values but not keys, while `redact_value` collapses on a marker key | **fixed**: both asserts inspect keys |

Gate: 88 suites / 876 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 21)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `f16fbe6`. One high, three
mediums and one low.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | a redacting `stats` answer still returned `nodes`/`edges`: a redacting caller could count the secret cone | **fixed**: a redacting answer omits the size; `a_redacting_stats_answer_hides_the_size` (a non-redacting caller still sees it, and knows the module anyway) |
| 2 | high | the Connect client armed a socket timeout only when a deadline was given, and `read_head` got `None`: a compare-hold peer held it forever | **fixed**: a default `CONNECTION_WAIT` arms both timeouts and the head deadline |
| 3 | medium | a patch stored its arena directly, so a replaced ancestor could orphan a secret node and the module looked secret forever | **fixed**: the patched module is canonicalized, validated and its hash re-seeded (`a_patch_that_orphans_a_secret_canonicalizes`) |
| 4 | medium | metadata queries checked only the node count before a walk bounded by edges and array width | **accepted residual**: the walk is linear and the wall ceiling still refuses; an edge ceiling is tracked with the resource-bomb pass |
| 5 | low | a scoped unresolvable path answered `rpc/invalid-argument` while an outside one answered `rpc/path-not-granted`: a field-existence oracle | **fixed**: a scoped caller gets one answer |

Also: the stalled-head transport test now names a client deadline longer than the
server's own window (the new default is shorter), and the MCP membership timing
test uses a 1 s bound that still separates linear from quadratic on a loaded
machine.

Gate: 88 suites / 871 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9; hardening status clean.

### R-07 domain operations - 2026-11-03 (round 20)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `4f96b57`. Six findings; the
dimension claim was a false positive (the test now asserts the string), the rest
are closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the evaluator dimension was claimed lost | **false positive**: `active/X004-array-length` contains `array`; the test now asserts `array_len` in `Display` |
| 2 | medium | `SchemaArray` joined `structural_resolve` but not `in_scope_node` | **fixed**: the subtree walk follows it |
| 3 | low | `immutable_target` used the library resolver only | **fixed**: it falls back to the structural walk |
| 4 | medium | the Connect client ignored its own `limits.max_bytes` when sizing a response | **fixed**: `min(MAX_BODY, limits.max_bytes)` |
| 5 | low | the drain could add 500 ms past the connection budget | **fixed**: 100 ms, inside the documented 2 s |
| 6 | low | a `SchemaArray` element accepted any segment, and the public helpers disagreed with the capability resolver | **fixed**: only index `0`; the helpers fall back to the structural walk |

Gate: 88 suites / 868 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 23)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `dd5ed9f`. Round-22 fixes
verified; one medium (the process secret branch was dead) and four lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the argument loop refused `Value::Secret` as a malformed argument before the policy check, so the promised `rpc/tool-policy` never fired | **fixed**: the secret check runs before the loop |
| 2 | low | the status line was not counted in the head bytes the grant pays for | **fixed**: `header_bytes` starts at its length |
| 3 | low | the wasm input was cloned before the grant check, and input plus output could each use the full grant | **fixed**: the check precedes the copy and the output cap is the remainder |
| 4 | low | entropy was charged before the pointer check, so a refused call burned the budget | **fixed**: charged after a successful copy |
| 5 | low | the process paragraph owned an HTTP sentence and the grant refusals were undocumented | **fixed**: `wire.md` updated |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 22)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `bbd53c1`. Round-21 fixes
verified; round 21's zero-grant fix was partial. One medium, eight lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `LocalProcess` (and the wasm adapter) still did the work under a zero-byte grant | **fixed**: both refuse before spawning or running; `rpc/budget-exceeded` |
| 2 | low | a failed compare-exchange in the shared output budget buffered the bytes free | **fixed**: retry the exchange |
| 3 | low | `HttpTool::policy` advertised `max_request / 6` with no static ceiling | **fixed**: `max_request.min(MAX_REQUEST_BYTES)` |
| 4 | low | a `u64::MAX` MCP wall grant overflowed into an instant timeout | **fixed**: clamped to 300 s at use |
| 5 | low | the HTTP head and body each got the full grant, so their sum could exceed it | **fixed**: the body cap is the grant minus the head bytes |
| 6 | low | the wasm input was not bounded by the grant | **fixed**: `rpc/budget-exceeded` before the guest runs |
| 7 | low | a secret process argument was `rpc/invalid-argument` | **fixed**: `rpc/tool-policy`, as in the other adapters |
| 8 | low | the spec rows missed the request ceiling, the byte-grant refusals and the outgoing MCP codes, and the process section owned an HTTP sentence | **fixed**: `wire.md` updated |
| 9 | low | the wasm embedder clock wrapped negative past `i64::MAX` | **fixed**: saturated |
| 10 | low | an `expect` sat inside the adapter boundary | **fixed**: `match String::from_utf8` |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 21)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `5a68d09`. All ten round-20
fixes present; one medium (the process ceiling shared the verdict, not the
buffer) and nine lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | both process readers buffered a full ceiling each, so transient memory reached twice the grant | **fixed**: the readers draw from one atomic budget; a compare-exchange loop rather than `fetch_update`, which is deprecated on newer toolchains and whose replacement is past the MSRV |
| 2 | low | per-line HTTP caps ignored the grant | **fixed**: `min(static, header_cap)` for the status and header lines |
| 3 | low | the outgoing MCP static-ceiling arm was dead code (the grant check subsumed it) | **fixed**: the static ceiling is checked first, as on the receive path |
| 4 | low | one `as usize` budget cast remained | **fixed**: `usize::try_from` |
| 5 | low | a nested secret argument was `rpc/invalid-argument` in the wasm adapter | **fixed**: the shared `args_contain_secret` check reports `rpc/tool-policy` |
| 6 | low | the wasm adapter ignored the byte grant for its output | **fixed**: an output past the grant is `rpc/budget-exceeded` |
| 7 | low | a zero-byte grant let a process or HTTP call do its work before the kernel refused the answer | **fixed**: both adapters refuse before spawning or connecting |
| 8 | low | a direct `timeout_ms = 0` assignment spawned and then timed out | **fixed**: clamped at use |
| 9 | low | `initialize` errors dropped the server code | **fixed**: `mcp/initialize:<code>` (spec row and test updated) |
| 10 | low | `max_request` had no static backstop | **fixed**: `MAX_REQUEST_BYTES` (64 MiB) at use |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 20)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `6e9487f`. Round-19 fixes
verified; one high, two mediums, seven lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | wasmi does not charge fuel for `memory.grow`, so a guest could grow to the configured 256 MiB ceiling under a 10 000 fuel grant | **fixed**: the store limiter ceiling is `min(configured, fuel / FUEL_PER_MEMORY_KIB * 1024)`; `a_memory_grow_is_capped_by_the_fuel_grant` (256 MiB grow under 10k fuel refused without allocating) |
| 2 | medium | each process stream was capped separately, so both together buffered twice the grant | **fixed**: one ceiling for the sum; `both_process_streams_share_the_byte_grant` |
| 3 | medium | the response header block was not capped by the grant | **fixed**: `min(64 KiB, grant)`; `a_response_head_past_the_byte_grant_is_refused` |
| 4 | low | the outgoing MCP line was capped at 1 MiB, not by the grant (JSON escaping can multiply the arguments) | **fixed**: a line past the grant is `rpc/budget-exceeded` |
| 5 | low | the request body was capped by `max_request` only | **fixed**: `min(max_request, grant)` |
| 6 | low | `budget.max_bytes as usize` truncated on a 32-bit target | **fixed**: `usize::try_from(..).unwrap_or(usize::MAX)` in all three adapters |
| 7 | low | the spec rows still named the static ceilings | **fixed**: `wire.md` names the grant in each |
| 8 | low | a secret argument was `rpc/invalid-argument` | **fixed**: `rpc/tool-policy` |
| 9 | low | memory grown by the start function was `wasm/limits` | **fixed**: `wasm/fuel` |
| 10 | low | a send with no deadline waited forever for the writer's ack | **fixed**: 30 s bound on the ack |

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 19)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `2d5fd8f`.
All seven round-18 fixes present; two mediums (one a contract regression the
round-18 test had masked) and seven lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the wasm reservation charged the *configured* ceiling, so a two-page module under a small grant was refused, and memory growth was never charged | **fixed**: the module's declared initial memory (`exports()` -> `MemoryType::minimum`) is reserved; a shortfall is `wasm/fuel`; the two-page case is now asserted to run; `a_memory_reservation_is_charged_before_instantiation` |
| 2 | medium | response/output buffering was bounded only by the adapter's static cap, never by `call.budget.max_bytes` | **fixed**: the HTTP body cap, the process output cap and an MCP answer line are each `min(static, grant)`; `a_response_past_the_byte_grant_is_refused`, `an_answer_past_the_byte_grant_is_refused` |
| 3 | low | `send_line_within` enqueued before checking the deadline, so a spent grant still wrote the frame | **fixed**: the check is first; `a_spent_deadline_does_not_enqueue_the_frame` (an echo child must receive nothing) |
| 4 | low | the budget shortfall was `wasm/limits` although the spec defines that as a resource over a ceiling | **fixed** with #1: `wasm/fuel` |
| 5 | low | adapter bodies were cloned before the UTF-8 decision | **fixed**: `FromUtf8Error::into_bytes` on both paths |
| 6 | low | the `mcp/<code>` comment claimed `initialize` behaves the same; it reports `mcp/initialize` | **fixed**: the comment states the difference |
| 7 | low | `MAX_JSON_NODES` said "either adapter" while only HTTP applies it | **fixed**: the doc names the HTTP adapter and records the MCP bound (1 MiB line) |
| 8 | low | `object as usize` truncated a `u64` on a 32-bit target | **fixed**: `usize::try_from` |

Residuals recorded: the MCP reader queue is 64 x (1 MiB + 2); a parent-directory
swap between `canonicalize` and spawn still redirects the pinned path; the HTTP
adapter's resolver has no ceiling of its own; the more obscure documented codes
still lack a direct test (tracked in the log).

Gate: 86 suites, all green on both feature sets; clippy/fmt/fuzz clean;
negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 18)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `fc176bd`. All five
round-17 fixes verified. One medium (a wasm wall bypass the earlier section had
recorded as a residual) and six lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `WasmTool` materialised the declared memory (up to 256 MiB, ~90 ms) before charging its fuel, so a 1 ms grant spent host CPU on an allocation it then refused | **fixed**: the declared ceiling is reserved against the fuel before `instantiate_and_start`, and the difference against the materialised size is refunded; `a_memory_reservation_is_charged_before_instantiation`; two fuel tests now set the memory ceiling explicitly |
| 2 | low | only one leading BOM was stripped, so `"\u{FEFF}\u{FEFF}[huge]"` or `" \u{FEFF}[huge]"` skipped the size gate and answered text | **fixed**: the decode and the gates share one `trim_start_matches` over whitespace and BOM; the token test runs three prefixes |
| 3 | low | a frame that reused our id but carried a `method` was accepted as the answer | **fixed**: `mcp/id-mismatch`; `a_server_request_with_our_id_is_not_an_answer` |
| 4 | low | a failed `tools/list` was reported as a missing array (`mcp/tools`), losing the server's code | **fixed**: `mcp/<code>` like `initialize`; `a_tools_list_error_keeps_the_server_code` |
| 5 | low | a NUL in the working directory reached `Command` and surfaced as a provider fault | **fixed**: `rpc/invalid-argument` at `with_current_dir` and at invoke; `a_nul_working_directory_is_refused` |
| 6 | low | `body_exact` allocated the peer-declared length before reading | **fixed**: grows with the bytes that arrive, 4 KiB at a time |
| 7 | low | `send_line(None)` spun forever on a full writer queue | **fixed**: the queue wait is bounded at 5 s even with no deadline; the ack stays unbounded because a large line may legitimately take long |

Residuals recorded: a parent-directory swap between `canonicalize` and spawn can
still redirect the pinned path (needs directory write access); the HTTP
adapter's resolver has no ceiling of its own (operator endpoint, documented);
the MCP reader queue is 64 x 1 MiB.

Gate: 86 suites, all green on both feature sets; clippy/fmt clean; negative
controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 17)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `843bbeb`. All eight
round-16 fixes verified against the code and the tests. Five new lows, all
fixed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | low | the size-gate comment still described the removed `-2` arithmetic and the old code | **fixed**: the comment describes the two gates and their codes |
| 2 | low | `text_fails_only_on_a_number`'s doc named only objects and arrays while the code admits a number | **fixed** |
| 3 | low | `pin_program` fell back to the raw path when `canonicalize` failed, so a symlink planted before the first spawn chose the binary | **fixed**: a program that does not resolve is `rpc/invalid-argument` at construction; `a_program_that_does_not_resolve_is_refused`; the red-team case now uses a real shell |
| 4 | low | `json_to_value` still invented `0.0` for a number with no `f64` form | **fixed**: it is `Null`, matching the integer case; `a_json_integer_past_i64_is_not_rounded` asserts it |
| 5 | low | a leading BOM hid a huge body from the size gate, so it answered text; the path sentence in the spec said "below 0x21 or 0x7f" | **fixed**: one leading BOM is ignored before the gates and the decode; the spec says outside `0x21..=0x7e`; the token test runs a BOM-prefixed body and a small BOM object |

Gate: 86 suites, all green on both feature sets; clippy/fmt clean; negative
controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 16)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `10be022`.
Eight of the ten round-15 fixes held; one medium (a bare scalar bad number
downgraded to text), one false claim (the node band), and three paths shipped
without a covering test.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | a body that is only a number (`1e400`) failed to parse and was downgraded to text, while the spec promises a refusal | **fixed**: the discriminator admits a leading `-` or digit, and only a literal that holds a digit counts as a bad number, so `- not json` stays text; `a_json_body_with_an_unrepresentable_number_is_refused` |
| 2 | low | the `MAX_JSON_NODES - 2` arithmetic assumed a tree has at most two more nodes than tokens; a chain of single-element arrays has more, so a size refusal still surfaced as `http/bad-number` | **fixed**: the node ceiling is its own predicate, `json_too_many_nodes`, answered as `http/too-complex` before the number check; the token gate is back at `MAX_JSON_NODES`; `a_json_body_past_the_token_ceiling_is_too_complex` |
| 3 | low | the spec and `security.md` said resolution precedes the deadline while the code started the deadline first | **fixed**: the deadline binding moved below `to_socket_addrs`, matching both specs |
| 4 | low | an orphaned doc paragraph documented the token counter as a number check | **fixed**: deleted |
| 5 | low | the `http/too-complex` row named the wrong constant and scope | **fixed**: tokens in an object/array body, or decoded nodes |
| 6 | low | `json_text_too_complex`, the `{`/`[`-only rule, both truncation codes and the reader window had no test | **fixed**: HTTP tests for a >2^20-token body, a >1 MiB CSV answer (stays text), a short body and a truncated head; a real `StdioTransport` child for an exact-cap line and an unterminated overlong one |
| 7 | low | the reader accepted an overlong line whose tail was whitespace and left the tail in the pipe | **fixed**: `read == MAX + 2 && !line.ends_with('\n')` is `mcp/line-too-long`, with the caller's check as the second line |
| 8 | low | a lowercase allowlist entry never matched because `invoke` uppercases | **fixed**: `HttpTool::new` stores uppercase; `a_lowercase_allowlist_entry_matches` |

Residuals recorded: resolution has no ceiling of its own in the HTTP adapter
(operator endpoint, now stated in both specs); the MCP reader queue is
count-bounded at 64 x (1 MiB + 2); `json_to_value` keeps
`as_f64().unwrap_or(0.0)` although no current representation can reach it.

Gate: 86 suites, all green on both feature sets; clippy/fmt clean; negative
controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 15)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `38294cf`.
One high and one medium, both introduced by the round-14
`serde_json/arbitrary_precision` switch, plus eight lows. The feature is
reverted: number exactness is enforced on the text, where the literal still
exists.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `arbitrary_precision` kept `1e400` as a literal with no finite `f64`, and `json_to_value`'s `as_f64().unwrap_or(0.0)` invented `0.0` (sign lost) | **fixed**: the feature is gone; a string-aware scanner validates every literal before or beside the decode — a float must parse finite, an integer must fit `i64`/`u64`; `{"amount":1e400}`, `-1e400` and the past-`u64` integers are refused end to end; `a_json_body_with_an_unrepresentable_number_is_refused`, `an_mcp_result_with_an_unrepresentable_number_is_refused` |
| 2 | medium | the `$serde_json::private::Number` magic key decoded a peer object as a number in both directions | **fixed** with the same revert; a regression test pins the key as an ordinary map entry |
| 3 | low | the reader's line-cap arm was unreachable, so a truncated overlong line was handed back as a line | **fixed**: the dead arm is gone and the truncation contract is documented at the read; the session's inclusive cap is pinned by an exact-cap test and one byte over |
| 4 | low | `mcp/too-complex` was documented and emitted by no path | **fixed**: the row is gone; the MCP line cap (1 MiB) cannot build 2^20 nodes |
| 5 | low | between the token gate and the tree ceiling a size refusal was reported as `http/bad-number` | **fixed**: the token gate runs at `MAX_JSON_NODES - 2`, so a tree that passes it cannot trip the node arm |
| 6 | low | the complexity gate judged non-JSON bodies (CSV, log text) and mislabelled them | **fixed**: it runs only for a body that opens as an object or an array |
| 7 | low | the spec said the deadline covers resolution; the code starts it after resolution | **fixed**: the spec says resolution uses the resolver's own timeout because the endpoint is the operator's |
| 8 | low | the `## 6. Transports` heading was merged into the table header row | **fixed**: heading and header are separate lines |
| 9 | low | `json_to_value` substituted `Null` for a `u64` past `i64::MAX` and said so nowhere | **fixed**: the doc states the one partial case and that both adapters gate it; no peer answer reaches it |
| 10 | low | `http/read:truncated body` carried a space | **fixed**: `http/read:truncated-body`, documented with `http/read:truncated` |

Residuals recorded: `json_to_value` stays infallible (a `Result` would be a
public break; the predicate is the gate); the reader still drops the rest of an
overlong line, which the session refuses before parsing; resolution has no
ceiling of its own (operator endpoint).

Gate: 86 suites; 865 tests all-features and 795 no-default-features, all pass;
clippy/fmt clean; negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 14)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `eb4fa43`.
Two highs (one a round-13 regression) and two mediums, plus five lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | an integer past `u64::MAX` or below `i64::MIN` is parsed as a float, so the round-13 check never saw it and two answers differed only by a value nobody wrote | **fixed**: `serde_json/arbitrary_precision` keeps the literal, so an integer with no fraction or exponent that does not fit `i64` is refused; the deleted cases are restored |
| 2 | high | the node ceiling ran after the tree was decoded: a 64 MiB flat array allocated ~3.5 GiB before the refusal | **fixed**: a string-aware pass counts structural tokens before parsing and refuses `http/too-complex` |
| 3 | medium | the receive line cap counted the delimiter while the send cap did not | **fixed**: the receive comparison allows the two delimiter bytes |
| 4 | medium | `HTTP/1.<digit>` was a prefix, so `HTTP/1.1x 200` passed | **fixed**: the version is `HTTP/1.<digit>` followed by a space |
| 5 | low | the process code table had a paragraph inside it and the new codes were undocumented | **fixed**: the table is whole; `*-too-complex` and the 16 MiB per-stream ceiling are documented |
| 6 | low | a `setsid` descendant keeps the drain threads alive | **recorded** |
| 7 | low | the 5 ms poll makes a short grant overshoot | **recorded** |
| 8 | low | the wasm 128 KiB minimum is checked after the run | **recorded** for the ABI pass |
| 9 | low | the fuel-per-memory prose was off | **recorded** |

Gate: 88 suites / 878 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 13)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `f16fbe6`.
The round-12 number check was over-broad (it refused every float); one medium and
ten lows, all closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `json_has_unrepresentable_number` refused every non-integer JSON number, so `{"price": 9.99}` failed | **fixed**: only a u64 past `i64::MAX` is unrepresentable (`Value::Float` is the form for a float); the test now covers `9.99`/`1e3` and a wide tree |
| 2 | medium | the spec rows still described the old status rule and lacked `*-bad-number` | **fixed**: `http/<status>` covers non-2xx, `http/status` names three digits and the range, both `bad-number` rows exist, the output ceiling is documented |
| 3 | low | ADR-0019 contradicted the wasm adapter on `wasm/input` and `clock_ms` | **recorded** for the ADR pass |
| 4 | low | a dead second body-ceiling branch remained | **removed** |
| 5 | low | a duplicate pre-send deadline check could poison an untouched session | **removed**: the session's own check runs first |
| 6 | low | `LocalProcess` still transcoded binary output | **fixed**: a non-UTF-8 stream is a module value |
| 7 | low | the two post-spawn `?` arms leaked the child | **fixed**: both kill the tree |
| 8 | low | the decoded JSON tree was unbounded (a 1 MiB array is ~500k values) | **fixed**: a 2^20-node ceiling in the same walk |
| 9 | low | the MCP line cap was off by one (the delimiter counted) | **fixed** |
| 10 | low | the HTTP version check accepted `HTTP/1. 200` | **fixed**: `HTTP/1.<digit>` |
| 11 | low | a test asserted only `> 0` | **recorded**: the malformed-answer test is strengthened in the next round |

Also fixed: a test built a 2^40-node JSON tree (doubling) and hung the suite; it
now uses a flat wide array.

Gate: 88 suites / 874 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9; hardening status clean.

### R-08 tools and MCP - 2026-11-03 (round 12)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `4f96b57`.
One medium and twelve lows; no authority escalation.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | a JSON number past `i64` on either sign was substituted (`null` or a rounded float) | **fixed**: `json_has_unrepresentable_number` refuses it in both adapters (`http/bad-number`, `mcp/bad-number`); both signs are tested |
| 2 | low | `max_output` was unclamped at the reader | **fixed**: clamped to 16 MiB at use |
| 3 | low | `wire.md` still said the deadline covers resolution | **fixed** |
| 4 | low | the `rpc/budget-exceeded` row named the output ceiling, which answers `rpc/tool-policy` | **fixed** |
| 5 | low | the two body ceilings answered different codes | **fixed**: `http/body-too-large` for both framings |
| 6 | low | a binary body was transcoded with replacement characters | **fixed**: a non-UTF-8 HTTP body is a module payload |
| 7 | low | 3xx was reported as a successful call | **fixed**: only 2xx succeeds |
| 8 | low | the status accepted `+200`/`000200` | **fixed**: exactly three digits |
| 9 | low | `value_to_json` recurses under an iterative guard | **recorded**: the kernel gates a dispatched call; the adapters refuse a module/non-finite shape first |
| 10 | low | the `from_bytes` doc claimed WAT support | **fixed** (doc) |
| 11 | low | the workdir is absolute-checked, not canonicalised | **fixed** in the spec text |
| 12 | low | `security.md` overstated the tool-policy gating | **fixed**: `allow_process` gates `LocalProcess`; HTTP and MCP do not need it |

Gate: as above (the same commit).

### R-07 domain operations - 2026-11-03 (round 19)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `b1a331f`. Two highs and two
mediums; the round-18 test only tripped the provider gate.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the engine reports its ceilings as evaluation codes (`active/X001..X006`), so a budget refusal answered `rpc/domain` and the `Limit` arm was dead | **fixed**: those codes map to `rpc/budget-exceeded` with their dimension; `an_evaluator_array_ceiling_is_a_budget_refusal` (200k elements) |
| 2 | high | two resolvers: the provider's `resolve` walked tables only, so a dotted array path (`app.0`) or a semantic wrapper answered `rpc/invalid-argument` | **fixed**: both resolution sites fall back to `structural_resolve`; `an_array_element_path_resolves` |
| 3 | medium | the Connect head-error refusal did not drain before closing (the other 13 did) | **fixed** |
| 4 | medium | the drain stopped after 16 reads, so a 1 MiB body still ended in a reset that discarded the 413 | **fixed**: time-bounded, 16 KiB chunks |
| 5 | low | `SchemaArray` was missing from both walkers | **fixed** |
| 6 | low | bridge and projection depth ceilings collapsed to `"value"` | **fixed**: prefix-matched |

Gate: 88 suites / 866 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 11)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `b1a331f`.
No criticals or highs; two mediums and twelve lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the send deadline did not cover the enqueue: a full capacity-1 writer queue made the next send wait forever | **fixed**: `try_send` under the deadline, 1 ms polls, `Timeout` on expiry |
| 2 | medium | the flood refusal covered the wait loop but not the post-exit reader wait, so a descendant that outlived the leader still burned the grant | **fixed**: the same ceiling in that arm |
| 3 | low | a JSON integer past `i64::MAX` was rounded through `f64` | **fixed**: it answers `null`, never a different number; `a_json_integer_past_i64_is_not_rounded` |
| 4 | low | lossy UTF-8 transcoding handed the caller bytes the peer never wrote | **recorded**: the adapters are text protocols; a binary result needs a module payload, tracked with the tool policy |
| 5 | low | a `request` with no method guessed `GET` | **fixed**: refused; `a_request_without_a_method_is_refused` |
| 6 | low | the process code table lacked `process/thread` and `rpc/budget-exceeded` | **fixed** |
| 7 | low | `security.md` still said the deadline covers resolution | **fixed** |
| 8 | low | the `mcp/bad-response` row did not describe a malformed `error` | **fixed** |
| 9 | low | the workdir stays absolute-checked rather than canonicalised | **recorded** in both specs |
| 10 | low | the wall ceiling starts after the spawn | **recorded** |
| 11 | low | wasm memory grown inside `run` is not fuel-charged | **recorded**: the store ceiling still fails closed |
| 12 | low | a dead statement from round 10 | **fixed** |
| 13 | low | the wasm scope refusal had no test | **fixed**: `a_scoped_wasm_call_is_refused` |
| 14 | low | public `max_body`/`max_request` fed an allocation | **fixed**: clamped to 64 MiB at use |

Gate: as above (the same commit).

### R-07 domain operations - 2026-11-03 (round 18)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `78c6396`. All five round-17
fixes verified; five lows, **no critical/high/medium**.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | low | no test pinned the evaluator ceiling dimensions | **fixed**: `evaluator_limit_dimensions_are_preserved` (a tiny node budget answers `rpc/budget-exceeded` naming `nodes`) |
| 2 | low | no boundary test for the synthetic level of a duration | **fixed**: `the_synthetic_level_counts_against_the_ceiling` (63 tables + a terminal duration is refused) |
| 3 | low | `structural_resolve` handled a table and an array but not a `SchemaTable`, so a scoped schema field was refused | **fixed**: the same field walk applies |
| 4 | low | the depth probe mixed `+ 1` with `saturating_add` | **fixed**: saturating throughout |
| 5 | low | array and key ceilings collapsed to `"value"` while the kernel names `array_len` | **fixed**: `array*`/`key*` map to their own dimension |

Also fixed this round, out of scope: the Connect bridge's refusal paths closed
the socket with unread data in the receive buffer, which the stack answers with
a reset that discards the 400 just written. Two integration tests flaked with
`WSAECONNRESET` under load (1 in 5 suite runs). The server now half-closes and
drains before closing, and the raw test client half-closes after its body:
**6 of 6 full-suite runs clean** afterwards.

Gate: 88 suites / 863 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9; hardening status clean.

### R-07 domain operations - 2026-11-03 (round 17)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `d3facc0`. One round-16 fix
had not landed and two were incomplete; four lows and three hardening notes.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | low | the `DurationMs` saturation never landed (the edit was lost with a later assertion in the same batch); the cast still wrapped | **fixed**: `i64::try_from(..).unwrap_or(i64::MAX)`; `a_duration_past_i64_saturates` |
| 2 | low | `escaped` covered a subset of the crate's invisible-character set (`U+2028`, zero-widths, tag characters) | **fixed**: it reuses `security::is_invisible_or_reordering`; `a_displayed_path_cannot_forge_a_log_line` |
| 3 | low | `Provider`, `Payload`, `Replay`, `Receipt` and `Transport` printed caller-influenced text raw | **fixed**: all five are escaped |
| 4 | low | an evaluator `Limit` collapsed every ceiling to `"value"` | **fixed**: `node*`, `depth*` and `wall*` map to the provider's own vocabulary |
| 5 | low | the depth probe ignored the level `DurationMs`/`Quantity` add when converted | **fixed**: both count one level |
| 6 | low | the blanket `From<active_infinity::Error>` mapped a budget or evaluation failure to `rpc/payload` | **fixed**: removed; both remaining `?` sites map explicitly |

Gate: 88 suites / 858 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 16)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `7aff2d2`. All six round-15
fixes verified; two mediums and two lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | an evaluator resource ceiling surfaced as `rpc/payload` instead of `rpc/budget-exceeded` | **fixed**: a `Limit` from the engine is the provider's value budget |
| 2 | medium | the semantic unwrap loop was unbounded: a hand-built `Semantic { inner: self }` would hang the scope check | **fixed**: bounded by the node count with a self-reference guard |
| 3 | low | `DurationMs(u64)` cast to `i64` wrapped negative | **fixed**: saturated |
| 4 | low | a path or method with a newline or bidi override reached `Display` verbatim (log forging) | **fixed**: caller text is escaped in `Display` (`PathNotGranted`, `TopicNotGranted`, `MethodNotGranted`) |

Gate: 88 suites / 856 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 10)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `d3facc0`.
Six of the eight round-9 fixes held fully; two highs and four mediums, plus
five lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the writer-thread spawn failure path returned without killing the child (the reader path did) | **fixed**: it kills the tree too |
| 2 | high | a child that floods its output blocked on the pipe, so the call burned the whole grant and answered `Timeout` instead of the output refusal | **fixed**: the wait loop drains the report channel and refuses `rpc/tool-policy` as soon as a buffer passes `max_output`; `an_output_flood_is_refused_not_waited_out` (200k lines, 5 s grant, refused in < 3 s) |
| 3 | medium | a timeout after the frame left was treated as retryable: the answer was still in flight and a retry read it as the next answer while the peer had run the tool | **fixed**: every receive timeout poisons the session; `a_post_send_timeout_poisons_the_session` |
| 4 | medium | `LocalProcess` used `thread::spawn` (panics on failure) and leaked the child | **fixed**: a named builder, a `process/thread:<err>` code, and the tree is killed |
| 5 | medium | the spec claimed one deadline covers resolve; resolution happens outside it | **fixed**: the spec states the resolver is outside the deadline |
| 6 | medium | `WasmTool` accepted a `path_scope` the kernel cannot enforce | **fixed**: refused with `rpc/tool-policy`, as the text adapters do |
| 7 | low | a malformed JSON-RPC error object was reported as `mcp/0` | **fixed**: `mcp/bad-response`; `a_malformed_error_object_is_a_bad_response` |
| 8 | low | two handshake constants, and the fallback used unchecked `Instant + Duration` | **fixed**: one constant, `checked_add` |
| 9 | low | `http/body:<err>` was documented and never emitted; the status-line UTF-8 fault was described narrowly | **fixed**: the table matches the code |
| 10 | low | the argument-cap test only asserted the arithmetic | **recorded**: the strengthened kernel+policy test is scheduled with the resource-bomb pass |
| 11 | low | the workdir is absolute-checked but not canonicalised, while the spec implied a symlink swap was covered | **fixed**: the spec says what the code does |

Residuals recorded: the reader queue is count- not byte-bounded (64 x 1 MiB);
the writer blocks on a full pipe until the session drops; `kill_process_tree`
can lose a tree that `setsid`s away and may signal a recycled pid; MCP has no
`notifications/initialized`, `protocolVersion` check or pagination; positional
`argN` arguments cannot address a declared `inputSchema`.

Gate: 88 suites / 861 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 9)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `7aff2d2`.
All round-8 fixes held; three mediums and five lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `path_scope` was silently inert on the text-only adapters: the kernel inspects `Value::Path`, and a process/MCP argument is text | **fixed**: both refuse a scoped call with `rpc/tool-policy`; `a_scoped_process_or_mcp_call_is_refused` |
| 2 | medium | the advertised `max_arg_bytes` was the frame size, while JSON escaping is up to six-fold | **fixed**: the cap is a sixth of the frame/request minus the envelope; `the_advertised_cap_leaves_escaping_room` |
| 3 | medium | a whitespace-only line ended the header block, so a field written after it became payload | **fixed**: only an empty line ends the block; a folded line is `http/headers`; `a_whitespace_only_line_does_not_end_the_headers` |
| 4 | low | `max_output as u64 + 1` overflowed on a caller-set `usize::MAX` | **fixed**: saturating |
| 5 | low | a failed helper-thread spawn leaked the child process | **fixed**: the tree is killed before the error returns |
| 6 | low | two handshake ceilings and the spec named the unused one | **fixed**: one 5 s constant; the spec names it |
| 7 | low | a NUL in a program path or workdir surfaced as a spawn fault | **fixed**: `pin_program` refuses it at construction |
| 8 | low | the provider error-code table was out of step with the code | **fixed**: `mcp/tools`, `mcp/thread`, `mcp/write:closed`, `http/header-not-utf8`, `http/body-too-large` documented; `http/body:<err>` removed; the header conditions named |

Also observed: `has_method_does_not_rebuild_the_method_table` flaked once under
build load (2 000 lookups over 4 096 tools in <300 ms) and passed on rerun and in
isolation.

Gate: as above (the same commit).

### R-07 domain operations - 2026-11-03 (round 15)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `b4d3cbf`. The semantic
walk fix had not landed (the edit was lost when a later assertion failed in the
same batch) and a declassifying patch still served a hash entry.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `structural_resolve` still sliced the full path by the current segment's length and skipped a segment: a single-segment path over a semantic root panicked, and a legal nested name was refused; the round-14 test used no scope so it never reached the code | **fixed**: the wrapper is unwrapped inline before each step (no slicing, no skipped segment); `a_scoped_semantic_wrapper_resolves` installs with a scope |
| 2 | high | a patch that removed the last secret kept the `Hash` provenance entries, which name the pre-patch image | **fixed**: a secret-bearing history drops hash-valued entries alongside `parent`; `a_patch_removing_the_last_secret_drops_hash_entries` |
| 3 | medium | the over-deep evaluate refusal had no test | **fixed**: `an_over_deep_evaluation_is_a_budget_refusal` |
| 4 | low | the `provenance: None` arm skipped the wall check | **fixed**: every arm charges it |
| 5 | low | `redact_value`'s map-key collapse was unpinned | **recorded**: fail-closed, no behavior change |
| 6 | low | the empty-placeholder over-collapse was unpinned, and the placeholder set was read from the cone instead of the source | **fixed**: the set comes from a redacted copy of the source; `an_empty_placeholder_collapses_public_empty_text` pins both halves |

Also: a pathless node inside the scope's subtree (behind a semantic wrapper or
an array) is now inside for every scope check, and a synthetic label falls back
to a subtree walk instead of being treated as outside.

Gate: 88 suites / 852 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 14)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `349cc67`. Four of five
round-13 fixes held; the semantic-wrapper walk was broken and a patch-history
oracle remained.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a patch that replaced the last secret cleared the `holds_secret` flag, so the cone and the stored provenance still carried the raw pre-patch content address | **fixed**: the pre-patch secret set decides, the cone drops provenance, and a secret-bearing history records no `parent`; `a_patch_removing_the_last_secret_serves_no_parent` |
| 2 | high | the semantic-wrapper branch sliced the full path and skipped a segment: a single-segment path over a semantic root panicked (index out of bounds) | **fixed**: the wrapper is unwrapped inline before each step, no slicing; `a_semantic_wrapper_is_transparent_to_the_scope` |
| 3 | medium | the same branch consumed a segment, so a legal `Table -> Semantic -> Table` name was refused | **fixed** by the same rewrite |
| 4 | low | provenance text was stripped only when it *started* with `blake3:` | **fixed**: an embedded address is dropped too; `an_embedded_content_address_is_dropped` |
| 5 | low | the depth refusal on the evaluate path mapped to `rpc/payload` instead of `rpc/budget-exceeded` | **fixed**: the value returns unmarked and the caller's own gate answers |
| 6 | low | an empty placeholder (a marker-substring secret) collapses every empty string | **accepted**: content-free and fail-closed on the category; recorded rather than special-cased |

Gate: 88 suites / 848 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-08 tools and MCP - 2026-11-03 (round 8)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `349cc67`.
All round-7 fixes held in code; one high, two mediums and seven lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the MCP reader thread fed an unbounded channel: a server streaming frames grew host memory at pipe speed | **fixed**: `sync_channel(64)` for lines and 1 for the writer, so the child blocks on its pipe, which the deadline already bounds |
| 2 | medium | a space before a header colon hid `transfer-encoding`/`content-length` from every framing check | **fixed**: the name must be an RFC 9110 token and a length must be digits; `a_header_name_is_a_token_and_a_length_is_digits` (three probes) |
| 3 | medium | the HTTP write phase armed one per-syscall timeout, so a peer reading a byte at a time stretched it past the ceiling | **fixed**: `write_within` re-arms and re-checks the deadline every 4 KiB |
| 4 | low | a body serialisation fault silently sent an empty body | **fixed**: the call is refused |
| 5 | low | a NUL in an MCP program or argument surfaced as `mcp/spawn:<os text>` | **fixed**: `rpc/invalid-argument`; `a_nul_in_an_mcp_spawn_is_refused` |
| 6 | low | the public `workdir` field could be set relative after construction | **fixed**: `invoke` re-checks the absolute path; `a_relative_workdir_is_refused_at_invoke` |
| 7 | low | the round-7 test asserted only `rpc/provider`, not the subcodes | **fixed**: `provider_code()` is asserted (`mcp/tool-name`, `mcp/tools`) |
| 8 | low | `handshake_within(t, None)` had no ceiling | **fixed**: a 10 s default |
| 9 | low | the advertised `max_arg_bytes` equalled the frame/request cap, so an argument at the advertised size was refused | **fixed**: 256 bytes are reserved for the envelope |
| 10 | low | u64-only JSON integers round through `f64` | **recorded** (round-7 #3), no authority impact |

Gate: as above (the same commit).

### R-07 domain operations - 2026-11-03 (round 13)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `7c80955`. All six round-12
fixes verified; two highs, one medium and two lows, closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `dependents`/`dependencies` checked only the result set, never the entry node, so an alias to an outside node answered (and a redacting answer returned the marker, an outside-taint oracle) | **fixed**: both arms require the entry node to be named by the scope, as `why`/`impact` already did; `a_scoped_dependency_query_refuses_an_alias_entry` (both capabilities) |
| 2 | high | the round-12 hash fix missed `provenance` and the cones: a non-redacting caller on a secret-bearing module still received the raw parent content address | **fixed**: `provenance` and both cones drop every content address when the module holds a secret, for every capability; `a_secret_bearing_module_serves_no_raw_parent_hash` |
| 3 | medium | `structural_resolve` walked only tables, so a legitimate scoped array element (`app.0`) was refused and its label dropped | **fixed**: numeric segments select array elements, a `Semantic` wrapper is transparent; fail-closed on anything else |
| 4 | low | a quantity whose unit is a placeholder stayed text while a table key collapsed | **fixed**: the same collapse applies to a unit |
| 5 | low | the walk-amplification residual was under-counted (adjacency three times, `value_paths` twice, wall checked after) | **recorded accurately**: linear per build, bounded by `max_nodes`, planned with the resource-bomb pass |

Also tightened: the two alias tests now build a module with no real field of that
name, so the refusal comes from the structural check, not from the resolver's
table-first preference.

Gate: 88 suites / 845 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 12)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `a9a6ec8`. It found that the
round-11 scope fix had not landed (the edit was lost when a later assertion in
the same batch failed), plus three more highs/mediums.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | no `structural_resolve` existed: `in_scope_path`, the label filter, entry resolution and the immutability check all followed bindings, so an undotted or dotted `bind("app", outside)` still widened the scope (the round-11 test passed on a `value_paths` tie-break, not on a guarantee) | **fixed**: `structural_resolve` walks table fields from the root (no bindings, no annotations, empty/`..` segments refused) and backs `in_scope_path` and the label filter; `an_undotted_binding_alias_does_not_widen_the_scope` passes for the right reason |
| 2 | high | one placeholder from the first secret node: a module with a normal secret and a marker-substring secret mapped only the first form, so the second came back as `Text("")` | **fixed**: the set of every redacted `Str` for a secret node is mapped, with the marker as the fallback; `a_marker_substring_secret_is_a_value_secret` now runs both orders |
| 3 | medium | per-call walk amplification (adjacency and `value_paths` rebuilt several times, wall checked only at the end) | **accepted residual**: linear per build and bounded by `max_nodes`; one adjacency + one path map per call and an edge ceiling are tracked for the resource-bomb pass |
| 4 | high | a non-redacting `content_hash` served the raw hash over the secret heap: an offline brute-force oracle over a low-entropy secret | **fixed**: a secret-bearing module is hashed in redacted form for every capability; the slot cache still holds the raw canonical hash (the module's identity and a patch's parent); `a_secret_bearing_module_is_hashed_redacted_for_every_caller` |
| 5 | medium | `mark_secret_texts` ran before the depth gate, so a deep value aborted instead of being refused | **fixed**: the iterative depth check runs first and refuses `infinity/limit` |
| 6 | low | `mark_secret_texts` left a marker in a table key or a quantity unit, while `redact_value` collapses such a map | **fixed**: a table whose key matches a placeholder collapses to `Value::Secret` |

Observed once: `connect_bridge_moves_a_module_and_rejects_bad_frames` failed on
the first `--no-default-features` run (the malformed-frame post) and passed on
the rerun and in isolation; recorded as a flake to watch, no code change (the
bridge is untouched by this round).

Gate: 88 suites / 843 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9.

### R-07 domain operations - 2026-11-03 (round 11)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `5b3e567`. All seven
round-10 fixes held; one high, two mediums and two lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the round-10 root fix covered only the root: every scope check used one `value_paths` name plus `resolve_path`, so an undotted binding that spells the scope exactly (`bind("app", outside)`) presented an outside node as in-scope for `evaluate`, `subgraph`, `why` and `patch` | **fixed**: `in_scope_path` resolves the name by walking table fields from the module root (`structural_resolve`), never through a binding, so an alias cannot move a node into a scope; the label filter uses the same rule. `an_undotted_binding_alias_does_not_widen_the_scope` (three methods) |
| 2 | medium | the evaluated placeholder was read from the first secret node's redacted form and skipped the mapping entirely if that form was not a `Str`; table keys and quantity units were never mapped | **fixed**: the redactor always writes a `Str`, and the marker is the fallback, so the mapping never stops. Table keys and unit text are names, not values: mapping them would change the value's shape, and a unit that copies a secret is a module-author error (recorded) |
| 3 | medium | a metadata call rebuilds adjacency and `value_paths` several times, and the wall ceiling is checked only at the end | **accepted residual**: the work is linear per build and bounded by `max_nodes`; the plan is one adjacency + one path map per call plus an edge ceiling, tracked for the RPC cross-cutting pass on resource bombs |
| 4 | low | `on_drop` reclaim had no section test | **fixed**: `the_last_drop_reclaims_the_module` drops the last handle and finds no module on the next mint |
| 5 | low | a real field named `a[0]` resolves and passes the label filter, so a receiver cannot tell it from a synthetic label | **recorded**: escaping every label changes the wire text a caller uses in paths; the synthetic forms are refused, and a real field keeps its own name |

Residuals recorded: taint completeness depends on `edges()` covering every
child-bearing variant (a per-variant secret test is planned with the Infinity
re-round); `MAX_DROP_LOG` truncates diagnostics by design; the hidden-annotation
presence bit and `stats` counts are accepted oracles.

Gate: 88 suites / 841 tests all-features and no-default-features, clippy/fmt/doc
clean; negative controls 9/9; hardening status 13 invariants / 145 checks.

### R-07 domain operations - 2026-11-03 (round 10)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `ed6e888` on
`active-infinity` 2.4.1. Six round-9 fixes held, three were partial; one
critical, two highs, two mediums and four lows, all closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | `install` stored the caller's arena while hashing the canonical image, so `annotations` served an intent/constraint source that copied a secret literal: the encoder had redacted it in the bytes but not in the stored module | **fixed**: `install` stores `decode(encode(module))`, so class and hash agree; `an_installed_annotation_copy_is_not_served` (both capability modes) |
| 2 | high | `tainted_nodes` counted `children()` but walked `edges()`, which also carries constraint edges: a self-referential constraint re-enqueued forever and a butterfly DAG re-enqueued exponentially (3.2 s at depth 22) | **fixed**: a monotone worklist, O(V+E); `a_self_referential_constraint_terminates` (2 s bound) |
| 3 | high | a binding can name the module root, its label resolves back to it, so a scoped `patch` replaced the whole module and deleted every outside subtree | **fixed**: a scoped patch refuses the root target; `a_scoped_patch_cannot_replace_the_module_root` |
| 4 | medium | `@node[id]`/`@annotation[i]`/`@constraint[i]` labels survived redaction (a path-depth, budget or collision fallback) | **fixed**: a label must resolve back to its node; `a_redacting_answer_names_no_synthetic_label` (80-deep chain) |
| 5 | medium | when a secret is a substring of the marker the redactor writes `""`, and only `***SECRET***` was mapped back, so an evaluated secret came back as ordinary empty text | **fixed**: the placeholder is read from the redacted module and mapped to `Value::Secret` (an empty placeholder over-redacts empty data, the fail-closed side); `a_marker_substring_secret_is_a_value_secret` |
| 6 | low | a hidden annotation still reported its kind and count on the secret cone | **fixed**: the hidden set collapses to one marker entry with no node or kind; `a_redacting_annotation_answer_collapses_the_hidden_set` |
| 7 | low | `install` served nodes the cached hash does not cover | **fixed** by #1 |
| 8 | low | the last capability drop never reclaimed the module slot | **fixed**: `on_drop` removes the slot; a stale object is `unknown module` |
| 9 | low | the wall ceiling was checked only after the walk | **partially addressed**: the walks are linear now (#2), so the exposure is the annotation-chain fixpoint; recorded as a residual |

`stats.secrets` now reports the canonical count (two nodes for a promoted
secret locator: the literal and its reference).

Residuals recorded: an unscoped `evaluate` resolves host `Env` (tested as a
design choice under I-11); literal-only redaction is recomposable by a module
author; `content_hash` for a non-redacting capability stays a full-image oracle;
a cone reply carries no redacted flag; `next_object` overflow is theoretical.

Gate: 88 suites / 839 tests all-features, clippy/fmt/doc clean; negative
controls 9/9; hardening status 13 invariants / 145 checks.

### R-08 tools and MCP - 2026-11-03 (round 7)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `5b3e567`. Both round-6
fixes verified; three lows, two closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | low | `contains_module`/`contains_nonfinite` recursed: a direct `Provider::invoke` bypasses the kernel's depth gate, and a deeply nested value would abort the stack in the walk | **fixed**: both walks are iterative, like `Value::is_tainted`. A run-time test is not possible: dropping a 20 000-deep `Value` overflows the derived recursive `Drop` before the adapter sees it, so the recursion is closed by construction and the `Value` drop is recorded as a library-level residual |
| 2 | low | a nameless `tools/list` entry was skipped and a non-array `tools` yielded an empty session: malformed handshake data looked usable | **fixed**: both refuse (`mcp/tool-name`, `mcp/tools`); `a_nameless_tool_entry_is_refused`, `a_hostile_tool_list_is_refused` |
| 3 | low | `json_to_value` maps a u64-only JSON integer through `f64` (precision past 2^53) | **residual**: inbound fidelity only, no authority impact (call ids compare raw `Json`); recorded |

### R-08 tools and MCP - 2026-11-03 (round 6)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `ed6e888`. All six round-5
fixes verified in code; one was incomplete (NUL only) and one new medium.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | an empty or `=`-bearing env key reached `Command`: a spawn-time provider fault, or silent mangling on Windows | **fixed**: `valid_env_entry` refuses it in both adapters as `rpc/invalid-argument` |
| 2 | medium | a non-finite float serialised to JSON `null`, so the peer acted on a null nobody wrote | **fixed**: refused like a module in both adapters |
| 3 | low | a spent-deadline `Timeout` from the pre-check still poisons the session | **residual**: the pre-check makes it unreachable (nothing was enqueued); recorded |

New coverage: env keys, non-finite arguments and bodies, nested module, spent
handshake.

Gate: as above (the same commit).

### R-07 domain operations - 2026-11-03 (round 9)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `3ce5069`.
It confirmed five of the six round-8 fixes and found one half-fix, three new
highs/mediums and four lows. All closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a redacting `subgraph` still returned the cone's provenance (the parent content address and a `Hash` entry): an offline equality oracle over the secret heap, while `patch` cleared it | **fixed**: the redacting cone clears provenance like the patch path; `a_redacting_subgraph_carries_no_provenance` |
| 2 | high | redaction rewrote only `is_secret()` nodes: a plain `Str` holding the same bytes was neither replaced in a cone nor refused in an evaluated value | **fixed**: `interop::Redactor` in Active Infinity 2.4.x — the library that holds the heap — covers every text surface, and the provider redacts cones, patches and the evaluated copy; `a_redacted_cone_carries_no_secret_literal_copy`, `an_evaluated_secret_copy_is_not_text`, `review_module_payloads_redact_a_secret_copy` (negative control I-3) |
| 3 | medium | the write-confinement relation followed only subject -> expression, so a scoped write could rewrite an outside subtree's rule expression | **fixed**: the relation is undirected at the fixpoint; `a_scoped_patch_cannot_change_an_outside_rule_expression` |
| 4 | low | a redacting cone dropped every intent/constraint while `annotations` hid only tainted ones: the two answers disagreed | **fixed**: only rules on tainted nodes are dropped; `a_redacting_cone_keeps_rules_outside_the_secret_cone` |
| 5 | low | an encode failure on the second patch reported `active/lower` (an evaluator class) | **fixed**: `Error::Payload(code)` (no reachable trigger through the public API; an error-code correction) |
| 6 | low | a redacting, unscoped `why`/`impact` still emitted `Str[7]` labels for pathless nodes: an arena-position oracle | **fixed**: pathless labels are dropped under redaction too; `a_redacting_answer_never_names_a_node_index` |
| 7 | low | the `install` doc claimed a lazy hash while `install` seeds it | **fixed**: the doc matches the code |

Residuals recorded: a default-minted capability has `redact = false`, so the
oracle mitigations are opt-in; the `blake3:` prefix rule is textual; a binding
on a read-closure node still refuses a scoped read (fail-closed); the wall
ceiling is checked after the work.

Gate: 87 suites / 833 tests all-features, clippy/fmt/doc clean; negative
controls 9/9; hardening status 13 invariants / 145 checks.

### R-08 tools and MCP - 2026-11-03 (round 5)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `3ce5069`. All six round-4
fixes held; three highs/mediums and three lows, all closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `get`/`post` silently dropped a `Text` argument (only `request` consumes one) | **fixed**: refused; `a_text_argument_on_a_named_method_is_refused` |
| 2 | medium | MCP accepted a `Value::Module` (and a module nested in a body) and sent `{"$module_bytes":N}`: the peer acted on a request nobody made | **fixed**: a recursive check refuses it in both adapters; `a_module_argument_is_not_sent` |
| 3 | medium | write faults were labelled `http/read:`, so a retry policy would retry a half-sent POST | **fixed**: `map_http_write` (`http/write:`), documented direction; no reachable trigger on this host (a closed peer surfaces on the read), so the mapping is inspected rather than test-forced |
| 4 | low | a bodyless POST sent the four bytes `null` under `content-length: 4` | **fixed**: no body object means an empty body; `a_bodyless_post_sends_no_body` |
| 5 | low | a send under a spent deadline reported `Timeout` but still reached the wire (the frame was enqueued first) | **fixed**: the deadline is checked before enqueueing, and the request path refuses a spent deadline without poisoning; `a_spent_deadline_does_not_write_a_line` |
| 6 | low | a NUL in an exact-matched process argument (or an env entry) panicked `Command` | **fixed**: refused as `rpc/invalid-argument`; `a_nul_argument_is_refused` |

Gate: as above (the same commit).

### R-07 domain operations - 2026-11-02 (round 8)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `8481c61`. Two highs and two
mediums, plus three lows; all closed except the two it called residuals.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the Kahn taint pass counted a node's children including duplicates while the dependents index is deduplicated, so a node naming one child twice never reached zero and the taint stopped below it: a redacting `annotations` returned the intent above it in clear | **fixed**: unique children; `a_doubly_referenced_secret_taints_everything_above_it` |
| 2 | high | a redacting `provenance` answer dropped `parent` but still served `Hash` entries (the patch `Input` lineage), the same content-address oracle | **fixed**: under redaction every `blake3:` value is dropped; `a_redacting_provenance_answer_serves_no_hash` |
| 3 | medium | a redacting `subgraph`/`patch` cone kept intent and constraint-source text and bindings on tainted nodes, while `annotations` hid them: the two answers disagreed | **fixed**: `redact_cone_metadata` keeps only `@ai_immutable` and drops a binding that names a tainted node; `a_redacting_cone_carries_no_annotation_text` |
| 4 | medium | the write-confinement check was weaker than the read check: it followed a constraint expression but not the expression's dependencies, and accepted an `Env` expression | **fixed**: both checks run the same closure and refuse an environment node |
| 5 | low | `active_value_too_deep` pushed every child of a container before the first check | **fixed**: one frame per open container, like the value walks |
| 6 | low | `nodes_within_scope` treated every pathless node as inside while `scope_closure` treats it as outside: a scoped `dependents`/`impact` dropped a floating node and presented a filtered answer as complete | **fixed**: only the module root is pathless-inside |
| 7 | low | the evaluate wall check ran before the value conversion, so the conversion itself was unmeasured | **fixed**: the check runs after the conversion |

Gate: 806 tests all-features, 0 failed; clippy/fmt/doc clean; negative controls
9/9.

### R-08 tools and MCP - 2026-11-02 (round 4)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `8481c61`. The round-3 fixes
hold; three mediums and three lows, all closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | a write that hit its socket timeout was reported as `http/write:…` (a provider fault) while a read timeout is `rpc/timeout` | **fixed**: write errors go through the same mapping; `a_stalled_http_reader_reports_the_ceiling` |
| 2 | medium | a connect timeout was discarded and every connect failure collapsed to a provider fault | **fixed**: the last error decides, and a timeout is `rpc/timeout` |
| 3 | medium | MCP dropped `Cap`/`Promise` arguments and HTTP dropped any shape that was not a method text, a path or a body map: the peer acted on a subset | **fixed**: both refuse the request; `an_undeliverable_argument_is_refused` |
| 4 | low | the base check admitted bytes above ASCII | **fixed**: the base must be printable ASCII like the path; `a_non_ascii_base_is_refused` |
| 5 | low | a zero wall grant became one millisecond, and the process adapter spawned the child before checking | **fixed**: a zero grant is `rpc/budget-exceeded` before any work or spawn; `a_zero_wall_grant_is_a_budget_refusal` |
| 6 | low | a framing fault on receive did not poison the session until the next mismatch | **fixed**: any non-timeout receive error poisons at once |

Gate: 806 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-07 domain operations - 2026-11-02 (round 6, closing round 5's verification)

The round-5 verification confirmed the read-side binding fix (and proved it
fails without it) but found the write side untouched and three smaller issues.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| V1 | high | `impact` checked the *dependency* closure and answered the *dependent* closure, so a Ref alias outside the scope appeared in the answer | **fixed**: the affected set (node + dependents) is checked with the resolve-back rule; `a_scoped_impact_cannot_answer_through_a_reference_alias` |
| V2 | high | `effects_within_scope` used prefix matching without resolve-back and treated a pathless node as in scope, so a scoped write escaped while the reads refused | **fixed**: the same `in_scope_path`, and the only pathless node allowed is the module root (every other pathless node is a floating value or an expression the cone can carry) |
| V3 | medium | `keep_scoped_bindings` computed the cone's inside set with the pre-remap id | **fixed**: `restrict` already copies only in-cone bindings, so only the name is filtered |
| V4 | low | a scoped cone stripped `@ai_immutable`, handing the recipient a subtree it may rewrite | **fixed**: `keep_immutable_annotations` keeps the guards (they carry no free text); `a_scoped_cone_keeps_the_immutability_guard` |
| V5 | low | any binding on a read-closure node makes scoped reads refuse | **accepted residual**: fail-closed, and the operator controls bindings |

Verified clean: a path resolution that does not round-trip is refused, a scoped
patch reply carries neither provenance nor intent text, and a Ref alias in the
dependency direction refuses.

Gate: `scripts/local_gate.sh` green; all-features 719.

### R-07 domain operations - 2026-11-02 (round 5, closing round 4's verification)

The round-4 verification confirmed T1-T8 and found one high: `value_paths`
reports a *binding* name for a bound node, so an outside value bound as
`app.sneaky` passed the scope check and a scoped `evaluate`/`why`/`subgraph`
returned it.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| U1 | high | a binding laundered an outside node into the scope: the reported path looked in-scope but did not resolve back to the node | **fixed**: `in_scope_path` requires the path to resolve to the same node, and a scoped cone drops bindings whose name or value is outside it; `a_binding_cannot_launder_an_outside_node_into_the_scope` |

Verified in the same pass: promise `Path` arguments are re-checked at dispatch,
an interpolated secret is fail-closed, an unscoped subgraph keeps annotations and
provenance, and the scoped patch cone strips them.

Gate: `scripts/local_gate.sh` green; all-features 717.

### R-07 domain operations - 2026-11-02 (round 4, closing round 3's verification)

The round-3 verification found five of nine dispositions partial and eight
demonstrable escapes. All are closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| T1 | high | a **pathless** value node in the closure was treated as in scope (`None => false`), so a floating `Str` referenced by a constraint leaked | **fixed**: a pathless node in a closure is out of scope (`None => true`); labels still drop them; `a_scoped_answer_cannot_reach_a_pathless_expression` |
| T2 | high | the constraint-chain fixpoint was capped at 8 iterations, so a 10-deep chain was accepted | **fixed**: the loop runs until the closure stops growing; `a_deep_constraint_chain_is_followed` |
| T3 | high | annotation `intent`/`source` text is copied by `restrict`, so an allowed cone carried an outside source marker | **fixed**: a scoped `subgraph`/`patch` cone clears annotations as well as provenance; `a_scoped_cone_reply_carries_no_annotation_text` |
| T4 | medium | `why`/`impact` still emitted `Kind[index]` labels under a scope | **fixed**: both use `scoped_labels`; `scoped_labels_never_name_a_node_index` |
| T5 | medium | the scoped `patch` reply carried the module's provenance and parent hash | **fixed**: the patch cone clears provenance and annotations under a scope; `a_scoped_patch_reply_carries_no_provenance` |
| T6 | medium | `patch` had no wall ceiling | **fixed**: `check_wall_budget` before the reply |
| T7 | low | `impact` used the dependency closure check, missing `Env` and constraint expressions | **fixed**: `impact` uses `scope_closure` |
| T8 | low | `immutable_node` built adjacency twice per patch | **fixed**: one pair per call |

Verified: an interpolated node, a parameter default holding `Env`, a two-deep
constraint chain, and an unscoped `subgraph` (provenance kept) behave correctly.

Residual: `value_paths` returns the binding name for a bound node, so an outside
alias makes an in-scope read refuse (fail-closed, installer-controlled).

Gate: `scripts/local_gate.sh` green; all-features 716.

### R-07 domain operations - 2026-11-02 (round 3, fix verification)

Reviewer: Muse at `d03413c`. It verified N1-N8 (N4 and N6 fixed; N1, N2, N3, N5,
N7 partial) and demonstrated nine more findings with black-box probes.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| S1 | high | the constraint-expression of an annotation whose subject is in the cone was not in the read closure, so a scoped `evaluate`/`subgraph` carried it | **fixed**: `scope_closure` unions constraint expressions (to a fixpoint) into the closure; `a_scoped_answer_cannot_reach_a_constraint_expression_outside_the_scope` |
| S2 | high | a constraint's free-text `source` travelled in cone bytes | **fixed with S5**: a scoped cone reply carries values only |
| S3 | high | an `Env` node in the cone read the host environment under a scope (no path, so no closure could see it) | **fixed**: `scope_closure` refuses a closure containing `Env`; `a_scoped_evaluate_refuses_a_host_environment_read` |
| S4 | medium | a pathless root passed the scope check and `labels_for` emitted `Kind[index]` node-id labels | **fixed**: `scoped_labels` drops pathless labels under a scope (the root of every walk is pathless, so refusing would make the queries unusable) |
| S5 | medium | `restrict` copies provenance wholesale, so an allowed leaf `subgraph` returned the producer and parent hash | **fixed**: a scoped `subgraph` clears provenance; `a_scoped_subgraph_carries_no_provenance` |
| S6 | high | an ancestor patch deleted a marked subtree because the immutability check walked dependencies only | **fixed**: `immutable_node` walks both directions (a marked node above or below the target refuses); `an_ancestor_patch_cannot_delete_an_immutable_subtree` |
| S7 | low | `value_paths` returns the binding name for a bound node, so an outside alias made an in-scope read refuse | **accepted residual**: fail-closed and installer-controlled; recorded |
| S8 | medium | `evaluate` had no node ceiling (the engine reported `rpc/domain`) and `patch` had no wall check | **fixed**: `check_node_budget` in `evaluate` (`rpc/budget-exceeded`, integration test updated), `check_wall_budget` in `patch`; `evaluate_respects_the_node_budget` |
| S9 | medium | `immutable_node` rebuilt adjacency per mark on a method with no wall check | **fixed**: one dependency walk and one dependent walk per patch |

Verified clean: promise/channel/promise-path smuggling (the kernel re-checks
scope and shape at dispatch), Ref and interpolated chains, patch rollback, and
no panic or unbounded loop in `restrict`.

Gate: `scripts/local_gate.sh` green; all-features 711.

### R-07 domain operations - 2026-11-02 (round 2, confirmation)

Reviewer: Muse (the DeepSeek proxy was returning 403), at `07968a0`. It verified
D-1..D-12 and found four partial dispositions plus eight new defects, one of them
critical: the scope check covered the *argument*, not the answer. Tests:
`tests/domain_confinement_tests.rs` (6), all driving a shared-DAG module built
directly so the hostile shape is exact.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| N1 | critical | a scoped `evaluate`/`why`/`subgraph` followed references out of the scope: `app.x = Ref(ops.secret)` returned `OUTSIDE-CANARY` and the `subgraph` bytes carried it | **fixed**: each of the three checks the transitive dependency closure against the scope and refuses with `rpc/path-not-granted`; `a_scoped_evaluate_cannot_follow_a_reference_outside_the_scope`, `a_scoped_why_cannot_name_an_outside_dependency` |
| N2 | high | scoped `impact`/`dependents`/`dependencies` named labels outside the scope through a shared node | **fixed**: the dependent/dependency sets are checked against the scope; `a_scoped_impact_cannot_name_an_outside_dependent` |
| N3 | high | `stats`/`annotations`/`provenance`/`content_hash` answered globally under a scope, with the path argument ignored (counts and a content hash are oracles over the hidden part) | **fixed**: all four are refused under a scope (`rpc/path-not-granted`); `a_scoped_capability_cannot_read_global_metadata` |
| N4 | high | `subgraph` and `content_hash` ignored `max_nodes` (500 nodes under a ceiling of 8 succeeded) | **fixed**: both run `check_node_budget` and `check_wall_budget`; `subgraph_and_content_hash_respect_the_node_budget` |
| N5 | high | `@ai_immutable` was checked per path, so a shared node rewritten through an alias outside the marked subtree succeeded | **fixed**: `immutable_node` refuses a target that is, or is a dependency of, an immutable node; `an_alias_cannot_bypass_ai_immutable` |
| N6 | medium | the scoped-write effect closure ignored constraint expressions and binding-only dependents | **fixed**: constraint expressions watched by an affected node join the closure, and a binding that names an affected node must be in scope |
| N7 | medium | only four methods had a wall check; `subgraph`, `stats`, `annotations`, `provenance` and `content_hash` had none | **fixed**: every arm checks the wall ceiling |
| N8 | low | `calls` advanced before `serve`, so a refusal after the slot was taken counted as served | **fixed**: it advances only on an answered call; `refused_call_does_not_advance_calls` (round 1) now holds |

Verification notes: `evaluate` of an in-scope value with no reference still
answers; a `subgraph` of a leaf with no outside edge answers; the scope refusal
is fail-closed for a subtree that references outside data.

Gate: `scripts/local_gate.sh` green; all-features 706.

### R-09 transports - 2026-11-02 (round 7, closing round 6's verification)

The round-6 verification (Muse) confirmed M4 and the HTTP/2 half of M6, and
found four issues in the round-6 code and its tests: the drip test never reached
the total deadline, the response-write and client-read budgets were per piece,
and the bridge counted a failed response as served. All four are fixed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| D1 | medium | the drip test's budget was exceeded by its own prefix, so the stream died on a 429 before the total body deadline could fire; the test passed without the fix | **fixed**: the budget leaves room for the prefix and the drips, a second stream is issued every 100 ms so the accept-inactivity deadline cannot end the connection first, and the client drips until the server resets. Verified by mutation: with the total deadline removed the test fails after 200 rounds (23.7 s); restored, it passes in ~2.5 s |
| D2 | medium | `respond_body` re-armed the deadline per 16 KiB piece, so a peer granting one byte per window held the task for pieces × deadline | **fixed**: one total budget (8 × the window, capped at 30 s) wraps the per-piece wait |
| D3 | medium | the HTTP/2 client's read bound was per chunk, so a compliant drip with no caller deadline was unbounded | **fixed**: a total read budget (8 × the inactivity bound, capped at 30 s) |
| D4 | low | the bridge returned served = 1 after a failed response write | **fixed**: it returns 1 only when the response was written |

The same pass audited QUIC and TCP as **CLEAN** (no demonstrable defect in
`read_frame_body`, `reply`, `send` or `recv`), with residuals recorded: 128
HTTP/2 streams can pin 30 s of transient work, `block_in_place` serialises slow
handlers, QUIC can buffer up to the flow-control window before the frame reader
sees it, and the bridge ignores a write-timeout arming failure.

### R-09 transports - 2026-11-02 (round 7b, second clean audit)

Reviewer: Muse again, at `b689025`, with a CLEAN-TWICE instruction. Verdict on
D1-D4: D2, D3 and D4 fixed in code (tests still thin, recorded below), D1's code
fixed but its test not discriminating — the connection died on accept-inactivity
before the body total could fire. Fixed by keeping a second stream active every
100 ms; the mutation check (total deadline removed) now fails after 200 rounds.
**Final hostile pass over the HTTP/2 server and client and the bridge: CLEAN.**

Recorded residuals for this section:
- `respond_status`'s early refusals have no write deadline (a zero-window peer
  could park one; sizes are tiny, so it is not demonstrable).
- the bridge's response write uses a per-syscall timeout; loopback absorbs it.
- the bridge client's response-head read has no wall deadline unless the caller
  sets `with_deadline`.
- the H2 client's request write is unbounded without a caller deadline.

### R-09 transports - 2026-11-02 (round 6, second reviewer: Muse)

Reviewer: the local Muse proxy (`muse-spark-1.3-contributor`, `xhigh`) — the
CommandCode proxy had begun answering HTTP 403, so this round is the second
opinion the marathon asks for. It re-checked R1-R6 and found one fix complete
(R6) and five partial, plus two new issues.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| M1 | high | the HTTP/2 body deadline was per chunk, so a drip of one byte every 200 ms inside a 300 ms window held the reservation and `serve` forever | **fixed**: a total body deadline (8 × the inactivity bound, capped at 30 s) runs with the per-chunk bound; `a_dripping_body_cannot_hold_the_http2_budget_forever` |
| M2 | high | the HTTP/2 response write was unbounded: `send_data` buffers without a reservation, so a peer with a zero window parked the task and its reservation | **fixed**: `respond_body` reserves capacity per 16 KiB piece and waits for the grant under the deadline, resetting the stream on expiry |
| M3 | medium | the HTTP/2 client's response read had no inactivity bound | **fixed**: 30 s by default, the client's own deadline when set |
| M4 | low | the bridge armed the accepted stream's socket timeout but read from its `try_clone`, which can carry a stale timeout | **fixed**: `read_head`, `read_line_before` and `read_body_by_deadline` take the `BufReader` and arm `reader.get_ref()` |
| M5 | low | `set_read_timeout`/`set_write_timeout` failures were ignored (fail-open) | **partly fixed**: the frame path treats an arming failure as a timeout; the response path keeps the previous budget rather than aborting a valid response |
| M6 | low | a response write failure was reported as a served call | **fixed** with M2: the write returns false on expiry, and `serve` counts only a completed response |

Verified in the same pass: `call_many` order holds under a reset stream (the
indexed slots make it fail-closed), and `read_line_before` re-arms on buffered
bytes because each `fill_buf` checks the clock first.

Residual risks (unchanged): a write budget sized to the read deadline can still
be tight for a 64 MiB reply on a slow link; the QUIC buffering ceiling is the
flow-control window, not `MAX_INFLIGHT_BODY`; the QUIC idle timeout is
peer-resettable.

### R-09 transports - 2026-11-02 (round 5, closing the round-4 findings)

The round-4 verification named two highs and four smaller issues; all six are
fixed here, each with a test that drives the hostile shape rather than a code
path.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| R1 | high | an HTTP/2 stream that sent a byte and never ended its body was read with no deadline, pinning its reservation for the life of the process and keeping `serve` from joining (measured: one stalled byte made a valid call on another connection answer 429, and `serve` was still running past a 300 ms deadline) | **fixed**: each `body.data()` await is bounded by the connection deadline as an *inactivity* bound, answering 408 so the `Reservation` drops and the task ends; `a_stalled_stream_releases_the_budget_and_the_connection` |
| R2 | high | `read_until` loops `fill_buf` inside one call, so a single head line without a newline held the serial bridge past its deadline (measured 5.87 s against 2 s) | **fixed**: `read_line_before` re-arms the deadline before every `fill_buf`; the test now drips one line and starts its clock before the drip |
| R3 | medium | the response used whatever remained of the read deadline; a body landing at the edge left milliseconds and the write failure was discarded | **fixed**: the response gets a fresh `CONNECTION_WAIT` write budget |
| R4 | low | `read_frame_before`'s doc claimed the deadline ends a drip, but a blocked read cannot be interrupted without a socket timeout | **fixed**: `TcpTransport::recv` re-arms the socket timeout to the time left before every read, and the doc says a socket caller must do the same |
| R5 | low | no per-frame write deadline: a reader that stops holds a serial server for bytes × timeout | **fixed**: `send` arms a fresh write budget per frame |
| R6 | low | `call_many` detached its tasks on a timeout (dropped `JoinHandle`s keep running with a sender clone) | **fixed**: a `JoinSet` aborts them, and results are re-ordered by index so the documented request order holds |

Verified in the same pass: Q1 (4096 idle streams parked in 603 ms, a real call
answered in 1.6 ms) and Q3 (a 4 KiB drip ended the connection at 2.105 s against
a 2 s deadline) are closed with measurements.

Residual risks (recorded): quinn buffers up to the flow-control window before the
frame reader sees it, so the real QUIC buffering ceiling is 256 connections ×
8 MiB; the QUIC idle timeout is peer-resettable; the bridge answers 4xx with
unread body bytes.

### R-09 transports - 2026-11-02 (round 4, fix verification at `1ce655a`)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`. It re-read every
path named in round 3, re-ran the transport suites, and drove ten temporary
probes (removed) against real sockets. Verdict: Q1 and Q3 are closed **with a
measurement**; Q2, Q4, Q9 and Q12 are partial; the other seven hold.

| # | Sev | Claim checked | Verdict |
|---|-----|---------------|---------|
| Q1 | high | budget follows arrived bytes | **fixed, measured**: 4096 idle streams that sent a 4-byte header each (16 connections, 64 MiB announced) were parked in 603 ms and a real call on a 17th connection was answered in **1.6 ms**. The named test (`quic_round2_tests.rs:20`, four streams) cannot fail without the fix: four streams reserve four 64 KiB steps, 256 KiB of a 256 MiB budget |
| Q2 | high | head drip bounded by the connection deadline | **partial**: `read_head` re-arms per *line* (`connect.rs:393`), but `read_until` (`connect.rs:403`) loops over `fill_buf` inside one line with the timeout armed once. Measured: **5.87 s** of hold for one 40-byte line at 100 ms/byte against `CONNECTION_WAIT` 2 s; the ceiling is `MAX_HEAD` 16 KiB × the interval (≈8.6 h at 1.9 s/byte) |
| Q3 | high | one wall deadline per TCP frame | **fixed, measured**: a 4 KiB body dripped at 300 ms/byte with a 2 s `with_timeout` ended the connection at **2.105 s** (served 0); the timeout did not poison the next connection |
| Q4 | medium | HTTP/2 deadline is inactivity-only | **partial**: it now wraps `connection.accept()` only, but on expiry the loop breaks, stops polling the `Connection`, and the in-flight response is lost. Measured: an 800 ms handler under a 200 ms deadline → the client got `response: stream closed because of a broken pipe` |
| Q5 | medium | every QUIC reply is bounded | fixed in code (all six early paths call `reply`); no test stalls a receive window |
| Q6 | medium | `call_many` honours the deadline | fixed in code; untested |
| Q7 | medium | panic isolation | fixed: CLI loops + QUIC/HTTP/2 `catch_unwind`; `peer.rs` is covered by `serve_connection`'s own catch. No poisoned kernel: `DispatchGuard` restores `dispatching` and the provider during `resume_unwind`, after every job is settled |
| Q8 | medium | no anonymous off-host QUIC bind | fixed in code; **untested** — the refusal string only exists in `src` |
| Q9 | low | socket-option failure drops one connection | **partial**: the CLI (`main.rs:738`) and the bridge recover, but `src/bin/peer.rs:158` still ends the process with `?` |
| Q10 | low | only documented refusal classes | fixed; `the_client_preserves_a_peer_refusal_code` drives it |
| Q11 | low | tail window documented | fixed (`wire.md:345`) |
| Q12 | low | budget doc says server-wide | **partial**: `with_inflight_budget` was reworded, `MAX_INFLIGHT_BODY` (`http2.rs:80`) still says "one connection"; no test exercises a shared budget across connections |
| Q13 | low | exact reservation | fixed: 64 KiB steps keep `Vec` capacity exact |

Remaining defects (round 4):

| # | Sev | Finding | File:line | Missing test |
|---|-----|---------|-----------|--------------|
| R1 | high | an HTTP/2 stream that sends one byte and never ends its body is never read with a deadline, so its `Reservation` is held for the life of the process and `serve` can never join it. Measured with `with_inflight_budget(1)`: one stalled 1-byte stream made a valid call **on another connection** answer `rpc/wire` (429) immediately and again 2 s later; `serve()` had not returned after 3 s against a 300 ms deadline. At the default budget two 64 MiB streams on one connection pin the whole 128 MiB server-wide, permanently | `http2.rs:372`, `:311`, `:246` | `a_stalled_stream_releases_the_budget_and_the_connection` |
| R2 | high | the bridge head drip of Q2, one line, no newline (above) | `connect.rs:393`, `:403` | a single-line drip with the clock started *before* the drip |
| R3 | medium | the bridge arms its response write with whatever remained of the *read* deadline (`arm_deadline` inside the body loop); a body that lands at 1.99 s of a 2 s deadline leaves milliseconds to write a large 200, and the failure is discarded (`let _ =`) | `connect.rs:314`, `:369` | a body delivered near the deadline still returns a complete 200 |
| R4 | low | `read_frame_before`'s doc claims the deadline ends a drip; it only observes the deadline *between* reads. Measured: a 200 ms deadline with no socket timeout was still blocked after 2 s. In-tree callers co-arm the socket timeout, so the bound holds, but the API contract is false for a library caller | `mod.rs:403` | a deadline with no socket timeout fails closed |
| R5 | low | the write side has no per-frame deadline (`write_vectored` loops under a per-call timeout). On this host an idle reader accepted a 62 MiB frame in 705 ms (loopback buffers it), so no stall was demonstrable; on a host with small loopback buffers the hold is `bytes × write_timeout` | `mod.rs:464` | a slow reader cannot keep a serial server past N × the deadline |
| R6 | low | `call_many` detaches its per-request tasks when the deadline fires (dropped `JoinHandle`s keep running with a sender clone) | `http2.rs:633`, `:652` | the task set is empty after a timed-out `call_many` |

Verified clean this round: h2 reclaims the connection window when a stream that
was refused before its body is reset (40 × 64 KiB refusals, then a valid call on
the same connection); the QUIC reservation is proportional to delivered bytes
and released on every path; no second logical message on any transport.

Residual risks (updated): quinn buffers received data up to the flow-control
window before `read_frame_before` sees it, so the real QUIC ceiling is
`MAX_CONNECTIONS` 256 × `CONNECTION_RECEIVE_WINDOW` 8 MiB = 2 GiB and not
`MAX_INFLIGHT_BODY` 256 MiB (`quic.rs:468` vs `:997`); reaching it costs the peer
one byte of traffic per byte buffered. The QUIC idle timeout remains
peer-resettable, the bridge answers 4xx with unread body bytes, and the shm
straddle/truncated branches remain fuzzer-only.

### R-09 transports - 2026-11-02 (round 3, fix verification)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `4b18153`.
It re-ran the transport suites and measured every round-2 claim with its own
probes (temporary, removed). Verdict: eight of sixteen partial or unexercised.
Three were highs that reproduce the same amplifier one step over.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| Q1 | high | the stepwise QUIC reservation was taken **before** the read, so 4096 streams that sent only a 4-byte header held the whole 256 MiB budget and denied every peer (measured with 4100 streams, ~16 KiB on the wire) | **fixed**: `read_chunk` + reserve only the bytes that arrived; one whole-frame deadline, exact `try_reserve` so a body is not double-counted; `an_idle_announcement_does_not_consume_the_quic_body_budget` |
| Q2 | high | the bridge armed its wall deadline once; `read_head`'s per-line reads got a fresh socket timeout, so a head drip held the serial accept slot (measured 18.5 s against a 2 s deadline) | **fixed**: `read_head` re-arms the connection deadline before every line and answers 408 on expiry; `a_dripping_head_cannot_stretch_the_bridge_connection` |
| Q3 | high | the same per-read timeout on the framed TCP transport let a body drip keep `read_frame` alive forever, so the serial peer never accepted again | **fixed**: `read_frame_before` checks one wall deadline between reads, `TcpTransport` carries the deadline from `with_timeout`, and `recv` applies it; `a_dripping_client_does_not_block_the_peer`, `a_timed_out_frame_does_not_poison_the_next_connection` |
| Q4 | medium | `with_connection_deadline` was a total connection lifetime, so an active HTTP/2 agent was cut off mid-session (the CLI lost every connection after 10 s) | **fixed**: the deadline now wraps `connection.accept()` only, so it is an inactivity bound |
| Q5 | medium | the six early-error QUIC replies were written without a deadline, so a peer with a one-byte receive window parked the task and held its permit | **fixed**: every reply goes through `reply()`, which bounds the write and resets the stream |
| Q6 | medium | `call_many` ignored the client deadline | **fixed**: the join loop runs under it |
| Q7 | medium | a provider panic exited the CLI peer loops, and QUIC/HTTP/2 answered a bare reset | **fixed**: `catch_unwind` around the handler in QUIC and HTTP/2 (answering `rpc/provider`), and `dispatch_guarded` in all four CLI kernel loops |
| Q8 | medium | an unauthenticated QUIC listener could bind a non-loopback address | **fixed**: `start_with_identity` refuses `client_ca: None` on a non-loopback bind |
| Q9 | low | a socket-option failure on an accepted socket ended the server | **fixed**: the option is best-effort and the connection is dropped |
| Q10 | low | `refusal()` accepted any lowercase `rpc/*` token, so a peer could invent a class | **fixed**: only `ERROR_CODES` survive; everything else is `rpc/provider` |
| Q11 | low | the QUIC trailing-byte window is a timing property | **documented** in `wire.md` §6 (one stream carries one frame; a byte after 250 ms is discarded, and a peer that needs the guarantee closes the stream) |
| Q12 | low | the HTTP/2 budget doc and test name still said "per connection" | **fixed**: "across every connection of this `serve` call", test renamed |
| Q13 | low | a growing body could double its capacity transiently | **fixed** by Q1's exact `try_reserve` per delivered chunk |

Verified clean by the reviewer: no leak of the HTTP/2 reservation on any path
(including abort), no poisoned state after a caught panic (the kernel's
`DispatchGuard` restores), and no second logical message can be smuggled.

Residual risks (recorded): the QUIC idle timeout is peer-resettable, so the slot
count is the connection cap; the bridge answers 4xx and closes with unread body
bytes; `MAX_INFLIGHT_BODY`'s doc math describes an attack the per-stream cap
already prevents.

### R-09 transports - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `05ec397`.
It re-ran the seven transport suites (43 tests) and drove its own probes against
real sockets. Round 1: 15 fixed, 7 partial, 0 not fixed. New: two highs, eight
mediums, six lows. Tests: `tests/transport_round2_tests.rs` (6), plus QUIC cases
in `transport_hardening_tests` and the peer/CLI accept paths.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| N1 | high | the QUIC global body budget was charged from the **announced** length, so four idle streams that sent a 4-byte header reserved 256 MiB and answered `rpc/backpressure` to every peer (proven) | **fixed**: `BodyBudget` reserves in 64 KiB steps as bytes arrive and releases when the body is dropped; `an_idle_announcement_does_not_consume_the_quic_body_budget` |
| N2 | high | `active-rpc-peer` had no socket deadline and accepted serially: one silent client blocked every later peer forever (proven) | **fixed**: `TcpTransport::with_timeout` on the accepted socket with a 5 s deadline, and bounded accept retries; `a_silent_client_does_not_block_the_peer` |
| N3 | high | the Connect bridge set a per-read timeout, so a body drip held its only accept slot indefinitely (proven) | **fixed**: one wall deadline per connection, recomputed into the socket timeout before every read (`arm_deadline`, `read_body_by_deadline`), 408 on expiry; `a_dripping_body_cannot_stretch_the_bridge_connection` |
| N4 | high | the QUIC accept loop awaited a full slot table for `HANDSHAKE_WAIT`, so ~256 cheap connections could stall the listener | **fixed**: `try_acquire_owned` and drop the incoming when the table is full |
| N5 | medium | a complete QUIC frame was not answered until the peer FINished its send half (proven), and the tail check was unreachable | **fixed**: read exactly the announced length (`read_frame_body`) and probe for trailing bytes with `read_chunk`, not `read_to_end`; `a_complete_frame_without_fin_is_answered` |
| N6 | medium | QUIC response writes had no deadline: a peer that withholds receive credit parked the task forever | **fixed**: the write and `finish` run under `STREAM_WAIT`, then the stream is reset |
| N7 | medium | the mutual-TLS client hardcoded SNI `localhost`, so a deployment certificate for `rpc.internal` could never verify | **fixed**: `connect_mutual_tls_with_name`; the old entry point delegates with `localhost` |
| N8 | medium | the HTTP/2 body budget was per connection, so N connections pinned N × 128 MiB | **fixed**: one `Arc<AtomicUsize>` budget is shared by every connection of a `serve` call |
| N9 | medium | one accept error killed the bridge, the CLI and the peer, and the HTTP/2 server spun 64 times with no backoff before exiting | **fixed**: bounded retry with backoff everywhere; `Interrupted`/`ConnectionAborted` are transient, a persistent failure backs off before giving up |
| N10 | medium | a handler panic was fatal on the synchronous transports (the kernel runs on the serving thread) | **fixed**: `catch_unwind` around the handler on TCP/shm and in the bridge, answered as `rpc/provider`, and the connection continues; `a_panicking_handler_does_not_kill_the_connection` |
| N11 | low | `content-length: +N` was accepted | **fixed**: 1..=20 ASCII digits after trimming; `a_signed_content_length_is_refused` |
| N12 | low | a strict bridge still read up to 64 MiB before refusing | **fixed**: the body ceiling is `min(MAX_BODY, limits.max_bytes)`; `a_strict_bridge_answers_413_without_reading_the_body` |
| N13 | low | QUIC reported a stall as `rpc/wire` | **fixed**: a read timeout is `rpc/transport`; `TooLong`/truncation stay `rpc/wire` |
| N14 | low | the three non-TCP clients had no internal deadline | **fixed**: `with_deadline` on `ConnectClient`, `Http2Client` and `QuicClient` wraps one request (the CLI's helper thread is no longer the only bound) |
| N15 | low | bare-LF and EOF-terminated heads were accepted | **fixed**: CRLF is required, a bare CR in a field is refused, and EOF before the blank line is an incomplete head; `a_bare_lf_head_is_refused`, `a_head_that_ends_at_eof_is_refused` |
| N16 | low | a panic while holding the shared-memory lock poisoned the segment permanently | **fixed**: every lock recovers the guard with `PoisonError::into_inner` |

Also verified by the reviewer and unchanged: no malformed frame, stream, header
or ring state can kill or panic a server; no transport can smuggle a second
logical message in one frame.

Residual risks (recorded): HTTP/2 and Connect carry no identity by design, the
QUIC idle timeout is peer-resettable so slot count is the real connection cap,
and the shm straddle/truncated branches remain fuzzer-only.

### R-10 bulk transfer - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `6cc077a`.
The frame codecs held: the reviewer found no panic, no unbounded allocation and
no plan that lies about its own hashes. The two defects were in the provider that
gives the format a consumer.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| B1 | medium | a retransmitted `plan` frame (ordinary on a flaky link) built a fresh receiver, discarding every chunk the caller had already sent and paid for | **fixed**: the same root keeps the existing receiver and reports its missing count; a different root is still refused; `a_retried_plan_keeps_the_received_chunks` |
| B2 | medium | `finish` took the transfer before validating: a wrong marker or an early `finish` destroyed the received chunks | **fixed**: the marker and completeness are checked against a borrowed transfer, and only a successful finish consumes it; `a_refused_finish_keeps_the_transfer` |

Gate: `scripts/local_gate.sh` green; bulk suites 12 + 16.

### R-11 identity - 2026-11-02 (round 3, fix verification)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `6cc077a`.
Verified N1, N2, N4, N5 fixed; N3, N6, N7 partial; seven new findings, one high.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | `src/bin/peer.rs` admitted only the module arm: `hello`, `ping`, `pipeline` and `sequential` ran before any policy check, so an off-host caller could spend the peer's capability and the shared lane budget (5 000 `pipeline` requests exhausted a 10 000-call lane) | **fixed**: admission runs once at the top of `dispatch`, before every arm, and the module arm uses the admitted identity; the loopback flag now comes from `stream.peer_addr()`, not the listener, so a wildcard bind still serves a local client and still refuses a remote one; `a_wildcard_peer_still_serves_a_local_client` |
| F2 | medium | an **expired** descendant still blocked `introduce_to` (only revoked ones were skipped), and expiry is monotonic, so a dead child was permanent denial of service | **fixed**: expired records are skipped too; `an_expired_descendant_does_not_block_introduction` |
| F3 | low | the idempotency cache re-checked the live binding but returned a promise whose job was stamped for the *first* caller, so another peer's replay failed at dispatch with a confusing `rpc/identity` | **fixed**: the cache stores the claiming fingerprint and a replay from another peer is refused at the hit; `an_idempotency_key_belongs_to_the_peer_that_claimed_it` |
| F4 | low | truncating the escaped subject could end mid-escape (`\u{1b}` minus its last digit), leaving a dangling backslash | **fixed**: the escaped form is built one character's escape at a time and stops before the budget |
| F5 | low | any *non-empty* placeholder certificate (an exporter string, a proxy header, a config value) still yields one shared, bindable identity | **accepted and documented**: the constructor says to pass only the authenticated DER and names the shared-principal hazard; a `VerifiedCertificate` witness type is a public API change to schedule with ADR-0011 |
| F6 | low | `admit(Some(anonymous), loopback=true)` under `local()` was labelled `Unauthenticated` while `None` was labelled `Loopback` | **fixed**: an explicit anonymous identity is normalised to none before the match, so one label follows the connection |
| F7 | low | ADR-0011 said a rebind is `rpc/attenuation-escalation`; the code and the tests say `rpc/identity` | **fixed**: the ADR names `rpc/identity` for a rebind and keeps the escalation class for an attenuation-narrowing failure |

Also verified clean: no second `Job` construction site, so the stamped identity
cannot be lost on a requeue; every dispatch funnels through phase 1; the
fingerprint reaches no event, receipt or envelope except the documented public
label in `cap.introduced`.

### R-11 identity - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `ea3f658`.
It re-checked the eight round-1 dispositions (six fixed, two partial) and then
reviewed the module and every enforcement site. Tests:
`tests/identity_round2_tests.rs` (8), `tests/identity_tests.rs` (+1).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| N1 | medium | `from_certificate(&[])` produced a `MutualTls`, bindable identity, so every caller that passed an empty exporter, proxy header or config string shared one wildcard fingerprint | **fixed**: empty evidence is `anonymous()`; the empty-certificate digest is refused by `bindable` as a second layer; `an_empty_certificate_is_not_a_bindable_identity` |
| N2 | medium | the binding was checked at queue time only, so a call queued anonymously on an unbound capability ran after the operator introduced it to someone else | **fixed**: `Job` stamps the presented fingerprint and dispatch phase 1 re-checks it; `a_queued_call_does_not_survive_a_later_binding` and `a_queued_call_from_the_bound_peer_still_runs` |
| N3 | low | the escaped subject could reach six times `MAX_SUBJECT_BYTES` (3072 bytes for 512 escapes), so the bound in the doc was false | **fixed**: the escaped form is bounded again at a character boundary; `a_subject_stays_bounded_when_every_character_escapes` |
| N4 | low | `IdentityPolicy::local()` labelled a loopback caller `Anonymous`/`Unauthenticated`, because the loopback arm also required `require_identity` | **fixed**: `loopback && trust_loopback` labels first; `local_policy_labels_a_loopback_peer_as_loopback` |
| N5 | low | `is_attenuation_of` reports true for a child that drops a bound parent's binding (it models `attenuate`'s merge) | **documented and pinned**: the predicate models the operation, a validator must merge before minting; `a_child_that_omits_a_binding_inherits_it` |
| N6 | low | a revoked descendant bound to another peer blocked `introduce_to` forever | **fixed**: revoked records are skipped in the subtree validation; `a_revoked_descendant_does_not_block_introduction` |
| N7 | medium | `IdentityPolicy::admit` had no non-test caller: the bridge and HTTP/2 dispatched with `None`, so `require_identity` gated nothing | **fixed**: `Agent::dispatch_envelope` admits under the policy and dispatches the admitted identity; `src/bin/peer.rs` uses it with a loopback-derived flag, so an off-host listener refuses anonymous callers; `the_dispatch_helper_admits_before_it_dispatches` |

Verified clean by the reviewer (no change): no rebinding path; a bound
capability cannot travel over a channel; the record seal covers `bound_to`; the
descriptor and the envelope carry no identity.

Residual risks (recorded): an in-process caller can still fabricate a
`PeerIdentity` (no wire path reaches it), one leaf per process means two
processes sharing a certificate share a binding, and a receipt cannot name the
audience of an unbound capability.

Gate: `scripts/local_gate.sh` green; all-features 686 passed.

### R-12 replay - 2026-11-02 (round 3, fix verification)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `08e49a5`.
Asked to verify N1-N11 one at a time and then attack the new code. It ran the
replay suites itself (14/14, 13/13, 10/10, 4/4, 17/17). Verdict: N2, N3, N4, N5,
N6, N7, N9, N10, N11 fixed; **N1 and N8 partial**, with eight new findings. All
are fixed here.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| R12-4 | medium | `reserve_op` poisoned the recorder at `MAX_OPS`, so an honest session one operation past a complete, encodable package refused with "the recorder lost events" (a wrong diagnosis for a legal ceiling) | **fixed**: the op ceiling is a refusal that leaves the recorder usable; only a lost capture poisons. `a_session_past_the_op_ceiling_is_refused_at_record_time` now asserts the session up to the ceiling packages, encodes, decodes and replays |
| R12-3 | low | `Recorder::call` never checked `MAX_STRING`, so a 1 MiB+1 method recorded, packaged and replayed but `encode` refused it | **fixed**: the same ceiling as `encode`; `a_call_method_over_the_string_ceiling_is_refused_at_record_time` |
| R12-2 | low | no record-time body budget: 20 legal mints of 64 × 64 KiB methods recorded, then `encode` refused; at the op ceiling the recorder could retain gigabytes | **fixed**: `Recorder` tracks the encoded body (header, each op, each input entry, checksum) and refuses the crossing operation; `the_recorder_refuses_a_body_over_the_package_ceiling` drives the recorder itself to the 64 MiB ceiling and asserts the retained session still encodes and decodes |
| R12-5 | low | the CLI's `--force` temp path was predictable and written with `fs::write`, which follows a planted symlink; no `sync_all`, and a failed write left the temp behind | **fixed**: `create_new` (fails on any existing path, symlink included), a pid+nanos suffix, `sync_all` before the rename, and removal on failure; `replay_dump_leaves_no_temporary_files` and (unix) `replay_dump_replaces_a_destination_symlink_not_its_target` |
| R12-1 | low | the input entries used 64-bit digests while the module's bar is 128 bits, and a call's digest was not domain-separated | **fixed**: 16 bytes everywhere, `digest_of_text` prefixes a domain; `the_input_digests_are_128_bits` |
| R12-6 | low | `encode` accepted an empty op list or a foreign header that `replay` refused | **fixed**: `encode` refuses a missing header; the round-1 test now asserts the encoder refusal, and the argument-total test builds a legal header |
| R12-7 | low (doc) | "argument wire size" was wrong: `Op::Call.arg_bytes` is the synthesized text length, and the charged wire size is the separate `call.queued` number | **fixed** in `src/replay.rs`, ADR-0018 and `docs/spec/wire.md` |
| R12-8 | low (doc) | the `revoke_subtree` doc comment had been fused onto `MAX_METHOD_EVENT_BYTES` | **fixed**: the doc is on its function again |

Also: `set_latency` now captures, so a future clock that emits an event cannot
leave it for the next operation's trace.

Gate: `scripts/local_gate.sh` green; all-features 673 passed; CLI suite 5 (6 on
unix).

### R-12 replay - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `ada2025`.
The reviewer read the round-1 entry first and re-checked every disposition, then
reviewed the module as hostile code. Verdict on round 1: five of the nine
dispositions were **partial** — F1 (the op-list comparison), F2 (the trailing
release), F3 (the method count), F4 (the argument and body ceilings) and F6 (the
header check on `replay_trace`). Tests: `tests/replay_round2_tests.rs` (14),
`cli/active-rpc-cli/tests/replay_cli_round2_tests.rs` (4), one unit test for the
introduction fingerprint, one in the observability suite for the method label.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| N1 | medium | the recorder could emit packages its own decoder refuses: `arg_bytes` per call, the 16 MiB total, the method count and the 64 MiB body were unchecked at record and at encode (and `"x".repeat(arg_bytes)` aborted on a caller-chosen size) | **fixed**: `MAX_METHODS` shared by record/encode/decode; `Recorder::call` refuses the per-call and the running total before allocating; `encode` checks both, the event length and a running body ceiling; `tests/replay_round2_tests.rs` (`a_call_over_the_arg_ceiling…`, `a_declared_argument_total…`, `a_mint_with_too_many_methods…`, `the_encoder_refuses_a_body…`, `a_recorder_package_at_the_edges_always_decodes`) |
| N2 | medium | the replayed-op comparison was tautological (`replay_trace` rebuilt the list from the package), so a doctored grant, TTL, latency or refused call's method replayed clean | **fixed**: every operation appends an `op.*` input entry (digest of the grant, TTL, parent, method digest, size, target) before its kernel events, and the tautological comparison is gone; `editing_a_grant_is_refused`, `editing_a_ttl_is_refused`, `editing_the_latency_is_refused`, `editing_a_refused_calls_method_is_refused`, `editing_a_revoked_target_is_refused`; the round-1 tests now require a `mismatch` instead of accepting either error |
| N3 | medium | the transient handle was dropped after `capture`, so an operation's own `cap.released` landed outside its trace (the round-1 test accepted `retained` *or* `released`) | **fixed**: the clone is dropped before the capture; `a_trailing_handle_release_is_in_the_trace` counts retains against releases, and the round-1 test now requires `cap.released` |
| N4 | low | a revoke that succeeded returned `rpc/replay` when the capture lost events, so a caller read a fired kill switch as a failed one | **fixed**: `capture_acted` keeps the kernel's answer and lets `package()` refuse; `a_recorder_that_lost_events_still_reports_the_kernel_outcome` |
| N5 | low | `replay_trace` (public) skipped operation 0 without the header-latency check | **fixed**: the check moved into `replay_trace`; `the_diagnostic_path_refuses_a_package_without_its_header_latency` |
| N6 | low | 32-bit discriminators where the comments claimed uniqueness (introduction fingerprint, method digest tail) | **fixed**: 128 bits in both; `two_introductions_are_distinct_in_the_trace` (unit) and `two_long_method_names_with_a_shared_prefix_stay_distinct` drive the mapping |
| N7 | low | `replay dump` accepted `--emit-cap-hex`, ignored it and never validated it | **fixed**: removed from the allowlist; `replay_dump_rejects_the_capability_flag` |
| N8 | low | `replay dump` overwrote an existing artifact silently, with `session.arrp` as the default | **fixed**: refuses a non-empty destination unless `--force` (validated as a boolean), and writes beside the destination then renames; `replay_dump_refuses_to_overwrite_without_force` |
| N9 | low | an oversize package exited 2 (usage) while a damaged one exited 1, and the CLI re-declared the 64 MiB constant | **fixed**: `read_bounded_artifact` classifies the ceiling as a refusal, and the ceiling is `active_rpc::replay::MAX_PACKAGE_BYTES`; `an_oversize_package_is_refused_not_usage` |
| N10 | low | `Recorder::call` reached `String::repeat` with a caller-supplied size | **fixed** by N1's ceiling |
| N11 | low | ADR-0018 called the tape-wrap guard unreachable; a revoke over a subtree larger than the tape reaches it | **fixed**: the ADR says so, and N4's test drives 17 000 attenuations then one revoke |

Residual risks (recorded, no action): package integrity is Blake3-only by
design, so N2 pins inputs against naive edits, not against a party that re-runs
the replay; `Recorder` has no introduce/channel/tool op, so those trace arms stay
unexercised; `docs/spec/wire.md` now documents `ARRP`.

Gate: `scripts/local_gate.sh` green (all-features 669, no-default, clippy both
sets, fmt, doc, fuzz, control-plane, CLI, negative controls 9/9, MSRV 1.88).

### R-14 wasm tools - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `cb44d07`.
Tests: `tests/wasm_round2_tests.rs` (5, feature-gated) and
`tests/wasm_hardening_tests.rs` (+1). Four of the five fail against the pre-fix
tree; the rate test pins the numbers the fixes are derived from.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `env.random` bounded one request only, so a guest loop made the host produce 37 MiB of CSPRNG in 25.6 ms under a **1 ms** wall grant | **fixed**: `HostState::random_used`/`max_random` bound the call cumulatively (`MAX_RANDOM_PER_CALL`, 64 KiB); `a_random_loop_cannot_outlive_its_wall_budget` |
| 2 | medium | instantiating a guest materialises its declared memory and wasmi charges no fuel for it (5.5 ms release for 16 MiB, 90 ms for 256 MiB under any grant) | **fixed**: the declared memory is charged at `FUEL_PER_MEMORY_KIB` (2) before the guest runs; `declared_memory_is_charged_against_the_grant` |
| 3 | medium | a trap raised in `start` was classified `wasm/instantiate`, so a caller that retries fixable modules looped forever | **fixed**: `classify_instantiation` maps a trap code to `wasm/trap`; `a_start_trap_is_wasm_trap` |
| 4 | low | the log was left in place on the instantiate/memory-error paths, and `start`'s log was dropped | **fixed**: both error paths take the store log into `self.log` |
| 5 | low | a refused `invoke` returned with the previous call's log intact, attributing one caller's bytes to another caller's failure | **fixed**: `invoke` clears the log before the first refusal; `a_refused_invoke_clears_the_log` |
| 6 | low | `FUEL_PER_MEMORY_KIB` and the entropy budget were undocumented magic numbers | **fixed**: documented against the measurements above, with the rate test |
| 7 | low | `Response::Module` documented as "a serialized Active Infinity module" although native and WASM tools return opaque bytes | **fixed**: `src/value.rs` says "a serialized Active Infinity module, or opaque provider bytes" |

Gate: `cargo test --all-features` 648 passed, 0 failed; clippy clean on both
feature sets; fmt and doc clean.

### R-13 receipts - 2026-11-02 (round 4, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `cb44d07`.
Tests: `tests/receipt_round4_tests.rs` (5). The log, the writer and the reader
are real files and real threads.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the stale-lock steal judged staleness and then renamed *whatever* was at the path, so two stealers could each move the other's fresh lock and both append | **fixed**: the steal is by identity — `stale_nonce` reads the nonce it judged, `nonce_of` checks the stolen file, and a mismatch renames it back; `an_unidentifiable_lock_is_refused_within_a_bounded_time` |
| 2 | medium | the append cache revalidated length and header start, so a replacement of exactly the same length with another chain was trusted and the append linked to a head the file does not carry | **fixed**: revalidation also compares `read_tail_head` with the cached head; `a_replacement_at_the_same_size_and_start_is_not_trusted` |
| 3 | medium | an egress refusal (budget or secret) was decided after the pre-dispatch receipt was dropped and before the settle receipt, so the call was receipted as nothing | **fixed**: the refusal is receipted as `Refused(code)` before the settle phase; `an_egress_refusal_is_receipted_as_an_egress_refusal` |
| 4 | low | `set_receipt_sequence` accepted a rewind and a start above `u64::MAX - MAX_LOG_RECORDS` | **fixed**: both refused, and the adopted gap is counted in `receipts_dropped`; `the_sequence_setter_refuses_a_rewind_and_an_impossible_start` |
| 5 | low | a reader landing mid-append called an intact log damaged after one 20 ms sleep | **fixed**: `read_stable` retries while the length keeps changing (10 × 20 ms) and reports "being written by another process" rather than damage; `a_reader_does_not_call_an_in_progress_append_damage` |
| 6 | low | an unidentifiable or held lock cost ~3 s of retries before refusal | **fixed**: 40 attempts (~1.8 s, still above one append plus `sync_data`), documented |
| 7 | low | `receipt_method`'s fallback could still produce a label `valid_method` rejects | **fixed**: the fallback is `"<unrepresentable>"`; `tests/receipts_tests.rs` covers the escaped label |

Also closed while fixing (R-14 interplay): `content_hash` for a redacting
capability now hashes `redact_module`'s output, so the hash no longer offers an
equality oracle over a secret the module was meant to hide
(`tests/domain_hardening_tests.rs`,
`a_redacting_capability_hashes_the_redacted_image`).

Gate: full `gate-rpc.sh` green — all-features and no-default suites, clippy on
both sets, fmt, doc, the fuzz and control-plane and CLI manifests, and
`python scripts/negative_controls.py --check` 9/9.

### R-16 security helpers and persistence - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `af12e3a`.
One high, four mediums and six lows were open; the high was a regression of the
round-1 export fix.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | `export_capability` reserved the grant and consumed the record id before `from_json` validated the record, so an unexportable capability was refused and left dead | **fixed**: build, seal and read back the record first, then reserve and consume |
| F2 | high | `redact_module` replaced secret nodes before encoding, which empties the secret heap before the codec's fragment check runs: a literal in an annotation, provenance or a binding name survived | **fixed**: encode first (fragments still present, so the label checks apply), then replace and re-encode |
| F3 | medium | `RecordStore` was check-then-mark: two processes restored one record into two grants; `MemoryRecordStore` accepted a duplicate | **fixed**: an atomic `claim` (default insert-if-absent), called after the seal and binding and before the mint; a duplicate `mark_restored` is an error |
| F4 | medium | a sealed record with `lease_ms` and no `expires_at` restored with no deadline | **fixed**: the parser refuses it |
| F5 | medium | egress never applied the secret helpers, so a provider bug could leak structural secrets or skip redaction | **fixed**: a redacting call gets `redact_value`; a non-redacting call refuses a module with secret nodes and still accepts the marker and opaque bytes |
| F6 | medium | a record whose deadline passed is refused even when the restorer's virtual clock is unrelated | **noted**: the lease alone cannot distinguish a same-domain expiry from a foreign epoch, and restoring on the lease would hand a fresh lease to an expired record; refusing is the safe side (documented in `kernel.rs`) |
| F7 | medium | the parser accepted an empty or reordering method and a malformed topic, then the mint reported `rpc/invalid-argument` | **fixed**: validated in `from_json` as `rpc/persistence` |
| F8 | medium | the invisible-character set missed 15+ format characters, the variation-selector supplement and the invisible fillers | **fixed**: the ranges are added and table-tested |
| F9 | medium | a duplicate JSON key (serde keeps the last) or an unknown field was outside the seal | **fixed**: the text must be the canonical rendering of the parsed value, and an unknown field is refused |
| F10 | low | the seal had no purpose prefix, so a MAC from another protocol over the same key could pass | **fixed**: `active-rpc/capability-record-seal/v1\0` |
| F11 | low | a `Value::Map` key bypassed both helpers | **fixed**: a key carrying the marker collapses the map to the marker |

Routed from this review to the domain section and fixed there:
**`content_hash` was an equality oracle over the secret heap for a redacting
capability**; it now hashes the redacted image.

An extra correction found while fixing F5: `redact_value` collapsed a `Text` that
*is* the marker, so an already-redacted answer (`["***SECRET***"]`) was destroyed
on a second pass; and it refused opaque `Value::Module` bytes (a WASM tool's
binary output) because they do not decode as an image. Both are fixed.

Gate: 643 all-features (74 suites), 583 no-default, control plane 46, CLI 33,
clippy/fmt/doc clean. Commit `cb44d07`.

### R-15 observability - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `af12e3a`.
One high, two mediums and four lows were open; the review confirmed that no
payload or secret reaches a trace, that `label`'s arithmetic is exact, that
`events_since` never skips a concurrent event, and that one operation never
emits two refusals.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the whole `call_idempotent*` path returned early without recording anything, so a replay refused because the capability was revoked left no `call.refused` and no counter, and a key reused with different arguments did the same | **fixed**: `record_refusal` / `record_refusal_in` is called at every early return; `an_idempotent_replay_refusal_is_observable` |
| 2 | medium | a budget or tool refusal decided at dispatch (a promise's resolved bytes, a shape ceiling, the egress charge) settled as a bare rejection: `budget_exhaustions`/`tool_refusals` stayed flat and the dimension was lost | **fixed**: the settle path pushes `budget.exhausted`/`tool.refused` and counts them; `a_dispatch_time_ceiling_is_counted` |
| 3 | medium | `revoke` counted and recorded again for an already-revoked capability: a retry loop over-reported the kill switch and could flush the tape | **fixed**: `was_revoked` guards the record and the counter; `revoking_twice_is_one_revocation` |
| 4 | low | `caps per message` fell through `budget_dimension` to `other` | **fixed**: it keeps its own label, and `other` is documented as the catch-all |
| 5 | low | `promise.rejected` was said to carry a provider-authored code | **false positive**: `Event::PromiseRejected` uses `Error::code`, which is the closed envelope class (`rpc/provider` for any provider text); a test pins it |
| 6 | low | `calls_refused` counts refused sends and publishes but was documented as calls-only | **fixed**: the doc says what it counts |
| 7 | low | the tape has no epoch, so a collector paging with `last_sequence + 1` silently drops events after a restart | **documented**: a collector must reset its cursor when `events_total` decreases |

Gate: 643 all-features, 583 no-default, control plane 46, CLI 33, clippy/fmt/doc
clean. Commit `cb44d07`.

### R-18 CLI - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `d2ee809`,
driving the built binary against scripted hostile TCP/HTTP peers. One high,
eight mediums and ten lows were still open; three round-1 fixes had regressed or
were partial. Every fix has a test in `tests/hostile_input_round2_tests.rs`.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| N1 | high | `events --follow` was a usage error: `reject_unknown` refused any flag with an empty value, so the documented bare form exited 2 and only the undocumented `--follow=1` worked | **fixed**: one `BOOLEAN_FLAGS` list exempts every boolean from the value rule |
| N2 | medium | `pipeline`/`loadgen` never correlated reply ids: one replayed `Response` answered every request and both reported a clean run | **fixed**: each reply must answer an outstanding request, once; `a_replayed_answer_is_not_a_pipeline_success` |
| N3 | medium | `--timeout-ms` was consumed only by the tcp arm; connect/http2 (and the connect phase) hung on a silent peer, and `loadgen` had no flag | **fixed**: one `with_deadline` wraps the exchange on every transport, and `loadgen` gained the flag; `a_silent_peer_is_a_deadline_on_every_transport` |
| N4 | medium | a boolean was true regardless of its value: `--emit-cap-hex=false` printed authority, `--chain-only=0` downgraded a verification | **fixed**: `flag_bool` parses bare/`true`/`1`/`yes` and `false`/`0`/`no`, and refuses anything else |
| N5 | medium | the demo peer's `sum` used `+=`: `i64::MAX + 1` from the wire panicked (exit 101) and wrapped in release | **fixed**: `checked_add` with `rpc/invalid-argument` |
| N6 | medium | `events` printed a non-JSON 200 raw on an exit-0 path (a forged ANSI/HTML body) | **fixed**: a 200 whose body is not the event array is a refusal |
| N7 | medium | `events` had no connect/read deadline and no per-poll bound | **fixed**: socket read/write timeouts plus the per-poll deadline |
| N8 | medium | `receipts` and `replay` never validated flags or positionals: `--limt 1` printed an unverified listing with exit 0 | **fixed**: per-subcommand allowlists and positional counts |
| N9 | medium | `--cert` was accepted on cleartext transports (and `peer --cert-out` silently wrote nothing): the flag implied a check that never ran | **fixed**: both require `--transport quic` |
| N10 | low | the default `peer` output printed a sentence where the documented `awk '/^cap=/'` expects 32 hex characters | **fixed**: the hint is a `#` comment, and README and the man page pass `--emit-cap-hex` with the bearer-authority caveat |
| N11 | low | the bearer id had to be passed in argv (process table, shell history) | **fixed**: `--cap-file` (a 0600 file), preferred in the docs |
| N12 | low | `pipeline --calls 0` reported a round trip it never made | **fixed**: a usage error |
| N13 | low | `http_get` ignored `Content-Length`, and `dechunk` accepted a body with no terminal chunk; headers were matched by substring | **fixed**: headers by name, a declared length is enforced, a chunk must be followed by CRLF and the body must terminate |
| N14 | low | the http2 peer had no served-connection deadline, so `--limit` was unreachable behind a stalled client | **fixed**: `Http2Server::with_connection_deadline` (default 60 s, the peer uses 10 s) |
| N15 | low | a CRLF receipt-key file (66 bytes) was refused by a 65-byte ceiling; the mode check re-stat'ed a path | **fixed**: 68 bytes and a trim, and the mode check stats the open handle |
| N16 | low | `println!` panicked on EPIPE: `receipts show \| head` exited 101 | **fixed**: every operator line goes through `out_line`, and a closed pipe is a clean stop |
| N17 | low | `loadgen` cloned the payload per worker (64 GiB of address space at the ceilings), had no request cap, and a failed spawn panicked; `pipeline` kept every reply | **fixed**: one `Arc<[u8]>`, `MAX_REQUESTS`, `Builder::spawn` as exit 3, and a `MAX_PIPELINE_BYTES` retention ceiling |
| N18 | low | `dispatch` charged egress as `payload.len()` only, so echoed arguments were free outbound | **fixed**: the value plus the payload is charged before the response is returned |
| N19 | low | `std::env::args()` panics on non-UTF-8 argv (exit 101) | **fixed**: `args_os` with a usage refusal |

Gate: CLI 33 (was 22), 627 all-features, 567 no-default, control plane 46,
clippy/fmt/doc clean, negative controls 9/9. Commit `af12e3a`, CI green on both
orgs.

### R-17 introduction and topics - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `d2ee809`.
Two highs and five mediums were still open; the review confirmed that the publish
grant, the topic bounds and the backpressure code held.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| R2.1 | high | a wall-clock TTL never fired on `publish`, `send`, `attenuate`, `introduce_to`, `export` or a restore: the stored clock only moved on a dispatch, so a 1 ms lease published forever | **fixed**: `refresh_clock` at the top of every synchronous authority check; proved by removing it (the test fails) |
| R2.2 | high | `Agent::channel` returned a clone of the channel, which owns its queue and can `recv`: a lane refused a read took the mailbox, payload and transferred capability ids included, and the control plane cloned up to 64 MiB per channel per refresh | **fixed**: `ChannelStats` (counts and names only) |
| R2.3 | medium | `subscribe`/`close`/`destroy`/`create` take no authority, and `UnknownChannel` doubles as "not subscribed", so an in-process caller learns which ids exist | **documented**: `Agent` is the host's authority object and no envelope path reaches those methods; the ADR, `wire.md` and `Lane::channels` now say so, and the false "anti-oracle" and "advisory" claims are gone |
| R2.4 | medium | `introduce_to` accepted a borrowed handle: a receiver could bind the sender's capability to a peer of its choosing and lock the owner out | **fixed**: `cap.is_owning()`, as `export_capability` already required; proved by removing the check |
| R2.5 | medium | `send` bypasses the publish grant and can fill a channel with topic-less messages | **documented** as the host-side path (`publish` is the capability-gated one); a closed channel now answers `invalid-argument` instead of `backpressure` |
| R2.6 | medium | topics, channel names and intro names accepted U+2028/U+2029, bidi controls, zero-width and tag characters (only Cc/C1 were refused) | **fixed**: one `security::valid_text`, used by method names, topics, provider names, channel names, intro names and `Channel`; proved by reverting the rule |
| R2.7 | medium | duplicate provider names tied on the sort key, so the same surface encoded to different bytes and a different fingerprint | **fixed**: a duplicate provider name is refused |
| R2.8 | low | a `u64` budget ceiling above `i64::MAX` wrapped to a negative module integer | **fixed**: `i64::try_from` with a refusal |
| R2.9 | low | `intro()` called provider code while holding the kernel borrow: a provider that calls back in panicked on a re-borrow, and one that calls `intro()` recursed | **fixed**: the provider table is taken out and restored by a guard; `a_provider_may_call_the_agent_from_methods` |
| R2.10 | low | the duplicate-capability check was a linear scan per capability with no per-message ceiling | **fixed**: `MAX_CAPS_PER_MESSAGE` (1 024) and a `BTreeSet` |
| R2.11 | low | `Channel::send_topic` stored an unvalidated topic | **fixed**: `push` validates it, so the type boundary enforces the rule |
| R2.12 | low | `Message.from` is the caller-supplied lane, and `publish_as`/`send_as` do not check lane ownership | **documented**: the lane is host-selected and `Agent` is the authority object; the recorded residual (no publisher identity) stands |
| R2.13 | low | a closed and full channel answered `backpressure` (retry) instead of `invalid-argument` | **fixed**: `can_send()` is checked first |
| R2.14 | low | `wire.md`, ADR-0020 and `Lane::channels` contradicted the code on the read gate, the publish grant and the topic bounds | **fixed** |

Gate: 627 all-features (71 suites, 8 new), 567 no-default, control plane 46,
CLI 22, clippy/fmt/doc clean. Commit `190e9c9`, CI green on both orgs.

### R-20 fuzz program - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `09b1c82`.
Verdict: not clean. K1 and K3 confirmed fixed; K2 confirmed only for `Arg::Value`
at queue time. Three highs, three mediums and five lows were still open, and all
of them were real:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| C1 | high | a promise argument bypassed every shape ceiling: queue time sees a placeholder, dispatch substituted the value and re-checked only bytes | **fixed**: dispatch measures the resolved arguments; `a_promise_argument_is_measured_when_it_resolves` drives a wide value through a permissive capability into a narrow one |
| C2 | high | `Value::wire_size` recursed and ran *before* the depth guard, so a deep value aborted the process where no `catch_unwind` reaches | **fixed**: `wire_size` is `shape().size`, one iterative pass (depth, width, size); `shape_refusal` is the single place the ceilings are compared |
| C3 | high | a provider's response was never shape-checked against the grant | **fixed**: egress runs `shape_refusal` before the byte charge; `a_response_wider_than_the_grant_is_refused`, `a_response_deeper_than_the_grant_is_refused` |
| C4 | medium | `send` and `publish` carried no shape ceiling at all | **fixed**: both run `shape_refusal` (lane budget for `send`, the intersected grant for `publish`) |
| C5 | medium | `max_value_size` is documented as the materialised value size and implemented as the largest *scalar*: a list of 200 `Null` is 205 bytes and passed a ceiling of 8 | **fixed**: `Shape.size` is the wire size, matching the doc and `active_core`'s notion; `a_list_of_scalars_over_max_value_size_is_refused` |
| C6 | medium | F5 was only half fixed: `MemoryTransport` answered by method name with a fixed request id, so a fuzzed `tools/list` body never got past `initialize`, and `tools/call` results were never parsed | **fixed**: the transport echoes the request id (which is what a real server does, and what made the MCP scenario single-shot), and the target places the fuzzed body in each of the three parsers, then drives `tools/call` |
| C7 | medium | F8 was only half fixed: the "value size" probe always exceeded `max_bytes` first, so deleting the shape check would not have failed it, and `max_array_len` was never probed | **fixed**: `max_bytes` is generous, each probe is built past its own ceiling, and the refusal must *name the dimension* |
| C8 | medium | the PR fuzz lane still discarded its crash artifacts, and the nightly lane's 16 × 600 s campaign did not fit its 180-minute ceiling (and a timeout skips the `always()` upload) | **fixed**: the PR job uploads `fuzz/artifacts` + corpus; the nightly runs 420 s per target under a 300-minute ceiling |
| C9 | low | three targets named invariants in their headers that nothing asserted | **fixed**: the domain target drives the methods that exist (`metadata` is not one — the first block had been dead), asserts a redacting capability never carries the canary, and the wasm target asserts the limit ceilings; the framing target's unreachable "declared header" claim is replaced by what the public API can reach |
| C10 | low | every action was on a moving tag, and the release job held `contents: write` | **fixed**: `checkout`, `upload-artifact` and `setup-python` are pinned by SHA with the tag in a comment (`dtolnay/rust-toolchain` keeps its version tag: the ref *is* the toolchain selector) |
| C11 | low | `fuzz_docker.py` let `TimeoutExpired` escape, aborting the lane and leaving the container running | **fixed**: the container is named, removed on a timeout, and the target is recorded as a failure |
| C12 | low | 411 untracked seeds contradicted "corpora are committed" | **fixed**: committed; `CORPUS.md` now says how to count them instead of a number that rots |

Also in this round: `ERROR_CODES` (31 codes) is the closed catalogue, compared
against `Error::code`, the wire spec and a sample of variants by the conformance
suite — four variants had no test, and `rpc/persistence` was undocumented.
`observability::label` keeps its declared 128-byte ceiling including the ellipsis
(it could return 131).

**Verified pre-fix**: 8 of the 16 `budget_shape_tests` fail against `09b1c82`
(the four new boundaries and the size semantics), the MCP target fails against
the old transport, and the label test fails against the old formatter.

Campaign after the fixes: 16 targets × 3000 runs, clean; the two repaired targets
re-run clean, and `fuzz_wasm_module` measured 3 846 exec/s over 50 000 runs.

Gate: 619 all-features (70 suites), 559 no-default, control plane 32, CLI 22,
clippy/fmt/doc clean on both feature sets, fuzz clippy clean, negative controls
9/9. Commit `1c4cb37`, CI green on both orgs.

### R-19 control plane - 2026-11-02 (round 2, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `09b1c82`.
Verdict: not clean. Two highs and six mediums were still open; the review also
confirmed that three of the five round-1 fixes were real.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| P1 | high | the MCP step was single-shot: the transport answered with a fixed request id, so every run after the first got `mcp/id-mismatch` and the ladder painted a red stage that said only "Scenario panic" | **fixed**: `MemoryTransport` echoes the request id; the scenario maps a refusal to a stage carrying its code; a panic reports its message; `every_ladder_step_passes_twice` runs the whole ladder twice |
| P2 | high | the WebSocket's `RecvError::Lagged` arm was `{}`: the lag signal P7 claimed to have added was never in the tree | **fixed**: a lag pushes an `event_gap` frame with the skipped count (`gap_frame`), unit-tested |
| P3 | medium | `/logs/since` gave no gap signal when the 500-event ring wrapped | **fixed**: the envelope carries `oldest` and `gap`; `/logs/tail` carries `oldest` and `truncated` |
| P4 | medium | the `event_gap` marker was category `system`, i.e. not protected from the eviction it reports | **fixed**: `code == "rpc/audit-gap"` is protected, and `Health.audit_gap` is sticky |
| P5 | medium | `.layer()` before `.fallback_service()`: static assets answered `Host: evil.example` with 200 | **fixed**: the layer comes after the fallback; `a_static_asset_with_a_foreign_host_is_refused` |
| P6 | medium | no `X-Frame-Options`/`frame-ancestors`: a framed dashboard defeats both the Host and Origin guards with one click | **fixed**: one middleware stamps `x-frame-options`, `frame-ancestors 'none'`, `script-src 'self'`, `style-src 'unsafe-inline'`, `nosniff`, `base-uri`/`form-action 'none'` |
| P7 | medium | `/health` could not fail (`kernel: "up"` was a constant) and a dead worker kept answering 200 | **fixed**: `Heartbeat` staleness, `catch_unwind` around every command, a panic republishes `kernel: "down"` |
| P8 | medium | `redaction_ok` was written only on success, so a projection error kept last run's `true` | **fixed**: the flag is cleared before the first projection |
| P9 | medium | `BenchmarkReport.samples` was rebroadcast in every snapshot (~96 KB per client per second after a 5 000-iteration run) | **fixed**: `skip_serializing`; the CSV endpoint still serves them |
| P10 | low | the `"::1"` allow-arm was dead: `rsplit_once(':')` turned `Host: ::1` into `":"` | **fixed**: `is_loopback_host` parses the bracketed form and refuses a bare IPv6 address |
| P11 | low | the Origin check ignored scheme and port: another local program on 9999 drove the plane | **fixed**: `same_origin` compares host and port, and the WS upgrade uses it too |
| P12 | low | the process policy was a prefix wildcard over a shell (`"echo*"` + `cmd /C`) | **fixed**: the exact command line `echo active` is allowlisted, and a new stage proves `echo active & whoami` is refused. (The adapter's metacharacter refusal already covered the exploit the review named, so the finding was **partly a false positive**; the scenario now tests both lines of defence.) |
| P13 | low | the process stage printed `cmd` while the registered program is an absolute path | **fixed**: the core carries the program and the stage prints it |
| P14 | low | the kernel secret was a source constant, so every process derived the same capability and correlation ids | **fixed**: `Agent::new()` (a random secret per process) |
| P15 | low | `activity.progress` can never be a fraction (the worker publishes after a command returns) | **fixed in the label**: the field documents that it is a final count and the UI says "iterations" |
| P16 | low | the verdict conjoined only the *last* stage although its comment said "conjunction of its own stages" | **fixed**: every stage must be green |
| P17 | low | the MCP client accepted any `--attach`, interpolated an unvalidated scenario id into a URL, and read stdin with `lines()` | **fixed**: the base must be a loopback origin, the id must be a declared scenario, and a request line is bounded at 1 MiB (`read_bounded_line`) |
| P18 | low | one document-level `mouseup` was registered per track per render (~6/s, each retaining its track) and the status said "live" on a frozen socket | **fixed**: one document handler for every brush; the status follows the last frame's age. Verified by dragging in headless Chrome |
| P19 | low | `PlaneCore::new()` bound a listener and spawned a thread that outlived the core; `spawn_worker` built two cores per worker | **fixed**: the stub loop stops on drop (woken by one connection), `spawn_worker` builds one core and takes the state from its first snapshot; `dropping_a_core_closes_the_http_stub` |
| P20 | low | a kernel restart (`total < seen`) reported "0 events were evicted" and discarded the new tape | **fixed**: a restart is reported as a restart with its own count |

**Browser verification** (headless Chrome over CDP, `control-plane` on :8795):
`/` and `/app.js` served under the new CSP with **0 console errors**, 20 gauges
showing measured values (encode 319.6 µs, decode 117.4 µs, hash 69.5 µs), a
scenario run from the ladder (5 green stages), a level-6 run with no failures, a
brush drag that set the window (`Brush: 23:42:18 → 23:42:59`), and the status
leaving "live" when the plane was stopped. The first pass found 294 CSP
violations: the dashboard draws bar widths with inline styles, so
`style-src 'unsafe-inline'` is required (scripts stay `'self'`).

Gate: control plane 46 (was 32), 619 all-features, 559 no-default, CLI 22,
clippy/fmt/doc clean. Commit `d2ee809`.

### R-20 fuzz program - 2026-11-02 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `4c127c4`.
No critical. The verdict was that `fuzz/` was "a smoke suite dressed as a
security gate": five targets could not fail on the defect they named, three
named invariants were no-ops, the two highest-risk parsers (MCP responses, module
/domain) were unreachable from any input, and the nightly lane discarded the only
artifact that would reproduce a crash. Nine highs, eight mediums, five lows.

Fixing the targets found **three real kernel defects** that no unit test reached.
They are the reason this section is not cosmetic: each was a check that existed
in a declaration and nowhere else.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | `fuzz_promise_graph`: the foreign-promise branch inspected `agent.call(..).err()`, but the refusal happens at dispatch, so the only assertion was `starts_with("rpc/")`, which every error satisfies. The named invariant was never checked | **fixed**: the foreign promise is refused at *queue* with `rpc/unknown-promise` (`expect_err`) |
| F2 | high | `fuzz_capability_lifecycle`: a `for (_, cap) in &drops { let _ = cap; }` loop claimed to assert "exactly once per object"; a kernel that never notifies, or notifies N times, passed | **fixed**: `drop(caps)` then `assert_eq!(drops.len(), 1)`. This exposed **K1** immediately: the kernel notified once *per capability*, so nine notifications arrived for one object |
| F3 | high | `fuzz_tool_process`: an argument policy that admitted `"ok;rm -rf /"` produced `Ok` and the target passed; only `Err` was asserted | **fixed**: the argument policy is enforced at dispatch, so the assertion moved to `promise.value()`: `Ok` only for `"ok"`, otherwise exactly `rpc/tool-policy` |
| F4 | high | `fuzz_transport_framing`: "a frame larger than the segment is refused" required `payload.len() > capacity`, but `SharedSegment::new` clamps to 1024 and the largest seed is 901 B, so the branch was unreachable | **fixed**: the oversize frame is built in-target (`vec![0u8; capacity + 1]`) and the write must be refused |
| F5 | high | `fuzz_tool_mcp`: the untrusted *server response* parser was never fuzzed (the input was a constant `BTreeMap`); the malformed-response cases were two hard-coded strings | **fixed**: `data` is fed back as the `initialize`/`tools/list`/`tools/call` response body and must be `rpc/provider` |
| F6 | high | `nightly.yml` had no job timeout and no artifact upload, so a 200k-run crash was written to a gitignored directory and lost | **fixed**: `timeout-minutes: 120`, `-max_len=65536`, `upload-artifact` (`if: always()`) for `fuzz/artifacts` and the grown corpus |
| F7 | high | `fuzz_wasm_module` installed the OS CSPRNG as `env.random`, so a failure on the guest's random path did not replay from the input | **fixed**: `random: false`; the clock is seeded by the embedder |
| F8 | high | `fuzz_budget_matrix` could not tell "each ceiling binds" from "refuses everything": the loop broke on three codes and only asserted `calls <= max_calls` (true at zero calls), and the four shape ceilings used a fixed budget and fixed values | **fixed**: the first refusal must be `rpc/budget-exceeded` after exactly `max_calls`, and the `depth`/`max_value_size` probes are data-driven. This exposed **K2**: `max_depth`, `max_array_len` and `max_value_size` were never enforced on a call at all |
| F9 | high | the domain and durable-record parsers had no target, and `STATUS.md` filed the Infinity names as `n/a` rather than an open gap | **fixed**: `fuzz_domain_module` (decode, canonical install, every domain method over fuzzed paths) and `fuzz_persistence_record` (`from_json`, canonical round trip, a seal that never verifies under a foreign key); invariant rows H1.25/H1.26 added and the matrix regenerated |
| F10 | medium | `fuzz_tool_http` never called the allowed path, and accepted `rpc/invalid-argument` where the contract is `rpc/tool-policy` | **fixed**: the allowed path must be admitted and every escape must be `rpc/tool-policy` |
| F11 | medium | `fuzz_channel_cap_transfer` asserted nothing on the receive half and only `!drops.is_empty()` on the drop half | **fixed**: the payload is compared, and `drops == vec![(0, cap.id())]` |
| F12 | medium | `fuzz_arp1_frame`: a decoder that ignored the caller's limits passed, and the surviving assertions restated `decode`'s own work | **fixed**: a strict profile must refuse an envelope it bounds |
| F13 | medium | `fuzz_bulk_plan` restated `decode_for`'s invariants and replayed the sender's own frames in order, so truncation, reordering and conflicting data were never exercised | **fixed**: a deterministic permutation, a tampered last byte and a truncated frame, with the receiver's `missing()` set asserted |
| F14 | medium | `fuzz/README.md`, `STATUS.md` and `CORPUS.md` hid two targets and claimed a longer `main` campaign that no workflow ran | **fixed**: all three name sixteen targets, the campaigns table matches the workflows, and `tests/fuzz_manifest_tests.rs` fails when a workflow, the fuzz README, the corpus inventory or the runner script omits a target |
| F15 | medium | `scripts/fuzz_docker.py` held a hand-copied target list that ended at `fuzz_topic_policy` and printed "all 12 targets completed" while four never ran | **fixed**: the list is read from `fuzz/Cargo.toml`, `--build` exits cleanly, `-max_len` matches CI, and the manifest test forbids a hard-coded list |
| F16 | medium | the fuzz binary was not the shipped build: `default-features = false, features = ["wasm-tools"]` compiled out QUIC and HTTP/2 | **fixed**: `features = ["wasm-tools", "quic", "http2"]` |
| F17 | medium | `fuzz_receipt_log` created, locked, synced and unlinked a file per execution, so its 200k-run bound could never be reached; `fuzz_replay_package` returned from the whole target for a package over the replay ceiling, skipping its structured half | **fixed**: the disk half runs on one input in sixteen (the parser half still sees every input); the over-ceiling package skips only its replay half |
| F18 | low | `let _ = Value::Null`-style noise, and `let _ =` calls standing in for checks | **fixed** |
| F19 | low | failure messages did not name the invariant (two targets asserted the same literal code for different rules) | **fixed**: one message per assertion |
| F20 | low | `fuzz_wasm_module`'s size ceiling and its "the log is per call" claim were asserted nowhere | **fixed**: an oversize module built in-target must be `wasm/module`, and the log is drained and bounded after each call |
| F21 | low | repeated seeds across targets, and a 0-byte receipt seed | **noted**: the action-stream seeds are identical by design (the same alphabet is interpreted per target), and the empty log is a real case (`verify_bytes(&[])`) |

**K1 - `on_drop` fired once per capability (high).** The kernel notified the
provider for every capability record that reached zero references, so a provider
reclaiming per-object state on the first notification freed an object its parent
could still call. The notification now fires when the last live capability for
`(provider, object)` goes. `tests/redteam_tests.rs`
(`threat_revocation_and_lifetime_edges`) and `tests/unit_tests.rs`
(`capability_lifecycle_matches_the_bounded_model`, 625 sequences) hold the
contract; the second had encoded the old rule and now asserts "exactly one
notification, after the last handle, naming the object".

**K2 - the budget's shape ceilings were never enforced (high).** `max_depth`,
`max_array_len` and `max_value_size` were declared, intersected, exported and
documented, and `call_inner_payload` checked only `max_bytes`. An in-process
caller could hand a provider a value 10 000 levels deep under a grant that said
"depth 2"; a peer's value was refused by `WireLimits` at ingress, which is why
the wire tests never saw it. Now checked before the provider runs, with the
dimension in the refusal and its own metrics label; `Value::shape()` measures
depth, width and the largest scalar in one iterative pass (the check that bounds
nesting must not be the thing that overflows the stack), and
`tests/budget_shape_tests.rs` (10 tests, seven of which fail against the pre-fix
tree) pins it.

**K3 - the per-object scan was quadratic (medium).** Deciding "is this object
still referenced" scanned every live capability, so a mint/drop loop was
quadratic: dropping 20 000 capabilities took 1.33 s in a release build. A
per-object count next to the registry makes one cycle constant work: 20 000
drops in 31 ms, 60 000 in 116 ms, and 60 000 capabilities on one object produce
exactly one notification. `tests/perf_budget.rs::capability_churn_is_linear`
compares per-capability cost at 2k and 20k; `docs/spec/performance.md` records
the numbers and the reproduction command.

Campaign: `python scripts/fuzz_docker.py --all --runs 3000` on
`active-fuzz:1.88`, sixteen targets, `-max_len=65536`. The first pass reached 840
executions in `fuzz_wasm_module` and stopped on a wrong assertion in the new
size-ceiling check (the refusal is `wasm/module`, not `wasm/limits`); the target
was corrected and re-ran clean, and a follow-up `--runs 50000` run measured
3 846 executions/s with no crash. The crash input from the `on_drop` discovery
was promoted into the corpus as `r20-on-drop-per-object.bin`.

Gate: `cargo test --all-features` 611 passed across 68 suites;
`--no-default-features` 551; control plane 32; CLI 22; clippy, fmt and `cargo
doc -D warnings` clean on both feature sets; fuzz crate clippy clean; negative
controls 9/9.

### R-02 kernel dispatch - 2026-11-01 (round 3)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, repository tool
access. Tests: `tests/marathon_round2_fixes_tests.rs`; twelve of its thirteen
tests fail on the pre-fix tree (one of them hangs, which the reviewer predicted:
"control-flow certain; not executed"). The thirteenth exercises API that only
exists after the fix and passes with an accessor shim, so it is evidence for the
API and not for the defect.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| H-1 | high | export stamped the export-time clock mode, not the deadline's domain | **fixed**: `CapRecord.wall_clock` is set at mint and inherited by attenuation; export writes it and attenuation refuses a parent whose deadline is in another domain; `a_record_keeps_the_clock_mode_its_deadline_was_taken_in`, `attenuation_refuses_a_clock_mode_change` |
| H-2 | high | dropping the parent handle freed the ancestor meters, so every child spent the grant again | **fixed**: `CapRecord.descendants` keeps an ancestor's record and meter alive while any derived capability can call through it, and removal cascades up the lineage; `dropping_the_parent_handle_keeps_the_subtree_bound` |
| H-3 | high | a provider that awaited a promise spun forever (regression from round 2) | **fixed**: `await_promise` refuses with `rpc/provider` while a dispatch owns the kernel; `a_provider_awaiting_its_own_call_is_refused` (hangs pre-fix) |
| M-4 | medium | a provider unwind left `dispatching` set and the provider removed, wedging the kernel | **fixed**: `DispatchGuard` restores both on unwind; `a_panicking_provider_does_not_wedge_the_kernel` |
| M-5 | medium | `on_drop` ran with the kernel mutably borrowed, so any agent call panicked | **fixed**: every notification is queued and delivered by `deliver_pending_drops` with no borrow held; a provider that is already being notified queues the nested drop; `a_provider_may_use_the_agent_inside_on_drop` |
| M-6 | medium | revoking one restored copy left its siblings alive | **fixed**: restore refuses a second live copy of a credential and revoke dooms every live capability carrying a tombstoned record id; `restoring_the_same_record_twice_is_refused` |
| M-7 | medium | `send` charged nothing and needed no capability | **fixed**: a send charges the lane's bytes (payload plus one id per transfer) and one lane call, and a channel has a queued-byte ceiling; `a_send_consumes_the_lane_byte_budget`, `a_channel_accounts_for_queued_bytes` |
| L-8 | low | a vanished provider was `rpc/invalid-argument` at call time and `rpc/provider` at dispatch | **fixed**: both are `rpc/provider` |

### R-04 promises / pipeline - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `09704cc`.
Twelve findings; the round-1 table above stays valid for the parts it verified.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | the envelope guard was per method: `active-rpc-cli peer` served every connection through `call_with_payload` and accepted a decoded `Arg::Promise` | **fixed**: the refusal moved to the kernel boundary (`call_with_origin(.., from_peer)`), and the CLI uses `call_from_envelope`; `an_envelope_cannot_carry_authority_arguments` |
| F2 | high | `await_promise` from `on_drop` spun: the delivering provider is not `dispatching`, so the round-1 guard did not fire | **fixed**: the loop now requires a round trip to have happened, else `rpc/unresolvable-promise`; `awaiting_from_on_drop_returns_instead_of_spinning` (hangs pre-fix) |
| F3 | medium | phase 3 and `fail_job` emitted `PromiseResolved`/`PromiseRejected` and advanced the counters after a *failed* transition | **fixed**: both are inside `settled_now` |
| F4 | medium | an in-batch cancelled promise never became trim-eligible, so repeated cancellations leak records until the promise ceiling wedges the kernel | **fixed**: `cancel` records the terminal state for an in-batch job too |
| F5 | medium | the empty-batch arm trimmed settled records while the queue still held a consumer for them (spurious `rpc/pipelined-cycle`) | **fixed**: no trim while the queue is non-empty |
| F6 | medium | `cancel_tree`'s queue filter was O(jobs × queue): 10 000 jobs = 658 ms (measured) | **fixed**: one `BTreeSet` of queued ids |
| F7 | medium | `order_candidates` scanned `ordered` per dependency: a 2 000-link chain = 808 ms (measured) | **fixed**: a `BTreeSet` of promises produced in the batch |
| F8 | medium | the idempotency key ignored the arguments: the same key with different arguments returned the first result | **fixed**: the cache stores an argument fingerprint (shape and content, secrets by marker only) and refuses a mismatch; `an_idempotency_key_refuses_different_arguments` |
| F9 | low | a cached replay was refused at the lane call ceiling, exactly when a retry is needed | **fixed**: the capacity check is on the miss path; `a_cached_replay_is_served_at_the_lane_ceiling` |
| F12 | low | settlement walks a provider-controlled value with no depth bound: a 200 000-deep response aborted the process | **fixed**: dispatch refuses a value deeper than the wire limit as `rpc/provider`; `a_provider_value_deeper_than_the_wire_limit_is_refused` |

Carried (documented, not fixed here):

| # | Sev | Reason |
|---|-----|--------|
| F10 | low | a `PromiseHandle` is not bound to its kernel, so two agents in one process can mix ids; the fix is a kernel nonce in every handle-accepting method, which changes the handle type |
| F11 | low | idempotent refusals skip `CallRefused`/metrics; the accounting helper exists (`note_refusal`) and the wiring is a follow-up |
| F13 | note | `JobState::Done` is vestigial; the invariant "a job leaves `jobs` only at settlement" should be asserted or the enum removed |

Gate: `cargo test --all-features` 444 passed, 0 failed; the CLI suite 17 passed;
clippy clean on both feature sets and the CLI; fmt clean.

### R-06 budgets - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `64ea410`.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | a sealed record was never consumed: export → restore → spend → drop → restore refilled the same grant without bound, so a record stored in a config system was an unlimited credential | **fixed**: `Kernel.consumed_records` marks a record on export and `Kernel.restored_records` marks it on restore; a second export or restore is `rpc/persistence`; `an_exported_record_is_consumed`, `a_record_restores_once_per_kernel` |
| 2 | high | export recorded only the capability's own remainder and restore minted an unlineaged capability, so a restored child escaped the parent's grant | **fixed**: export clamps the record to the minimum remaining of the capability *and* every ancestor, then **reserves** that grant on every meter (`BudgetMeter::check_reserve`/`reserve`), so the local subtree cannot spend it twice; `a_restored_child_cannot_outspend_its_parent` |
| 3 | medium | response bytes are not a budget dimension: a 32-byte grant can return 1 MiB | **fixed**: dispatch charges the response's wire size against the capability, its ancestors and the lane before settlement, so a response that does not fit settles as `rpc/budget-exceeded`; `a_response_larger_than_the_remaining_grant_is_refused`, and `budget.rs` says the ceiling covers both directions |
| 4 | medium | `max_wall_ms` is enforced only by `LocalProcess`; MCP has no deadline and HTTP uses a fixed 10 s | **carried**: threading the ceiling into the adapters is mechanical but changes three adapters' timeouts; logged for R-08 (tools) where the adapters are audited |
| 5 | low | send/publish refusals advance `budget_exhaustions` without an `Event::BudgetExhausted`, and the dimension vocabulary has more values than the spec lists | **carried** with #3/#4; the event and the spec list are one change |

Gate: `cargo test --all-features` 448 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-06 budgets - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `22c3d66`
plus `d801371`. Tests: `tests/promise_tests.rs` (4 new, failing-first;
`tests/r06_audit_probe*.rs` were the scratch probes and are removed).

Verified clean, by probe rather than by reading: export → restore → re-export →
restore across three kernels carries the grant once (3 calls in, 3 calls out,
0 in the exporting kernels); a child attenuated *after* an export cannot see the
reserved grant (the chain is charged, not the child's ceiling); a restore whose
`mint_restored` fails does **not** consume the record; a dropped parent handle
still binds its child; two sibling exports cannot each carry the ancestor's
whole remainder; and an export of a spent, revoked or expired capability still
refuses.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a refused export still burned the grant and the record: the empty-path-scope check ran *after* `reserve` and after `consumed_records.insert`, so one malformed field destroyed the authority and made the record unexportable | **fixed**: the check moved above the reserve; `a_refused_export_keeps_the_grant_and_the_record` |
| 2 | high | a tombstone did not reach a live capability: `tombstone_record` only filled the set, and dispatch never consults it, so a credential restored before the kill list was replayed kept serving its whole lease | **fixed**: `tombstone_record` revokes every live capability carrying the id (shared `revoke_subtree` with `revoke`); `a_tombstone_revokes_the_live_capability_it_names` |
| 3 | medium | `consumed_records` and `restored_records` had no ceiling and are not covered by `durable_ceiling_reached`: 70 000 export/drop cycles grew the set forever (measured) | **fixed**: `MAX_RECORD_IDS` (65 536) with `set_record_id_ceiling`; a new export or restore past it is `rpc/budget-exceeded`; `the_record_id_sets_are_bounded` |
| 4 | low | a sealed record whose budget disables a ceiling was refused as `rpc/invalid-argument`, outside the durable vocabulary | **fixed**: restore reports `rpc/persistence`; `a_record_that_disables_a_ceiling_is_a_durable_refusal` |
| 5 | low | ADR-0010 still said "one live capability per credential", while the code restores once per kernel and consumes on export | **fixed**: the ADR addendum states consumption, the lineage reserve, the bounded sets, the kill-switch semantics and the startup order |
| 6 | low | an export and a restore emit no event (`CapMinted` is reused), so authority leaving the process is not on the trace | **carried**: the event names are a schema change with `docs/spec/observability.md` and the ADR-0014 list; one change |
| 7 | low | the lineage clamp skips an ancestor whose meter is missing (`if let Some`), so the clamp degrades fail-open if the "an ancestor outlives its descendants" invariant is ever broken | **carried**: today unreachable (`drop_record` refuses an ancestor with `descendants > 0`); the fail-closed form needs an error path no test can reach |
| 8 | low | `object` is a provider-local id: a restart with a different registration order re-mints a credential against a different object | **documented** in ADR-0010 as a provider contract; a name-based object identity is a record format change |

Gate: `cargo test --all-features` 456 passed, 0 failed; `cargo test
--no-default-features` 0 failed; clippy clean on both feature sets; fmt clean.

### R-06 budgets - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`. All five round-1
claims were verified with fresh probes (lineage clamp = capability ∩ every
ancestor and the same grant reserved on that chain; a three-kernel
export→restore→re-export→restore carries 3 calls in, 3 out, 0 left behind; a
child attenuated *after* an export cannot spend the reserved grant; a failed
`mint_restored` does not mark the record; spent/revoked/expired exports still
refuse; a hostile record cannot insert into either set). Two new highs:

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a *refused* export burned the grant and marked the record consumed: the empty-path-scope check ran after `reserve` and the consumed insert, so one mistyped field destroyed a durable credential | **fixed**: every "the record cannot be built" refusal now happens before the reserve; `a_refused_export_keeps_the_grant_and_the_record` |
| 2 | high | `tombstone_record` filled the set but never reached a live capability: a record restored before the kill list was replayed (or tombstoned at runtime) kept spending for its whole lease | **fixed**: `tombstone_record` revokes every live capability carrying the id through a shared `revoke_subtree`; `a_tombstone_revokes_the_live_capability_it_names` |
| 3 | medium | the consumed/restored mark sets had no ceiling | **fixed**: `MAX_RECORD_IDS` (65 536) with `set_record_id_ceiling`, refused as `rpc/budget-exceeded`; `the_record_id_sets_are_bounded` |
| 4 | low | a record with a zero budget answered `rpc/invalid-argument` | **fixed**: restore maps it to `rpc/persistence` |
| 5-8 | low | export/restore emit no event; the clamp is fail-open on a missing ancestor meter; `object` is a provider-local id; provider error text is delivered unbilled | carried in the reviewer's table with reasons |

The reviewer applied its fixes directly to the working tree; they are in commit
`da59ba9` together with the R-07 D-1 fix and the removal of the scratch probes.

Gate after the D-2..D-12 work: `cargo test --all-features` 466 passed, 0 failed
(and the `--no-default-features` suite green); clippy clean on both feature sets;
fmt clean.

### R-06 budgets - 2026-11-02 (round 3, confirmation)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `32454ca`.
Targeted suites were green (`budget_shape` 16, `payload_budget` 3, `promise` 26)
and the reviewer verified 8 of the 13 prior claims fixed (`R1-1`..`R2-5`); the
verdict was not CLEAN because of the new defects below and five open items.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| R2-6 | low | export and restore emit no event of their own; a restore reads as a plain mint | **fixed**: `Event::CapExported`/`CapRestored` are on the tape, in `EVENT_NAMES`, in the projection, in the replay trace, and in `docs/spec/observability.md`; ADR-0014 carries the addendum; `export_and_restore_are_on_the_trace` |
| R2-7 | low | six `if let Some(meter)` sites skip the charge when a chain member has no meter | **fixed, with the case the first fix got wrong**: the audit's own regression suite showed a provider dropping the last handle to its own object *during* a call, so a chain member's meter legitimately disappears mid-call. `meter_for`/`meter_mut_for` now return `None` only when the capability has no record either (dropped); a live capability with no meter fails closed with `rpc/persistence`. Tests: `a_capability_without_a_meter_fails_closed`, `a_publish_from_a_capability_without_a_meter_fails_closed`, plus the existing `on_drop_is_delivered_when_a_provider_releases_during_its_own_call` |
| R2-8 | low | `object` is a provider-local id | **documented**: security model row (a capability names one provider, so an object number means nothing across providers) |
| 1 | medium | `Value::shape()` measured the whole value before the ceilings were compared: an in-process 1M-element list under `max_array_len: 3` pushed 1M work items first | **fixed**: `Value::shape_exceeded` is a bounded walk that returns at the first violation; `shape_refusal` calls it first and only then measures. `a_million_wide_list_is_refused_without_a_full_walk` measures both walks in one process (10× headroom required) |
| 2 | medium | `max_wall_ms` does not preempt a custom `Provider::invoke` | **accepted design, documented**: the security model now states that every shipped adapter enforces the ceiling and that a provider is trusted code on the dispatch thread; preemption would need a thread per call or an interpreter |
| 3 | low | `job.call.budget` was frozen at queue time, so a lane narrowed afterwards did not bind the dispatch | **fixed**: dispatch recomputes `capability ∩ lane` from the live records and uses it for the byte re-check, the resolved-argument shape re-check, the `Call::budget` the provider receives and the egress shape check; `lane_attenuation_after_queue_binds_dispatched_promise` |
| 4 | low | `MAX_CAPS_PER_MESSAGE` is a fixed kernel ceiling, not a budget field | **documented + pinned**: security model row; `a_narrow_lane_cannot_mass_transfer_capabilities` (a 1-call lane still cannot move 1 025 handles) |

Gate after these fixes: `cargo test --all-features` (all green, see below);
clippy and fmt clean on both feature sets.

### R-06 budgets - 2026-11-02 (round 4, the confirmation re-audit)

Reviewer: Muse (DeepSeek V4.1 Flash was unavailable behind its proxy) through the
Copilot CLI, `xhigh`, at `3146200`. Verdict: **NOT CLEAN** — the five round-3
claims held, with two incomplete, and it found six new defects (one high).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | `shape_exceeded` compared the size ceiling only when a container folded into its parent, so a list of a million texts under a 1 KiB ceiling was walked in full | **fixed**: the per-container accumulator is compared after every scalar and every map key, and it only grows, so a container over the ceiling is refused before its parent folds it; `a_nested_accumulator_over_the_size_ceiling_is_refused_early` (10× headroom against `shape()`) |
| F2 | medium | every child of a container was pushed before any was visited and the stack popped last-first, so a violation in element 0 was checked last | **fixed**: one frame per open container (`NextList`/`NextMap` iterators), children visited in order; `a_violation_in_the_first_element_is_found_without_walking_the_rest` |
| F3 | medium | the export path still skipped a meterless ancestor (the fail-open the round closed everywhere else) | **fixed**: the ancestor clamp and both export loops require a meter; `an_export_with_a_meterless_ancestor_is_refused` |
| F4 | medium | a provider destroying its own lane mid-batch rejected the promise of the job it was running, and the same dispatch then settled it again: two events, a refusal receipt for a call that ran, a double-settle counter | **fixed**: `JobState::Running` is set before the provider runs; `destroy_lane` fails only `Queued` jobs and keeps a running job's record so its own dispatch settles it once; `destroying_a_lane_mid_batch_settles_its_running_call_once` |
| F5 | low | `call_inner_payload` never refreshed the clock, so in wall-clock mode an expired capability was queued and charged and refused only at dispatch | **fixed**: refresh at the queue and on the idempotent replay path; `a_ttl_that_elapses_between_calls_is_refused_at_the_queue` |
| F6 | low | argument byte sums wrapped in release instead of saturating | **fixed**: `fold(0u64, u64::saturating_add)` at the queue and dispatch sites |
| F7 | residual | the global channel byte ceiling lets one lane backpressure unrelated lanes | **documented** in the security model: the bytes belong to the channel, not the sender, and per-lane attribution is not meaningful while any subscribed lane may receive |

The same pass found a copy in `Channel::send_sequence`: `push` cloned the whole
message for a return value the kernel discards, so every send copied the payload
(64 MiB at the frame ceiling). The queue now stores the only copy;
`a_kernel_send_does_not_copy_the_payload` measures with a counting allocator and
fails against the old code.

Gate: `cargo test --all-features` 733 passed, 0 failed; clippy and fmt clean.
### R-06 budgets - 2026-11-02 (round 5)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `c62916e`. It confirmed F2-F6
and found F1 partial plus three new defects; the runtime `Value` walk had one
more unbounded case.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| N1 | medium | a child folded into its parent without a ceiling check, so a list of a hundred thousand small lists was refused only at the root | **fixed**: the parent accumulator is compared on every fold; `a_list_of_small_lists_is_refused_by_the_parent_ceiling` |
| N2 | high | the queue path measured the arguments with `wire_size()` (a full walk) and walked the path scope before the shape gate, so a hostile value cost its real size at the boundary the gate exists for | **fixed**: the shape gate runs before the path walk, the tool ceiling and the byte measurement; `a_hostile_value_is_refused_before_the_kernel_measures_it` (the refusal now also drops the value, which is linear, so the test holds 3× headroom against a walk that costs far more per element) |
| N3 | medium | the idempotency fingerprint hashed the whole value before any shape check | **fixed**: the keyed path shape-checks against the capability's budget before hashing; `an_idempotent_call_refuses_a_hostile_value_before_hashing_it` |
| N4 | low | cancelling a promise whose job was already running counted as a kernel double settlement, because phase 3 tried to settle a cancelled record | **fixed**: phase 3 recognises the cancelled state and does not count it; `cancelling_a_running_call_is_not_a_double_settlement` |

Also fixed while in the file: `Value::is_tainted` was a public recursive walk
with no depth bound, so a caller could overflow the stack through a predicate
that only reads. It is iterative now, like `shape`.

Gate: `cargo test --all-features` 742 passed, 0 failed; clippy and fmt clean;
`negative_controls.py --check` 9/9 (two anchors retargeted after the meter and
dispatch refactors).

### R-05 lanes / channels - 2026-11-02 (round 2, confirmation)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `c62916e`. It verified all
round-1 work (the 11 lane tests and the allocator test) and found six new
defects; the carried item now has an ADR.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `publish` still went through `Channel::send_topic`, which clones the message for a return value the kernel discards: up to 64 MiB copied per publish | **fixed**: `Channel::send_topic_sequence` stores the only copy; `a_publish_does_not_copy_the_payload` (counting allocator) |
| 2 | low | `destroy_lane` swept the dependencies of every job on the lane, including the running one kept by the round-4 fix, and the dispatch released them again at settlement: `saturating_sub` hid it while the dependency's waiter count dropped to zero under a running job (premature trim eligibility) | **fixed**: the sweep is gone; `fail_job` releases doomed jobs and a running job releases its own at settlement; `destroying_a_lane_does_not_release_a_running_jobs_dependency` (reads the waiter count from inside the provider; fails with the sweep restored) |
| 3 | low | a lane name was checked for length only, while channel names and topics are validated text | **fixed**: `valid_text`; `lane_and_channel_names_are_validated_text` |
| 4 | low | subscriptions only grew, so a lane at its ceiling could never subscribe again and read access could not be withdrawn | **fixed**: `Agent::unsubscribe`; `a_lane_can_release_a_subscription` |
| 5 | low | `destroy_channel` dropped a backlog with no event | **fixed**: `channel.destroyed` with the dropped count, in the closed name set, the projection, the replay trace and the spec; `destroying_a_channel_reports_its_backlog` |
| 6 | low | channel names are not unique and the docstrings said a peer subscribes by name | **fixed**: the docstrings say a channel is addressed by its id; names are operator labels |
| 7 | carried | `recv` is ambient for a holder of the `Agent` | **ADR-0024**: a subscription is kernel-local state, not authority; the advisory gate stays, untrusted code never holds the `Agent`, and a capability-mediated receive is a future feature with its own ADR |

Gate: `cargo test --all-features` 742 passed, 0 failed; clippy and fmt clean.

### R-06 budgets - 2026-11-02 (round 6)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `3e31202`. It verified N1-N4
and `is_tainted`, and found five siblings of the patterns the previous rounds
fixed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `publish` measured the payload with `wire_size` before the shape gate (the call path's round-5 sibling) | **fixed**: the gate runs before the measurement; `a_hostile_publish_is_refused_before_the_kernel_measures_it` |
| 2 | medium | dispatch computed the resolved argument bytes and walked the path scope before the shape gate | **fixed**: the gate runs first over the substituted arguments; `a_promise_that_resolves_to_a_hostile_value_is_refused_at_dispatch` |
| 3 | high | `path_outside_scope` was recursive, so a deep value could abort the process in the check that exists to refuse it | **fixed**: iterative with an explicit stack; `a_deep_path_nest_is_walked_iteratively` |
| 4 | low | the idempotency gate used the capability budget alone, and the method name was cloned into the key before any bound | **fixed**: the gate intersects the lane budget; a method longer than a grant is `rpc/invalid-argument` before anything copies it (`MAX_GRANTED_METHOD_BYTES`); `the_idempotent_gate_uses_the_lane_intersection`, `an_oversized_method_name_is_refused_before_it_is_copied` |
| 5 | low | `fail_job` and `Agent::resolve` still counted a cancelled promise as a double settlement | **fixed**: both check the cancelled state, like phase 3 |

Residual, documented in the security model: `Value` has a derived destructor, so
a value nested tens of thousands deep overflows the stack when dropped. Every
wire path bounds depth at 64 and every kernel walk is iterative; only in-process
code that builds such a value can reach it, and an iterative destructor would
forbid destructuring the crate's primary data type by value. Tracked for a major
version.

Gate: 749 tests all-features, 0 failed; clippy and fmt clean.

### R-05 lanes / channels - 2026-11-02 (round 3)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `3e31202`. It verified all
six round-2 fixes and found five more.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | medium | the lane/channel name error said `1..=1024 bytes`, the constant was 256, and the spec said 128 (the topic rule) | **fixed**: one bound (128 everywhere), messages name it, and the test checks the message |
| F2 | medium | `unsubscribe` answered `Ok` for a destroyed channel while every other channel operation answers `rpc/unknown-channel` | **fixed**: the channel is looked up first; `unsubscribing_from_a_missing_channel_is_refused` |
| F3 | high | at dispatch, a job whose lane record was gone fell back to the capability budget: a wider grant in exactly the case that should fail closed | **fixed**: a missing or closed lane is `rpc/unknown-lane`; the budget is still intersected when the lane is live |
| F4 | low | `subscribe`, `unsubscribe` and `close_channel` were silent, so the tape did not show who gained read access or when sends stopped | **fixed**: `channel.created`, `channel.subscribed`, `channel.unsubscribed`, `channel.closed` in the closed set, the projection, the replay trace and the spec; `subscription_lifecycle_is_on_the_tape` |
| F5 | low | the channel sequence counter used `+= 1` (debug panic at the wrap) | **fixed**: `checked_add`, refused as backpressure |

Gate: 749 tests all-features, 0 failed; clippy and fmt clean.

### R-06 budgets - 2026-11-02 (round 7)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `08896cd`. It verified the
round-6 fixes and found two highs: the out-of-band resolve path and the dispatch
clone.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | `Agent::resolve` stored any value with no shape or byte check: a narrow grant could be answered with a 10 MiB value and no budget was charged | **fixed**: the out-of-band answer is gated against the answering call's `capability ∩ lane` budget and charged as egress before it becomes the promise's value; `an_out_of_band_resolve_is_bound_by_the_grant` |
| F2 | high | dispatch cloned a resolved promise value before any gate, and `Value::clone` recurses | **fixed**: a value deeper than `MAX_VALUE_DEPTH` is refused before the clone (and F1 keeps such a value out of a promise in the first place); `a_deep_resolved_value_is_refused_before_the_dispatch_clone` |
| F3 | medium | the idempotent path copied the method into its key map before the length bound | **fixed**: the bound (and `MAX_ARGS_PER_CALL`) runs at the top of the keyed entry; `an_idempotent_call_bounds_its_method_before_copying_it` |
| F4 | medium | an in-process caller could hand the kernel an unbounded argument vector, making every refusal cost its own length | **fixed**: `MAX_ARGS_PER_CALL` (4 096, the wire's bound) at both entries; `an_unbounded_argument_list_is_refused_before_any_walk` |
| F5 | low | the documented `Drop` residual omitted the derived `Clone`/`PartialEq` recursion | **documented**: the residual covers both, and F1/F2 gate the reachable paths |
| F6 | low | lane byte accounting used `saturating_add`, so a saturated lane would pass forever | **fixed**: `checked_add` in the egress charge |

Gate: 755 tests all-features, 0 failed; clippy/fmt/doc clean; negative controls
9/9.

### R-05 lanes / channels - 2026-11-02 (round 4)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `08896cd`. All five round-3
fixes hold; five new defects.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `recv` reported `rpc/unknown-channel` for a destroyed lane, while every other operation says `rpc/unknown-lane` | **fixed**: `check_subscriber` checks the lane first; `receiving_on_a_destroyed_lane_is_unknown_lane` |
| 2 | medium | `subscribe`/`unsubscribe`/`close_channel` pushed an event even when nothing changed, so a no-op loop could evict the bounded tape | **fixed**: an event only on a state change; `a_no_op_subscription_change_is_not_an_event` |
| 3 | medium | `destroy_lane` pushed a rejection and a completion event per queued job: a full lane wrote tens of thousands of records and evicted the tape | **fixed**: the doomed jobs fail quietly, receipts still record each refusal, and `lane.destroyed` carries the count (now `{ lane, jobs }`); `destroying_a_full_lane_does_not_flood_the_tape` (2 000 jobs, at most 3 events) |
| 4 | low | `charge_dispatch_delta`/`charge_egress` skip the lane when it was destroyed mid-call | **documented in code**: the capability chain is still charged in full and the lane no longer exists, so there is no lane grant left to exceed; erring the other way would refuse a call the provider already ran |
| 5 | low | the topic refusal said "without control characters" while the rule also refuses reordering and invisible characters | **fixed**: one message for the one rule |

Gate: 755 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-06 budgets - 2026-11-02 (round 8)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `174bb7d`. It verified F1-F5
of round 7 and found two mediums and six lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | dispatch cloned the queued arguments before any gate, so a value queued under a wide lane and then narrowed was copied first (a `Value` clone recurses) | **fixed**: the queue-time arguments are shape-gated against the lane's current budget before the substitution loop copies anything; `a_value_queued_under_a_wide_lane_is_gated_after_attenuation` |
| 2 | medium | `resolve` settled a promise whose capability was revoked or whose lane was gone, while dispatch refuses both | **fixed**: the out-of-band answer re-checks the capability (live, unexpired) and the lane before it settles; `an_out_of_band_resolve_rechecks_the_authority` |
| 3 | low | `value_too_deep` pushed every child of a wide value before refusing | **fixed**: it is the bounded `shape_exceeded` probe with the other ceilings disabled |
| 4 | low | the lane byte checks still used `saturating_add` in five places | **fixed**: one checked form at every site, refused as `rpc/budget-exceeded` |
| 5 | low | `BudgetExceeded("args")` mapped to the `other` dimension | **fixed**: `budget_dimension` and the spec's dimension list name `args` |
| 6 | low | the `Value` depth residual did not mention the derived `Clone`/`PartialEq` recursion | **documented**: the security model and the `value` module docs state all three |
| 7 | low | `send` charges the lane, not a capability meter | **documented design**: a channel is not a capability (ADR-0024), so the lane is the only budget a send can be charged to; the security model says so |
| 8 | low | the keyed entry that takes a payload *size* cannot tell two same-length bodies apart | **fixed**: `call_idempotent_as_with_body` fingerprints the content, domain-separated from the size form, whose doc now states the limitation; `an_idempotent_body_is_fingerprinted_by_content` |

Gate: 760 tests all-features, 0 failed; clippy/fmt/doc clean; negative controls
9/9.

### R-05 lanes / channels - 2026-11-02 (round 5)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `174bb7d`. **No critical,
high or medium findings**; two lows, both fixed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | low | closing an open receive-only channel changed its stats with no `channel.closed` event, because the event was gated on `can_send()` | **fixed**: the gate is the channel's `closed` flag; `closing_a_receive_only_channel_is_an_event` |
| 2 | low | `recv_topic` answered `Ok(None)` for a filter the channel could never hold, while publish refuses the same text | **fixed**: `check_topic` after the subscriber check (order preserves the no-oracle rule) and the same rule in `Channel::recv_topic`; `a_receive_filter_is_validated_text` |

Residual risks it recorded, none a defect: subscriptions are ambient by design
(ADR-0024), ids are monotonic and never reused, `calls_refused` counts
entry-point refusals with pre-dispatch drops visible in receipts, and the topic
message exists as two literals (kernel and channel).

Gate: 760 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-06 budgets - 2026-11-02 (round 9)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `15ff0f9`. It verified all
seven round-8 claims and found two highs in the two paths the round had just
touched.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | the queued-argument gate is budget-relative, so a lane whose budget allows a deep value still reached the substitution loop, where the recursive `Value::clone` aborts the process | **fixed**: the absolute wire depth ceiling (`MAX_VALUE_DEPTH`) binds the queued path too; `a_deep_queued_value_is_refused_before_the_dispatch_clone` |
| F2 | high | `resolve` took no peer and never checked `bound_to`, so an out-of-band answer settled a call dispatch would have refused for the wrong identity | **fixed**: `Agent::resolve_as(peer, …)` presents the verified identity and compares the binding; `resolve` presents none and refuses a bound call with `rpc/identity`; `a_bound_capability_needs_its_peer_to_resolve` |
| F3 | medium | `resolve` compared an expiry against a clock it never refreshed in wall-clock mode | **fixed**: `refresh_clock` at entry; `a_wall_clock_expiry_binds_an_out_of_band_resolve` |
| F4 | medium | `call_idempotent_as_with_body` charged for the body but delivered an empty payload to the provider on the miss path | **fixed**: the miss call carries the bytes (`call_with_origin_payload`); `an_idempotent_body_reaches_the_provider` |
| F5 | low | the queue byte sums still saturated (a `u64::MAX` ceiling would pass exactly at `MAX`) | **fixed**: `checked_add` for the argument fold, `args + payload` and the publish `payload + topic` |
| F6 | low | the spec's `dimension` list omitted `args` although the kernel emits it | **fixed**: the table names it |

The control-plane crate also had to follow the round-4 `LaneDestroyed { lane,
jobs }` shape change: the CI run for `174bb7d` was red on `E0164` in
`control-plane/src/plane.rs`, fixed in `ee4fbf1` (the dashboard record now names
the job count). The lesson is recorded in the workspace memory: an event-shape
change is a workspace-wide grep, not a kernel-only edit.

Gate: 764 tests all-features, 0 failed; control-plane 28 + 11 + 7 pass;
clippy/fmt/doc clean; negative controls 9/9.

### R-06 budgets - 2026-11-02 (round 10)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `e83a018`. Round-9 fixes
verified; two highs and four lower findings, all closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `resolve_as` skipped the egress policy dispatch applies: a secret-bearing module was stored on a plain cap, and an unredacted one on a redacting cap | **fixed**: the same `catch_unwind { redact or assert }` runs before the charge, plus the absolute depth gate; `an_out_of_band_answer_obeys_the_egress_policy` |
| 2 | high | the absolute `MAX_VALUE_DEPTH` gate existed only at dispatch, so a deep value could be stored at the queue, the keyed path, `send`, `publish` or `resolve`, where the derived destructor would later abort the process | **fixed**: the absolute depth probe runs next to every ingress shape gate (after it, so a wide value is still refused in constant time) |
| 3 | medium | a cached replay returned a value the lane would no longer allow, with no charge | **fixed**: the hit path re-runs the shape gate against `capability ∩ lane`; `a_cached_replay_obeys_the_narrowed_lane` |
| 4 | medium | a provider answer deeper than the wire reported `rpc/provider` on one side and `rpc/budget-exceeded` on the other | **fixed**: both are budget refusals with the dimension and event; `a_provider_answer_deeper_than_the_wire_is_a_budget_refusal` |
| 5 | low | the dispatch byte sums and one channel sum still saturated | **fixed**: `checked_add` at all of them |
| 6 | low | the recursive redact/assert helpers were reachable with an unbounded value | **fixed by #2**: every stored or settled value is now at most 64 deep |

Gate: 768 tests all-features, 0 failed; clippy/fmt/doc clean; negative controls
9/9; control-plane green.

### R-04 promises / pipelining - 2026-11-02 (round 3, confirmation)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `e83a018`. It re-checked the
two earlier rounds, upgraded one carried low to a high, and found five more.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | a `PromiseHandle` was not bound to its kernel: ids are a per-kernel counter, so a handle from one agent awaited/resolved/cancelled the other agent's call with the same number | **fixed**: `Agent::owns_promise` (pointer identity of the kernel cell) guards `await_promise`, `cancel`, `cancel_tree`, `resolve_as` and `promise_waiters`; `a_promise_handle_names_its_own_kernel` |
| F2 | high | `resolve_as` skipped the egress gates dispatch enforces | **fixed** with R-06 round 10 #1 (one code path) |
| F3 | medium | `cancel_tree` never marked a cancelled *running* promise trim-eligible, so repeated cancellations leaked records to the promise ceiling | **fixed**: every target is recorded settled (idempotent), as `cancel` already did |
| F4 | medium | when a resolve won the race with the provider, dispatch charged egress a second time and then counted the discarded outcome as a kernel double settlement, while the receipt said refused | **fixed**: dispatch skips the charge when the promise is already settled and does not count the discard as a double settlement |
| F5 | low | an unknown capability on the keyed path returned without the refusal accounting every other arm performs | **fixed**: one pre-check that records; the shape block's `?` is now unreachable |
| F6 | low | `JobState::Done` was write-only (set immediately before the record is removed) | **fixed**: the variant and its two references are gone |
| F7 | low | authority refusals that only surfaced at dispatch (revoke, expiry, binding, gone lane) were invisible to `calls_refused`/`identity_refusals` and the tape | **fixed**: phase 3 counts and emits `CallRefused` for them |

The two remaining residuals are documented, not defects: `flush_promise_refops`
can defer a stale reference count when a borrow is held (try_borrow only fails
inside a borrow; rare), and `PipelinedCycle` is a dead fail-closed arm.

Gate: 768 tests all-features, 0 failed; clippy/fmt/doc clean; negative controls
9/9.

### R-06 budgets - 2026-11-02 (round 11)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `aa7a955`. Every round-10
claim held except one hole, which the same pass in R-04 found independently.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `resolve_as` did not check that the handle belongs to this kernel, while every other handle entry does: a handle from another agent could settle a job with the same numeric id | **fixed**: `owns_promise` at the top of `resolve_as`; `a_promise_handle_names_its_own_kernel` (covered through `resolve`, `resolve_as` and `cancel`) |

Residual risks it recorded and this commit closes or accepts: the keyed hit
re-checks shape but not the absolute depth of the cached value (unreachable — a
cache entry is only created from an admitted, gated call); `resolve_as` with no
matching job skips the gates (unreachable — a pending promise always has a
job); `Channel::send*` is public without a shape gate (the kernel gates before
it calls); the `next_promise`/`next_job` counters wrap only at 2⁶⁴.

Gate: 768 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-04 promises / pipelining - 2026-11-02 (round 4)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `aa7a955`. One high (the
same `resolve_as` gap), one medium and two lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `resolve_as` accepted a foreign handle | **fixed** with R-06 round 11 #1 |
| 2 | medium | `cancel_tree` recorded settled promises twice (queued targets in both loops, already-settled dependents re-recorded), inflating the settled size and evicting live records early | **fixed**: the walk collects the promises it actually cancelled, the queued loop records them, and the final loop records only cancelled-minus-queued, once |
| 3 | low | the idempotent hit's `UnknownCapability` arms return without the refusal accounting | **accepted**: the keyed entry pre-checks and records the capability before the hit block, so those arms are unreachable; a comment in the code says so |
| 4 | low | `cancel_tree` returned every dependent it walked as if it had cancelled it | **fixed**: it returns the cancelled set, and the doc says so |

Residuals: `waiters += 1` is non-saturating (bounded by the job ceiling); a
cancelled in-flight job can seal an `Admitted` receipt for a value never
delivered (the caller sees `rpc/promise-cancelled`, the receipt records the
provider's outcome).

Gate: 768 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-06 budgets - 2026-11-02 (round 12, first clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `9335f7e`. **CLEAN** — every
budget gate verified on the shipped path, `resolve_as owns_promise` present with
its test, `cancel_tree` recording settled once.

Residuals it recorded, all accepted or closed here:

- A resolve that races a dispatch may still charge egress on the loser's side
  (fail-closed: it drains the caller's own grant, never over-delivers).
- `Budget::check` allows a `u64::MAX` ceiling, so a minter can authorize a very
  large shape walk against itself. A minter is trusted; the walk is bounded by
  the value it built.
- `send` charges the lane only: a channel is not a capability (ADR-0024).
- An unknown budget dimension maps to `other` for the event label while the wire
  code stays `rpc/budget-exceeded`.

### R-04 promises / pipelining - 2026-11-02 (round 5, first clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `9335f7e`. **CLEAN** —
`resolve_as` enforces `owns_promise`, `cancel_tree` records settled once and
returns only the promises it cancelled.

Residuals, two closed here and one accepted:

- `waiters += 1` is now `saturating_add` (release was already saturating).
- `resolve_as` with no matching job now fails closed for a pending promise
  (`rpc/unresolvable-promise`) instead of skipping every gate; a settled one
  still reports `rpc/promise-resolved`.
- Cancellations have no event of their own (the queued-refusal receipt records
  them when receipts are enabled). Adding a `promise.cancelled` event is a
  schema change with no security dimension; it is left as a documented
  observability gap rather than smuggled into this round.

Gate: 768 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-06 budgets - 2026-11-02 (round 13, second clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `92ca341`. **CLEAN** again,
so the section closes per the loop's rule.

Re-verified on the shipped path: the queue charges before work; dispatch
re-gates under `capability ∩ lane(current)`; the promise-growth delta and the
both-direction egress charge; lane cumulative bytes; monotone attenuation; a
zero ceiling is refused; and `shape_exceeded` bounds every walk before a full
measurement.

Residuals (no action): a lifetime `max_bytes` naturally exhausts a long-lived
lane, so operators mint fresh grants; over-narrow grants deny availability,
which is the safe direction; `to_active_budget.max_keys` is tighter than either
parent ceiling, also the safe direction.

### R-04 promises / pipelining - 2026-11-02 (round 6, second clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `92ca341`. **CLEAN** again.
It verified `src/promise.rs`, the dispatch/cancel/idempotency paths, ADR-0005,
the wire spec's promise and cycle codes, and the 27 promise + 2 cancellation +
3 idempotency tests.

Checks held: lane-scoped dependencies, the envelope's authority refusal, the
revoke/expiry/identity re-check at dispatch, the pre-work budget charge plus the
dispatch delta and egress, single settlement with the cancelled and
out-of-band guards, cycle detection, the secret-free fingerprint, and
handle-pinned retention.

Residuals (no action): the `u64` promise counter wraps only at 2⁶⁴; pinned
handles plus the 1024 idempotency entries bound retention by design;
cross-provider chains cost one batch per provider by design.

### R-03 capabilities - 2026-11-02 (round 4, confirmation)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `d4a40bc`. It verified the
round-1..3 invariants (monotone attenuation on every field including the clock
domain, no escalation through introduction or restore, revocation reaching
descendants and tombstones, export carrying the remainder) and found two highs
in the handle API.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `attenuate` accepted a borrowed/imported handle: a borrow laundered a grant and pinned the owner's record alive through `descendants` | **fixed**: an imported handle is `rpc/identity` (the owner attenuates); `a_borrowed_handle_neither_attenuates_nor_revokes` |
| 2 | high | `revoke` accepted a borrowed handle, so any channel receiver holding an id could kill the sender's grant | **fixed**: the same ownership guard on `revoke` |
| 3 | medium | `restore` checked the tombstone before the binding, contradicting its own ordering comment: a wrong peer could probe which record ids were revoked | **fixed**: binding first, then the tombstone; `a_tombstoned_record_reports_the_binding_first`; the two older tests now present the record's peer |
| 4 | low | an expired export returned `Revoked` with no `cap.expired` event | **fixed**: the event, like every other expiry path; `an_expired_export_is_an_expiry_event` |
| 5 | low | `Lane::complete` used an unchecked increment | **fixed**: `saturating_add` |
| 6 | low | `path_scope` and tool-policy names were not validated as text at mint, while the record parser refuses them: a mint could produce an unexportable capability | **fixed**: `MAX_PATH_SCOPE_BYTES` and the method-name rule in `check_method_names`; the two tests that relied on the mint accepting an unreadable scope now assert the mint refuses it |
| 7 | low | `from_peer` was never `true`, so the envelope authority guard existed twice and the generic choke point never fired | **fixed**: `call_from_envelope` passes `from_peer=true` and its duplicate loop is gone |

### R-02 kernel dispatch - 2026-11-02 (round 4, confirmation)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `d4a40bc`. Rounds 1-3 hold;
two highs and three mediums.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | an out-of-band resolve sealed no receipt, so the losing dispatch sealed `Refused` while the caller held a value | **fixed**: the resolve marks the job receipted before its cleanup and seals `Admitted`; a discarded dispatch outcome seals nothing; `an_out_of_band_resolve_seals_an_admission` |
| 2 | high | egress skipped the lane leg when the lane was gone (a provider that destroyed its own lane mid-call could return a huge value unbilled) | **fixed**: a missing lane is `rpc/unknown-lane`; the mid-batch test now expects the running call's response to be refused |
| 3 | medium | `fail_job` never counted `calls_refused` and emitted no `CallRefused`, so a destroyed lane's jobs were invisible to the counters | **fixed**: the counter always, the event unless the destroy is coalescing |
| 4 | medium | a cached replay is served with no egress charge | **rejected with reasoning**: a replay performs no new delivery and no new provider work — that is the property the key exists for (R-04 round 2 #9), and charging it would make a retry fail exactly when the grant is tight |
| 5 | medium | a panic in phase 1 or phase 3 stranded the rest of the batch (already dequeued, never scheduled) | **fixed**: `BatchGuard` fails any batch job still present on the way out |
| 6 | low | a batch for a provider that vanished still emitted `BatchDispatched` and advanced the round-trip counter | **fixed**: the counter and the event come after the provider check |

Gate: 771 tests all-features, 0 failed; control-plane green; clippy/fmt/doc
clean; negative controls 9/9.

### R-03 capabilities - 2026-11-02 (round 5, first clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `69415e0`. **CLEAN** — every
round-4 fix verified on the shipped path: the ownership guards on
`attenuate`/`revoke`, the restore order (seal, binding, tombstone), the
`cap.expired` event on an expired export, the mint's `path_scope`/tool-name
text rules, the single `from_peer` guard, and the saturating lane counter.

Residuals (low, no action): the record parser defers scope control characters
and tool names to `mint_restored`'s `check_method_names`, so the error class is
`rpc/invalid-argument` rather than `rpc/persistence` (the record still needs a
valid seal to get that far); `CapAttrs` can express `topics=Some` with
`publish=false`, an incoherent but non-escalating grant; `is_attenuation_of`
answers "a child must not add a binding" by relying on `attenuate`'s inherit,
which is documented; the record-id sets fail closed at their ceiling.

### R-02 kernel dispatch - 2026-11-02 (round 5)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `69415e0`. Round-4 fixes
verified; two highs and one medium, all closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `cancel` treated a batched-but-not-started job as "running" (its lookup was queue membership, and the batch dequeues), and dispatch never re-checked the promise, so a cancelled or answered job still ran its provider | **fixed**: `cancel` removes a job whose state is `Queued` wherever it is, and dispatch phase 1 refuses to run a job whose promise is already settled; `a_batched_job_cancelled_by_an_earlier_call_does_not_run`, `a_batched_job_answered_by_an_earlier_call_does_not_run` |
| 2 | high | cancelling a running job sealed no receipt, so executed work had no decision on the tape | **fixed**: `cancel` seals `Refused("rpc/promise-cancelled")` and marks the job receipted; `cancelling_itself_is_on_the_tape` |
| 3 | medium | a dispatch-only `PathNotGranted` (a pipelined value escaping the scope) bumped no counter and emitted no event | **fixed**: the dispatch accounting arm covers path, method, read-only, topic, promise and settlement classes; `a_dispatch_time_path_refusal_is_counted` |

Gate: 775 tests all-features, 0 failed; control-plane green; clippy/fmt/doc
clean; negative controls 9/9.

### R-03 capabilities - 2026-11-02 (round 6, second clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `79a54bc`. **CLEAN** again,
so R-03 closes per the loop's rule. It reports no bug, race, panic, exhaustion,
escalation, oracle, wire or error-code defect in `src/cap.rs` or the kernel's
capability paths.

Residuals (no action): transferring a token through the CLI's `hex()` is a
deliberate authority transfer; `next_serial` wraps only after 2⁶⁴ mints with the
live set capped; a wall-clock restore relies on the deployment's clock setting
and refuses a mismatch; ancestor `descendants` counters saturate, bounded by
`MAX_LINEAGE_DEPTH`.

### R-02 kernel dispatch - 2026-11-02 (round 6)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `79a54bc`. Three mediums and
one low; three fixed, one documented.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the out-of-band flag was set only on the success branch, so a running job settled out of band (cancel or resolve) whose provider then failed sealed a second receipt and counted a double settlement | **fixed**: the flag is the promise's state, computed once before either branch; `a_cancelled_running_job_seals_one_receipt_even_when_it_fails` |
| 2 | medium | cancelling a queued job sealed a receipt but bumped no counter and emitted no `call.refused`/`job.completed`: the tape ended at `call.queued` | **fixed**: the counters and both events, in `cancel` and in `cancel_tree`; `cancelling_a_queued_job_is_an_event_and_a_refusal` |
| 3 | medium | a dispatch `BudgetExceeded`/`ToolPolicy` bumped only its dimension counter, so `call.refused` alerts missed it | **fixed**: both arms count `calls_refused` and emit `CallRefused`; `a_dispatch_budget_refusal_is_a_refused_call` |
| 4 | low | dispatch does not re-check the method grant, read-only or the tool allow-list | **documented**: capability attributes are immutable after the mint except the binding, which dispatch does re-check; the arms exist for a future attenuation of a live capability |

Gate: 778 tests all-features, 0 failed; clippy/fmt/doc clean; negative controls
9/9.

### R-01 wire ARP1 - 2026-11-02 (round 3)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `e346633`. It verified the
round-2 ceilings and found three mediums and one low.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | the delta's two count fields returned `rpc/wire` on truncation while the base and the ids were `rpc/capability-table` | **fixed**: both counts map to the table class; `a_truncated_delta_is_a_capability_table_fault` |
| 2 | medium | a non-canonical map accepted descending keys (and a descriptor descending methods): decode sorted the map, re-encode differed, so two images named one value and the raw-hash agreement a replay relies on broke | **fixed**: map keys and descriptor methods must be strictly increasing; `a_non_canonical_map_is_refused`, `a_non_canonical_method_order_is_refused` |
| 3 | low | the descriptor path scope was a hardcoded 1024 bytes, so a strict peer still accepted a 512-byte scope | **fixed**: `WireLimits.max_path` (1024 default, 128 strict); `a_strict_profile_bounds_the_path_scope` |
| 4 | medium | `Value::shape`/`wire_size`/`is_tainted` pushed every child of a container before visiting any, so a standalone caller of `wire_size` on a hostile wide value allocated one work item per element | **fixed**: one frame per open container in all three, like `shape_exceeded`; the kernel's gates were already bounded, this closes the direct-call path |

Residual: the report's own note that `wire_size` remains O(n) for an admitted
value — it is a measurement, and every caller that must refuse chooses
`shape_exceeded` first.

Gate: 790 tests all-features, 0 failed; clippy/fmt/doc clean; control-plane
green; negative controls 9/9.

### R-02 kernel dispatch - 2026-11-02 (round 8)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `e346633`. One medium and two
lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | medium | `cancel_tree` treated a batch job that had not started as a running one, so it sealed a receipt but counted nothing and emitted no `call.refused` (the `cancel` path did both) | **fixed**: a job whose state is `Queued` is cancellable wherever the batch put it; `a_tree_cancel_of_a_not_yet_started_job_counts_it` |
| 2 | low | the pre-substitution gate used the budget copy taken at queue time, so a capability or lane attenuated in between let the value be cloned before the refusal | **fixed**: the gate uses the capability's current budget intersected with the lane's |
| 3 | low | `fail_job` counted a promise answered out of band as a double settlement (it excluded only `Cancelled`) | **fixed**: a failed reject means the promise was already settled by a caller decision or a repeated failure, and neither is a kernel double settlement |

Gate: 790 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-01 wire ARP1 - 2026-11-02 (round 4, first clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `283d803`. **CLEAN** — the
delta counts and their bounds, the strictly increasing map keys and descriptor
methods, `max_path` (1024 default, 128 strict), and the one-frame-per-container
walks in `is_tainted`/`shape`/`shape_exceeded` all verified on the shipped path.

Two of its residuals are closed here: the argument wire size now counts the tag
byte (an argument was undercharged by one byte), and a truncated capability
count is `rpc/capability-table` like the rest of the table. The rest are
documented: the wire accepts method and scope text the mint refuses (the call
path refuses it, and a refusal event must be able to carry any name); the
capability-table order is not enforced (the delta base is a hash of the exact
bytes by design); kind-specific body shapes are the transport's check.

### R-02 kernel dispatch - 2026-11-02 (round 9, first clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `283d803`. **CLEAN** — the
`cancel_tree` Queued classification, the current-grant dispatch gate and the
`fail_job` settlement rule verified, with 11/11 dispatch tests.

Two of its residuals are closed here: the promise substitution now shape-gates a
resolved value before copying it (an over-grant value doubled its memory before
the refusal), and `cancel_tree` on a cancelled root answers
`rpc/promise-cancelled` like `resolve`. The remaining two are by design: a
running-cancel seals a receipt but no `call.refused` (the provider already ran),
and a stuck pipeline reports the cycle before the authority refusal.

Gate: 790 tests all-features, 0 failed; clippy/fmt/doc clean.

### R-02 kernel dispatch - 2026-11-02 (round 10, second clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `7258f47`. **CLEAN** again,
so R-02 closes per the loop's rule. It verified the settled-job skip, the
revoke/expiry/binding/lane re-checks, the gate and effective budget plus
`charge_dispatch_delta`/`charge_egress` before settlement, the secret
redact/assert, one receipt with `calls_refused`/`call.refused`, no double
settlement on the cancel/resolve race, and the panic guards; the 11 dispatch
tests and the full suite pass.

Residuals, no action: `order_candidates` is quadratic for a 100 000-job batch
(bounded by the job ceiling and a pathological shape); `fail_job` and a dispatch
provider refusal count differently by design (one never ran, the other did);
`Arg::Cap` is a bearer transfer by ADR-0004.

### R-01 wire ARP1 - 2026-11-02 (round 5, second clean pass)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `7258f47`. **CLEAN** again,
so R-01 closes. It probed `wire.rs`, `value.rs`, the round-2 tests and the wire
spec: fail-closed decode with the `rpc/wire` / `rpc/capability-table` split,
canonical map and method order, the arena and depth ceilings, bit-exact floats,
and no secret bytes on the wire.

Residuals, no action: the `as u32` length casts are unreachable without an OOM
first; `with_capacity` is bounded by the receiver's limits; a duplicate added
descriptor is refused by `apply_to` rather than decode (same class); `Value::Path`
and `Module` are bounded by the envelope and the dispatch budget.

### R-07 domain operations - 2026-11-02 (round 7)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `79b6c8c`. Rounds 1-6 stand;
two highs and two mediums, all closed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `effects_within_scope` followed constraint expressions in a single pass, so with the annotations recorded in reverse order the tail was missed and a scoped write went through that the forward order refused | **fixed**: the walk is a fixpoint, like `scope_closure`; `a_reverse_order_constraint_chain_is_followed_to_its_end` |
| 2 | high | a redacting caller could compare the `parent` content address in the provenance (on a patch cone and in the `provenance` answer) with a guessed hash: an equality oracle over secrets | **fixed**: a redacting patch cone carries no provenance, and a redacting `provenance` answer omits `parent`; `a_redacting_patch_cone_carries_no_provenance` |
| 3 | medium | the wall ceiling was measured before the metadata work (so it always passed) and the scoped evaluate path never checked it | **fixed**: the check runs after the answer is built, and evaluate measures its own work |
| 4 | medium | the evaluator's depth ceiling is larger than the wire's, so its answer was converted (recursively) before the wire could refuse it | **fixed**: an iterative `active_value_too_deep` gate refuses a result deeper than `MAX_VALUE_DEPTH` before the conversion |

Gate: 799 tests all-features, 0 failed; clippy/fmt/doc clean; control-plane green;
negative controls 9/9.

### R-08 tools and MCP - 2026-11-02 (round 3)

Reviewer: Muse through the Copilot CLI, `xhigh`, at `79b6c8c`. The 24 earlier
fixes hold; two highs and four mediums, plus three lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the HTTP reader armed the socket timeout once and each byte reset it: a peer dripping one byte per period could hold a 150 ms grant for minutes | **fixed**: lines and bodies are read in chunks with the socket re-armed and the deadline re-checked per chunk; `a_dripping_body_cannot_stretch_the_wall_ceiling` |
| 2 | high | `StdioTransport::send_line` blocked with no deadline: a server that stops reading plus a large frame wedged the dispatch thread | **fixed**: a writer thread, `send_line_within(deadline)`, and the session passes its deadline; `a_stalled_mcp_reader_cannot_block_the_send` |
| 3 | medium | a failed send left the stream desynchronised without poisoning the session | **fixed**: poison before returning, like a framing error |
| 4 | medium | the shell metacharacter set missed glob, brace, tilde and comment syntax, so a prefix grant plus a shell listed the filesystem through stdout | **fixed**: `* ? [ ] { } ~ # !` added (backslash stays legal: it is a path separator on Windows); `a_prefix_argument_cannot_expand_a_glob` |
| 5 | medium | `to_uppercase` mapped `ß` to `SS` (an alias of an allowlisted method) while the token check refused legal `M-SEARCH` | **fixed**: ASCII uppercase and the RFC 9110 token set; `the_http_method_is_ascii_and_a_token` |
| 6 | medium | several adapters silently dropped part of a request (a second text or path, a body on a bodyless method, an envelope payload) | **fixed**: one method, one path, one body object; a body on a bodyless method and a payload the adapter cannot send are `rpc/invalid-argument`; `an_undeliverable_request_is_refused` |
| 7 | low | a secret argument travelled to an external peer as `***SECRET***` | **fixed**: MCP and HTTP refuse a tainted argument with `rpc/tool-policy`; `a_secret_argument_is_not_sent_to_a_peer` |
| 8 | low | the HTTP parse accepted a status below 100 as success, ignored a colon-less header line, and never validated the base | **fixed**: 200..=599 only, colon-less lines refused, base and path must be printable ASCII; `a_malformed_http_answer_is_refused` |
| 9 | low | a failed `set_read_timeout`/`set_write_timeout` was swallowed, falling back to blocking I/O | **fixed**: both are `rpc/timeout` |

Gate: 799 tests all-features, 0 failed; clippy/fmt/doc clean; control-plane green;
negative controls 9/9.

### R-08 tools / MCP - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `0953e7a`
(probes compiled against an isolated `git archive` snapshot because this
worktree was being edited). Five highs, four mediums, six lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `LocalProcess` joined its pipe readers with no deadline: a descendant that inherited the pipe kept the call alive past the ceiling (measured 8.2 s on a 300 ms grant) | **fixed**: the readers report over a channel and the wait is bounded; `taskkill /T` ends the tree on Windows; `capability_wall_budget_caps_a_slow_tool` (19 s child, 120 ms ceiling, returns < 5 s) |
| 2 | high | MCP had no deadline: a silent server held the dispatch thread forever | **fixed**: the transport trait has a deadline-aware read, `StdioTransport` reads on a thread and abandons the wait; `a_silent_stdio_server_times_out` (real silent child at 400 ms) |
| 3 | high | `HttpTool` ignored the wall ceiling (fixed 10 s, no write timeout) | **fixed**: read and write timeouts are `min(10 s, ceiling)` |
| 4 | high | HTTP connect was unbounded (21.15 s measured to a blackhole) | **fixed**: resolve, then `connect_timeout` per address under the ceiling |
| 5 | high | the response status and header lines were unbounded (a 64 MiB line accepted; a header stream aborts the allocator) | **fixed**: `read_line_bounded` per line plus a 64 KiB / 128-field block budget |
| 6 | medium | after an over-long MCP line the session resynchronised on the tail, so one stream answered two calls | **fixed**: the reader thread stops on a framing error, so the tail can never answer a later request |
| 7 | medium | the tool-list duplicate check was a scan (32 000 tools: 12.7 s) | **fixed**: a `BTreeSet` |
| 8 | medium | a bare program name resolves through the ambient `PATH`; `cwd` is inherited | **carried**: requiring an absolute program path is a contract change (the control plane spawns `cmd`/`sh` by name); logged for the R-19 control-plane pass |
| 9 | medium | a timeout kills the child, not its descendants, and the readers were detached | **partly fixed**: the tree is ended on Windows and the reader wait is bounded everywhere; a Unix process group needs a `libc`-level `setsid`, carried |
| 10 | low | `Transfer-Encoding: chunked` was returned as a body | **fixed**: anything but `identity` is refused, as are 1xx and non-`HTTP/1.x` status lines |
| 11 | low | a GET always sent `content-length: 4` | carried with #8 (the request shape belongs to the same pass) |
| 12 | low | the outbound MCP line was uncapped | **fixed**: refused before send |
| 13 | low | non-text process arguments were silently dropped | **fixed**: `rpc/invalid-argument` |
| 14 | low | an MCP notification desynchronised the session | carried: fail-closed today (an unexpected frame is fatal), a skip-up-to-N rule is a protocol decision |
| 15 | low | `bounded_description` missed U+2028/U+2029 and invisible formatters | carried with #8 (same small edit) |

Gate: `cargo test --all-features` 469 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-19 control plane - 2026-11-02 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `1a949e4`.
No critical; the reviewer confirmed no authority reaches the UI model (every id
is a correlation hash, peer fingerprints are truncated, `Value::Secret` carries
no content). Three highs, five mediums, eight lows.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| P1 | high | `redaction_ok` failed open: a projection error became `""`, which does not contain the canary, so the health flag said PASS | **fixed**: fail closed on a projection error |
| P2 | high | a wrapped kernel tape was silently trimmed (`min(tape.len())`) and the cursor advanced past the hole, leaving an audit gap with no marker | **fixed**: `events_since` + an explicit `event_gap` record with the count |
| P3 | high | only the WS upgrade checked Origin; any page could POST `/demo/scenario`, `/demo/level` or `/benchmark/run` at the loopback plane, and DNS rebinding made the snapshot readable | **fixed**: a `loopback_only` middleware on every route (foreign `Host` refused; a foreign `Origin` on a mutating route refused; an absent one is a local script); `a_foreign_host_is_refused`, `a_cross_origin_post_is_refused` |
| P4 | medium | a scenario could report success while its own stage was red | **fixed**: the verdict is the conjunction with the last stage |
| P5 | medium | the call storm accepted any refusal as the budget ceiling | **fixed**: only `rpc/budget-exceeded` counts, other errors are counted separately and fail the probe |
| P6 | medium | provider payloads are echoed into the operator surface unlabelled, and the "canary absent" test could not exercise the echo path | **fixed in part**: the echo is `{:?}`-quoted and truncated; the test still cannot carry provider text into the snapshot, which is noted |
| P7 | medium | WS lag was swallowed (`RecvError::Lagged` → nothing), so the dashboard skipped state silently | **fixed**: the socket pushes an `event_gap`-shaped message with the skipped count |
| P8 | medium | "budget pressure", `pipeline_depth`, `caps_live` and `observers` do not mean what their captions say | noted (demo gauges); `observers` is the one an operator acts on and is listed below |
| P12 | low | `UiEvent.method` was always `None` although the kernel records the method | **fixed**: populated from `Event::CallQueued` |
| P16 | low | two `innerHTML` sinks interpolated `event.category` raw | **fixed**: `escapeHtml` on both |
| — | low | benchmark, process-stage label, duplicate cores, `catch_unwind` torn state | noted: the benchmark and the stage label are demo fixtures with their own tests; the core duplication and torn state are recorded |

Recorded: the demo gauges (P8), the benchmark's unconditional `ok`, the
per-core HTTP stub, and the `catch_unwind` torn state are demo-surface
simplifications, documented rather than fixed; none of them hides a failed
security check.

Gate: `cargo test` 31 passed (1 + 6 API + 25 plane), clippy clean.

### R-18 CLI - 2026-11-02 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `026c122`,
driving the built binary against scripted hostile peers. No critical; four
highs, eight mediums, seven lows. The pattern was "the binary tells the operator
what it decided, not what happened": a non-response read as success, an ignored
flag that silently downgraded a transport, a raw bearer id on stdout.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| C1 | high | `call`/`pipeline` treated every kind except `Error` as success, so a `Hello` or `Request` reply exited 0 | **fixed**: only `Kind::Response` is an answer, the request id must match, and every non-response counts as a failure in `pipeline`; `a_reply_that_is_not_a_response_is_a_refusal`, `a_reply_for_another_request_is_a_refusal` |
| C2 | high | the peer printed the raw capability id (bearer authority) while help claimed it printed none | **fixed**: the default announcement prints the correlation id; `--emit-cap-hex` is the transfer form and the help says it is authority; tests pass the flag |
| C3 | high | unknown flags were ignored and `--flag=value` unparsable, so `--transport=quic` ran plaintext TCP and `--paylod` sent nothing with exit 0 | **fixed**: `--name=value` parses, every command has an allowlist (`reject_unknown`), a transport outside the four names is a usage error; `flags_accept_the_equals_form_and_unknown_options_are_refused` |
| C4 | high | no read or write deadlines: a silent peer hung `call`/`pipeline`, and `peer --limit` could not be reached | **fixed**: `TcpTransport::connect_with_timeout`/`with_timeout`, `--timeout-ms` on the client commands, a 10 s deadline on a served connection |
| C5 | medium | `parse_cap` sliced a 32-*byte* non-ASCII `--cap` and panicked (exit 101) | **fixed**: `is_ascii` check; `a_non_ascii_capability_is_a_usage_error` |
| C6 | medium | a peer-supplied method was printed raw, so a newline or an ANSI escape forged a line on an exit-0 path | **fixed**: `{:?}` in the description and the refusal |
| C7 | medium | `dechunk`'s `cursor + size` overflowed and panicked on a hostile chunk size | **fixed**: checked adds plus a body ceiling; `a_hostile_chunk_size_is_a_transport_error` |
| C8 | medium | the certificate and the receipt key were read unbounded | **fixed**: both go through `read_bounded` (65 bytes for a key) |
| C9 | medium | `loadgen` silently raised `--requests` to `--concurrency`, and threads were uncapped | **fixed**: a usage error when requests < concurrency, concurrency capped at 1 024 |
| C10 | medium | the demo receipt key is a source constant, so "macs verified" proves nothing about a real kernel | **fixed in the output**: `receipts dump` says the key is public and the log proves the format |
| C11 | medium | `receipts show` printed a possibly forged log as plain evidence, and `--limit 0` exited 0 with no output | **fixed**: a header says the listing is unverified structure, and `--limit 0` is a usage error |
| C12 | medium | `receipts repair` printed a bare `ok` while proving only framing | **fixed**: it says "structure only; pass a receipt key" |
| C13 | low | no request-id correlation | **fixed** with C1 |
| C14 | low | `doctor` prints compile-time facts and cannot fail | noted: it reports the build, and the exit code is the build's |
| C15 | low | `--limit 0` means "forever" on tcp and 1 on the other transports | documented in the help |
| C16 | low | a reason-phraseless `200` was rejected | **fixed**: the status code is parsed, not substring-matched |
| C17 | low | empty flag values silently fell back | **fixed**: `reject_unknown` refuses an empty value |
| C18 | low | the key-file permission check is unix-only | documented: Windows ACLs are the deployment's |
| C19 | low | vacuous tests (help list, a literal `round_trips=1`) and no hostile cases | **fixed**: the help list covers every command, and `tests/hostile_input_tests.rs` (5) drives the four hostile paths |

Gate: `cargo test --all-features` 597 passed, 0 failed across 68 suites;
`--no-default-features` 537 passed, 0 failed; CLI 17 + 5 hostile tests; clippy,
fmt and `cargo doc -D warnings` clean on both feature sets.

### R-17 introduction and topics - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `5bc90f7`,
with probes. No critical; two highs, six mediums, three lows. The first high is
the kind of gap that only a probe finds: the isolation the multi-tenant test
advertised was the sequential channel id, not a check.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| T1 | high | `recv`/`recv_topic` took only a `ChannelId` and never consulted `subscribers`, so any lane could drain any channel (ids are a counter) | **fixed**: both take the lane and require a subscription; the refusal is `rpc/unknown-channel` so ids are not an oracle; `a_lane_that_did_not_subscribe_cannot_read_a_channel` |
| T2 | high | topic grants filtered publishers only; a message carried no publisher, so a subscriber could not tell two publishers apart | **partly fixed**: the root cause (any cap could publish) is closed by the publish grant; per-message publisher identity is recorded as the residual below |
| T3 | medium | any live capability was a publish grant | **fixed**: `CapAttrs::publish` (default false, monotone, persisted), `allow_publish`/`restrict_topics`; `publishing_requires_an_explicit_grant`, `attenuation_cannot_add_the_publish_grant` |
| T4 | medium | topics were unvalidated: empty was publishable, no ceiling, control characters reached an error verbatim | **fixed**: 1..=128 bytes, no control characters, at the grant and at publish; `a_topic_must_be_bounded_and_printable` |
| T5 | medium | `Agent::channel` returned a detached clone whose mutators reported success | documented: the type is a snapshot; the mutating methods are for the kernel's own use |
| T6 | medium | an introduction was not canonical: provider order and duplicate methods changed its bytes (and the fingerprint) | **fixed**: sort providers, sort and dedupe methods; `an_introduction_is_canonical_whatever_order_the_caller_used` |
| T7 | medium | `introduce_to` binds the live subtree irreversibly, so the grantor loses local use | documented as the intent in ADR-0017 (hand-over, not share); an embedder that wants to keep authority attenuates a child |
| T8 | medium | `channel.push` reported a full queue as a spent budget, and `publish_inner` charged before queueing | **fixed**: both ceilings are `rpc/backpressure`, which `note_refusal` does not count as an exhaustion |
| T9 | low | introduction names were unbounded and the encode error lost its reason | **fixed**: `check_name` + the reason kept; `an_introduction_refuses_an_unprintable_name` |
| T10 | low | no test touched receive isolation, empty/huge/control topics, or the publish grant | **fixed**: `tests/intro_topic_hardening_tests.rs` (6) plus the updated topic/lane/multi-tenant suites |
| T11 | low | `queued_size` duplicated the kernel's byte formula | noted: the two agree, and the count check in the kernel now matches the channel |

Recorded residual: `Message` does not name the publishing capability, so two
grants for the same topic are indistinguishable to a receiver. Adding the
publisher correlation id to `Message` is additive and is the next step.

Gate: `cargo test --all-features` 597 passed, 0 failed across 68 suites;
`--no-default-features` 537 passed, 0 failed; clippy, fmt and
`cargo doc -D warnings` clean on both feature sets; control plane 30, CLI 17.

### R-16 security helpers - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `179c3ff`,
with probes. No critical. Two mediums and two lows; the reviewer also ran a
second independent pass and recorded four refuted hypotheses, which is why the
report is short.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| S1 | medium | `CapabilityRecord::attrs` was public and unauthenticated: `from_json` never checks a seal, so a record with `seal: null` (or an edited one) could be turned into `CapAttrs` and minted, bypassing the tombstone and replay protection. The crate's own test advertised the bridge | **fixed**: `attrs` is `pub(crate)`; the audited path is `restore_capability` (seal, tombstone, binding, clock), and SECURITY.md says the parser is not a verifier; `an_unsealed_record_parses_but_never_restores` |
| S2 | medium | the "already restored" set was per process, so a restart (or a second kernel) restored the same sealed record again and re-funded the full budget | **fixed**: `RecordStore` + `MemoryRecordStore`, `Agent::restore_capability_with`; the store is marked after the mint and a store that cannot write refuses the restore and revokes the grant; `a_record_restores_once_across_kernels_sharing_a_store`, `a_store_that_cannot_remember_refuses_and_revokes_the_grant` |
| S3 | low | `assert_no_secret_material` and `redact_value` passed `Value::Module` through: a module is the one variant that can carry a secret | **fixed**: both decode the module, one shared `security::redact_module` (also used by the domain provider), and the catch-all arm is now an explicit match; `a_module_that_carries_a_secret_is_refused_and_redacts` |
| S4 | low | `export_capability` could emit a record the parser refuses (path scope over 1 KiB, provider name over 128 bytes), after reserving the grant and consuming the record id | **fixed**: the record round-trips through `from_json` before the reserve; `an_export_that_would_be_unreadable_is_refused_before_it_costs_anything` |
| — | low | the parser reported a bad record budget as `rpc/invalid-argument` while restore said `rpc/persistence` | **fixed**: the parser speaks the durable vocabulary; `a_record_with_a_zero_ceiling_is_a_persistence_refusal` |

Recorded residual: a deployment still has to *wire* a `RecordStore` (the CLI has
no durable store), so the shipped default is single-use **per process**. The
registers carry it as the deployment half of RPC-5.

Gate: `cargo test --all-features` 591 passed, 0 failed across 67 suites;
`--no-default-features` 531 passed, 0 failed; clippy, fmt and
`cargo doc -D warnings` clean on both feature sets; control plane 30, CLI 17.

### R-15 observability - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `b686836`,
with probes. No critical: no authority or secret reaches a trace. Four highs,
nine mediums, six lows. The theme is *the schema was closed on paper only*: a
projected name was missing from the set, a restarted kernel was indistinguishable
from a quiet one, and three counters disagreed with the tape.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| H1 | high | `provider.panicked` was projected but absent from `EVENT_NAMES` and the spec, and the "closed set" test could not see it (its fixture omitted the variant) | **fixed**: the name is in the set, the spec and the fixture, and the fixture/count assertion now fails when they drift (`project` is the compile-time guard, the size check the runtime one) |
| H2 | high | `events_since(old_total)` on a *restarted* kernel returned `Some([])` — a recorder silently truncated its history instead of failing | **fixed**: `seen_total > total` returns `None` before the subtraction |
| H3 | high | `receipts.dropped` always carried `1` and then never fired again, contradicting the spec and the comment | **fixed**: the marker ladder is 1, 2, 4, 8 … with the running total, and `receipts_dropped` is exported as a counter |
| H4 | high | nothing identified the kernel, so a restart looked like a continuation and a collector merged two number spaces | **fixed**: `metrics_json` exports `events_total`/`events_retained`/`events_evicted` and the spec states that a decrease is a new epoch a collector must not merge |
| M1 | medium | `fail_job` pushed `promise.rejected` and counted it even when the record was already settled | **fixed**: both are gated on the settlement that actually happened |
| M2 | medium | `note_refusal` published the all-zero correlation id as the capability, so "no capability" looked like a real one | **fixed**: `CallRefused.cap`/`BudgetExhausted.cap` are `Option`, and the console renders none |
| M3 | medium | counters and tape disagreed by path: `budget_exhaustions` had no event, `identity_refusals` missed `Error::Identity` in `note_refusal`, and `send_as`/`publish_as` bypassed both | **fixed**: one `note_refusal` used by `call`, `send`, `send_as`, `publish`, `publish_as`, emitting the same event and counter set, with `budget_dimension` naming the ceiling |
| M4 | medium | the bounded tape dropped events with no counter, no event and no metric | **fixed**: `events_evicted`, exported with the gauges |
| M5 | medium | the `promises` gauge meant "retained records" and read as outstanding work | **fixed**: `promises_pending` and `promises_kept` are exported too |
| M6 | medium | the budget `dimension` set was documented as five values while the kernel emits fifteen | **fixed**: the full set is in the spec |
| M7 | medium | closed-label fields are `String` and were copied into `detail` unclamped, so a provider-controlled code reached telemetry raw | **fixed**: `observability::label` escapes and bounds every label at 128 bytes |
| M8 | medium | `BatchDispatched` retained a `BTreeSet` of lanes per record (up to 4 096 per batch) to report a count | **fixed**: the event carries `lane_count` |
| M9 | medium | the metrics test compared the projection with its own source: a counter that was never exported still passed | **fixed**: `counters_agree_with_the_tape` reconstructs each counter from the events |
| L1 | low | `TraceEvent.event` defaulted to an undocumented `"unknown"` | **fixed**: `project` is exhaustive, and the fixture/size check catches a missing arm |
| L2 | low | `round_trips`/`transfers` incremented without saturation | **fixed**: saturating adds |
| L3 | low | `round_trips`/`transfers` were stored twice, so the `Metrics` copy was permanently zero for an embedder that built one | **fixed**: one source (`Metrics`) |
| L4 | low | `cap.expired` repeats on every refused touch of an expired capability | documented: it is the touch that is reported, and the tape is bounded |
| L5 | low | the doc check was substring-only | the table row plus the projection test now pin the name |
| L6 | low | the demo peer returns a capability id in its reply | deliberate transfer; the CLI prints `round_trips` next to it |

Gate: `cargo test --all-features` 584 passed, 0 failed across 66 suites;
`--no-default-features` 524 passed, 0 failed; clippy, fmt and
`cargo doc -D warnings` clean on both feature sets; control plane 30, CLI 17.

### R-14 wasm tools - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `0448410`,
with probes run against the real module. One critical, three highs, five
mediums, six lows. The critical is the first finding in this program that a
`catch_unwind` could not contain: a 130-byte module asked for 1.6 GB of table
and the allocator aborted the process.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| W1 | critical | table elements were unbounded (`StoreLimits` default), so a tiny module forces a tens-of-GB allocation and Rust aborts the host | **fixed**: `WasmLimits::max_table_elements` (default 1 024, ceiling 65 536) is set on the limiter and validated; `a_module_with_a_huge_table_is_refused_without_allocating_it` (refused in < 2 s, not allocated) |
| W2 | high | a guest-sized linear memory was allocated unmetered at instantiate (256 MiB in 3.3 s at ~0 fuel), and the ceiling allowed 1 GiB | **fixed**: the memory ceiling drops to 256 MiB, the store limiter refuses a larger declared memory, and the refusal is classified `wasm/limits`; `a_memory_beyond_the_limit_fails_to_instantiate` |
| W3 | high | no wall or byte budget reached the adapter; `MAX_FUEL` allowed minutes of interpretation under any grant | **fixed**: the call's `max_wall_ms` buys `FUEL_PER_MS` (5 000) fuel and the smaller of the two applies; `MAX_FUEL` drops to 1e9; `a_wall_budget_bounds_the_fuel_a_guest_may_burn` |
| W4 | high | host imports were fixed per tool instance, so any `run` grant inherited clock/random/log and a `read_only` grant ran guest code | **fixed for what a capability can express**: `mutating` is now `true`, so a read-only grant is refused; per-capability import attenuation is recorded as the accepted design of ADR-0019 (the policy is the embedder's, per instance) |
| W5 | medium | `env.clock_ms` read `SystemTime` behind the kernel's back: a covert channel and a replay-determinism hole | **fixed**: the guest reads `Call::now_ms` (new field, the kernel's clock); an embedder outside the kernel seeds `set_time_ms`; `a_granted_clock_import_reports_the_embedder_clock`, `a_guest_reads_the_kernel_clock_through_the_kernel` |
| W6 | medium | the import allow-list matched name only, not kind or signature | **fixed**: `ExternType::Func` with the exact `FuncType`; `an_import_with_the_right_name_but_the_wrong_kind_is_refused` |
| W7 | medium | out-of-fuel during `start` was reported as `wasm/instantiate` | **fixed**: `classify_instantiation` (fuel, import, limits, instantiate); `a_start_function_out_of_fuel_is_a_fuel_refusal` |
| W8 | medium | a non-text argument was dropped and the guest ran on empty input, reporting success | **fixed**: exactly one text/module argument, no payload; `a_call_must_carry_exactly_one_text_or_module_argument` |
| W9 | medium | no fuzz target reached the sandbox | **fixed**: `fuzz_wasm_module` (4000 runs, 155 units, 67 MB RSS, no crash) with valid binary seeds, in all three workflow lists |
| W10 | low | a refused call handed back the previous call's log | **fixed**: `call` clears the log first and `invoke` keeps a trap's log; `a_refused_call_leaves_no_log_from_an_earlier_one` |
| W11 | low | binary output was converted with `from_utf8_lossy`, reporting success on mangled bytes | **fixed**: valid UTF-8 stays text, anything else travels as a module value; `binary_output_travels_as_a_module_value` |
| W12 | low | `mutating` returned `false` while `invoke` mutated provider state | **fixed** (see W4) |
| W13 | low | `used + len` could wrap on a 32-bit host | **fixed**: `saturating_add` |
| W14 | low | WebAssembly text was accepted as module bytes, and compilation is unmetered | **fixed**: the `\0asm` magic is required unless `accept_wat`; tests assemble their fixtures with the `wat` dev-dependency; `a_text_module_is_refused_by_default` |
| W15 | low | the ADR error table omitted `wasm/limits` and the text rule | **fixed**: the table and the limits section are current |

Gate: `cargo test --all-features` 583 passed, 0 failed across 66 suites;
`--no-default-features` 523 passed, 0 failed; clippy, fmt and
`cargo doc -D warnings` clean on both feature sets; `tests/wasm_tool_tests.rs`
24 and `tests/wasm_hardening_tests.rs` 10 (new); `fuzz_wasm_module` 4000 runs,
155 units, 67 MB, no crash.

### R-13 receipts - 2026-11-01 (round 3)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `67713dc`.
Part A: all sixteen round-2 findings COMPLETELY FIXED. Part B: nineteen new
findings, two high. All closed. It also caught a real CI failure before the run
finished: the key file was written `0644`, so the unix permission check refused
it (fixed with `set_permissions(0o600)` and verified in `rust:1.88`).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| N1 | high | the lock steal was check-then-unlink: two stealers could hand the lock to two writers, and a `Drop` then deleted a live lock | **fixed**: the steal is a `rename` (exactly one stealer moves that file) and `Drop` removes the lock only when the file's nonce is ours; `a_stale_lock_is_stolen_instead_of_blocking_forever`, `concurrent_writers_cannot_double_append` |
| N2 | high | `repair` could cut an intact tail: a length field corrupted to another in-range value looks torn by declaration, so good records after it were discarded | **fixed**: `tail_holds_a_record` scans one record past the damage for any record that decodes and refuses the cut; `a_corrupted_length_field_is_not_cut_away` |
| N3 | medium | a pre-dispatch refusal in a restarted session sealed `at_ms = 0`, which then poisoned the whole export | **fixed**: `seal_receipt` refreshes `now_ms` from the wall clock; `a_restarted_session_dates_its_first_refusal` |
| N4 | medium | the CLI test was red on unix (key file `0644`) | **fixed**: `set_permissions(0o600)` under `cfg(unix)`, verified by running the CLI tests in the Linux image |
| N5 | medium | `receipts.dropped` was outside the schema's closed set | **fixed**: `EVENT_NAMES`, a row in `docs/spec/observability.md`, and the variant in `every_event` |
| N6 | medium | the lock path used `with_extension`, so a log named `*.lock` was its own lock and `a.arrl`/`a.json` shared one | **fixed**: `lock_path` appends `.lock` to the file name; `a_log_named_lock_keeps_its_own_lock_file` |
| N7 | medium | readers took no lock, so a batch split across syscalls made a healthy live log look torn | **fixed**: `read_stable` re-reads once on a walk error, so a torn *read* clears and a torn *file* still fails |
| N8 | low | the writer wait budget was ~1 s | **fixed**: backoff to 50 ms, about 3 s |
| N9 | low | `set_receipt_sequence(u64::MAX)` repeated a sequence forever | **fixed**: the setter returns `Result` and refuses 0 and `u64::MAX`; the seal uses `checked_add`; `the_sequence_setter_refuses_zero_and_the_ceiling` |
| N10 | low | "unchanged" was decided by size only, so a same-size replacement was trusted | **fixed**: the header's start sequence is compared too; the first version of this fix inverted the comparison and the new test caught it; `a_log_replaced_at_the_same_size_is_not_trusted` |
| N11 | low | a failed `create` left an unrepairable file | **fixed**: the header is written to `<name>.writing` and renamed into place |
| N12 | low | `repair` could return success for a log it did not fix | **fixed**: the surviving prefix must walk, and the tail scan refuses a ceiling failure |
| N13 | low | `#[non_exhaustive]` is source-breaking, so 2.3.0 is not "additive" in the ADR-0006 sense | **fixed**: the CHANGELOG says so |
| N14 | low | cancel and out-of-band resolve dropped queued work with no receipt | **fixed**: `record_queued_refusal` seals `rpc/promise-cancelled`/`rpc/promise-resolved`; `a_cancelled_call_is_recorded_as_a_refusal`, `an_out_of_band_resolve_is_recorded_as_a_refusal` |
| N15 | low | `receipts repair` on a missing path exited 1 while every other command exits 2 | **fixed**: the same `exists()` check |
| N16 | low | refusal messages dropped the path | **fixed**: every receipts message names the file |
| N17 | low | `receipts dump` used `create` (start 1) and printed a re-read head | **fixed**: `create_starting_at(receipts[0].sequence)` and the snapshot's head |
| N18 | low | test gaps: the snapshot MAC check was discarded, one test hard-coded 134, no coverage for a corrupted length, a `*.lock` log, the sequence ceiling or a restart | **fixed**: `tests/receipt_round3_tests.rs` (9) covers each; the MAC check is asserted |
| N19 | low | stale docs still said receipts are sealed under "the kernel secret" | **fixed**: `receipts.rs` and ADR-0021 now say the derived receipt key |

Gate (round 3): `cargo test --all-features` 572 passed, 0 failed across 65
suites; `--no-default-features` 523 passed, 0 failed; clippy, fmt and
`cargo doc -D warnings` clean on both feature sets; control plane 30 and CLI 17
pass, and the CLI suite passes in `rust:1.88-bookworm`.

### R-13 receipts - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `6150e72`.
Part A verified all thirteen round-1 findings against the code (twelve
COMPLETELY FIXED, F8 NOT FIXED); Part B found sixteen more, each reproduced with
a probe. Three highs, six mediums, seven lows, all closed here. The repeated
theme: a writer that does not apply the reader's rules, and a key that was the
authority token itself.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| B1 | high | `--secret-hex` put the master kernel secret (which mints capability ids) on the command line, and both the CLI and the library sealed with it | **fixed**: receipts are sealed with `derive_receipt_key(secret)` (`active-rpc/receipt-key/v1`), exposed as `Agent::receipt_key`; the CLI takes `--receipt-key-file` (0600 on unix) and refuses the secret; `a_receipt_is_sealed_with_a_derived_key_not_the_kernel_secret` |
| B2 | high | a job failed before dispatch (unorderable pipeline, vanished provider, destroyed lane) settled with no receipt, so "no call" looked like "refused and undocumented" | **fixed**: `Job::receipted` plus one seal point (`Kernel::seal_receipt`) used by dispatch and `fail_job`; `a_refusal_before_dispatch_is_recorded`, `a_destroyed_lane_records_the_calls_it_drops` |
| B3 | high | the writer still accepted two records the reader rejects: `Refused("")`, and a start near `u64::MAX` where the writer used `saturating_add` and the reader `checked_add` | **fixed**: `encode_record` calls `fields_are_representable` (the reader's predicate), the writer uses `checked_add`, and a start within `MAX_LOG_RECORDS` of the ceiling is refused; `a_refused_code_the_reader_rejects_is_refused_by_the_writer`, `a_start_too_close_to_the_sequence_ceiling_is_refused` |
| B4 | medium | a 64-*byte* non-ASCII key made the CLI slice inside a character and panic (exit 101) | **fixed**: `parse_hex32` checks the alphabet first; CLI test covers it |
| B5 | medium | `receipts verify` read and walked the log six times and could print a head no MAC check covered | **fixed**: `ReceiptLog::snapshot` reads once (`Snapshot` carries records, start, head, last time); the CLI verifies and prints from it |
| B6 | medium | a crash mid-`write_all` left the log unreadable and unappendable, with total loss (`truncate`) as the only exit | **fixed**: `ReceiptLog::repair` cuts back to the last complete record only when the tail is genuinely torn (declared length past EOF) and refuses damage inside; `receipts repair`; `a_torn_tail_is_repaired_and_the_surviving_chain_verifies`, `repair_keeps_a_damaged_record_inside_the_log` |
| B7 | medium | a stale `.lock` blocked appends forever and cost 1.18 s per attempt | **fixed**: the lock records pid and start time, and one older than 120 s is stolen; `a_stale_lock_is_stolen_instead_of_blocking_forever` |
| B8 | medium | `create`/`truncate` bypassed the writer lock, so a create racing an append left the fresh log corrupt | **fixed**: `create_locked` takes the same lock first; `create_honours_a_held_writer_lock` |
| B9 | medium | the default `receipts verify` exited 0 with `ok` for a forged and truncated log | **fixed**: one of `--receipt-key-file`, `--expect-head`, `--chain-only` is required (exit 2 otherwise) |
| B11 | low | `create` overwrote any existing file of ≤ 16 bytes | **fixed**: any existing content is refused; `create_refuses_any_existing_content` |
| B12 | low | the append encoded a whole batch before applying the size ceilings | **fixed**: both ceilings are checked as they are crossed |
| B13 | low | a broken link named a 1-based index, not the sequence | **fixed**: errors name the sequence |
| B14 | low | a second session could not append to an existing log (sequence restarted at 1, virtual clock at 0) | **fixed**: `Agent::set_receipt_sequence(next)` plus the documented wall-clock requirement; `a_second_session_continues_a_log` |
| B15 | low | human-readable lines printed caller-supplied paths unquoted | **fixed**: `{:?}` |
| B16 | low | `Event` grew a variant without `#[non_exhaustive]`, a breaking change for a downstream match | **fixed**: `#[non_exhaustive]`, and the crate moves to 2.3.0 (ADR-0006: additive API is a minor bump) |

Test gap closed from the same review: `fuzz_receipt_log` now fuzzes the *writer*
as well (`append` → `records` over arbitrary fields), because a writer-side hole
is invisible to a reader-only campaign. 4000 runs, no crash, 167 MB peak RSS.

Gate (round 2): `cargo test --all-features` 563 passed, 0 failed across 64
suites; `--no-default-features` 514 passed, 0 failed across 64 suites; clippy,
fmt and `cargo doc -D warnings` clean on both feature sets; control plane 30 and
CLI 17 pass; `tests/receipt_round2_tests.rs` (14) is new.

### R-13 receipts - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `8a6d901`,
running probes against the real API. Four highs, five mediums, four lows; all
thirteen were confirmed against the code, and the log format moved to `ARRL` v2.
The pattern behind three of the four highs is the same: a writer that does not
apply the reader's rules, and evidence that does not carry the decision it
claims to record.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | `append_all` never checked sequence continuity, so a wrapped ring (any session past 1024 calls) wrote a log its own reader refused and left the file unusable | **fixed**: the writer derives the expected sequence from the header's `start` plus the record count, and `create_starting_at(path, oldest)` exports a wrapped window honestly; `a_gap_in_the_sequence_is_refused_and_writes_nothing`, `a_kernel_ring_that_wrapped_exports_cleanly` |
| F2 | high | a truncated prefix verified: dropping the last records leaves a shorter self-consistent log, so an operator could not tell a short session from a doctored file | **fixed**: `verify_against(expected_head)` pins the head a verifier learned out of band; the CLI exposes `--expect-head`; `a_truncated_prefix_is_refused_against_the_pinned_head` |
| F3 | high | append was unauthenticated and the CLI never called `verify_macs`, so a log could be extended with fabricated records and still pass `receipts verify` | **fixed**: `append_verified(secret, ..)` refuses a receipt this kernel did not seal, `receipts verify --secret-hex` checks every MAC, and the unkeyed mode prints `chain-only (unauthenticated)`; `append_verified_refuses_a_forged_receipt` |
| F4 | high | the receipt was sealed at queue time, so a call that dispatch refused (revoked, expired, identity mismatch) kept an "authorized" receipt | **fixed**: the seal happens at dispatch with `Decision::{Admitted, Refused(code)}` as a record field; `a_dispatch_refusal_is_recorded_as_a_refusal`, `a_refusal_round_trips_through_the_log` |
| F5 | medium | concurrent appends could interleave between the walk and the write and corrupt the chain | **fixed**: `LogLock` takes a `create_new` lock file with a bounded retry and refuses instead of writing; `concurrent_writers_cannot_double_append` |
| F6 | medium | eviction and disable left no marker, so a bounded ring read as a complete history | **fixed**: `Agent::receipts_dropped()` plus one `receipts.dropped` event at the transition (one per eviction would flood the bounded tape); `evictions_are_counted_and_reported_once`, `disabling_receipts_counts_what_it_clears` |
| F7 | medium | the log was unbounded, every read pulled the whole file, and each append re-walked it (`O(n^2)`) | **fixed**: `MAX_LOG_BYTES`/`MAX_LOG_RECORDS` on read and write, reads through `take(ceiling + 1)`, and a cached `LogState` short-circuited by one `stat`; `an_oversized_log_is_refused_promptly`, `many_appends_stay_linear` |
| F8 | medium | the kernel could seal a receipt its own log rejects (a granted method that is empty, over 1 KiB, or carries a control character) | **fixed**: `check_method_names` at mint, restore and attenuate, and `append` applies the reader's predicates; `a_granted_method_the_log_cannot_hold_is_refused_at_mint`, `a_long_granted_method_is_recorded_exactly` |
| F9 | medium | a method name or code flowed into a log line and a terminal unescaped | **fixed**: `valid_method`/`valid_code` on encode and decode, and the CLI prints the method with `{:?}`; `a_receipt_the_reader_would_reject_is_refused_at_append` |
| F10 | low | verification errors named a 0-based record index, so the operator could not map one to a receipt | **fixed**: errors name the receipt `sequence` |
| F11 | low | a damaged header exited with the usage class, which a script cannot tell from a typo | **fixed**: a damaged log refuses (exit 1), a missing path is usage (exit 2) |
| F12 | low | `create` truncated an existing log, destroying evidence on a mistyped path | **fixed**: `create` refuses a log that holds records and `truncate` is the explicit "start over"; `create_refuses_to_overwrite_evidence` |
| F13 | low | records could be non-canonical: uppercase hex, arbitrary refusal codes, a reversed `at_ms` that only the reader rejected | **fixed**: one predicate per field shared by writer and reader, a non-decreasing time rule on both sides, and an unknown version refused; `time_that_runs_backwards_is_refused_on_both_sides`, `a_log_from_a_future_version_is_refused` |

Two findings were design, not just code: **the chain is not authenticity**
(a chain-only verify proves the file was not edited or reordered, and only
`verify_macs` proves the kernel wrote it) and **a prefix is a valid log** (so
truncation needs a pinned head). Both are now stated in ADR-0021 and
`docs/spec/wire.md`, with the CLI wording matching.

Also fixed while in the section: `Decision::Refused` carries an owned code, so
the reader rebuilds any code the writer accepted instead of keeping a
hand-maintained allowlist that a new `Error` code would break; `verify_header`
returns only the start sequence; `append_inner` lost a dead parameter; and
`fuzz_receipt_log` is new (3000 runs, 132 new units, 167 MB peak RSS, no crash),
registered in all three workflow target lists.

Gate: `cargo test --all-features` 549 passed, 0 failed across 63 suites;
`--no-default-features` 500 passed, 0 failed across 63 suites; clippy, fmt and
`cargo doc -D warnings` clean on both feature sets; control plane 30 and CLI 17
pass; `rust:1.88-bookworm` runs the receipt suites green.

### R-12 replay - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `2361b7d`.
No critical and no high: decoding was already total and fail-closed, no value can
enter a package, and there is no reachable nondeterminism. Five mediums and four
lows, all fixed; one measured cost was the headline (a 2.1 MB package pinned a
core for **85.9 s** in release).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | medium | a `Call` op could be edited to another granted method or size and `replay()` still passed: no event carried the method or the charged size | **fixed at the decision layer**: `Event::CallQueued` now carries the method (bounded, escaped, with a digest tail when truncated) and the charged argument bytes, and the trace renders `call.queued:<method>:<bytes>`; `replay` also compares the rebuilt op list. Proven by mutation: with the method removed from the trace, an edited package replays clean; `changing_a_recorded_call_method_is_refused`, `changing_a_recorded_arg_size_is_refused` |
| F2 | medium | a refused `mint`/`attenuate`/`revoke` skipped `capture`, so a session ending on one lost `cap.retained`/`cap.released`/`cap.expired` and still replayed | **fixed**: every refusal captures before returning; `a_trailing_refused_attenuation_keeps_its_events` |
| F3 | medium | `encode` truncated a method length to `u16`, so a ≥64 KiB name re-framed the rest of the op stream (the kernel accepts such a name) | **fixed**: method names and counts are checked at record time and the encoder is fallible with checked conversions; `a_method_name_over_64k_is_refused_at_record_time` |
| F4 | medium | the recorder emitted packages its own decoder rejected (op count, method count) | **fixed**: `MAX_OPS`/`MAX_TRACES`/method count are enforced while recording, `package()` and `encode()` return `Result`; `a_session_past_the_op_ceiling_is_refused_at_record_time`, `the_encoder_refuses_a_package_over_a_ceiling` |
| F5 | medium | replay cost was O(ops × tape): `capture` cloned the whole bounded tape per operation (85.9 s release / 226 s debug for 100 000 calls) | **fixed**: `Agent::events_since(seen_total)` returns only the delta (or `None` on a wrap), so recording and replay are linear; `replaying_thousands_of_calls_is_linear` |
| F6 | low | the header latency is the *final* latency, used as the *initial* one on replay | **fixed**: a package whose first op is not `SetLatency(latency_ms)` is refused; `a_package_that_does_not_begin_with_its_latency_is_refused` |
| F7 | low | the trace dropped discriminators (panic phase, introduction peer) | **fixed**: `provider.panicked:<phase>` and `cap.introduced:<fingerprint prefix>`; the raw identity is never recorded |
| F8 | low | a package-controlled event name flowed raw into the mismatch message (newlines, ANSI) | **fixed**: at most 64 characters, `escape_debug`-rendered; `a_mismatch_message_is_bounded_and_escaped` |
| F9 | low | a failed `capture` left the recorder poisoned while `package()` still produced a short trace | **fixed**: the recorder latches `poisoned` and `package()`/`encode()` refuse |

Spec and docs: ADR-0018 now says the recorder drives its own kernel (a package
describes a synthetic session carrying sizes, not argument fidelity), names the
`u16` method limit, and states that the checksum detects corruption rather than
authentication. The reviewer's note that `wire.md` had no ARRP section is
recorded here rather than adding a wire format the CLI already documents.

Also: the CLI's `replay dump`/`run` propagate the new fallible `package()`/
`encode()`, and `fuzz_replay_package` follows the fallible `set_latency`.

Gate: `cargo test --all-features` 527 passed, 0 failed; `--no-default-features`
478 passed; clippy, fmt and `cargo doc -D warnings` clean in three
configurations; control plane 30 and CLI 17 pass; the replay suites pass in
`rust:1.88-bookworm`. `tests/replay_hardening_tests.rs` (9) is new.

### R-11 identity - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `2361b7d`.
No critical. Three highs were fail-open binding paths, two mediums were contract
and availability, three lows defence-in-depth. All fixed here.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | the all-zero (anonymous) fingerprint is a wildcard: `bound_to([0;32])` matched an anonymous peer, contradicting I-13 and the API docs | **fixed**: `identity::presented_fingerprint` models "no identity" as `None`; `identity::matches` is a constant-time compare; the kernel uses both at all five enforcement sites, and `mint`/`attenuate`/`restore`/`from_json` refuse a zero binding; `a_zero_fingerprint_binding_is_refused` |
| 2 | high | every loopback peer shares one *bindable* fingerprint, so a capability bound to `admit(None, true)` was usable by any local process (and by a co-hosted TLS terminator) | **fixed**: `AdmittedIdentity::can_bind` requires `TrustLevel::Authenticated`; `mint_bound`/`introduce_to` refuse a loopback peer; the deployment guide and ADR-0011 say so; `a_loopback_peer_cannot_hold_a_binding`, and the policy test now asserts the refusal |
| 3 | high | the verification contract was honour-system: `PeerIdentity::from_certificate` accepts any bytes and `admit` returns `Authenticated` without touching them | **fixed in documentation and types**: `from_certificate` states it is record-keeping, not proof; `Agent::call_peer` takes the `AdmittedIdentity` the policy returned, so mint and dispatch share one gate; `call_peer_uses_the_admitted_identity` |
| 4 | medium | `with_subject` re-hashed the fingerprint, so attaching a SAN broke every binding and the "digest of the certificate" claim | **fixed**: the subject is a label and the fingerprint is untouched; the identity value still includes the label. `certificate_identities_are_stable_and_subject_sensitive` now pins that |
| 5 | medium | `introduce_to` bound only the root; children minted earlier stayed usable by another peer and transferable | **fixed**: introduction binds the live subtree (validated first: a descendant bound to another peer refuses the introduction); `introduction_binds_the_existing_subtree` |
| 6 | low | the default `cert:` label was 8 bytes of the fingerprint, and the subject length was framed as `u32` | **fixed**: 16 bytes; the length is `u32::try_from` with a saturated fallback rather than a truncating cast |
| 7 | low | `bound_to` accepted zeros and rebinding; the record parser accepted a zero binding while rejecting a zero record id | **fixed** with #1: the kernel validates every path that sets a binding, and `CapabilityRecord::from_json` refuses an unbindable fingerprint |
| 8 | low | five fingerprint comparisons short-circuited | **fixed**: `identity::matches` folds the difference; the value is a public label, so this is defence in depth |

Documented residual: a caller that fabricates a `PeerIdentity` in-process can bind
to it. No wire path reaches that — the QUIC transport reads only the leaf rustls
verified, HTTP/2 and the bridge present no identity, and an envelope has no
identity field — and the kernel treats the value as the caller's claim about its
own connection.

Gate: `cargo test --all-features` 518 passed, 0 failed; `--no-default-features`
469 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the identity and bulk suites pass in `rust:1.88-bookworm`.

### R-10 bulk transfer - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `dd50c0d`.
No critical. The chunk codec was fail-closed (nothing stored before length and
hash validation), but the section was a library with no consumer, and the two
properties that make a transfer safe — charging the budget and binding the plan
to the authority that opened it — were absent from the API. Three highs, four
mediums, five lows; all fixed here.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | bulk bytes were never charged: a 1 GiB receiver ceiling against a 64 MiB grant, with no meter anywhere | **fixed**: `BulkReceiver::with_budget` charges every accepted frame's wire size before it is stored (`rpc/budget-exceeded`, nothing retained), `accept_charged` takes a caller callback, and the ceiling defaults to the grant; the provider path is charged by the kernel on ingress. `a_receiver_charges_every_chunk_and_stores_nothing_refused`, `the_kernel_grant_and_byte_budget_bound_a_bulk_transfer` |
| 2 | high | a plan was self-authenticating only: no binding to the envelope, capability, peer or an expected root, so plan substitution and whole-transfer replay were accepted | **fixed**: the root now folds a transfer context (request id + capability id), `BulkPlan::new_with_context`/`decode_with_context` implement it, and `BulkReceiver::with_expected_root` plus `BulkProvider::with_expected_root` refuse a substituted plan; `a_substituted_plan_is_refused_by_the_pinned_root`, `a_plan_is_bound_to_its_transfer_context` |
| 3 | high | `frames_for` materialised an unbounded, duplicate-laden peer list (25 GiB from a 100 000-index request) | **fixed**: deduplicated, bounded by the plan, one frame at a time via `frame_at`, and `frames_from` refuses a resume point past the plan; `a_resume_request_is_deduplicated_and_bounded` |
| 4 | medium | the response envelope payload was never charged on egress; `max_bytes` ("both directions") was bypassed by the reference dispatcher's echo | **fixed**: `Agent::charge_egress_bytes`, called by the CLI dispatcher before attaching the echoed payload; `egress_payload_bytes_are_charged` |
| 5 | medium | no consumer of `ARBL`/`ARBC`, no encoding for the missing list or the finish marker, no credit window; `frames()` re-materialised the body and `encode` re-hashed | **fixed**: `BulkProvider` (`plan`, `put`, `missing`, `finish`) receives the frames as ARP1 envelope payloads through a capability, so authority and the ingress charge apply; `ARBM`/`ARBF` complete the protocol; `frame_at` streams, and a chunk frame carries the hash it was built with. `a_bulk_transfer_through_the_kernel_assembles_the_body`, `a_request_frame_round_trips_and_refuses_an_off_plan_index`, `a_finish_marker_names_the_transfer` |
| 6 | medium | `finish` peaked at 2-3x the advertised ceiling and hashed every byte three times | **fixed**: chunks are removed from the map as they are appended (peak = body + one chunk) and the accept path uses the hash `decode` already verified, so a byte is hashed twice (decode + final verify) |
| 7 | medium | `decode` accepted a 16 TiB claim from a 64 MiB frame and allocated the hash vector before any ceiling check | **fixed**: the declared total and the chunk count (65 536) are checked before `Vec::with_capacity`; `a_plan_counts_are_bounded_before_allocation` |
| 8 | low | the idempotent call path had no payload parameter, a free-payload path for any future dispatcher | **fixed**: `call_idempotent_as_with_payload` charges the payload and includes its size in the fingerprint; `an_idempotent_call_with_a_payload_is_charged_and_fingerprinted` |
| 9 | low | `BulkPlan::new` truncated the chunk count to `u32` instead of using `expected_chunks` | **fixed**: `new` goes through `expected_chunks` (which now also enforces `MAX_CHUNKS`), with a `debug_assert` on the hash count |
| 10 | low | `BulkChunk::new` accepted >8 MiB and `encode` truncated the length to `u32` | **fixed**: `BulkChunk::try_new` refuses an oversized chunk and a zero chunk size; `a_chunk_cannot_exceed_the_frame_ceiling` |
| 11 | low | `frames_from` silently accepted an impossible resume point (a stall) while `frames_for` errored | **fixed**: `frames_from` returns `Result` and refuses `from > chunks` |
| 12 | low | `Debug` dumped raw body bytes (log exfiltration, log bomb) | **fixed**: manual `Debug` for plan, chunk, sender, receiver and provider prints shape only; `debug_does_not_print_the_body` |

Also fixed while triaging: `Call` gained `payload` (the kernel now hands the
envelope payload to a provider instead of discarding it after the charge), and
the fuzz target `fuzz_bulk_plan` now drives `BulkReceiver`/`finish`/`BulkRequest`
instead of only the decoders.

Spec corrections: `docs/spec/wire.md` §9 (frames travel as envelope payloads,
`ARBM`/`ARBF`, bounded counts, the context in the root, the 1 MiB strict-profile
note) and ADR-0013 (the root is integrity, not authority; `finish` verifies the
body against the plan rather than "recomputing the root"; the ceiling language).
`tests/doc_gate.rs` now lists `rpc/bulk`.

Gate: `cargo test --all-features` 514 passed, 0 failed; `--no-default-features`
465 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the bulk, transport and frame suites pass in `rust:1.88-bookworm`.
`tests/bulk_hardening_tests.rs` (14) is new.

### R-09 transports - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `c89cf3b`.
No critical. Four highs, eleven mediums and three lows; it proved the highs with
temporary probes and deleted them, leaving the tree clean. Every finding below is
fixed here with a test; the two frame oracles were shown to fail pre-fix with a
targeted mutation (`read_frame` reserved **67 109 933 bytes** from a four-byte
header, and `serve_connection` returned `Err` after a bad frame).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | a non-UTF-8 request head killed the bridge: `read_line` returns `InvalidData` and `serve` propagated it, so one packet ended `active-rpc peer --transport connect` | **fixed**: the head is read as bytes under the remaining budget and decoded lossily; a head fault answers `400 rpc/wire` for that connection; `a_non_utf8_request_head_is_a_400_and_the_bridge_keeps_serving` |
| 2 | high | the bridge had no read deadline and accepts serially: one `POST …` without a newline blocked every later peer indefinitely | **fixed**: `CONNECTION_WAIT` (2 s) on every accepted stream, and a stalled connection answers 400 and returns; `a_stalled_head_does_not_block_the_next_connection` |
| 3 | high | `serve_connection` returned the peer's error after replying, and `peer.rs` plus the CLI use `?`, so one bad frame ended the process | **fixed**: a frame error ends the connection and returns `Ok(served)`; the mutation that restores `Err` makes the test fail; `a_malformed_frame_ends_the_connection_not_the_server` |
| 4 | high | QUIC read streams serially with no deadline: a stream that sent four bytes and stopped parked every later stream forever | **fixed**: each stream runs on its own task with `STREAM_WAIT` (10 s), so a stalled stream cannot block the others; `a_stalled_stream_does_not_block_another_stream` |
| 5 | medium | `read_frame` allocated the announced body immediately: a four-byte header forged a 64 MiB zeroed buffer per connection | **fixed**: the body grows with the bytes that arrive (`take(len).read_to_end`), verified against the announced length; `a_maximum_length_header_does_not_reserve_the_body` (tracking allocator, measured) |
| 6 | medium | QUIC `read_to_end(64 MiB)` per stream meant 256 connections could pin 16 GiB, and the window constants did not bound it | **fixed**: the frame prefix is read and validated first, the body is read to exactly that length, and a server-wide `MAX_INFLIGHT_BODY` (256 MiB) budget refuses the excess with `rpc/backpressure` |
| 7 | medium | QUIC ignored bytes after the frame, while the bridge refused them | **fixed**: the stream is read to exactly the announced length, and quinn reports `TooLong` for a longer stream (`rpc/wire`); `trailing_bytes_after_a_quic_frame_are_refused` |
| 8 | medium | QUIC hardcoded `WireLimits::default()`, so a server could not apply `strict()` | **fixed**: `QuicServer::with_limits` writes through a shared lock that the serve task reads per stream, and the client has `with_limits`; `quic_applies_the_server_wire_limits` |
| 9 | medium | 256 QUIC slots with a 5 s keep-alive: keep-alive defeats the idle timeout, and a full table dropped newcomers | **fixed**: keep-alive is gone (the 30 s idle timeout frees slots), a full table waits up to `HANDSHAKE_WAIT` for a slot, and a handshake that outlives it is abandoned |
| 10 | medium | a one-to-three-byte header at end of stream was reported as a clean close | **fixed**: a partial header is `rpc/transport`; `a_partial_header_at_end_of_stream_is_refused` |
| 11 | medium | `SharedSegment::advance(len)` trusted its argument: a wrong length left `tail` inside a payload, and `advance(usize::MAX)` overflowed | **fixed**: `advance()` reads the length from the frame header, bounds-checks it and returns `Result`; `shared_memory_write_is_total_after_a_desynchronised_advance` |
| 12 | medium | the "zero-copy" claim was false: the frame is borrowed but the decoded envelope owns a copy of the payload | **fixed**: the claim is corrected in the module docs, ADR-0003 and `wire.md`, and `recv_zero_copy` is renamed `recv_in_segment` with the cost stated |
| 13 | medium | a duplicate `content-length` or any `transfer-encoding` was accepted by the bridge (request smuggling behind a proxy) | **fixed**: exactly one length, no transfer coding; `conflicting_framing_headers_are_refused` |
| 14 | medium | `MAX_HEAD` was checked only after `read_line` had buffered the whole line | **fixed** with the byte-bounded head read; `a_head_line_without_a_newline_is_refused_at_the_ceiling` |
| 15 | medium | an HTTP/2 peer's `rpc/...` refusal collapsed to `rpc/provider` and its body could be carried into the error | **fixed**: `Error::provider_code` exposes the class, the body is read as a bounded token and anything else becomes `rpc/provider`; `the_client_preserves_a_peer_refusal_code` |
| 16 | medium | one HTTP/2 `accept` error aborted the server | **fixed**: transient accept errors are retried, and only `MAX_ACCEPT_FAILURES` in a row is fatal |
| 17 | medium | HTTP/2 has no identity parameter, although `docs/deployment/identity.md` told deployers to pass one | **fixed**: the deployment doc now states that the shipped HTTP/2 transport is plaintext, carries no identity, and that a bound capability needs QUIC mutual TLS. Documented residual: there is no identity channel on this transport |
| 18 | medium | no transport checked `Envelope::kind`, so a response envelope carrying a capability and a method was dispatched | **fixed** on TCP, the bridge, HTTP/2, QUIC and the CLI dispatcher; `a_response_envelope_is_refused_on_the_framed_and_bridge_transports` |
| 19 | medium | the bridge's served-count assertion in `tests/integration_tests.rs` was swallowed by a mangled comment (`\n` escapes) | **fixed**: the assertion is restored, with the count corrected to mean "calls that reached the handler" |
| 20 | low | the QUIC client hardcoded SNI `localhost`, so a certificate for `rpc.internal` could never verify | **fixed**: `QuicClient::connect_with_name` |
| 21 | low | `MAX_FRAME_BYTES` was documented as the transport ceiling but `read_frame` honoured only `WireLimits`; a partially written frame left the TCP stream reusable | **fixed**: the ceiling is `min(limits.max_bytes, MAX_FRAME_BYTES)`, and a failed write poisons the connection |
| 22 | low | shared-memory counters went backwards on drain, compaction allocated a full copy, and the inspection closure ran under the lock | **fixed**: lifetime byte and frame totals, `copy_within` for a contiguous unread region, and the re-entrancy contract documented |

Also updated: `docs/spec/wire.md` (transport table, error-class note) and
`docs/adr/0003-transports.md` (the borrowed-read claim).

Gate: `cargo test --all-features` 500 passed, 0 failed; `--no-default-features`
451 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the 10 transport tests, 3 frame tests and 11 tool tests pass in
`rust:1.88-bookworm`. `tests/transport_hardening_tests.rs` and
`tests/transport_frame_tests.rs` are new.

### R-08 tools / MCP - 2026-11-01 (round 2)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `db3af5a`.
It reproduced the gates itself and probed each carried fix. Verdicts: #11
(HTTP framing) and #14 (notification skip) verified; #8, #9, #15 verified with
caveats; three new highs and six mediums came out of the same pass, all fixed
here. Every fix carries a test, and each test was shown to fail against the
tree before it.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 8 | medium | a bare program name resolved from the ambient `PATH`, and `cwd` was inherited (carried from round 1) | **fixed**: `pin_program` refuses a non-absolute path and pins the canonical one; `LocalProcess::with_current_dir` pins the directory (refusing a relative one), `StdioTransport` pins it at spawn; `taskkill.exe` comes from `SystemRoot`; `a_bare_program_name_is_refused` |
| 9 | medium | a timeout killed the direct child only; the readers were detached (carried) | **fixed**: the child leads its own process group on Unix and the group gets SIGKILL (`/bin/kill`, then `/usr/bin/kill`); Windows keeps `taskkill /T`; `a_timeout_kills_the_descendant_tree` (proved on Linux) |
| 11 | low | a GET carried `content-length: 4` and a `"null"` body (carried) | **fixed**: only POST, PUT and PATCH send content; `a_get_request_has_no_body`, `a_post_carries_its_body_and_length` |
| 14 | low | an MCP notification desynchronized the session (carried) | **fixed**: a frame without an `id` that has a `method` is skipped up to `MAX_MCP_NOTIFICATIONS` (16), then the session is poisoned; `a_notification_before_the_response_is_skipped`, `exactly_the_notification_ceiling_is_skipped` |
| 15 | low | `bounded_description` missed U+2028/U+2029 and invisible formatters (carried) | **fixed**: separators, bidi controls, zero-width joiners, tag characters, invisible operators and variation selectors become spaces; `a_description_cannot_inject_a_line_separator` |
| N1 | high | the reader-wait timeout returned `rpc/timeout` without killing the tree: a leader that exits at once leaves a descendant holding the pipes and acting after the grant was refunded | **fixed**: `kill_process_tree` runs on both timeout paths and on a wait error; `a_timeout_after_the_leader_exits_kills_the_tree` (the mutation that removes only this call makes it fail) |
| N2 | high | the HTTP ceiling was a per-read socket timeout, not a wall deadline: a server dripping a byte per 35 ms held a 60 ms grant for 2.07 s and the call succeeded | **fixed**: one deadline for the exchange, threaded through `DeadlineReader` (connect, every read, body) and re-checked after each read; a timed-out read is `rpc/timeout`; `a_dripping_server_cannot_stretch_the_wall_ceiling` |
| N3 | high | `McpSession::handshake` had no deadline at all: a silent server blocked the caller forever | **fixed**: `DEFAULT_MCP_HANDSHAKE_TIMEOUT_MS` (5 s) covers `initialize` and `tools/list`; `handshake_within` takes an explicit one; `an_mcp_request_carries_a_deadline`, `an_expired_deadline_sends_no_frame` |
| N4 | medium | the duplicate-name check was still a linear scan (round-1 #7's `seen` set was dead code): 8 000 tools took 1 007 ms | **fixed**: one `BTreeSet` insert decides duplicates, and `MAX_MCP_TOOLS` (4 096) bounds the table |
| N5 | medium | stdout and stderr were labelled by channel arrival order (8 of 20 runs swapped) | **fixed**: each reader sends its tag; `stdout_and_stderr_are_not_swapped` (20 runs) |
| N6 | medium | every dispatch rebuilt the MCP method table through the default `has_method` (1.19 ms and ~1 MB per call at 7 000 tools) | **fixed**: `McpSession` and `ModuleProvider` answer from their own tables; `has_method_does_not_rebuild_the_method_table` |
| N7 | medium | HEAD, 204 and 304 responses were read as if they carried a body, so an allowlisted HEAD endpoint stalled until the ceiling | **fixed**: those replies return an empty body; `a_head_response_has_no_body` |
| N8 | medium | a `*` allowlist rule is a command-line prefix: with `cmd /C` and `echo*`, `echo ok & del …` was arbitrary command execution | **fixed**: an argument admitted only by a prefix rule may not contain shell syntax (command separators, redirection, `^`, parentheses, quotes, `$`, backtick, `%`, newline, NUL); `a_prefix_argument_cannot_smuggle_a_command` |
| N9 | low | tag characters, U+2061-U+2064, U+180E and variation selectors survived the description scrub | **fixed** with the carried #15 |
| N10 | low | a repeated or unparsable `content-length` silently switched framing | **fixed**: `http/headers`; `a_repeated_content_length_is_refused` |
| N11 | low | `Value::Path` and the `request` method text reached the request line unsanitised | **fixed**: a control character in either is `rpc/tool-policy`; `a_path_with_a_control_character_is_refused` |
| N12 | low | the MCP deadline was checked after `send_line`, so an expired call still mutated the server | **fixed**: the check runs before the frame leaves; `an_expired_deadline_sends_no_frame` |
| N13 | low | `StdioTransport` children had no process group and `Drop` killed the leader only | **fixed**: `process_group(0)` at spawn and `kill_process_tree` on drop |
| N14 | low | test gaps: the notification boundary, a server-initiated request, a framing fault, and the fuzz target still passing a text path | **fixed**: four tests plus `fuzz_tool_http` now sends `Value::Path` |
| N15 | low | `lane_queue_depth` walked the queue per lane on every dashboard snapshot | **fixed**: `Agent::lane_queue_depths` is one pass; the control plane uses it; `lane_queue_depths_count_the_undispatched_calls` |
| N16 | low | two wall-ceiling tests flaked under a saturated parallel run (5 s bound) | **fixed**: the bound is 10 s, and the comment says why the margin exists |
| N17 | low | the control plane is a separate workspace, so root `cargo test` never builds it (it did not compile at `fd64122`) | **fixed**: it was repaired and CI's `control-plane` job (format + tests) is green; the root workspace is unchanged on purpose, because the crate has its own dependency set |

Residual risks recorded, not defects: the `poisoned` flag is provider-wide, so
one desync ends every capability on that MCP provider; a transient MCP timeout
poisons the session on the next call (the abandoned answer is an id mismatch);
`SystemRoot` is trusted to locate `taskkill.exe`; a distroless image with
neither `/bin/kill` nor `/usr/bin/kill` falls back to the leader only; Windows
children inherit every inheritable handle (no `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`).

Gate: `cargo test --all-features` 487 passed, 0 failed; `--no-default-features`
441 passed; clippy and fmt clean in three configurations; control plane 30 and
CLI 17 pass; the 11 tool tests and the fuzz crate build in
`rust:1.88-bookworm`, where both process-group tests run.

### R-07 domain operations - 2026-11-01 (round 1, in progress)
Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`, at `22c3d66`.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| D-1 | critical | `Call.path_scope` was never enforced by the domain provider: a capability confined to `app` returned the whole module (pathless `evaluate`, `patch` outside the scope, `stats`/`annotations`/`provenance`/`content_hash`, and dependents labels) | **fixed**: `ModuleProvider::serve` refuses a path outside the scope and refuses a pathless form under a scope (`rpc/path-not-granted`); `tests/domain_scope_tests.rs` (4) |
| D-2 | high | metadata queries ignore `Budget` and are quadratic: `why`/`impact` took 2.5 s at 3 000 nodes and 10.7 s at 6 000 (measured) | **fixed**: one adjacency and one path map per call, `max_nodes` refused as `rpc/budget-exceeded`, and a walk past `max_wall_ms` refused; `why_is_linear_in_module_size`, `metadata_queries_respect_max_nodes` |
| D-3 | high | an unchecked index in the taint walk, a quadratic taint fixpoint, and a panicking call that destroyed the module object | **fixed**: one Kahn pass over a checked adjacency, `invoke` re-inserts the slot through `catch_unwind` and resumes the unwind, and `install` validates a module as canonical before storing it; `a_deep_chain_redacts_quickly` (4 000 links, 4.9 s measured before), `install_refuses_a_dangling_locator` |
| D-4 | high | `restrict`/`subgraph` dropped annotations, so a projection lost `@ai_immutable` and a constraint whose expression was outside the cone | **fixed**: the cone grows to include every in-cone constraint expression, annotations are remapped, and bindings plus provenance travel with it; `subgraph_preserves_annotations` |
| D-5 | medium | `patch` ignored `@ai_immutable` and replaced the provenance with an empty one | **fixed**: a target or ancestor under `@ai_immutable` is `rpc/read-only`, and the new provenance keeps the producer chain with the old content address as `parent`; `patch_refuses_an_ai_immutable_node`, `patch_preserves_the_parent_provenance` |
| D-6 | medium | provenance/annotation text left a copy of a secret literal as ordinary text | **fixed**: the provenance map is built from `interop::provenance_lines` (a copy becomes the marker), and `install` refuses a non-canonical arena that could carry one; `provenance_redacts_secret_literals` |
| D-7 | medium | a scoped `patch` changed a value outside the scope through a shared node | **fixed**: a scoped write is refused (`rpc/path-not-granted`) when any named dependent of the target lies outside the scope; `a_scoped_patch_cannot_change_a_value_outside_its_scope` |
| D-8..D-12 | low | redacting `stats` disclosed the secret count and hidden annotations their node id; lowering faults used `rpc/payload`; the drop log was unbounded; `timestamp_ms as i64` wrapped; a refused call counted as served | **fixed**: the count is omitted under `redact`, a hidden annotation names no node, encode/lower faults are `rpc/domain` (`active/lower`), `MAX_DROP_LOG` bounds the log, `i64::try_from` clamps, and `calls` advances only after the slot is taken |

Gate after the D-2..D-12 work: `cargo test --all-features` 466 passed, 0 failed
(and the `--no-default-features` suite green); clippy clean on both feature sets;
fmt clean.

### R-05 lanes / channels - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`. Tests:
`tests/lane_tests.rs` (10, the file the section map named); six fail on the
pre-fix tree, four are coverage of behaviour that already worked (the lane
charge from R-02 round 2, per-channel byte accounting, and the documented
"a lane is not an authority boundary").

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | `destroy_lane` scrubbed the queue with a linear `Vec::contains` per job: 40 000 jobs blocked the kernel for 10.6 s (measured) | **fixed**: a `BTreeSet` of doomed ids; `destroying_a_full_lane_does_not_block_the_kernel` asserts a 5 s ceiling on 40 000 jobs |
| 2 | medium | a publish checked the message count but not the channel's byte ceiling, charged every meter, and then the channel refused: the grant was gone and nothing was queued | **fixed**: capacity is checked before any charge and answers `rpc/backpressure`; `a_publish_refused_on_a_full_channel_charges_nothing` |
| 3 | medium | no aggregate queued-byte ceiling: 4 096 channels × 64 MiB is 256 GiB | **fixed**: `MAX_QUEUED_CHANNEL_BYTES` (256 MiB) is tracked by the kernel and released on receive and on channel destroy |
| 4 | medium | `Channel::close()` was unreachable: `Agent::channel` returns a snapshot | **fixed**: `Agent::close_channel`; `closing_a_channel_stops_sends` |
| 5 | low | `Lane.caps` and `Lane.ready` were never written and the module doc described a scheduler that does not exist | **fixed**: both fields and the stale doc are gone; the module now states that a lane is a budget and lifecycle scope, not an authority boundary; `a_lane_is_not_an_authority_boundary` |
| 6 | low | send/publish refusals were not counted and a duplicated capability id double-counted a transfer | **fixed**: `note_refusal` counts and logs them, and a duplicate id is `rpc/invalid-argument`; `refusals_are_counted`, `a_message_cannot_transfer_the_same_capability_twice` |
| 7 | low | `attenuate_lane` does not invalidate work already reserved under the old ceiling | **documented**: reservations are final (the call was charged against the old grant); the doc now says so |
| 8 | low | names were unbounded and subscriptions had no per-lane cap | **fixed**: `MAX_OBJECT_NAME_BYTES` (256) and `MAX_CHANNELS_PER_LANE` (1 024); `names_and_subscriptions_are_bounded` |
| 9 | low | every send cloned the payload although only the sequence was used | **fixed**: `Channel::send_sequence`; the kernel uses it |
| 10 | low | `recv` is ambient: a provider holding the agent can drain any channel | **carried**: this is the documented residual (R-02 #8b/#17) and needs an ADR for subscription-based receive |

Gate: `cargo test --all-features` 440 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-04 promises / pipeline - 2026-11-01 (round 1)

Reviewer: DeepSeek V4.1 Flash through the Copilot CLI, `xhigh`. Tests:
`tests/promise_tests.rs` (15), the file the section map named and that did not
exist; fourteen of them fail on the pre-fix tree. The fifteenth covers the
phase-3 settlement gating, which this scenario cannot reach, so it is coverage
and not proof.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | promise ids were accepted from any lane and from envelopes: cross-tenant disclosure plus a membership oracle | **fixed**: a dependency must have been minted on the calling lane, and `Agent::call_from_envelope` refuses promise and capability arguments for transports (used by `peer.rs` and `thin_peer`); `promise_from_another_lane_is_refused`, `an_envelope_cannot_carry_authority_arguments` |
| 2 | high | the idempotency key outlived its promise, so a replay silently re-executed a mutating call | **fixed**: `trim_settled` pins a record an idempotency key still names; `an_idempotent_replay_survives_the_retention_window` |
| 3 | medium | an idempotent replay skipped lane existence, closure and capacity and was not lane-scoped | **fixed**: the lane is validated before the cache lookup and the key includes it; `an_idempotent_replay_needs_a_live_lane`, `an_idempotent_key_is_lane_scoped` |
| 4 | medium | cancelling a promise in the current batch completed its lane twice and logged a settlement that never happened | **fixed**: only a job still in the queue is dequeued, and phase 3 emits the event and the metric only when the transition succeeded; `cancelling_inside_dispatch_counts_once` |
| 5 | medium | `resolve` left the producing job queued: the provider ran anyway and the settlement was counted twice | **fixed**: a successful out-of-band resolve dequeues its job; `resolving_a_queued_promise_prevents_the_provider_call` |
| 6 | medium | a promise retain/release was dropped when the kernel was borrowed, so a live handle lost its record | **fixed**: promise reference operations queue in FIFO order and are drained by `run`; `a_clone_under_a_borrow_keeps_the_handle` |
| 7 | medium | `cancel_tree` was O(targets × jobs): a 4 000-link chain blocked the kernel for 3.1 s (measured) | **fixed**: one reverse index and a `BTreeSet` of targets |
| 8 | medium | `run`/`await_promise` from `on_drop` failed that provider's queued work as `rpc/provider` | **fixed**: `next_batch` skips a provider that is being notified and `run` returns when nothing is runnable; `run_from_on_drop_does_not_kill_queued_jobs` |
| 9 | low | a re-entrant `run` silently succeeded while a re-entrant await returned `rpc/provider` | **fixed**: both are now "no progress"; the await reports `rpc/unresolvable-promise`, which does not invite a retry |
| 10 | low | `PromiseRecord.waiters` was incremented and never released | **fixed**: every job removal releases its dependencies; `waiters_return_to_zero` |
| 11 | low | `Arg::Cap` from an envelope was forwarded unvalidated | **fixed** with finding 1 |
| 12 | low | rejected error text did not count toward the retention ceiling | **fixed**: `record_settled` charges the error text |
| 13 | low | `peek` on a pending promise returned the terminal `rpc/unresolvable-promise` | **fixed**: a pending peek is `rpc/invalid-argument`; `peek_on_a_pending_promise_is_not_unresolvable` |
| 14 | low | the section's test file did not exist | **fixed**: `tests/promise_tests.rs` |

### R-03 capabilities - 2026-11-01 (round 3)

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| H-1 | high | a virtual deadline is not comparable across kernels (unrelated epochs), and attenuation stamped a child with the parent's domain | **fixed**: a child is stamped with the clock that produced its deadline, attenuation refuses a bounded parent from the other domain, and the record carries a sealed `lease_ms` that restore uses as the ceiling; `a_child_after_a_clock_switch_is_stamped_with_the_new_domain`, `a_virtual_deadline_does_not_inflate_across_a_restart` |
| M-3 | medium | export wrote the grant, not the remainder, so export/drop/restore refilled a spent budget | **fixed**: the record carries the remaining calls and bytes, and a spent grant is refused; `a_restored_copy_cannot_refill_a_spent_grant` |
| L-1 | low | restore accepted an unbound record and bound it to any admitted peer | **fixed**: `rpc/identity`; `an_unbound_record_is_refused_by_restore` |
| L-2 | low | the tombstone ceiling was soft | **fixed**: the ceiling counts live durable grants as well, so revoke cannot pass it |
| L-3 | low | a full tombstone set turned a valid restore into `rpc/budget-exceeded` | **fixed**: `mint_restored` bypasses the tombstone ceiling |
| L-4 | low | export emitted `path_scope: ""`, which `from_json` refuses | **fixed**: an empty scope is refused at export |
| L-5 | low | a borrow failure mid-delivery discarded already-taken notifications | **fixed**: entries are pushed back before returning |

Gate: `cargo test --all-features` 430 passed, 0 failed; clippy clean on both
feature sets; fmt clean; the nine negative controls pass.

### R-03 capabilities - 2026-11-01 (round 2)

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | high | a derived capability freed its ancestors' meters when the parent handle dropped | **fixed** with the same `descendants` accounting as R-02 H-2 |
| F2 | high | tombstones were memory-only, so a restart resurrected a revoked durable record, and `revoke` on a dropped record was a silent no-op | **fixed**: `Agent::tombstone_record` / `record_is_tombstoned` / `record_tombstone_count` let a deployment replay its kill list, and `revoke` returns `Result` with `rpc/unknown-capability` for an id that is not live; `a_tombstone_replayed_at_startup_refuses_the_record` (API-addition test) |
| F3 | medium | one record restored into N independent grants | **fixed**: `restoring_the_same_record_twice_is_refused` |
| F4 | low | every revocation tombstoned an ephemeral record id, forever | **fixed**: only durable records are tombstoned, and the set has a ceiling (`MAX_TOMBSTONES`) that refuses a new durable mint instead of evicting; `a_revocation_tombstones_only_durable_records` |
| F5 | low | the deferred ref-op drain was one-shot, so a retain queued during the drain could be overtaken | **fixed**: `enqueue_or_apply` keeps FIFO across both paths and the drain loops (bounded); exercised by `a_drop_raised_inside_on_drop_is_delivered_once` |
| F6 | medium | `on_drop` ran under a borrow | **fixed** with R-02 M-5 |
| F7 | low | `revoke` rebuilt the whole ancestor index per call | **fixed**: `Kernel.children` is maintained on attenuation and drop, so a revocation walks only its subtree. Event volume stays one `CapRevoked` per record (the honest record of the action); the aggregate event is not worth a contract change |
| F8 | medium | `await_promise` livelocked inside a provider | **fixed** with R-02 H-3 |
| F9 | low | an unbound record exported before `introduce_to` restored for any peer | **fixed**: export refuses an unbound durable capability (`rpc/identity`); `an_unbound_durable_capability_cannot_be_exported` |

Carried as accepted residuals (documented, not defects): `max_bytes` bounds
ingress, not egress; `Value::wire_size` recurses under the decoder's nesting
limit; a revoked capability keeps its registry slot while a handle exists;
rotating the seal key invalidates earlier records (by design, documented in
ADR-0010).

Gate: `cargo test --all-features` 414 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-02 kernel dispatch - 2026-11-01 (round 2)

Reviewer: same DeepSeek V4.1 Flash channel, `xhigh`, repository tool access.
Tests: `tests/marathon_kernel_round2_tests.rs` (9); eight of them fail against
the pre-fix tree (the ninth is a guard that must pass on both trees). The
pre-fix run also exposed the livelock the round-1 note called a "cycle": the old
selector returned an empty batch for a blocked head provider and the queue never
advanced, so the test binary spun for 17 minutes of CPU before it was killed.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 4 | medium | cross-provider pipeline failed as a cycle | **fixed**: `next_batch` scans providers in queue order and dispatches the first one with a runnable job; `order_candidates` only returns jobs whose dependencies are settled or produced earlier in the same batch; `a_cross_provider_pipeline_settles` |
| 6 | medium | a wall-clock record restored into a virtual kernel kept a deadline from another clock domain | **fixed**: `CapabilityRecord.wall_clock` travels in the JSON and `restore_capability` refuses a mismatch with `rpc/persistence`; `a_record_carries_its_clock_mode`, `a_wall_clock_record_does_not_restore_unbounded_in_virtual_mode` |
| 8 | medium | `publish` ignored `read_only` | **fixed**: a read-only grant cannot publish (`rpc/read-only`); `a_read_only_capability_cannot_publish` |
| 9 | medium | lane byte ceilings were per call and `publish` skipped the lane call budget | **fixed**: `Lane.bytes` accumulates both, and `publish` consumes lane calls and bytes; `a_lane_byte_budget_is_cumulative`, `publish_counts_against_the_lane_budget` |
| 10 | medium | `on_drop` was lost when the last reference died during dispatch | **fixed**: `Kernel.deferred_drops` holds the notification until the provider is re-inserted, then delivers it; `on_drop_is_delivered_when_a_provider_releases_during_its_own_call` |
| 11 | low | a nested `run()` inside a provider failed unrelated queued work | **fixed**: `Kernel.dispatching` makes the nested call return the current round-trip count while the outer dispatch continues |
| 18 | low | `restore_capability` took the first provider whose name matched | **fixed**: exactly one match is required (`rpc/persistence`); `restore_refuses_an_ambiguous_provider_name` |

Gate: `cargo test --all-features` 384 passed, 0 failed; clippy clean on the
default and all-features sets; fmt clean.

Carried (contract decisions, logged rather than half-fixed):

| # | Sev | Reason |
|---|-----|--------|
| 8b | low | `topics: None` means "any topic" and a grant with no publish method can publish; channel authority is ambient by design, so changing it needs an ADR |
| 17 | low | `recv`/`recv_topic` ignore lane subscription; subscription is advisory today and the contract needs an ADR |

### R-03 capabilities - 2026-11-01 (round 1)

Reviewer: Copilot CLI routed to CommandCode DeepSeek V4.1 Flash, `xhigh`, with
repository tool access. Tests: `tests/marathon_cap_tests.rs` (17); all 17 fail
against the pre-fix tree, proved by stashing `src/` and adding only the API
surface the tests name (no behavioural shim).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | critical | path scope was checked only against the queued arguments, so a promise argument delivered a `Path` the scope never saw | **fixed**: dispatch re-walks the resolved arguments; `a_pipelined_argument_cannot_carry_a_path_outside_the_scope` (asserts the provider never runs) |
| 2 | critical | the byte budget and the tool argument ceiling counted a promise as its 8-byte placeholder | **fixed**: dispatch measures the resolved arguments, refuses over the effective budget and the policy ceiling, and charges the difference to the capability, every ancestor and the lane before the provider runs; `a_pipelined_argument_is_charged_at_dispatch` |
| 3 | critical | a policy-less parent accepted any child `ToolPolicy`, so attenuation could grant `allow_process` | **fixed**: `CapAttrs::effective_tool_policy` (own methods, own byte budget, no process) is the parent for the comparison, in the predicate and in `attenuate`; `attenuation_cannot_add_process_execution` |
| 4 | high | a durable record revived a revoked capability | **fixed**: `CapRecord::record_id` (secret-derived, carried in the record) is tombstoned by `revoke` and refused by `restore_capability` with `rpc/revoked`; `a_revoked_durable_capability_cannot_be_restored` |
| 5 | high | records were unauthenticated authority: whoever wrote the JSON could mint what it described | **fixed**: `Agent::set_record_seal_key` + keyed Blake3 seal over every field, constant-time check before any field is read; a kernel without a key exports and restores nothing; `an_edited_or_unsealed_record_is_refused` |
| 6 | high | a child call did not consume the parent's budget, so delegation multiplied the grant | **fixed**: a call charges its whole lineage, checked first and then charged; publish does the same; `a_child_call_consumes_the_parent_budget` |
| 7 | high | `parse_hex32` sliced a 64-**byte** string of multi-byte characters and panicked | **fixed**: ASCII is required before slicing; `a_non_ascii_record_field_is_refused_without_panicking` |
| 8 | medium | `BudgetMeter::charge` compared with `saturating_add` and then added, so a byte count at the ceiling panicked in debug and wrapped in release | **fixed**: `checked_add` through `check`/`charge`, plus `check_bytes`/`charge_bytes` for dispatch; `a_meter_at_the_ceiling_never_wraps` |
| 9 | medium | `HttpTool` took a path from `Value::Text` that starts with `/`, so the kernel's path scope never saw it | **fixed**: the adapter reads `Value::Path` only; `a_text_argument_is_not_an_http_path` |
| 10 | medium | `to_active_budget` derived ceilings larger than the grant (`max_value_size * 4`) | **fixed**: derived ceilings are clamped to the grant; `evaluator_ceilings_never_exceed_the_grant` |
| 11 | medium | `CapTableDelta::apply_to` had no table ceiling | **fixed**: `MAX_CAP_TABLE` (4096) with `rpc/capability-table`; `a_delta_cannot_grow_the_table_past_its_ceiling` |
| 12 | medium | `retain`/`release` returned silently when the kernel was borrowed, so a handle dropped inside a provider notification lost its release | **fixed**: the operation is queued on a shared `Rc<RefCell<Vec<(CapId, bool)>>>` and applied at the next kernel borrow; `a_drop_inside_a_provider_notification_is_applied` |
| 13 | low | `CapabilityRecord::attrs` dropped `bound_to`, so the natural restore path minted an unbound capability | **fixed**: the binding is carried; `record_attrs_preserves_the_binding` |
| 14 | low | `export_capability` accepted an id-only (imported) handle | **fixed**: `CapHandle::is_owning` gates export; `export_from_an_imported_handle_is_refused` |
| 15 | low | duplicate method names decoded to a smaller set and re-encoded differently | **fixed**: a duplicate is `rpc/capability-table`; `a_descriptor_is_canonical_or_refused` |
| 16 | low | a descriptor with no methods was accepted by the wire and by `apply_to` | **fixed**: refused in both; `a_descriptor_is_canonical_or_refused` |
| 17 | low | durable-policy refusals used `rpc/capability-table` (a hostile-peer fault) while export/restore used `rpc/persistence` | **fixed**: both are `rpc/persistence`; `tests/persistence_tests.rs` and the round-1 kernel test updated |
| 18 | low | `CapHandle::into_id` leaked a reference and had no caller | **fixed**: removed |
| 19 | low | the registry and the attenuation chain were unbounded, and `revoke` was quadratic | **fixed**: `MAX_CAPS` (65536), `MAX_LINEAGE_DEPTH` (64), and a single parent/lineage index per revoke; `the_registry_and_the_lineage_are_bounded` |
| 20 | low | `cap_table_hash` asserted the encoding succeeded | **fixed**: it returns `Result`, so an unencodable table has no hash |

Also closed in this round (found while fixing): `publish` charged only the
payload, so a 1 KiB topic name rode through a 32-byte grant; it now charges
topic bytes and the lineage (`tests/topic_tests.rs`,
`a_publish_charges_the_capability_byte_budget`).

Documented residual (the predicate is honest, the operation is strict): a child
that omits the identity binding reports monotone because `attenuate` inherits
the parent's binding. `CapAttrs::is_attenuation_of` now says so, and a caller
validating foreign attributes must apply the binding itself.

Gate: `cargo test --all-features` 401 passed, 0 failed; clippy clean on both
feature sets; fmt clean.

### R-01 wire ARP1 — 2026-10-31

Reviewer: Copilot CLI → Muse proxy, `xhigh`, repo tool access. Tests:
`tests/marathon_wire_tests.rs` (5); three of them fail against the pre-fix tree.

| # | Severity | Finding | Disposition |
|---|---|---|---|
| 1 | high | list/map counts are checked against the frame budget, not the remaining bytes | **rejected**: every iteration consumes at least one byte and fails when the input ends, so the loop is bounded by the frame; the preallocation is capped at 1024. The check is coarse, not an amplification |
| 2 | medium | `Value::Bool` accepted any non-zero byte and re-encoded as 1 (§8.5 re-encode stability) | **fixed**: only 0 and 1 decode; `a_boolean_that_is_not_zero_or_one_is_refused` |
| 3 | medium | faults inside a capability descriptor leaked `rpc/wire` instead of `rpc/capability-table` | **fixed**: `read_cap` translates scalar-reader faults and keeps descriptor-level reasons; `a_zero_capability_id_is_refused` |
| 4 | medium | duplicate map keys collapsed on decode and re-encoded shorter | **fixed**: a duplicate key is `rpc/wire`; `a_duplicate_map_key_is_refused` |
| 5 | low | `len as u32` casts in the encoder | **rejected**: every count is bounded by `WireLimits` before it can reach `u32::MAX`, and the payload path checks explicitly |
| 6 | low | `cap_table_hash` hashed the empty table on an encode error (fail-open) | **fixed**: the encoder's invariant is asserted, so two tables can never share the fallback hash |
| 7 | low | a zero capability id was accepted | **fixed** on both the wire path and the programmatic delta path; the id is not a capability |
| 8 | low | `CapTableDelta::apply_to` skipped the budget check the wire path applies | **fixed**: added descriptors are checked for a disabling budget; `a_delta_addition_with_a_zero_budget_is_refused` |

Gate: clippy clean; `cargo test --all-features` 365 passed, 0 failed.

### R-02 kernel dispatch - 2026-11-01 (round 1)

Reviewer: Copilot CLI routed to CommandCode DeepSeek V4.1 Flash, `xhigh`, with
repository tool access. Tests: `tests/marathon_kernel_tests.rs` (10); all ten
fail against the pre-fix tree (verified by stashing `kernel.rs`/`cap.rs`/
`wire.rs`).

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| 1 | high | revocation missed descendants of a dropped intermediate (the record removal broke the parent chain) | **fixed**: `CapRecord::lineage` records every ancestor; `revoke` marks any record whose lineage contains the target; `revocation_reaches_a_grandchild_through_a_dropped_intermediate` |
| 2 | high | a call with an unknown promise dependency charged the meter, inserted a promise and sealed a receipt before refusing | **fixed**: dependencies are validated before any ceiling, charge, receipt or record; waiters increment only after a successful charge; `a_refused_promise_dependency_charges_nothing_and_leaves_no_record` |
| 3 | high | an idempotent cache hit returned a stored promise without re-checking revoke, expiry or the identity binding | **fixed**: `call_idempotent_as` re-checks liveness and binding on a hit; `an_idempotent_replay_is_refused_after_revoke` |
| 5 | medium | durable policy was bypassable through attenuation and export | **fixed**: both check `allow_durable`; `disabling_durable_refuses_attenuation_and_export` |
| 7 | medium | path scope only inspected top-level `Value::Path`; a nested list/map path escaped | **fixed**: the scope walk is recursive; `a_nested_path_argument_is_outside_the_scope` |
| 12 | low | a cap-table delta could remove an id and re-add it with wider authority | **fixed**: an added id that exists in the base table is refused; `a_delta_cannot_replace_an_id_with_a_wider_descriptor` |
| 13 | low | `send_as` reported `rpc/invalid-argument` for an unknown capability | **fixed**: `rpc/unknown-capability`; `send_reports_an_unknown_capability` |
| 15 | low | `mint_bound` silently overwrote a caller-supplied `bound_to` | **fixed**: a conflicting binding is `rpc/identity`; `mint_bound_refuses_a_conflicting_binding` |
| 16 | low | `subscribe` was refused with `rpc/backpressure` when the queue was full although it enqueues nothing | **fixed**: the check is gone; `subscribe_is_not_refused_by_a_full_queue` |
| 14 | low | idempotency keys were unbounded and the order deque grew on stale keys | **partly fixed**: keys are capped at `MAX_IDEMPOTENCY_KEY_BYTES` (256) and stale keys are removed from the deque; `an_oversized_idempotency_key_is_refused` |

Carried to round 2 (triaged, not yet fixed):

| # | Sev | Reason |
|---|-----|--------|
| 4 | medium | cross-provider pipeline: `next_batch` fails jobs whose producer is queued on another provider and mislabels the code as `rpc/unknown-capability`; needs a rework of the batch selector plus a scheduler test |
| 6 | medium | durable restore treats a wall-clock absolute deadline as the importing kernel's domain; needs a clock-mode field on `CapabilityRecord` (format change) and an ADR note |
| 8 | medium | `publish` is authorized by possession alone (no method grant, `read_only` ignored, `topics: None` means any topic); the design intent needs a decision before changing the contract |
| 9 | medium | lane byte budgets are per-call, and `publish` does not consume the lane call budget; needs a lane meter shared by call and publish |
| 10 | medium | `on_drop` is lost when the last reference dies during dispatch (the provider is removed for the call); needs a deferred-drop queue |
| 11 | low | a nested `run()` inside a provider fails unrelated work with `rpc/provider` |
| 17 | low | `recv`/`recv_topic` ignore lane subscription; subscription is currently advisory and the contract needs a decision |
| 18 | low | `restore_capability` resolves a provider by `name()`, first match wins when two share a name |

Gate: `cargo test --all-features` 375 passed, 0 failed; clippy clean on the
default and all-features sets; fmt clean.
