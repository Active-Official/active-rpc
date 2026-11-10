# Corpus and coverage inventory — active-rpc

Baseline: 1.1.9 at commit `69acea89bd03a9a69ff88cdd6dd8d12560a2d210`.
Coverage measured 2026-10-27 with
`cargo llvm-cov --locked --all-features --summary-only` on Windows x86_64
(MSVC).

## Conformance vectors

`tests/conformance_tests.rs` builds its vectors inline:

| Vector | What it pins |
|---|---|
| minimal request | exact `ARP1` bytes for a request with no arguments |
| golden decode | the same bytes decode to the expected method and argument list |
| re-encode | every encoding is a fixed point |
| capability table shape | pinned table layout and count prefix |
| truncated prefixes | every strict prefix of a valid envelope is rejected |
| header attacks | length, kind, version and count fields are mutated together |
| error catalog | every declared code is unique and documented |
| wire limits | argument, capability and depth ceilings |

These are real cases but not files. The framing corpus below adds the same
shape as committed seeds so libFuzzer starts from valid structure.

## Fuzz targets

Sixteen structure-aware targets. `fuzz/README.md` is the primary table; this one
records the corpus each target starts from. `tests/fuzz_manifest_tests.rs`
fails if a lane (a workflow, the fuzz README, this file or the runner script)
omits a target the manifest declares.

| Target | File | Corpus | Semantic oracle |
|---|---|---|---|
| `fuzz_arp1_frame` | `fuzz_targets/fuzz_arp1_frame.rs` | ping, truncated, trailing | decode totality, fixed point, strict limits, table agreement |
| `fuzz_capability_lifecycle` | `fuzz_targets/fuzz_capability_lifecycle.rs` | three action streams | attenuation narrows, revoked/foreign/forged refused, zero ceiling refused, one drop per object |
| `fuzz_promise_graph` | `fuzz_targets/fuzz_promise_graph.rs` | three action streams | single settlement, cancel, pipelining, destroyed lane, unknown promise refused at queue |
| `fuzz_budget_matrix` | `fuzz_targets/fuzz_budget_matrix.rs` | three action streams | each ceiling binds at its own value; zero ceilings refused |
| `fuzz_tool_mcp` | `fuzz_targets/fuzz_tool_mcp.rs` | three action streams | handshake is not a call; undiscovered tools refused; a malformed server response is `rpc/provider` |
| `fuzz_tool_http` | `fuzz_targets/fuzz_tool_http.rs` | three action streams | the allowed path is admitted; escapes are `rpc/tool-policy` |
| `fuzz_tool_process` | `fuzz_targets/fuzz_tool_process.rs` | three action streams | argv escapes are refused at dispatch |
| `fuzz_channel_cap_transfer` | `fuzz_targets/fuzz_channel_cap_transfer.rs` | three action streams | direction, close/drain, payload, no lifetime extension |
| `fuzz_transport_framing` | `fuzz_targets/fuzz_transport_framing.rs` | small frame, length prefix | ring capacity (oversize built in-target), frame bounds, gRPC framing |
| `fuzz_bulk_plan` | `fuzz_targets/fuzz_bulk_plan.rs` | plan and chunk frames | round trip, reorder/conflict/truncation refused, exact resume |
| `fuzz_replay_package` | `fuzz_targets/fuzz_replay_package.rs` | real package plus four variants | total decode, canonical re-encode, replay matches or refuses |
| `fuzz_topic_policy` | `fuzz_targets/fuzz_topic_policy.rs` | topic masks | publish exactly inside the grant, attenuation never widens |
| `fuzz_receipt_log` | `fuzz_targets/fuzz_receipt_log.rs` | real log plus three variants | reader total and canonical, writer/reader agreement |
| `fuzz_wasm_module` | `fuzz_targets/fuzz_wasm_module.rs` | four module classes | construction total, oversize module and huge table refused, bounded run with an embedder-seeded clock and entropy disabled |
| `fuzz_domain_module` | `fuzz_targets/fuzz_domain_module.rs` | module images and paths | the image parser is total; every domain method answers or refuses (`evaluate` / `patch` time-boxed on small images, RPC-26) |
| `fuzz_persistence_record` | `fuzz_targets/fuzz_persistence_record.rs` | sealed and edited records | parser total and canonical, seal only under its own key |

`common.rs` holds the deterministic `Echo` provider and budget helpers; it is
not a target. `fuzz/Cargo.toml` declares each binary.

## Committed corpora

One directory per target under `fuzz/corpus/<target>/`; the count moves every
time a campaign finds new coverage, so it is not written down here:

```text
git ls-files fuzz/corpus | wc -l
```

`fuzz/target` and `fuzz/artifacts` remain ignored. A crash libFuzzer writes
lands in `fuzz/artifacts/<target>/`; CI and the nightly lanes upload it, and
minimizing it into `fuzz/corpus/<target>/` is the first step of the fix.

## Coverage snapshot

| File | Regions | Lines | Functions |
|---|---|---|---|
| `src/bin/peer.rs` | 0.00% | 0.00% | 0.00% |
| `budget.rs` | 80.56% | 78.38% | 61.54% |
| `cap.rs` | 72.39% | 76.80% | 73.33% |
| `channel.rs` | 65.79% | 74.65% | 53.85% |
| `domain.rs` | 71.51% | 75.46% | 67.44% |
| `error.rs` | 93.40% | 88.52% | 50.00% |
| `kernel.rs` | 87.38% | 86.72% | 83.33% |
| `lane.rs` | 80.56% | 82.86% | 83.33% |
| `promise.rs` | 85.71% | 87.18% | 85.71% |
| `security.rs` | **48.89%** | **49.21%** | 55.56% |
| `tool.rs` | **17.61%** | **16.02%** | **12.31%** |
| `transport/connect.rs` | 76.27% | 78.16% | 64.71% |
| `transport/mod.rs` | 66.03% | 72.08% | 53.57% |
| `transport/quic.rs` | 78.71% | 80.73% | 44.44% |
| `transport/shm.rs` | 67.97% | 62.91% | 57.14% |
| `value.rs` | 60.00% | 53.49% | 64.71% |
| `wire.rs` | 88.82% | 90.93% | 96.97% |
| **Total** | **67.53%** | **68.52%** | **58.62%** |

Interpretation:

- `tool.rs` at 16% was the largest untested attack surface. The MCP, HTTP and
  process fuzz targets now drive the policy and JSON conversion paths; the
  remaining uncovered lines are real network and process execution.
- `security.rs` at 49% contains refusal branches that the tool targets now
  reach.
- `peer.rs` remains 0%; it is an operator binary, not a library surface.
- Shared-memory framing is now fuzzed directly.

## Corpus policy

1. Committed seeds under `fuzz/corpus/<target>/`; action streams give the
   structure-aware targets several reachable branches from the first run.
2. Every fixed bug adds a minimized seed named after the checklist item.
3. Seeds are deterministic and contain no customer data.
4. The corpus is hostile input: it runs under the same `WireLimits` and
   sanitizers as external bytes.
5. Short campaign on pull requests and `main`, longer on the nightly lanes;
   `-max_len=65536` is a campaign budget, not a parser ceiling (the wire,
   receipt and replay frames run to 64 MiB and the wasm module ceiling is
   1 MiB, each asserted by a control in its target).
