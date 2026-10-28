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

| Target | File | Corpus | Semantic oracle |
|---|---|---|---|
| `fuzz_arp1_frame` | `fuzz_targets/fuzz_arp1_frame.rs` | ping, truncated, trailing | decode totality, fixed point, strict limits, table agreement |
| `fuzz_capability_lifecycle` | `fuzz_targets/fuzz_capability_lifecycle.rs` | three action streams | attenuation narrows, revoked/foreign/forged refused, zero ceiling refused |
| `fuzz_promise_graph` | `fuzz_targets/fuzz_promise_graph.rs` | three action streams | single settlement, cancel, pipelining, destroyed lane |
| `fuzz_budget_matrix` | `fuzz_targets/fuzz_budget_matrix.rs` | three action streams | each ceiling binds; zero ceilings refused |
| `fuzz_tool_mcp` | `fuzz_targets/fuzz_tool_mcp.rs` | three action streams | handshake is not a call; undiscovered tools refused; malformed responses error |
| `fuzz_tool_http` | `fuzz_targets/fuzz_tool_http.rs` | three action streams | path and method escapes are `rpc/tool-policy` |
| `fuzz_tool_process` | `fuzz_targets/fuzz_tool_process.rs` | three action streams | argv escapes are refused before spawn |
| `fuzz_channel_cap_transfer` | `fuzz_targets/fuzz_channel_cap_transfer.rs` | three action streams | direction, close/drain, no lifetime extension |
| `fuzz_transport_framing` | `fuzz_targets/fuzz_transport_framing.rs` | small frame, length prefix | ring capacity, frame bounds, gRPC framing |

`common.rs` holds the deterministic `Echo` provider and budget helpers; it is
not a target. `fuzz/Cargo.toml` declares each binary.

## Committed corpora

| Directory | Seeds |
|---|---|
| `fuzz/corpus/fuzz_arp1_frame` | 3 |
| `fuzz/corpus/fuzz_capability_lifecycle` | 3 |
| `fuzz/corpus/fuzz_promise_graph` | 3 |
| `fuzz/corpus/fuzz_budget_matrix` | 3 |
| `fuzz/corpus/fuzz_tool_mcp` | 3 |
| `fuzz/corpus/fuzz_tool_http` | 3 |
| `fuzz/corpus/fuzz_tool_process` | 3 |
| `fuzz/corpus/fuzz_channel_cap_transfer` | 3 |
| `fuzz/corpus/fuzz_transport_framing` | 3 |

`fuzz/target` and `fuzz/artifacts` remain ignored.

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
5. Short campaign on pull requests; long campaign on `main` and nightly.
