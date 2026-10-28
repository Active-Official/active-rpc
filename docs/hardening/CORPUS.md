# Corpus and coverage inventory — active-rpc

Baseline: 1.1.9 at commit `69acea89bd03a9a69ff88cdd6dd8d12560a2d210`.
Measured 2026-10-27 with `cargo llvm-cov --locked --all-features --summary-only`
on Windows x86_64 (MSVC).

## Conformance vectors

There is no committed vector directory. `tests/conformance_tests.rs` builds its
vectors inline:

| Vector | What it pins |
|---|---|
| minimal request | exact `ARP1` bytes for a request with no arguments |
| golden decode | the same bytes decode to the expected method and argument list |
| re-encode | every encoding is a fixed point |
| capability table shape | pinned table layout and count prefix |
| truncated prefixes | every strict prefix of a valid envelope is rejected |
| header attacks | length, kind, version and count fields are mutated together, not one at a time |
| error catalog | every declared code is unique and documented |
| wire limits | argument, capability and depth ceilings |

This is a real corpus of cases but it is not a corpus of *files*, so it cannot
be handed to libFuzzer directly or published to an external researcher. H1.18
converts the inline cases into a committed `tests/vectors/` tree.

## Fuzz target (baseline)

| Target | File | Lines | Corpus in repo | Semantic oracle |
|---|---|---|---|---|
| `framing` | `fuzz/fuzz_targets/framing.rs` | 52 | **no** — CI writes one 28-byte ping envelope at run time | envelope decode is total and a fixed point; decoded counts respect `WireLimits`; capability table decoding agrees; every decoded budget has a finite call ceiling; gRPC unframe/frame is self-delimiting |

Gaps against H1.9–H1.17:

- One target covers the envelope, the capability table and the Connect framing
  helper. Capability lifecycle, promises, budgets, tools, channels and
  transports have no target.
- The corpus is one hand-written ping envelope. No truncated, oversized,
  overlapping or hostile-table seed is committed.
- Tool adapters (`tool.rs`) are the least covered code in the crate (16% lines)
  and have no fuzz target at all.

## Coverage snapshot (baseline)

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

- `tool.rs` at 16% is the largest untested attack surface: MCP, HTTP and local
  process adapters. H1.13–H1.15 and H2.12/D6 target it.
- `security.rs` at 49% contains the policy checks; uncovered branches are
  likely refusal paths.
- `peer.rs` is an operator binary; 0% is expected from library tests, but its
  error handling should be covered by an integration test.
- Transports sit at 63–81%; shared-memory framing has no hostile-frame fuzz
  target.

## Corpus policy

1. Committed seeds under `fuzz/corpus/<target>/` from the conformance cases and
   the hand-crafted near-miss list (H1.18).
2. Every fixed bug adds a minimized seed named after the checklist item.
3. Seeds are deterministic and contain no customer data.
4. The corpus is hostile input: it runs under the same `WireLimits` and
   sanitizers as external bytes.
5. Short campaign on pull requests; long campaign on `main` and nightly.
