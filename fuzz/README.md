# Fuzzing

Nine targets cover framing, authorization, promises, budgets, tools, channels
and transports. Every target drives the real kernel or adapter and asserts an
invariant, not only "did not crash".

| Target | Surface | Invariant |
|---|---|---|
| `fuzz_arp1_frame` | envelope and capability-table codecs, gRPC framing | decode is total and a fixed point; strict limits never panic |
| `fuzz_capability_lifecycle` | mint, attenuate, revoke, clone, drop, call, transplant | attenuation only narrows; revoked and foreign capabilities are refused |
| `fuzz_promise_graph` | pipelining, cancel, resolve, destroy lane | a promise settles once; a destroyed lane refuses calls |
| `fuzz_budget_matrix` | calls, bytes, wall, nodes, depth, array, value | zero ceilings are refused; each ceiling binds |
| `fuzz_tool_mcp` | `McpSession` over `MemoryTransport` | the handshake is not a call; undiscovered tools are refused |
| `fuzz_tool_http` | `HttpTool` allow-list | path and method escapes are `rpc/tool-policy` |
| `fuzz_tool_process` | `LocalProcess` argv allow-list | arguments cannot escape; no process is spawned for a refusal |
| `fuzz_channel_cap_transfer` | channel direction, close, capability transfer | direction is enforced; a transferred id does not retain the capability |
| `fuzz_transport_framing` | shared-memory ring, gRPC framing | a frame larger than the segment is refused; reads never pass the head |

## Running

`cargo-fuzz` does not launch on Windows MSVC: libFuzzer reports
`STATUS_DLL_NOT_FOUND`. The supported lane is the Linux container:

```bash
python scripts/fuzz_docker.py --build
python scripts/fuzz_docker.py --all --runs 20000
python scripts/fuzz_docker.py --target fuzz_promise_graph --runs 100000
```

The scripts mount the repository at `/work`, so the corpus grows in place.

On a native Linux host:

```bash
cargo +nightly fuzz run fuzz_arp1_frame -- -runs=200000
```

## Corpus

Seeds are committed under `fuzz/corpus/<target>/`:

- a well-formed ping envelope, a truncated envelope and an envelope with trailing
  bytes for the framing target;
- short action streams (`0..63`, an interleaved pattern, all `0xFF`) for the
  lifecycle, promise, budget, tool and channel targets, so mutations start from
  a sequence that reaches several branches;
- a small shared-memory frame and a length-prefixed gRPC frame.

Every fixed bug adds a minimized seed named after the checklist item. Seeds are
deterministic and treated as hostile input.

## Budgets

Pull requests run a short campaign per target; `main` and the nightly lane run a
longer one. A crash, an assertion failure or a panic fails the lane.
