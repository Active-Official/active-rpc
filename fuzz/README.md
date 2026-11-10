# Fuzzing

Sixteen targets cover framing, authorization, promises, budgets, tools, channels,
bulk transfer, replay packages, topics, receipts, the WASM sandbox, the module
provider, the durable record parser and transports. Every target drives the real
kernel or adapter and asserts an invariant, not only "did not crash".

| Target | Surface | Invariant |
|---|---|---|
| `fuzz_arp1_frame` | envelope and capability-table codecs, gRPC framing | decode is total and a fixed point; a strict limit profile refuses an envelope it bounds |
| `fuzz_capability_lifecycle` | mint, attenuate, revoke, clone, drop, call, transplant | attenuation only narrows; revoked and foreign capabilities are refused; one object produces exactly one drop |
| `fuzz_promise_graph` | pipelining, cancel, resolve, destroy lane | a promise settles once; a never-minted promise id is `rpc/unknown-promise` at dispatch; a destroyed lane refuses calls |
| `fuzz_budget_matrix` | calls, bytes, wall, nodes, depth, array, value | zero ceilings are refused; each ceiling binds at its own value, with the code that names it |
| `fuzz_tool_mcp` | `McpSession` over `MemoryTransport`, including the server's own response text | the handshake is not a call; undiscovered tools are refused; a malformed response is `rpc/provider` |
| `fuzz_tool_http` | `HttpTool` allow-list | the allowed path is admitted; path and method escapes are `rpc/tool-policy` |
| `fuzz_tool_process` | `LocalProcess` argv allow-list | an argument outside the allow-list is admitted never, refused as `rpc/tool-policy` |
| `fuzz_channel_cap_transfer` | channel direction, close, capability transfer | direction is enforced; the payload survives; a transferred id does not retain the capability |
| `fuzz_transport_framing` | shared-memory ring, gRPC framing | a write larger than the segment is refused (built in-target, so no seed can miss it); reads never pass the head |
| `fuzz_bulk_plan` | `ARBL` plans and `ARBC` chunks | a plan and its chunks round-trip; a reordered, conflicting or truncated frame is refused; resume stays exact |
| `fuzz_replay_package` | `ARRP` decode, re-encode, replay | decode is total; re-encode is canonical; a replayed trace matches or is refused |
| `fuzz_topic_policy` | capability-filtered topics | publish succeeds exactly inside the grant; attenuation never widens |
| `fuzz_receipt_log` | `ARRL` reader and writer | the reader is total and canonical; the writer never accepts a record its own reader rejects |
| `fuzz_wasm_module` | module bytes, fuel, imports | construction is total; the sandbox refuses a huge table; a run is bounded (the clock is embedder-seeded, so a failure reproduces from the input; entropy is disabled) |
| `fuzz_domain_module` | `ModuleProvider` install and path lookup | the image parser is total; a fuzzed path answers or refuses, never panics; `evaluate` / `patch` run time-boxed on small images (RPC-26), and the redaction oracle inspects answer bytes for secrets instead of formatting them |
| `fuzz_persistence_record` | `CapabilityRecord` JSON and seal | the parser is total and canonical; a seal never verifies under a key it did not use; an edited record breaks it |

The transplant invariant holds across kernels with **different** secrets. Two
kernels sharing a secret are one authority domain and derive the same ids by
design (`SECURITY.md`), so the target flips seed byte 0 before building the
second kernel. `tests/fuzz_regression_tests.rs` pins the seed pair that
collided on 2026-10-31 (a 44-byte seed and a one-byte seed expand to the same
32 bytes) and the header-latency seed.

## Running

`cargo-fuzz` does not launch on Windows MSVC: libFuzzer reports
`STATUS_DLL_NOT_FOUND`. The supported lane is the Linux container:

```bash
python scripts/fuzz_docker.py --build
python scripts/fuzz_docker.py --all --runs 20000
python scripts/fuzz_docker.py --target fuzz_promise_graph --runs 100000
```

The scripts mount the repository at `/work`, so the corpus grows in place, and
they read the target list from `fuzz/Cargo.toml`, so a new target is picked up
without editing a second list.

On a native Linux host:

```bash
cargo +nightly fuzz run fuzz_arp1_frame -- -runs=200000 -max_len=65536
```

`-max_len=65536` is a campaign budget, not a parser ceiling: the wire, receipt
and replay parsers accept frames up to 64 MiB, and the wasm module ceiling is
1 MiB. Those limits are asserted in-target with buffers built there (an
oversize module, a ceiling-sized filler), so a campaign never needs `-max_len`
to reach them. The budget is spent on structure instead of on a buffer the
parser refuses in its first few bytes (R-20 round 3, L5).

## Corpus

Seeds are committed under `fuzz/corpus/<target>/`:

- a well-formed ping envelope, a truncated envelope and an envelope with trailing
  bytes for the framing target;
- short action streams (`0..63`, an interleaved pattern, all `0xFF`) for the
  lifecycle, promise, budget, tool and channel targets, so mutations start from
  a sequence that reaches several branches;
- a real `ARRP` package from `active-rpc-cli replay dump` plus truncated,
  bad-checksum, trailing-byte and empty-header variants for the replay target;
- topic masks (unrestricted, two-topic grant, empty grant) with action bytes for
  the topic target;
- a real `ARRL` log with header-only and truncated variants, plus the input that
  found the writer/reader disagreement, for the receipt target;
- empty, memory-only, trapping and truncated WebAssembly modules;
- a small shared-memory frame and a length-prefixed gRPC frame.

Every fixed bug adds a minimized seed named after the checklist item. Seeds are
deterministic and treated as hostile input. `c10-transplant-distinct-secret.bin`
is the 2026-10-31 nightly crash: 44 leading `0x06` bytes meant the harness's
"other" kernel expanded to the *same* secret, so the target asserted against a
capability the first kernel had minted itself.

## Campaigns

| Lane | Bound | Artifacts |
|---|---|---|
| Pull request and `main` | 2 000 runs per target plus the seed count | the crash input and the corpus, always |
| Nightly (`fuzz-nightly.yml`) | 7 minutes per target (`FUZZ_SECONDS: 420`) | `fuzz/artifacts` and the grown corpus, always |
| Nightly matrix (`nightly.yml`) | 200 000 runs or 15 minutes per target, 120-minute job timeout | the crash input always; the grown corpus only on failure |

A crash, an assertion failure or a panic fails the lane. The corpus cache is
committed rather than carried between runs, so a regression is reproducible from
the repository alone.
