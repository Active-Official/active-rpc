# ADR-0019 — Fuel-metered WebAssembly guest tools

**Status:** accepted (2026-10-31). Feature `wasm-tools`; no wire change.

## Context

Tools are currently host functions written in Rust (MCP, HTTP, local process).
A third-party tool written in a portable language has no way to run inside the
capability model, and giving it host access would let it reach past the
capability that invoked it. Active RPC needs a sandbox whose resource use is
bounded and whose host surface is empty unless a capability explicitly widens it.

## Decision

- New optional feature `wasm-tools`, backed by the `wasmi` interpreter (pure Rust,
  deterministic fuel metering, no unsafe requirement in our code).
- `wasm_tool::WasmTool` implements `Provider`. It compiles a guest at
  construction and runs one instance per call.
- The kernel keeps authority: the tool is reachable only through a minted
  capability, and a method the capability does not grant is refused with
  `rpc/method-not-granted` before the guest runs.

### ABI v1

```text
exports:  memory (exported as "memory"), run(len: i32) -> i32
input:    host writes at offset 0          (≤ 64 KiB)
output:   guest writes at offset 65536, returns its length (≤ limit)
imports:  none; a module that declares any import is refused
```

### Limits

- **Fuel**: `WasmLimits::fuel` (default 1,000,000) is set before instantiation and
  covers `start` and `run`. An out-of-fuel trap is reported as `wasm/fuel`.
- **Memory**: a `StoreLimits` limiter caps linear memory at
  `max_memory_bytes` (default 16 MiB); a module that asks for more fails to
  instantiate.
- **Output**: `max_output_bytes` (default 64 KiB) bounds the returned length.
- **Input**: at most 64 KiB, the input window before the output area.

### Error codes (provider class `rpc/provider`)

| Code | Meaning |
|------|---------|
| `wasm/module` | the guest did not compile |
| `wasm/import` | the guest declares an import (host functions are not part of v1) |
| `wasm/instantiate` | instantiation failed, including memory limits |
| `wasm/memory` | the exported memory is missing or too small for the exchange |
| `wasm/entry` | the `run` export is missing or has the wrong type |
| `wasm/fuel` | the fuel budget was exhausted |
| `wasm/trap` | the guest trapped for another reason |
| `wasm/input` | the call input exceeds the input window |
| `wasm/output` | the returned length is negative or over the ceiling |

## Consequences

- The interpreter adds a dependency tree only when the feature is enabled;
  default builds are unchanged.
- Host functions are deliberately absent in v1. A v2 that imports host calls
  must route them through the same capability checks and is a new ADR.
- Output is text in v1; binary results should use a module value later.

## Addendum (2026-10-31) — ABI v2: declared host imports

ABI v1 allowed no imports at all, which made a guest that needs the time or
entropy impossible to write. ABI v2 keeps deny-by-default and lets the
**embedder** declare a host policy per tool instance:

```rust
WasmHostPolicy { clock, random, log, max_log_bytes }   // every flag defaults to false
WasmTool::from_bytes_with_policy(bytes, limits, policy)
```

| Import | Signature | Grant | Bound |
|---|---|---|---|
| `env.clock_ms` | `() -> i64` | `clock` | wall-clock milliseconds since the Unix epoch |
| `env.random` | `(ptr u32, len u32) -> i32` | `random` | at most 64 KiB per call, OS CSPRNG; bounds-checked against guest memory |
| `env.log` | `(ptr u32, len u32) -> i32` | `log` | at most `max_log_bytes` (policy ceiling 64 KiB) per call, captured by the host |

Rules:

- Construction lists the module's imports and refuses the whole module
  (`wasm/import`) if any import is not granted. A policy flag of `false` means
  the import must not exist, so the module cannot silently depend on it.
- `from_bytes` keeps the v1 behavior (`WasmHostPolicy::default()`), so existing
  guests and tests are unchanged.
- The host functions are read-only: clock, entropy and a per-call log buffer.
  They cannot touch the filesystem, the network, the environment or the kernel.
- Fuel, recursion, stack, memory and output ceilings are unchanged; the log is
  captured even when the guest traps, because it is diagnostic evidence.
- The kernel still gates whether the tool runs at all: the capability that
  points at the tool is the only way in, and its budget applies.

Limits of the profile:

- `clock_ms` is wall-clock, so a recorded session that calls a guest using it is
  not byte-deterministic. Replay packages record the demo provider, not WASM
  guests; keeping a guest deterministic requires it to take the time as input.
- There is no filesystem or network import. Adding one requires a new policy
  field, a capability-scoped path or address allow-list, and its own ADR.
