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
