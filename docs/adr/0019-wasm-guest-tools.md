# ADR-0019 - Fuel-metered WebAssembly guest tools

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
  covers `start` and `run`. An out-of-fuel trap is reported as `wasm/fuel`,
  including one raised by the `start` function. A capability's wall budget
  bounds it further: the call gets at most `max_wall_ms × FUEL_PER_MS`
  (5 000 fuel per millisecond), so a 100 ms grant buys 500 000 fuel whatever the
  tool's default is. Fuel is the instruction bound, not a wall clock: on a slow
  or loaded machine the same fuel takes far longer than the rate predicts, so
  every call is also bounded by a real wall-clock deadline enforced by a clock
  around the guest's execution (RPC-37). A direct `WasmTool::call` derives its
  deadline from its fuel budget (`fuel / FUEL_PER_MS`); a call through the
  kernel runs under the granted `max_wall_ms`. A guest that outlives its
  deadline is refused with `rpc/timeout`, and its worker thread is detached
  until its fuel exhausts.
- **Memory**: a `StoreLimits` limiter caps linear memory at
  `max_memory_bytes` (default 16 MiB, ceiling 256 MiB); a module that asks for
  more fails to instantiate with `wasm/limits`.
- **Table**: `max_table_elements` (default 1 024, ceiling 65 536) bounds every
  table the guest declares or grows. Without it a 140-byte module can ask for
  tens of gigabytes and a failed allocation aborts the process.
- **Output**: `max_output_bytes` (default 64 KiB) bounds the returned length.
- **Input**: at most 64 KiB, the input window before the output area.
- **Module text**: WebAssembly *text* is refused (`wasm/module`) unless the
  embedder sets `WasmHostPolicy::accept_wat`. Text expands far beyond its own
  size during compilation, and compilation happens before any fuel is charged.
  Text that is accepted is capped at 64 KiB (`MAX_WAT_BYTES`) *before*
  parsing, and the compile itself runs under a 5 s wall deadline
  (`MAX_COMPILE_WALL`, RPC-39) — see the addendum below.

### Error codes (provider class `rpc/provider`)

| Code | Meaning |
|------|---------|
| `wasm/module` | the guest did not compile, or was not binary module bytes |
| `wasm/import` | the guest imports something the policy does not grant (wrong name, kind or signature) |
| `wasm/limits` | a declared or grown resource is over a ceiling (memory, table) |
| `wasm/instantiate` | instantiation failed for another reason |
| `wasm/memory` | the exported memory is missing or too small for the exchange |
| `wasm/entry` | the `run` export is missing or has the wrong type |
| `wasm/fuel` | the fuel budget was exhausted, in `start` or in `run` |
| `wasm/trap` | the guest trapped for another reason. This is the **wasm provider's** code only: the kernel's own egress panic (a redaction walk that unwinds for any provider) reports `provider/egress-panic`, so a receipt can still attribute a trap to a wasm guest |
| `wasm/input` | the call input is missing, exceeds the input window, is not one text/module argument, or is a module image carrying a structural secret |
| `wasm/output` | the guest returned a negative length, which is its own fault signal |
| `wasm/output-limit` | the returned length is past the output ceiling (the static cap or the call's share); the adapter reports it as `rpc/budget-exceeded` when the grant is what bound it and as this code otherwise |
| `wasm/spawn` | the host could not start the guest's worker thread; the guest never ran |
| `wasm/timeout` | the compile outlived its wall deadline (RPC-39) |
| `rpc/timeout` | the wall deadline elapsed before the guest finished. This is not provider class: it is the top-level timeout code, shared with the other adapters |

## Consequences

- The interpreter adds a dependency tree only when the feature is enabled;
  default builds are unchanged.
- Host functions are deliberately absent in v1. A v2 that imports host calls
  must route them through the same capability checks and is a new ADR.
- Output is text when the guest returns valid UTF-8; other bytes travel as a
  module value, so a binary result is never mangled into replacement
  characters.

## Addendum (2026-11-09) — RPC-37: a real wall deadline

Fuel was the only wall-clock bound, and it is not a wall clock: on a slow or
loaded machine a 100 ms grant's worth of fuel runs well past the grant
(158 ms measured on the fix machine, 370-487 ms for 1M fuel in verification),
and a direct `WasmTool::call` took no wall parameter at all. Every call now
runs on a worker thread under a real wall-clock deadline: the granted
`max_wall_ms` through the kernel, the fuel-derived `fuel / FUEL_PER_MS` for a
direct call. A guest that outlives its deadline is refused with `rpc/timeout`;
the worker thread is detached and runs until its fuel exhausts, so the deadline
binds the caller even though the guest's remaining work is still bounded by
fuel. A watchdog that zeroes fuel from another thread was considered and
rejected: wasmi 2.0.0 exposes no interrupt handle, and `Store::set_fuel` needs
`&mut Store`, which the executing thread holds.

## Addendum (2026-11-09) — RPC-39: a wall deadline on compilation

Compilation happened before any fuel existed, with no time bound at all: a
1 MiB text module held the caller thread for ~1.1 s (1.24 s in verification)
while the fuel meter and the call deadline (RPC-37) both bound execution
only — the module does not exist yet when they would apply. Two bounds now
apply before execution can start: text input is capped at 64 KiB
(`MAX_WAT_BYTES`) *before* parsing (~70 ms worst case on the fix machine,
against ~1.0 s for a 1 MiB text module), and the parse plus `Module::new`
run on a worker thread under a 5 s wall deadline (`MAX_COMPILE_WALL`, one
default call's wall grant and 16x the worst legitimate compile measured —
~311 ms in debug for a binary just under the 1 MiB ceiling). A compile that
outlives its deadline is refused with `wasm/timeout` and its worker is
detached to finish on its own; the deadline is enforced by the join, never
by killing the worker. The timeout is a `wasm/...` provider code, not the
top-level `rpc/timeout` the call deadline reports: every construction
refusal is a provider-coded `wasm/...` error, and the fuzz target asserts
that shape. `from_bytes_with_policy_and_deadline` sets the deadline
explicitly; `from_bytes` and `from_bytes_with_policy` use the default.

## Addendum (2026-11-01) — R-14 hostile review

A hostile review of the sandbox found one critical and three high findings; all
are closed, and the contract tightened in five places:

- **Tables are bounded** (`max_table_elements`). A module declaring a huge table
  used to be instantiated for real: 130 bytes of WAT asked for ~1.6 GB, and an
  allocation failure aborts the process, which `catch_unwind` cannot contain.
- **A call's wall budget bounds the fuel** (`FUEL_PER_MS`), so a capability that
  granted 100 ms no longer buys minutes of interpretation.
- **The clock is the kernel's.** `env.clock_ms` used to read `SystemTime` behind
  the kernel's back, which is a covert channel and a replay-determinism hole. It
  now reports `Call::now_ms` (the kernel's clock); an embedder outside the kernel
  must seed it with `WasmTool::set_time_ms`.
- **Imports are matched on kind and signature**, not just on name: a memory
  called `env.log` is not a granted function.
- **`mutating` is honest.** A run mutates provider state (the guest log), so a
  read-only capability is refused instead of running third-party code.
- Smaller: the instantiate error is classified (fuel vs import vs limits), a call
  must carry exactly one text/module argument, a refusal leaves no stale log, and
  `used + len` cannot wrap on a 32-bit host.

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
| `env.clock_ms` | `() -> i64` | `clock` | the kernel's `Call::now_ms` (virtual by default; wall-clock only when the agent enables that mode) |
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

- `clock_ms` reports the kernel/embedder clock, so a guest under the default
  virtual clock is deterministic. A deployment that enables wall-clock mode makes
  the guest time-dependent; a recorded session then needs the guest to take the
  time as input, because replay packages record the demo provider, not WASM
  guests.
- There is no filesystem or network import. Adding one requires a new policy
  field, a capability-scoped path or address allow-list, and its own ADR.
