# ADR-0018 — Deterministic replay packages (`ARRP`)

**Status:** accepted (2026-10-31). New artifact format; the ARP1 envelope is
unchanged.

## Context

Debugging a capability decision after the fact needs the inputs and the
decisions together. Logs show events, but not the sequence of mints,
attenuations, calls, expirations and revocations that produced them, and a
recorded session must not become a second place where arguments or secrets leak.

## Decision

A replay package (`ARRP`, version 1) is a canonical little-endian artifact:

```text
magic "ARRP"            4
version u8              1
flags u16 LE            2      must be 0
latency_ms u64 LE       8      simulated provider latency per batch
op_count u32 LE         4
ops ...
trace_count u32 LE      4
traces ...
checksum               32      Blake3 over every preceding byte
```

Operation tags:

| Tag | Operation | Layout |
|-----|-----------|--------|
| 1 | Set latency | `ms u64` |
| 2 | Mint | `method_count u16`, `(len u16, bytes)*`, `ttl_flag u8`, `[ttl u64]` |
| 3 | Attenuate | `parent u32`, then the Mint layout |
| 4 | Call | `cap u32`, `method (len u32, bytes)`, `arg_bytes u64` |
| 5 | Revoke | `cap u32` |

Trace entries: `flags u8` (0 = no capability, 1 = capability), `event (len u32,
bytes)`, and `cap u32` when the flag is set.

Limits: `op_count ≤ 100,000`, `trace_count ≤ 1,000,000`, method and event names
≤ 1 MiB, methods per capability ≤ 64, `arg_bytes ≤ 1 MiB`. A package with an
unknown tag, a reserved flag set, trailing bytes, a bad checksum or an
out-of-range ordinal is refused with `rpc/replay`.

Semantics:

1. **Inputs, not values.** A call records its capability ordinal, method and
   argument wire size. The argument text is never stored; replay synthesizes a
   value of the same size. A package cannot leak the secrets it exercised.
2. **Ordinals, not ids.** Capability ids are replaced by first-seen ordinals, so
   the trace is stable across kernels with different secrets.
3. **Decisions are the trace.** Refusals (including an expired capability and a
   revoked one) appear as trace entries. Replay executes every operation,
   tolerates kernel refusals as recorded, and compares the whole trace; the first
   difference is reported with its index. **Every attempt is recorded, including
   one the kernel refuses**: a refused attenuation clones the parent handle
   first, so it emits `cap.retained`/`cap.released`, and a trace that carried
   those events without the input would not replay. A bad ordinal (a recorder
   bug, not a decision) is still refused before anything is recorded.
4. **Integrity, not authenticity.** Blake3 detects corruption and naive edits.
   A party that can rewrite the file can also recompute the checksum; a package
   is a debug artifact, not a signed attestation. Signing belongs with the
   receipt/release work and would be a new ADR.

## Consequences

- `active_rpc::replay` exposes `Recorder`, `ReplayPackage`, `Op` and `Trace`.
- `active-rpc-cli replay dump|run` records the demo session and verifies a
  package end to end; both are covered by the CLI test suite.
- Replay is deterministic because the kernel clock is virtual (`set_latency`
  advances it per batch); a future wall-clock mode needs a recorded time source.
- The decoder enforces a total package ceiling (64 MiB) and a ceiling on the
  sum of declared argument sizes (16 MiB), in addition to the per-field limits:
  the field limits alone allow an arbitrarily large body and 100k × 1 MiB of
  transient allocation during replay.
- The recorder tails the kernel tape by *total* event count. If the bounded tape
  wrapped between two captures, the recorder refuses with `rpc/replay` instead
  of shipping a trace with a missing prefix. No current operation emits enough
  events in one gap to reach this, so it is a guard rather than a reachable
  state today.
