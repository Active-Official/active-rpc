# ADR-0018 - Deterministic replay packages (`ARRP`)

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
≤ 1 MiB, methods per capability ≤ 64, `arg_bytes ≤ 1 MiB`, 16 MiB of declared
argument bytes per package, and a 64 MiB body. The recorder, the encoder and the
decoder enforce the same set, so a package that is written is a package that
reads. A package with an unknown tag, a reserved flag set, trailing bytes, a bad
checksum or an out-of-range ordinal is refused with `rpc/replay`.

Semantics:

1. **Inputs, not values.** A call records its capability ordinal, method and
   the size of the text value replay synthesizes. The argument text is never
   stored, and the number is the synthesized length, not the wire size the
   kernel charges (that appears as `call.queued:<method>:<bytes>`). A package
   cannot leak the secrets it exercised.
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

## Amendments (R-12 round 1, 2026-11-01)

- **The trace pins what a call asked for.** `Event::CallQueued` carries the method
  (bounded to 64 bytes, escaped, with a digest tail when truncated) and the
  charged argument size, and the trace renders `call.queued:<method>:<bytes>`.
  Without it a package could be edited from one granted method to another and
  still compare equal; no argument *value* is recorded.
- **The recorder enforces the decoder's ceilings.** `MAX_OPS`, the trace ceiling,
  the method count (64) and each method length (`u16`, 64 KiB) are checked while
  recording, `Recorder::package` and `ReplayPackage::encode` return `Result`, and
  a capture that lost events poisons the recorder. A refused mint, attenuation or
  revoke captures the events it emitted before returning.
- **A package begins with its header latency**, and replay refuses one that does
  not: the header is the initial rate, not only a summary of the last one.
- **Replay is linear in the operations.** `Agent::events_since` returns only the
  delta a capture missed instead of cloning the bounded tape per operation; the
  previous shape cost 85.9 s (release) for a 2.1 MB package of 100 000 calls.
- **A recorder is not an observer.** It drives its own kernel, so a package
  describes a synthetic demo session: the method and the argument *size* are
  faithful inputs, the argument shape is not.

## Amendments (R-12 round 2, 2026-11-02)

The round-1 amendment claimed the trace pinned a call's method and size. It did
for an admitted call (`call.queued:<method>:<bytes>`) and for nothing else: a
refused call's method, a mint's grant, a TTL, the latency operation and a
revoke's target were unpinned, and `replay` also compared a replayed op list it
had itself rebuilt from the package, so that comparison could never fire. The
following replace the earlier claim.

- **Every operation has an input entry in the trace.** `op.latency:<ms>`,
  `op.mint:<digest>:<ttl>`, `op.attenuate:<parent>:<digest>:<ttl>`,
  `op.call:<cap>:<digest>:<bytes>` and `op.revoke:<cap>`, appended before that
  operation's kernel events. The digest is 64 bits over length-prefixed method
  names, so the text of a caller-chosen name is never recorded. The entry is
  computed from the package's fields at replay time and from the live arguments
  at record time: an edit that is not followed by re-running the replay no longer
  matches the trace. The op-list comparison is gone; it proved nothing.
- **Record and encode enforce the same ceilings as decode**: argument bytes per
  call, the 16 MiB argument total, `MAX_METHODS` (64) per grant, and the 64 MiB
  body (checked as the body grows). Before this, a recorder could emit a package
  its own decoder refused, and `String::repeat` in `Recorder::call` would abort
  the process on a caller-chosen size.
- **An operation whose kernel action succeeded reports that action.** A capture
  that loses events poisons the recorder and `package()` refuses, but it does not
  turn a completed revocation into `rpc/replay`: a caller would retry a kill
  switch that already fired.
- **A borrowed handle's release belongs to the operation that borrowed it.** The
  transient `CapHandle` clone is dropped before the capture that closes the
  operation, so the trace never ends an operation on an unmatched retain.
- **`replay_trace` applies the header-latency rule too.** The diagnostic half is
  public and used to skip operation 0 without checking that it is the header.
- **The tape-wrap guard is reachable.** Revoking a subtree of more than
  `MAX_EVENTS` descendants emits every dropped capability in one operation, so a
  capture then fails by design; `a_recorder_that_lost_events_still_reports_the_kernel_outcome`
  drives it.
- **Discriminators are 128 bits.** The introduction fingerprint in the trace, the
  method digest tail in `call.queued` and every `op.*` digest are 16 bytes: a
  peer that chooses its certificate, or a caller that chooses two long names with
  a shared prefix, must not be able to target a collision. A call's method digest
  is domain-separated like a grant digest.

## Amendment (R-12 round 3, 2026-11-02)

The verification pass found four places where the round-2 claim was still looser
than it read.

- **The recorder budgets the body as it records.** A running byte count (header,
  each operation, each input entry, the checksum) refuses the operation that
  would cross `MAX_PACKAGE_BYTES`, so an embedder cannot retain a body that
  `encode` will reject. The operator's session up to that point stays valid and
  readable.
- **`encode` refuses a package `replay` refuses.** A missing or foreign header
  latency is an encode error, not only a replay error, so "written" implies
  "readable" implies "replayable".
- **A method over `MAX_STRING` is refused at record time**, matching `encode`.
- **The op ceiling is a refusal, not a poisoning.** Reaching `MAX_OPS` refuses
  the next operation and leaves the recorder usable; only a lost capture poisons
  a session. (The earlier code also reported the loss as `"lost events"` for a
  ceiling refusal, which was the wrong diagnosis.)

The CLI writes a package through a `create_new` temporary beside the destination
and renames it, so a planted symlink at the temporary path cannot redirect the
write, and an interrupted write leaves the previous artifact intact.

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
  of shipping a trace with a missing prefix. One operation can reach this today
  (a revoke over a subtree larger than the tape), and the recorder reports the
  revoke's own outcome while `package()` refuses.
