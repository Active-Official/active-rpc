# ADR-0026 - One method ceiling, 64, in every layer

**Status:** accepted (2026-11-09). Behaviour change to mint, attenuate and
restore: a grant carrying more than 64 names — methods, topics or tool names —
is refused with `rpc/invalid-argument` instead of minting a capability the
wire cannot encode and the replay cannot record. The introduction bound is
lowered from 4,096 to the same 64.

## Context

The kernel checked the shape of every name a capability grants — 1..=1,024
bytes, no control characters — but never counted the names
(`check_method_names`, RPC-07; round-1 A.2, F-R03-01 / SEC-F6). A
kernel-minted cap could carry 5,000 or 100,000 method names: verification
confirmed both mint, while the wire's default descriptor limit is 64
(`WireLimits::default().max_methods`) and the replay recorder refuses a
65th (`replay::MAX_METHODS`). The introduction allowed 4,096 methods per
provider, so the three layers disagreed twice over: a 65-method provider
was introduced in full and minted fine, then failed every call. A grant of
~1,000,000 names is also ~1 GiB of method names to copy, seal and replay.
Topics had no count ceiling anywhere, and `ToolPolicy.allowed` neither — the
same hole through two more name sets.

## Decision

1. **64, everywhere.** The ceiling is 64 because the wire and the replay
   already agree on it, and a grant larger than 64 cannot be encoded by the
   default wire or recorded by replay. Picking 4,096 would have left the
   disagreement for 65–4,096; raising the wire and replay to 4,096 was
   rejected — a bigger blast radius (wire denial-of-service posture, and
   tests that assert the encoder and the recorder refuse over-64 sets).
   The verifier's judgement and the F3 handoff design for BND-F5 both say
   64.
2. **One constant, not four.** `kernel::MAX_METHODS_PER_GRANT` is the
   ceiling; `intro::MAX_METHODS_PER_PROVIDER` aliases it, so the
   introduction cannot drift from the grant by construction. The wire and
   replay already hold 64 and are unchanged. A cross-layer test pins the
   equality (`kernel == intro == replay == WireLimits::default`), so a
   future change to any one of them fails loudly instead of silently
   re-opening the disagreement.
3. **The choke point is `check_method_names`.** All grant paths — mint,
   mint-as/bound, attenuate, restore — already call it, so the count checks
   there cover every path with no per-site edits. The checks run before any
   name is walked: a 100,000-name set is refused on its length alone. The
   same ceiling bounds methods, topics and `tool_policy.allowed`, so no
   name set can be the unbounded one instead. The refusal is
   `Error::InvalidArgument` (`rpc/invalid-argument`), the same family as
   the adjacent per-name shape refusals. Builders (`CapAttrs::new`,
   `with_methods`, `ToolPolicy::allow`, `restrict_topics`) still collect
   without refusing — they return `Self`, so the refusal lands at the
   grant, and their docs say so.
4. **Attenuation's subset rule fires first.** Attenuating a 64-method
   parent to 65 methods is a widening by definition, so it is refused
   with `rpc/attenuation-escalation` before the count check runs; the
   count check in `check_method_names` is the second line for a legacy
   parent that already holds more than the ceiling. No attenuate path can
   yield a grant over 64 either way.

## Consequences

- A provider with more than 64 methods is now omitted from introductions
  (taped once as `intro.skipped`, the existing deliberate over-bound
  policy) while remaining callable through a subset capability for the
  first 64 methods in `methods()` return order. Methods past the captured
  prefix are unreachable: a 65-method cap cannot mint, and a one-method
  cap for a past-prefix method mints but dispatch refuses the call
  (`rpc/method-not-granted`), because the kernel captured only the prefix.
  Which methods survive the capture is provider-returned order — that
  arbitrariness is R2-R17-03, a separate finding, not closed here.
- **Blast radius:** any deployment minting 65–4,096-method caps — only
  possible via the kernel, never via the wire — breaks at mint after this
  change. No in-repo test minted more than 64 methods through a kernel
  path; the wire-level and replay-level over-64 tests are untouched, and
  the introduction boundary tests follow the aliased constant. The MCP
  session tool count (`tool::MAX_MCP_TOOLS`, 4,096) is a different ceiling
  — a session may list up to 4,096 tools, but one capability cannot
  authorise more than 64 of them.
- No format change, no new API: the only new observable behaviour is the
  refusal, and the lowered introduction bound. The ceiling is the public
  constant `MAX_METHODS_PER_GRANT` (`src/kernel.rs`), next to
  `MAX_GRANTED_METHOD_BYTES`.
- **Residual, not closed here:** the count check bounds the grant, not
  the provider: a provider may still *advertise* any number of methods,
  and the captured prefix is the first 64 in provider order. The wire's
  `WireLimits.max_methods` stays configurable, so an embedder that raises
  it past 64 can decode descriptors the kernel will never mint — the
  kernel ceiling is the binding constraint for minted caps, and loosening
  the wire's decoder limit is out of scope (RPC-19 covers preallocation
  under loose limits).
