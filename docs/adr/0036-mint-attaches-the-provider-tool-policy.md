# ADR 0036 — Mint attaches the provider's tool policy by default

**Status:** Accepted 2026-11-10 (RPC-41).

## Context

Round 1, R-08 M1 (AUDIT-REPORT.md, R-08 section), verified CONFIRMED by W2
at both 89b6404 and 7702ece: the MCP session policy is advisory, not
automatic. The kernel enforces a tool policy only when `CapAttrs.tool_policy`
is `Some` (the dispatch gate and the dispatch-time re-check); minting a
capability for an MCP or HTTP tool without attaching
`session.policy()` / `http_tool.policy()` skips the method/arg-byte gate
entirely — only `CapAttrs.methods` and the budget still apply. W2's proof
(`w2_rpc41_mint_without_policy_skips_arg_gate`): the same MCP echo session,
the same 200,000-byte argument — without a policy the call succeeds; with
an explicit 1 KiB policy the identical call is refused `rpc/tool-policy`.

The kernel had the right gate and the wiring did not use it — the quiet
counterpart to RPC-36, where the kernel had the right read-only gate and
the MCP annotations never reached it. Every tool provider already builds
its policy (`McpSession::policy`, `HttpTool::policy`,
`LocalProcess::policy`); nothing called them at mint.

The fix is intentionally behaviour-changing: any embedder that today
mints a tool capability without a policy and relies on the absence of
the gate loses that absence. That reliance is exactly the bug, but the
change must be announced, not slipped in — hence this ADR and the
migration note.

## Decision

- **Mint attaches the provider's policy when the minter supplies none.**
  `Provider` gains a `tool_policy()` method (default `None`, following
  the `module_content_hash` precedent), implemented by the three tool
  providers to return their existing `policy()`. The policy is captured
  in `ProviderFacts` at registration, alongside `methods` and
  `mutating`, and `Agent::mint` attaches it when
  `attrs.tool_policy` is `None`. `mint_bound` funnels through `mint`,
  so it is covered.
- **An explicit policy wins.** The attach is a default, not a ceiling:
  a minter-supplied policy is kept as-is, narrower or wider than the
  provider's. A wider explicit policy is the operator's deliberate
  statement, and it is the remedy for the one edge below.
- **The attached policy is validated like a minter-supplied one.**
  `check_method_names` runs after the attach, so a hostile provider's
  tool names get the same refusal as a minter-supplied policy's: a
  policy naming more than 64 tools, or a name the wire cannot carry,
  refuses the mint. One refusal precedence changes: an unknown
  provider is now reported before an invalid method name.
- **Attenuation cannot drop the gate.** `CapAttrs::attenuate` already
  refuses a child without a policy under a parent with one, so a
  policy attached at mint cannot be laundered out through a
  delegation.
- **Plain providers are unaffected.** The trait default is `None`,
  so a provider with no tool-level gate mints exactly as before, and
  adding the method breaks no external `Provider` implementation.
  `WasmTool` keeps the default: its policy is `WasmHostPolicy`
  (import grants), a different concept, and its bounds are fuel, wall
  time and output, enforced by the adapter and the kernel budget.

Alternatives considered and rejected:

- **Failing mint when a tool provider has no policy.** The stricter
  option in the audit's recommendation. It would break providers whose
  `policy()` is `ToolPolicy::default()` (empty `allowed` — already a
  refusal for every method) and every existing mint site that omits
  the policy, including sites that mint correctly and would then need
  a one-line attach each. Attach-by-default fixes the wiring without
  a compile break and without inventing a new refusal.
- **Enforcing the effective policy at dispatch instead.** Using
  `CapAttrs::effective_tool_policy()` in the call gate would enforce
  a method allowlist and an argument ceiling for *every* capability,
  not just tools — and for a call with no payload the ceiling is the
  byte budget, so over-budget calls would change refusal code from
  `rpc/budget-exceeded` to `rpc/tool-policy`. The finding is about
  the mint wiring; the dispatch change would widen the blast radius
  to every provider for no gain.
- **Attaching the policy at restore too.** A restore re-mints a sealed
  record, and the sealed attributes are the credential. Silently
  narrowing a pre-fix exported record at restore would rewrite the
  terms of an existing credential; the remedy for a pre-fix grant is
  the same as for a pre-fix live capability — revoke it and re-mint.
  Restore is deliberately unchanged.

## Consequences

- A capability minted over an MCP, HTTP or process tool without an
  explicit policy now carries the provider's policy: MCP allows
  exactly the discovered tools at the session's argument ceiling
  (1 MiB line / 6 - 256 bytes, 174,506 bytes); HTTP allows
  `get`/`post`/`request` at the tool's request ceiling (the same
  174,506 bytes at the default 1 MiB request cap); a process tool
  allows `run` at 64 KiB with process execution granted — which also
  means a policy-less process mint can now spawn, where before the
  adapter refused every call for want of the process grant.
- An operator with an MCP server advertising more than 64 tools who
  mints without an explicit policy now gets a mint refusal
  (`rpc/invalid-argument`, "a capability grants too many tools"):
  the attached policy names every discovered tool, and no grant
  carries more than 64 names (RPC-07). The remedy is an explicit
  policy naming only the tools the capability may use
  (`ToolPolicy::allow(&[...])` or a narrowed `session.policy()`).
- Seven new tests pin the behaviour: the W2 shape refused on the MCP,
  HTTP and process legs; an explicit policy winning narrower and
  wider; attenuation unable to drop the attached policy; a 65-tool
  session refusing a policy-less mint (with the explicit-policy
  remedy minting); and a plain provider minting with no policy, as
  before.
- Per `docs/hardening/COMPATIBILITY.md`, a security behaviour change
  is recorded in an ADR (this one) and the release notes; the
  release-notes line is owed at the next release.
