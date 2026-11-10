# ADR 0037 — Control-plane MCP: plane responses are capped and embedded-plane answers are marked degraded

**Status:** Accepted 2026-11-10 (RPC-42).

## Context

Round 1, R-08 M5 (AUDIT-REPORT.md:514), verified CONFIRMED by W2 at both
89b6404 and 7702ece: the control-plane MCP attach reads the plane's
response with no byte ceiling, and falls back to an embedded plane
without saying so in any answer.

- `Attach::get` called `ureq`'s `into_json()`, which reads the whole body
  before parsing. The only bound was the 5 s `ureq` timeout — a time
  bound, not a size bound. W2's stub-plane probe served a 20 MB JSON body
  for `/metrics`: at the audited head the `cp_metrics` call errored after
  5.0 s having already read 15.3 MB (`timed out reading response at line
  1 column 15359904`); at the current head the full 20 MB came back
  (`resp bytes=20971732`, marker present) in 12.2 s. Either way there is
  no byte ceiling. The same unbounded `into_json()` served the
  scenario/level `POST` replies as well.
- `Attach::new` falls back to an empty embedded plane when the attach
  target is unreachable, printing one stderr line — and then answers
  tools from the embedded plane as if real. An agent that never sees
  that stderr line (the usual case: it reads the MCP stdout) has no way
  to tell a live snapshot from an empty local one.

The plane's own `/metrics` is tens of KiB, so a 1 MiB ceiling leaves an
order of magnitude of headroom for a legitimate snapshot.

The fix is intentionally behaviour-changing in two narrow ways: a plane
response past the ceiling is now refused instead of read, and every
embedded-plane answer carries a new `degraded` key. Both changes must
be announced, not slipped in — hence this ADR and the migration note.

## Decision

- **Plane responses are read with a 1 MiB ceiling (`MAX_RESPONSE_BYTES`).**
  One helper, `read_json`, serves all three response sites (`GET` in
  `Attach::get`, the scenario `POST`, the level `POST`): it reads through
  `take(MAX_RESPONSE_BYTES + 1)`, so at most one byte past the ceiling is
  ever buffered however large the body the plane serves, and the
  connection is dropped as soon as the ceiling is crossed instead of
  draining the rest. A body past the ceiling is refused with a clear
  error (`control-plane response exceeds the 1048576-byte ceiling`),
  surfaced to the agent as a JSON-RPC internal error (-32603) — never
  truncated, because a truncated snapshot would still parse (or fail to
  parse) as if it were the plane's real answer. The ceiling matches the
  `MAX_REQUEST_LINE` ceiling already enforced on the MCP stdin side,
  and the 5 s / 60 s / 120 s `ureq` timeouts stay as the time bounds
  alongside it.
- **Every embedded-plane answer is marked `degraded`.** `Attach` gains
  `is_degraded()` (derived from `local`, not stored separately, so the
  flag and the fallback cannot drift apart) and `mark_degraded()`,
  applied at the one choke point in `call()`, so every tool is marked,
  whichever tool produced the answer, and a live-plane answer never is.
  The key goes inside the answer itself, so it is visible in the text
  the agent reads — a stderr line at startup is not enough, because the
  agent may never see it. The startup line is kept and strengthened
  (`using an embedded plane (answers are marked degraded)`). A
  non-object answer (none of today's tools returns one) is wrapped as
  `{"degraded": true, "value": …}` instead of left unmarked, so the
  invariant "every embedded-plane answer carries `degraded`" holds
  structurally rather than by inspection of each tool.
- **The fallback itself is preserved.** Returning an error instead of
  falling back was the audit's other alternative, and it would break
  offline use: operators who run `--mcp` with the plane down would see
  a startup failure instead of answers. Marking keeps offline use
  working while making it visible, which is the safer choice.

Alternatives considered and rejected:

- **Returning an error instead of silently falling back.** The audit's
  first alternative. It would break offline use (see above): `--mcp`
  with the plane down would fail at startup. The marking preserves
  that use while making it visible, and the startup stderr line says
  so.
- **Truncating an oversized response at the ceiling.** A truncated
  snapshot is worse than a refusal: it parses as a partial snapshot —
  or fails to parse — with no signal that anything is missing, so an
  agent would act on invented data. A clear error is the only honest
  answer to a body the plane should never legitimately serve.
- **Marking at each tool method instead of in `call()`.** Nine methods
  have local branches; marking each one separately is nine chances to
  miss a tool (and every future tool would need the same edit). One
  choke point in `call()` marks every answer by construction.
- **A larger ceiling, or no ceiling for the scenario/level POSTs.**
  The POST replies went through the same unbounded `into_json()` as
  the `GET`, so leaving them uncapped would leave the finding half
  open. 1 MiB already leaves an order of magnitude over the largest
  legitimate plane snapshot on every endpoint.

## Consequences

- A plane response larger than 1 MiB is refused with
  `control-plane response exceeds the 1048576-byte ceiling`, surfaced
  as a JSON-RPC internal error (-32603). A legitimate plane snapshot
  (tens of KiB) is unaffected — the boundary is pinned by test: exactly
  1 MiB parses whole, one byte past it is refused, on both the `GET`
  and a `POST` leg.
- Every tool answer from the embedded plane carries `"degraded": true`
  inside the answer text the agent reads; a live-plane answer never
  does. Offline `--mcp` use still works, and the startup stderr line
  now says the answers are marked degraded.
- Three new tests pin the behaviour: the oversized response refused
  (with the exact-boundary cases), the `POST` leg capped too, and the
  embedded-plane answers marked degraded on two tools with the
  live-plane answer unmarked.
- Per `docs/hardening/COMPATIBILITY.md`, a security behaviour change
  is recorded in an ADR (this one) and the release notes; the
  release-notes line is owed at the next release.
