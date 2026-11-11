# ADR-0040 - Retrospective: the yank of active-infinity 2.0.0, and the yank rule

**Status:** accepted (2026-11-11). Retrospective: records the 2026-10-27
yank of `active-infinity 2.0.0` and amends point 5 of
[ADR-0006](0006-versioning.md). ADR-0006 itself is not rewritten: this ADR
states the amendment, per the convention in the [ADR index](README.md).

## Context

ADR-0006 point 5 says: "A published version is never yanked without an
ADR."

On 2026-10-27, release `active-rpc` 1.1.9 (commit `69acea89`, "1.1.9:
track active-infinity 2.0.1 (2.0.0 yanked)") recorded in `CHANGELOG.md`
that the previous floor, `active-infinity 2.0.0`, "is yanked because it
still exposed `Validated::secret`". The 2.0.0 core still shipped a public
secret accessor; 2.0.1 removes the public plaintext secret accessors, and
1.1.9 moved the floor to 2.0.1 so that a fresh clone and a locked build
both resolve the fixed core.

No ADR was written at the time — neither authorising the yank in advance
nor recording it afterwards. At the audit, `rg -i yank docs/adr/*.md`
found only the rule itself. That is the process violation TEST-03
records: the yank was the right security call, but the ADR's own process
was bypassed and no ADR was filed afterwards.

Two scope facts, so this record cannot be misread later:

1. The yanked version is a dependency, `active-infinity 2.0.0` — not an
   `active-rpc` version. No `active-rpc` version has ever been yanked:
   `docs/hardening/STATUS.md` (H0.4) records that crates.io 2.0.0 "is
   published and not yanked", and `docs/release-runbook.md` (executed
   record) records that `active-rpc 2.2.0` on crates.io "is yanked
   `false`". ADR-0006's rule governs this crate's own publishing, but
   the same discipline applies to a yank this repo records and depends
   on: the yank was a supply-chain decision for this crate's consumers,
   and it went unrecorded either way.
2. The Infinity-side retrospective — Infinity ADR-0003's yank rule, and
   the `active-infinity` `CHANGELOG.md` yanks of 2.0.0 and 1.2.2 — is a
   separate fix in the `active-infinity` repo (TEST-03, Infinity half),
   not this ADR. This ADR records only what this repo yanked or
   recorded as yanked.

The yank itself was the right call. Leaving 2.0.0 resolvable would have
let consumers pin a core that exposes a public secret accessor — the
defect class Infinity ADR-0010 removed. The failure was process, not
judgement: the rule as written ("never yanked without an ADR") was
treated as if the security fix exempted the paperwork, and it does not
say that.

## Decision

1. **This ADR is the retrospective record for the yank.** Version
   yanked: `active-infinity 2.0.0`. Reason: it still exposed the public
   secret accessor `Validated::secret`. Replacement: `active-infinity`
   2.0.1. RPC release that carried the floor move: 1.1.9, commit
   `69acea89`, 2026-10-27. With this ADR filed, the TEST-03 violation
   in this repo is closed: the yank now has its ADR, late rather than
   absent.
2. **ADR-0006 point 5 is amended to read:** "A published version is
   yanked only for a secret-safety or security fix, and only with an ADR
   filed within one release of the yank. A yank for any other reason, or
   a yank with no ADR within one release, is a process violation." A
   blanket never-yank rule would force the project to keep shipping a
   known secret leak; the amended rule keeps the ADR discipline while
   permitting the one case where yanking is the right call, and it puts
   a deadline — one release — on the paperwork, so "retrospective"
   cannot drift into "never".
3. **The rule is enforced by a test, not by memory:**
   `tests/doc_gate.rs::every_yanked_version_has_an_adr`. If
   `CHANGELOG.md` names a version as yanked, an ADR must mention that
   version in a yank context (the version string and the word "yank" in
   the same numbered ADR file). A yank line that names no version fails
   the gate outright, so a future yank cannot dodge it by omitting the
   version. The same-ADR requirement is load-bearing: ADR-0019 mentions
   "2.0.0" only as wasmi's version, so a plain "some ADR mentions the
   version" check would have passed vacuously before this fix.

## Consequences

- The 2.0.0 yank is now on the record with its reason, its replacement,
  and the release that carried it. A consumer or auditor asking "why
  can't I resolve 2.0.0?" has an ADR to read, not a one-line changelog
  entry.
- A future yank needs its ADR within one release, and the doc gate fails
  the change that records a yank without one. The gate, not a release
  checklist, is what makes the deadline stick.
- The amended rule is narrower than the original in one direction only:
  it permits a secret-safety/security yank that the original wording
  forbade outright without an ADR. It is stricter in every other
  direction: the one-release ADR deadline is new, and the gate is new.
- Nothing about publishing, tagging, or dual-remote release changes.
  Yanking remains a last resort: the ordinary response to a bad release
  is still a fixed patch release, as `docs/release-runbook.md` (Rollback)
  already says.
