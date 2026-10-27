# ADR-0006 — Versioning and publishing

**Status:** accepted (2026-10-27)

## Context

The crate is unpublished. The wire format has its own version byte (`ARP1`,
version 1). The kernel API is new and will evolve as agents exercise lanes,
channels and tool adapters.

## Decision

1. The crate starts at **1.0.0**: the API is complete for the features the
   proposal requires, and the wire format is documented and pinned by a golden
   vector.
2. Semver for the crate:
   - **patch**: fixes, documentation, performance, no API or wire change;
   - **minor**: additive API or a new transport; the wire version may rise only
     for skippable additions;
   - **major**: any incompatible change to the envelope, the capability rules or
     a public API in a way that breaks a conforming peer.
3. The envelope version byte changes only for an incompatible layout change.
   Kind, flag, argument, value and error codes are permanent.
4. MSRV is 1.85, matching Active Infinity and the Active workspace.
5. Publishing: `cargo publish --dry-run`, then publish, then push the same tag to
   both organizations' remotes. A published version is never yanked without an
   ADR.

## Consequences

- Crate version and wire version can diverge; `PROTOCOL_VERSION` reports the
  wire version.
- A peer that meets an unknown kind, flag, tag or version refuses the envelope
  instead of skipping it, because a skipped argument would change a call's
  meaning.
