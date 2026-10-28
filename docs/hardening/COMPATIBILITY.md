# Compatibility and deprecation policy

This document is the written compatibility contract required by H8.1 and H8.5.

## Active Infinity (AINF)

| Change | Policy |
|---|---|
| major (`1.x` → `2.0`) | may change layout, meaning or canonical rules; readers refuse the old major with `infinity/version-major` |
| minor (`1.0` → `1.1`) | may add a section, node kind, unit or error code; an old reader refuses the new minor with `infinity/version-minor` |
| patch | no wire change; fixes must keep every valid image valid and every canonical image byte-identical |
| dialect hash | changes only when the meaning of an existing id changes, which the major/minor rules forbid under the same major |

A reader refuses a different dialect before parsing a record (`infinity/dialect`). A writer always emits the current major/minor.

## Unknown flags, kinds and extensions

- Header flag bits above the defined set are refused (`infinity/flags`).
- A node kind above the implemented range is refused (`infinity/node`).
- An unknown unit discriminant is `infinity/unknown-unit`; a named unit is the
  forward-compatible escape hatch (`UNIT_NAMED` with a non-empty string).
- An extension tag is opaque and order-independent. Duplicate tags are refused
  (`infinity/extension`); an unknown tag is preserved by decode/encode and
  redacted by the projections when its payload contains a secret.
- Unknown aux tags are refused where the consumer validates them
  (`infinity/type`, `infinity/node`); they are not silently ignored.

## Old images

The conformance suite is the regression contract. `tests/vectors/valid` holds
images that must validate and re-encode identically on every patch and minor
release. `tests/vectors/invalid` holds one image per declared failure code, so a
change that silently accepts a previously rejected class fails the suite.

AINF 1.0 is the only released wire version. When a 1.1 layout lands, the 1.0
vectors move to a frozen `v1` suite and remain in CI; they are never edited.

## Active RPC (ARP1)

| Change | Policy |
|---|---|
| envelope version | fixed at 1; a different version is `rpc/wire` |
| new method or capability attribute | additive; an old peer ignores an unknown method or refuses it with a stable code |
| new transport | additive; a transport that is unavailable returns `rpc/transport-unavailable`, never a silent fallback |
| error codes | stable strings; removing or renaming one is a major change |

## Deprecation window

A shipped behavior is deprecated in a `CHANGELOG.md` entry and a doc comment,
then kept for at least one minor release (or 90 days, whichever is longer)
before removal. Security fixes may remove a behavior immediately; the removal is
recorded in an ADR and the release notes, and the replacement is documented.
