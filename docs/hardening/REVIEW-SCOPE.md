# Review scope and cadence

This document freezes what an independent review covers, how findings are
graded, and when a new review is mandatory. It implements H3.1, H3.5 and H3.6.

## Scope

In scope for `active-infinity`:

- the wire layout, encoder, decoder, validator, zero-copy view and stream
  reassembly (`src/layout.rs`, `encode.rs`, `decode.rs`, `validate.rs`,
  `view.rs`, `stream.rs`);
- canonicalization and redaction (`src/canonical.rs`, `src/interop.rs`,
  `src/protobuf.rs`);
- the `active-core` bridge and the public API surface;
- the conformance vectors, fuzz targets, red-team battery and negative
  controls;
- `SECURITY.md`, the specs, the ADRs and this hardening directory.

Out of scope: the internals of `active-core`, the host kernel, a compromised
debugger, and confidentiality of a module at rest (the payload is in the image;
encrypt the store).

In scope for `active-rpc`:

- the ARP1 envelope and capability table (`src/wire.rs`);
- the kernel, capability table, attenuation, revocation, promises, lanes,
  channels and budgets (`src/kernel.rs`, `cap.rs`, `promise.rs`, `lane.rs`,
  `channel.rs`, `budget.rs`);
- domain operations and redaction (`src/domain.rs`, `src/security.rs`);
- tools and transports (`src/tool.rs`, `src/transport/*`);
- the conformance vectors, fuzz targets, red-team battery and negative
  controls;
- `SECURITY.md`, the specs, the ADRs and this hardening directory.

Out of scope: the QUIC/TLS implementations themselves, the operating system,
and a compromised local process with the same privileges.

## Method

1. Read the threat model and every invariant (I-1…I-12).
2. Run the full gates from a clean clone, including the negative controls.
3. Review the diff against the baseline commit, then the whole attack surface
   named above.
4. For each finding: give a severity, a concrete trigger, the invariant it
   breaks, and the smallest fix.
5. Require a regression test that fails on the pre-fix code.
6. Re-run the gates, the fuzz smoke and the negative controls.
7. Repeat until a full round reports no new findings.

## Severity

| Severity | Meaning | Gate |
|---|---|---|
| critical | secret disclosure, capability forgery or widening, silent canonical break, arbitrary code execution | block release |
| high | denial of service, revocation bypass, budget bypass, fail-open validation | block release |
| medium | information leak with limited impact, unstable error code, missing regression test | fix before the next minor |
| low | documentation defect, diagnostic quality, performance outside budget | schedule with an ADR if deferred |

## Mandatory review triggers

- any change to the wire layout, the canonical rules or the error-code catalog;
- any change to capability minting, attenuation, revocation, promises or
  budgets;
- a new transport, tool adapter or projection;
- a new public API item that can return module data;
- every release candidate;
- after any critical or high fix, a delta review of the sibling component.

## Cadence

- A full independent review per release candidate.
- A delta review after every critical or high fix.
- An annual full review once the project is in maintenance, or sooner after a
  new adversary class is published.

Every round is recorded in `REVIEWS.md` with the model or reviewer, the findings
and their disposition. A round without findings says so explicitly.
