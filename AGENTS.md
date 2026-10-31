# Agent rules for active-rpc

Active RPC moves authority and modules between agents. A mistake here is a
security bug, not a formatting bug.

## Read first

1. `docs/spec/wire.md` — envelope, capability table, error codes.
2. `docs/spec/security.md` — threats and controls.
3. `docs/adr/` — kernel design, transports, capability identity, promises.
4. `CHECKLIST.md` / `PROPOSAL.md` — plan and context.

## Non-negotiable invariants

- The registry is the authority; a wire descriptor grants nothing.
- Attenuation is monotone; widening is an error.
- Budget is charged before work and never exceeds capability ∩ lane.
- `Value::Secret` is the only secret representation on the wire.
- The kernel stays deterministic: no I/O, threads or clocks; add an event.
- `#![forbid(unsafe_code)]` stays.

## Workflow

- Change one behaviour at a time with a failing-first test.
- Keep the golden vector and the error-code table in step with the code
  (`tests/conformance_tests.rs` enforces it).
- Run: `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test`, `cargo test --no-default-features`.

## Remotes

`origin` is `Active-Official/active-rpc`; `ratio` is `RatioArtificiosa/active-rpc`.
A release tag goes to both.

## Stubs

A stub is allowed only when a later checklist item completes it, and it must carry
a `TODO(CHECKLIST <id>)` marker with the reason. An undocumented stub is a bug.

## Do not disable invariant tests

The canary/authority gate (`tests/invariant_gate.rs`), attenuation monotonicity,
revoke-at-dispatch and every redaction test are release gates. Do not delete
them, mark them `#[ignore]`, weaken their assertions, skip them with `cfg`, or
move the behavior past the test boundary. If a test cannot run on a platform,
make it fail closed with an explicit documented reason and keep an equivalent
gate in CI.

