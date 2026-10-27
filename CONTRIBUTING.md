# Contributing to Active RPC

## Before you start

1. Read `docs/spec/wire.md` (normative) and `docs/adr/`.
2. Run the gates: `cargo fmt --all --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test`,
   `cargo test --no-default-features`.

## Working against an unreleased Active Infinity

The crate depends on the published `active-infinity` so a fresh clone builds on its
own. To iterate on both repositories together, add a local patch (not committed):

```toml
# Cargo.toml (local only, or in an uncommitted .cargo/config.toml)
[patch.crates-io]
active-infinity = { path = "../Active-Infinity" }
```
Remove it before packaging: cargo package builds against the registry version,
which is what consumers get.

## Non-negotiable invariants

- **No ambient authority.** Every call names a capability; the kernel looks it up.
- **Monotone attenuation.** `CapAttrs::attenuate` refuses widening; new
  authority dimensions must have the same rule.
- **Fail closed.** Unknown kind, flag, tag, version or id is an error, never a
  skip.
- **Budget before work.** Charge, then dispatch; map the capability budget into
  the domain operation.
- **No secret bytes.** `Value::Secret` is the only representation on the wire.
- **Deterministic kernel.** No I/O, no threads, no clocks inside `kernel`; add an
  event instead of a sleep.

## Change shape

- One behaviour per change, with a test that fails before it and passes after.
- Wire-visible changes update `docs/spec/wire.md` in the same commit and the
  golden vector in `tests/conformance_tests.rs`.
- A structural decision gets an ADR.

## Tests

| Suite | What it must prove |
|---|---|
| `tests/unit_tests.rs` | capability, attenuation, drops, promises, lanes, channels, wire |
| `tests/integration_tests.rs` | domain operations, each transport, cross-process peer |
| `tests/concurrency_tests.rs` | lane interleaving, budget isolation, channel isolation, two agents over TCP |
| `tests/conformance_tests.rs` | the wire golden vector, error-code contract |
| `tests/redteam_tests.rs` | forgery, escalation, confused deputy, leakage, bypass, malformed frames |
| `tests/property_tests.rs` | envelope round-trip, decoder robustness, attenuation monotonicity |

## Commits and releases

- Imperative subject, body explains why.
- Releases follow ADR-0006: dry-run, publish, tag both remotes.

## Security reports

Do not open a public issue. Follow `SECURITY.md`.
