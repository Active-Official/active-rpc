# DeepSeek fix pack — investigation record (Active RPC)

Pack: `G:\AUDIT\Audit-Deepseek-Chat-on-Web-11-04-2026\deepseek-fixpack`. The audit
read truncated GitHub views, so every verdict below is re-established from this
tree; the pack author's pre-verdict is a hint, not evidence.

Tree: `c66870e` plus the changes recorded here. Protocol:
`01-investigation-protocol/PROTOCOL.md`.

| ID | Pack verdict | This tree | Action |
|----|--------------|-----------|--------|
| F-04 | CONFIRMED | **PARTIAL / real in the helpers** | iterative egress walks |
| F-01 | FALSE (Infinity) | FALSE (Infinity) | negative tests only |
| F-02/F-03 | PARTIAL | **CONFIRMED (hygiene)** | redacting `Debug` |
| F-05 | CONFIRMED (Infinity) | **CONFIRMED** | subtree value-plane walk |
| F-06/F-07 | already fixed / investigate | ALREADY_FIXED / PRODUCT_DECIDE | documented |
| F-08 | investigate | no widening path | documented |
| F-09 | CONFIRMED | **CONFIRMED (asymmetry)** | `encode_with_limits` |
| F-44 | CONFIRMED | **CONFIRMED** | policy + doc gate |

## F-04 — egress secret walks were recursive

- **Call sites found**: `kernel.rs` dispatch egress (`~4948`) and resolution
  egress (`~3388`) call `security::redact_value` or
  `security::assert_no_structural_secrets`; `assert_no_secret_material` is a
  public helper with no kernel caller.
- **Existing hardening**: both kernel paths refuse a value deeper than
  `wire::MAX_VALUE_DEPTH` (64) with `rpc/budget-exceeded` before the walk, using
  the iterative `Value::shape_exceeded`. The kernel was therefore not
  exploitable through a provider reply.
- **Gap**: the helpers themselves recurse, so a direct caller (an embedder, a
  future path that forgets the gate) overflows the stack on a provider-built
  value. `Value`'s derived `Drop` recurses too (documented in `value.rs`).
- **PoC**: `tests/egress_depth_tests.rs` builds a 10 000-deep list and map. On
  the pre-fix tree the test binary aborts with `STATUS_STACK_OVERFLOW`; after
  the fix all four tests pass.
- **Verdict**: CONFIRMED for the public helpers (availability + doc invariant);
  the kernel boundary already held.
- **Patch**: `security.rs` — explicit-stack walks for `redact_value`
  (post-order rebuild), `assert_no_secret_material` and
  `assert_no_structural_secrets`. Maps that carry the marker in a key still
  collapse to `Value::Secret`; marker text still stays text.

## F-02/F-03 — `Debug` over the payload

- **Call sites found**: `Envelope` is logged in examples and reachable from any
  `{:?}`; `Call` is handed to providers, which log.
- **Existing tests**: none asserted the format.
- **PoC**: `tests/debug_redaction_tests.rs` — a payload marker did not appear
  after the fix; before it, the derived formatter printed every byte.
- **Verdict**: CONFIRMED as hygiene (a payload can be a 64 MiB provider blob; a
  log line must not carry it). `Clone`/`PartialEq` are kept: removing them is a
  breaking change for a central type, and the payload on this wire is a
  redacted Infinity projection.
- **Patch**: hand-written `Debug` for `Envelope` and `Call`: kind, request id,
  bounded method label, argument and payload **sizes**, flags. A method longer
  than 64 characters is truncated with `…`.

## F-09 — `Envelope::encode` hard-coded the default profile

- **Call sites found**: every producer; transports with `with_limits` decode
  under the caller's profile.
- **Existing tests**: the strict decode paths.
- **PoC**: an envelope that is legal under `WireLimits::default()` and over
  `strict()` encodes today and is refused by a strict peer.
- **Verdict**: CONFIRMED (profile asymmetry). Round 9 already made the
  transports refuse a frame past their own `max_bytes` on send; the encoder
  itself had no strict form.
- **Patch**: `Envelope::encode_with_limits(limits)`; `encode()` delegates with
  the default profile (no API break).

## F-44 — SECURITY.md excluded the shipped minor

- **PoC**: `Cargo.toml` says 2.3.0 while `SECURITY.md` listed only 2.2.x.
- **Verdict**: CONFIRMED for the disclosure process.
- **Patch**: the table now lists 2.3.x as current and 2.2.x in its window, and
  `tests/doc_gate.rs::the_security_policy_lists_the_shipped_minor` fails when
  the shipped minor is not listed.

## F-06/F-07 — domain provider

- **F-06**: `ModuleProvider::invoke` takes the slot, runs `serve` inside
  `catch_unwind`, and re-inserts it on every path (`domain.rs:897-901`), so a
  panic does not lose the module. Verdict **ALREADY_FIXED**. Residual:
  `panic = "abort"` ends the process, which is a deployment choice.
- **F-07**: `patch` clones the arena before building the reply. The peak is one
  module copy, the module size is bounded at install, and the reply is the cone
  (usually smaller). A pre-clone byte refusal on the module size would break a
  legitimate small-cone patch of a large module, and copy-on-write is a
  redesign. Verdict **PRODUCT_DECIDE**: documented here; no change.

## F-08 — delta attenuation

`CapTableDelta::apply_to` refuses an added id that already exists in the base
(the replacement path), and the kernel's registry is the only authority: a
delta describes, `introduce`/`attenuate` decide. No widening path was found;
verdict **no change**.

## Unverified item 4 — envelope flags versus capability

`Call.read_only` and `Call.redact` are taken from the capability record
(`kernel.rs:3153-3154`), never from the envelope, so a peer cannot clear a
restriction with a flag. Verdict **no issue**.
