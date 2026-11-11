# ADR-0039 - Wire grammar by kind and descriptor method validity

**Status:** accepted (2026-11-10). Behaviour change to `Envelope::encode`,
`Envelope::decode`, `encode_capability_table`,
`decode_capability_table` and `CapTableDelta::apply_to`: a descriptor
method name must satisfy the same predicate the mint enforces, and an
envelope whose kind cannot carry the fields it carries is refused with
`rpc/wire` (RPC-53; audit probes
`r01_wire_accepts_descriptor_methods_mint_refuses` and
`r01_response_and_hello_carry_call_fields`).

## Context

Two drifts between what the wire accepts and what the rest of the crate
accepts, both in `src/wire.rs`:

1. **Descriptor method names (R01-2).** `check_descriptor` and
   `read_cap_inner` checked only length, canonical order and duplicates.
   A descriptor granting `""` or `"a\nb"` encoded, decoded and
   re-encoded fine, while `mint`/`attenuate` refuse the same names
   (`receipts::valid_method`: 1..=1024 bytes, no control, invisible or
   reordering characters). The wire and the registry disagreed about what
   a valid descriptor is — the exact class of drift `check_descriptor`'s
   own doc comment says it exists to prevent. Damage: a decoded
   descriptor with a control-character method that reaches a log line, an
   event, a receipt or a `MethodNotGranted{method}` error forges log
   lines / terminal escapes, and any consumer that assumes "decoded =
   mintable" (e.g. a future import path) silently diverges.
2. **Kind/field combinations (R01-3).** `decode_with` had no consistency
   check between `kind` and `method`/`args`/`payload`/`caps`/`cap_delta`.
   A `Kind::Response` could carry arguments, a payload and a full
   capability table; a `Kind::Hello` could carry arguments and a payload.
   All re-encoded identically, so the frames were "valid" wire images of
   meaningless messages. The refusal happened one layer up,
   inconsistently: `dispatch_envelope` refuses non-Request, each
   transport serve loop refuses non-Request, but a plain
   `Transport::recv` consumer or a future handler that reads
   `envelope.caps` off a Response gets a capability table from a message
   kind that should never carry one.

## Decision

1. **Reuse the mint's predicate, in both directions.** `check_descriptor`
   (encode side, which also covers the standalone table encoder and
   `CapTableDelta::apply_to`) and `read_cap_inner` (decode side) refuse
   any method name for which `!crate::receipts::valid_method(method)`.
   One predicate, no second copy of the character rule, so the wire and
   the registry cannot drift again. The length ceiling is unchanged: a
   1024-byte method still round-trips, and the strict profile's 64-byte
   ceiling still applies first.
2. **Enforce the per-kind grammar in `decode_with` and in
   `check_limits`.** The check lives in one new method,
   `Envelope::check_kind_fields`, called from both paths, because
   encoding is the inverse of decoding: a frame this crate would refuse
   must be refused locally, not by the peer (round 39, L-7). The
   verification report suggested decode-only; encode-only would have
   let a local caller emit a frame its own peer refuses, which is the
   asymmetry L-7 exists to prevent.
3. **The grammar, as written into spec §1.1:**
   - `Request`: the only call; carries anything.
   - `Response`: exactly one argument, and it must be the result value
     (`Arg::Value`); no method name, no capability table, no delta. Its
     payload is the echo channel and stays allowed.
   - `Error`: no arguments, no payload, no capability table, no delta;
     the method field carries the provider code.
   - `Hello`: the capability table it announces and nothing else — no
     arguments, no payload, no delta.

## Two refinements of the audit's literal prescription

The audit's R01-3 fix says "refuse `Kind::Response`/`Kind::Error` with
non-empty `args`/`payload`/`caps`/`cap_delta`". Taken literally that
refuses every response the crate itself produces, and one of its own
tests:

- `Envelope::response` builds exactly one `Arg::Value` (the result), and
  the spec (§1.1) already defines a Response as "a successful result
  (first argument is the value)". The rule is therefore "exactly one
  result value", not "no arguments": zero arguments, two arguments, or a
  promise/capability argument on a Response is refused.
- A payload on a Response is legitimate: the shipped `thin_peer`
  example echoes the request payload back in the response, and
  `http2_tests::http2_moves_an_envelope_and_returns_the_same_payload`
  asserts the client receives it. The payload echo is a channel, not a
  call field, so it stays allowed.

Two further refusals go one field beyond the audit's text, in the same
class the finding names ("decode accepts meaningless kind/field
combos"):

- A `Response` with a non-empty `method` is refused: `response()`
  defines the method as empty ("Method name (requests) or error code
  (errors)"), and nothing in the crate reads a Response method.
- A `Hello` with a `cap_delta` is refused: a delta applies to an
  already-negotiated table, and Hello *is* the negotiation, so a delta
  on a Hello can never apply to anything. No in-crate code constructs a
  Hello at all.

The `Error` method is deliberately *not* restricted: it carries the
provider code, sanitised by `bounded_provider_code` at construction.
The `Request` method is deliberately *not* restricted here either: a
control-character call method is refused at dispatch and escaped by
`receipt_method` before it reaches a receipt, which is a separate
concern from the descriptor/grammar drift this fix closes.

## Consequences

- **Wire-compat break, intended.** A peer that today round-trips a
  descriptor with an empty or control-character method, or sends a
  Response with a capability table, is refused with
  `rpc/capability-table` / `rpc/wire`. No conforming peer can produce
  such frames: the mint refuses the same method names, and no
  constructor in this crate builds such envelopes. The conformance
  golden vectors are unaffected (all valid frames); the new behaviour is
  pinned by `tests/wire_rpc53_tests.rs` (33 tests, including attacker
  bytes built by patching valid encodings, so the decoder is exercised
  independently of the encoder).
- **No behaviour change for valid traffic.** Every constructor's output
  still encodes and decodes: plain and payload-carrying responses,
  plain errors, and Hellos carrying a table all round-trip, pinned by
  the same test file.
- **Spec updated.** `docs/spec/wire.md` §1.1 now states the per-kind
  grammar normatively, so a future implementation cannot reintroduce
  the drift by reading the format doc alone.
