//! RPC-53 regression tests (round-1 Medium, W3-R1-RPC-WIRE-TEST, CONFIRMED).
//!
//! Two halves, both in `src/wire.rs`:
//!
//! * R01-2 — the wire accepts descriptor method names the mint refuses. A
//!   descriptor granting `""` or `"a\nb"` encoded, decoded and re-encoded
//!   fine, while `mint`/`attenuate` refuse the same names
//!   (`receipts::valid_method`: 1..=1024 bytes, no control, invisible or
//!   reordering characters). The fix reuses that one predicate in
//!   `check_descriptor` (encode side, including the standalone table encoder
//!   and `CapTableDelta::apply_to`) and in `read_cap_inner` (decode side).
//! * R01-3 — decode accepts meaningless kind/field combinations. The fix
//!   refuses them in `decode_with` and, symmetrically, in `check_limits`,
//!   so a frame this crate would refuse is refused locally instead of by
//!   the peer (round 39, L-7).
//!
//! Two deliberate refinements of the audit's literal R01-3 prescription,
//! both forced by the crate's own constructors (see ADR-0039):
//!
//! * A `Response` carries exactly one argument, and it must be the result
//!   value: `Envelope::response` builds exactly one `Arg::Value`, and the
//!   spec (§1.1) defines a Response as "a successful result (first argument
//!   is the value)". Refusing *any* argument on a Response would refuse
//!   every response the crate itself produces.
//! * A `Response` may still carry a payload: the shipped `thin_peer`
//!   example echoes the request payload back in the response, and
//!   `http2_tests::http2_moves_an_envelope_and_returns_the_same_payload`
//!   asserts the client receives it. The payload echo is a legitimate
//!   channel, not a call field.
//! * A `Hello` carrying a `cap_delta` is refused too, although the audit
//!   names only args/payload for Hello: a delta applies to an
//!   already-negotiated table, and Hello *is* the negotiation, so a delta
//!   on a Hello can never apply to anything. No in-crate code constructs a
//!   Hello at all, so the refusal breaks nothing.
//! * A `Response` carrying a non-empty `method` is refused: `response()`
//!   defines the method as empty ("Method name (requests) or error code
//!   (errors)"). The `Error` method is *not* restricted here: it carries
//!   the provider code, sanitised by `bounded_provider_code` at
//!   construction.
//!
//! The decode-side tests build attacker bytes by patching a valid encoding
//! in place (never by re-implementing the encoder): the encoder refuses
//! these frames after the fix, so a round-trip probe cannot exercise the
//! decoder. Each patch helper pins the frame layout with a length assertion,
//! so a format change fails the test loudly instead of patching the wrong
//! byte.

use std::collections::BTreeSet;

use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{
    decode_capability_table, encode_capability_table, CapDescriptor, CapTableDelta, Envelope, Kind,
};
use active_rpc::{Agent, Budget, Error, PromiseId};

fn descriptor(id: u8, methods: &[&str]) -> CapDescriptor {
    CapDescriptor {
        id: CapId([id; 16]),
        methods: methods.iter().map(|method| method.to_string()).collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::Null))
    }
}

fn assert_code(error: &Error, code: &str) {
    assert_eq!(error.code(), code, "{error}");
}

/// The same frame, re-labelled as `kind`: the body is a legal Request body,
/// so a refusal pins the kind/field rule, not the body encoding.
fn relabelled_as(bytes: &[u8], kind: Kind) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    bytes[5] = kind.code();
    bytes
}

/// A capability table whose only descriptor grants `valid_method`, built by
/// the crate's own encoder. Layout, in order: a u32 count, a 16-byte id, a
/// u32 method count, one u32 length plus the method bytes per method, seven
/// u64 budget ceilings, one read_only byte, one redact byte, and one
/// path-scope tag byte.
fn valid_table_bytes(valid_method: &str) -> Vec<u8> {
    let bytes =
        encode_capability_table(&[descriptor(9, &[valid_method])]).expect("a valid table encodes");
    assert_eq!(
        bytes.len(),
        4 + 16 + 4 + 4 + valid_method.len() + 56 + 1 + 1 + 1,
        "table layout changed; the patch offsets below are stale"
    );
    bytes
}

/// The valid table with its one method byte replaced by `byte`.
fn table_bytes_with_method_byte(byte: u8) -> Vec<u8> {
    let mut bytes = valid_table_bytes("m");
    bytes[28] = byte;
    bytes
}

/// The valid table with the middle byte of its one method replaced by `byte`.
fn table_bytes_with_middle_method_byte(byte: u8) -> Vec<u8> {
    let mut bytes = valid_table_bytes("aXb");
    bytes[29] = byte;
    bytes
}

/// The valid table with its one method shortened to the empty name: the
/// length prefix becomes 0 and the method byte is removed.
fn table_bytes_with_empty_method() -> Vec<u8> {
    let mut bytes = valid_table_bytes("m");
    bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
    bytes.remove(28);
    assert_eq!(bytes.len(), 87, "table layout changed");
    bytes
}

/// A request frame whose descriptor grants `m`, built by the crate's own
/// encoder. Layout, in order: the 16-byte header, the "echo" method as a
/// u32 length plus bytes, a u32 argument count, a u32 payload length, a
/// u32 capability count, then the descriptor: a 16-byte id, a u32 method
/// count, a u32 method length plus the method byte, seven u64 budget
/// ceilings, one read_only byte, one redact byte, and one path-scope tag
/// byte.
fn envelope_bytes_with_descriptor_method() -> Vec<u8> {
    let bytes = Envelope::request(1, "echo", vec![])
        .with_caps(vec![descriptor(9, &["m"])])
        .encode()
        .expect("a valid envelope encodes");
    assert_eq!(
        bytes.len(),
        120,
        "envelope layout changed; the patch offsets below are stale"
    );
    bytes
}

fn envelope_bytes_with_descriptor_method_byte(byte: u8) -> Vec<u8> {
    let mut bytes = envelope_bytes_with_descriptor_method();
    bytes[60] = byte;
    bytes
}

fn envelope_bytes_with_empty_descriptor_method() -> Vec<u8> {
    let mut bytes = envelope_bytes_with_descriptor_method();
    bytes[56..60].copy_from_slice(&0u32.to_le_bytes());
    bytes.remove(60);
    assert_eq!(bytes.len(), 119, "envelope layout changed");
    bytes
}

// --- R01-2: the mint half of the drift (control) ---

#[test]
fn mint_refuses_an_empty_method_name() {
    let agent = Agent::with_secret([0x7b; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register");
    let error = agent
        .mint(provider, 0, CapAttrs::new(&[""]))
        .expect_err("mint refuses an empty method name");
    assert!(matches!(error, Error::InvalidArgument(_)), "{error}");
}

// --- R01-2: encode side ---

#[test]
fn an_empty_descriptor_method_is_refused_by_the_encoder() {
    let error = Envelope::request(1, "echo", vec![])
        .with_caps(vec![descriptor(9, &[""])])
        .encode()
        .expect_err("an empty method name must not encode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_control_character_in_a_descriptor_method_is_refused_by_the_encoder() {
    let error = Envelope::request(1, "echo", vec![])
        .with_caps(vec![descriptor(9, &["a\nb"])])
        .encode()
        .expect_err("a control character in a method name must not encode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn an_invisible_character_in_a_descriptor_method_is_refused_by_the_encoder() {
    // `valid_method` refuses invisible/reordering characters, not just
    // control characters: the fix must reuse that predicate, not a
    // hand-rolled control-character check.
    let error = Envelope::request(1, "echo", vec![])
        .with_caps(vec![descriptor(9, &["a\u{200b}b"])])
        .encode()
        .expect_err("a zero-width space in a method name must not encode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_descriptor_with_only_valid_methods_still_encodes_and_decodes() {
    let bytes = Envelope::request(1, "echo", vec![])
        .with_caps(vec![descriptor(9, &["echo", "stats"])])
        .encode()
        .expect("valid methods still encode");
    let back = Envelope::decode(&bytes).expect("valid methods still decode");
    assert_eq!(back.caps.len(), 1);
    assert_eq!(
        back.caps[0].methods,
        BTreeSet::from(["echo".to_string(), "stats".to_string()])
    );
}

#[test]
fn a_descriptor_method_at_the_length_ceiling_still_round_trips() {
    // `valid_method` allows 1..=1024 bytes, the same bound the wire
    // ceiling enforces: the fix must not tighten the length rule.
    let method = "a".repeat(1024);
    let bytes = Envelope::request(1, "echo", vec![])
        .with_caps(vec![descriptor(9, &[method.as_str()])])
        .encode()
        .expect("a 1024-byte method still encodes");
    let back = Envelope::decode(&bytes).expect("a 1024-byte method still decodes");
    assert_eq!(back.caps[0].methods.len(), 1);
}

#[test]
fn a_standalone_table_with_an_invalid_method_is_refused() {
    let error = encode_capability_table(&[descriptor(9, &[""])])
        .expect_err("a standalone table with an empty method must not encode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_delta_adding_an_invalid_method_is_refused() {
    let delta = CapTableDelta::new(&[], vec![], vec![descriptor(9, &["a\nb"])])
        .expect("a delta builds before any descriptor check");
    let error = Envelope::request(1, "echo", vec![])
        .with_cap_delta(delta)
        .encode()
        .expect_err("a delta adding an invalid method must not encode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_delta_applying_an_invalid_method_is_refused() {
    let delta = CapTableDelta::new(&[], vec![], vec![descriptor(9, &["a\nb"])])
        .expect("a delta builds before any descriptor check");
    let error = delta
        .apply_to(&[])
        .expect_err("a delta adding an invalid method must not apply");
    assert_code(&error, "rpc/capability-table");
}

// --- R01-2: decode side (attacker bytes, patched valid encodings) ---

#[test]
fn an_empty_descriptor_method_is_refused_by_the_table_decoder() {
    let error = decode_capability_table(&table_bytes_with_empty_method())
        .expect_err("an empty method name must not decode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_control_character_in_a_descriptor_method_is_refused_by_the_table_decoder() {
    let error = decode_capability_table(&table_bytes_with_middle_method_byte(b'\n'))
        .expect_err("a control character in a method name must not decode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_lone_control_character_as_a_method_is_refused_by_the_table_decoder() {
    let error = decode_capability_table(&table_bytes_with_method_byte(b'\n'))
        .expect_err("a lone control character as a method name must not decode");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn an_empty_descriptor_method_is_refused_by_the_envelope_decoder() {
    let error = Envelope::decode(&envelope_bytes_with_empty_descriptor_method())
        .expect_err("an empty method name must not decode in an envelope");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_control_character_in_a_descriptor_method_is_refused_by_the_envelope_decoder() {
    let error = Envelope::decode(&envelope_bytes_with_descriptor_method_byte(b'\n'))
        .expect_err("a control character in a method name must not decode in an envelope");
    assert_code(&error, "rpc/capability-table");
}

#[test]
fn a_valid_descriptor_still_decodes_from_patched_bytes() {
    // The patch helpers themselves are honest: the unpatched bytes decode.
    let back =
        decode_capability_table(&valid_table_bytes("m")).expect("the unpatched table decodes");
    assert_eq!(back[0].methods, BTreeSet::from(["m".to_string()]));
    let back = Envelope::decode(&envelope_bytes_with_descriptor_method())
        .expect("the unpatched envelope decodes");
    assert_eq!(back.caps[0].methods, BTreeSet::from(["m".to_string()]));
}

// --- R01-3: Response ---

#[test]
fn a_response_with_a_capability_table_is_refused() {
    let desc = descriptor(7, &["echo"]);
    let error = Envelope::response(3, Value::text("x"))
        .with_caps(vec![desc])
        .encode()
        .expect_err("a response with a capability table must not encode");
    assert_code(&error, "rpc/wire");
    let bytes = Envelope::request(1, "echo", vec![])
        .with_caps(vec![descriptor(7, &["echo"])])
        .encode()
        .expect("a request with a capability table encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Response))
        .expect_err("a response with a capability table must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_response_with_a_capability_table_delta_is_refused() {
    let delta =
        CapTableDelta::new(&[], vec![], vec![descriptor(7, &["echo"])]).expect("a delta builds");
    let error = Envelope::response(3, Value::text("x"))
        .with_cap_delta(delta)
        .encode()
        .expect_err("a response with a capability-table delta must not encode");
    assert_code(&error, "rpc/wire");
    let delta =
        CapTableDelta::new(&[], vec![], vec![descriptor(7, &["echo"])]).expect("a delta builds");
    let bytes = Envelope::request(1, "echo", vec![])
        .with_cap_delta(delta)
        .encode()
        .expect("a request with a delta encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Response))
        .expect_err("a response with a capability-table delta must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_response_with_no_result_value_is_refused() {
    let literal = Envelope {
        kind: Kind::Response,
        request_id: 3,
        method: String::new(),
        args: vec![],
        payload: vec![],
        caps: vec![],
        redact: false,
        read_only: false,
        cap_delta: None,
    };
    let error = literal
        .encode()
        .expect_err("a response with no result value must not encode");
    assert_code(&error, "rpc/wire");
    let bytes = Envelope::request(1, "echo", vec![])
        .encode()
        .expect("a request with no arguments encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Response))
        .expect_err("a response with no result value must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_response_with_two_result_values_is_refused() {
    let bytes = Envelope::request(
        1,
        "echo",
        vec![Arg::Value(Value::text("x")), Arg::Value(Value::text("y"))],
    )
    .encode()
    .expect("a request with two arguments encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Response))
        .expect_err("a response with two result values must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_response_carrying_a_promise_argument_is_refused() {
    let bytes = Envelope::request(1, "echo", vec![Arg::Promise(PromiseId(7))])
        .encode()
        .expect("a request with a promise argument encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Response))
        .expect_err("a response carrying a promise argument must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_response_carrying_a_capability_argument_is_refused() {
    let bytes = Envelope::request(1, "echo", vec![Arg::Cap(CapId([3u8; 16]))])
        .encode()
        .expect("a request with a capability argument encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Response))
        .expect_err("a response carrying a capability argument must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_response_with_a_method_name_is_refused() {
    let literal = Envelope {
        kind: Kind::Response,
        request_id: 3,
        method: "echo".to_string(),
        args: vec![Arg::Value(Value::text("x"))],
        payload: vec![],
        caps: vec![],
        redact: false,
        read_only: false,
        cap_delta: None,
    };
    let error = literal
        .encode()
        .expect_err("a response with a method name must not encode");
    assert_code(&error, "rpc/wire");
    let bytes = Envelope::request(1, "echo", vec![Arg::Value(Value::text("x"))])
        .encode()
        .expect("a request with one argument encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Response))
        .expect_err("a response with a method name must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_response_with_a_payload_still_round_trips() {
    // The payload echo is legitimate: `thin_peer` returns the request
    // payload in the response and the HTTP/2 test asserts the client
    // receives it. A Response may carry a payload; it may not carry a call.
    let bytes = Envelope::response(3, Value::text("x"))
        .with_payload(vec![1, 2, 3])
        .encode()
        .expect("a response with a payload still encodes");
    let back = Envelope::decode(&bytes).expect("a response with a payload still decodes");
    assert_eq!(back.kind, Kind::Response);
    assert_eq!(back.first_value(), Some(&Value::text("x")));
    assert_eq!(back.payload, vec![1, 2, 3]);
}

#[test]
fn a_plain_response_still_round_trips() {
    let bytes = Envelope::response(3, Value::text("x"))
        .encode()
        .expect("a plain response still encodes");
    let back = Envelope::decode(&bytes).expect("a plain response still decodes");
    assert_eq!(back.kind, Kind::Response);
    assert_eq!(back.first_value(), Some(&Value::text("x")));
}

// --- R01-3: Error ---

#[test]
fn an_error_with_arguments_is_refused() {
    let bytes = Envelope::request(1, "rpc/wire", vec![Arg::Value(Value::text("x"))])
        .encode()
        .expect("a request with one argument encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Error))
        .expect_err("an error with arguments must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn an_error_with_a_payload_is_refused() {
    let bytes = Envelope::request(1, "rpc/wire", vec![])
        .with_payload(vec![1, 2, 3])
        .encode()
        .expect("a request with a payload encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Error))
        .expect_err("an error with a payload must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn an_error_with_a_capability_table_is_refused() {
    let error = Envelope::error(3, &Error::Wire("boom"))
        .with_caps(vec![descriptor(7, &["echo"])])
        .encode()
        .expect_err("an error with a capability table must not encode");
    assert_code(&error, "rpc/wire");
    let bytes = Envelope::request(1, "rpc/wire", vec![])
        .with_caps(vec![descriptor(7, &["echo"])])
        .encode()
        .expect("a request with a capability table encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Error))
        .expect_err("an error with a capability table must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn an_error_with_a_capability_table_delta_is_refused() {
    let delta =
        CapTableDelta::new(&[], vec![], vec![descriptor(7, &["echo"])]).expect("a delta builds");
    let error = Envelope::error(3, &Error::Wire("boom"))
        .with_cap_delta(delta)
        .encode()
        .expect_err("an error with a capability-table delta must not encode");
    assert_code(&error, "rpc/wire");
    let delta =
        CapTableDelta::new(&[], vec![], vec![descriptor(7, &["echo"])]).expect("a delta builds");
    let bytes = Envelope::request(1, "rpc/wire", vec![])
        .with_cap_delta(delta)
        .encode()
        .expect("a request with a delta encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Error))
        .expect_err("an error with a capability-table delta must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_plain_error_still_round_trips() {
    let bytes = Envelope::error(3, &Error::Wire("boom"))
        .encode()
        .expect("a plain error still encodes");
    let back = Envelope::decode(&bytes).expect("a plain error still decodes");
    assert_eq!(back.kind, Kind::Error);
    assert_eq!(back.method, "rpc/wire");
}

// --- R01-3: Hello ---

#[test]
fn a_hello_with_arguments_is_refused() {
    let bytes = Envelope::request(1, "hello", vec![Arg::text("hi")])
        .encode()
        .expect("a request with one argument encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Hello))
        .expect_err("a hello with arguments must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_hello_with_a_payload_is_refused() {
    let bytes = Envelope::request(1, "hello", vec![])
        .with_payload(vec![1, 2, 3])
        .encode()
        .expect("a request with a payload encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Hello))
        .expect_err("a hello with a payload must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_hello_with_a_capability_table_delta_is_refused() {
    let delta =
        CapTableDelta::new(&[], vec![], vec![descriptor(7, &["echo"])]).expect("a delta builds");
    let bytes = Envelope::request(1, "hello", vec![])
        .with_cap_delta(delta)
        .encode()
        .expect("a request with a delta encodes");
    let error = Envelope::decode(&relabelled_as(&bytes, Kind::Hello))
        .expect_err("a hello with a capability-table delta must not decode");
    assert_code(&error, "rpc/wire");
}

#[test]
fn a_hello_with_a_capability_table_still_round_trips() {
    // The table is Hello's purpose: a handshake announces capabilities.
    let bytes = Envelope::request(1, "hello", vec![])
        .with_caps(vec![descriptor(7, &["echo"])])
        .encode()
        .expect("a request with a capability table encodes");
    let back = Envelope::decode(&relabelled_as(&bytes, Kind::Hello))
        .expect("a hello with a capability table still decodes");
    assert_eq!(back.kind, Kind::Hello);
    assert_eq!(back.caps.len(), 1);
}
