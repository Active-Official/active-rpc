//! Marathon section R-01: ARP1 wire regressions.
//!
//! Each test corresponds to a finding in `docs/hardening/COPILOT-MARATHON.md`
//! and failed against the code as it stood before the fix.

use active_rpc::budget::Budget;
use active_rpc::cap::CapId;
use active_rpc::value::{Arg, Value};
use active_rpc::wire::{cap_table_hash, CapDescriptor, CapTableDelta, Envelope};

/// Byte offset of the first argument inside an encoded request.
fn args_offset(envelope: &Envelope) -> usize {
    let bytes = envelope.encode().expect("encode");
    let method_len = u32::from_le_bytes(bytes[16..20].try_into().expect("method length")) as usize;
    // magic(4) version(1) kind(1) flags(2) request_id(8) method_len(4) method
    16 + 4 + method_len + 4
}

#[test]
fn a_boolean_that_is_not_zero_or_one_is_refused() {
    // `Value::Bool` used to accept any non-zero byte and re-encode as 1, so two
    // byte images decoded to one value.
    let envelope = Envelope::request(1, "ping", vec![Arg::Value(Value::Bool(true))]);
    let mut bytes = envelope.encode().expect("encode");
    let at = args_offset(&envelope);
    // The argument is [arg kind = 0 (value)][value tag = 1 (Bool)][value byte].
    assert_eq!(bytes[at], 0, "the argument is a literal value");
    assert_eq!(bytes[at + 1], 1, "the value is a Bool");
    assert_eq!(bytes[at + 2], 1);
    bytes[at + 2] = 0x02;
    let error = Envelope::decode(&bytes).expect_err("0x02 is not a boolean");
    assert_eq!(error.code(), "rpc/wire", "{error:?}");
}

#[test]
fn a_duplicate_map_key_is_refused() {
    // Two entries with the same key collapse on decode and re-encode shorter.
    let mut map = std::collections::BTreeMap::new();
    map.insert("aa".to_string(), Value::Int(1));
    map.insert("bb".to_string(), Value::Int(2));
    let envelope = Envelope::request(1, "ping", vec![Arg::Value(Value::Map(map))]);
    let mut bytes = envelope.encode().expect("encode");
    let at = args_offset(&envelope);
    let position = bytes[at..]
        .windows(2)
        .position(|window| window == b"bb")
        .map(|offset| at + offset)
        .expect("the second key is in the frame");
    bytes[position..position + 2].copy_from_slice(b"aa");
    let error = Envelope::decode(&bytes).expect_err("duplicate keys are refused");
    assert_eq!(error.code(), "rpc/wire", "{error:?}");
}

/// Build one capability descriptor's bytes.
fn descriptor_bytes(id: [u8; 16], read_only: u8) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id);
    out.extend_from_slice(&0u32.to_le_bytes()); // methods
    for _ in 0..7 {
        out.extend_from_slice(&1u64.to_le_bytes()); // a budget with every ceiling at 1
    }
    out.push(read_only);
    out.push(0); // redact
    out.extend_from_slice(&u32::MAX.to_le_bytes()); // no path scope
    out
}

fn table(count: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(body);
    out
}

#[test]
fn a_zero_capability_id_is_refused() {
    let bytes = table(1, &descriptor_bytes([0u8; 16], 0));
    let error = active_rpc::wire::decode_capability_table(&bytes)
        .expect_err("a zero id is not a capability");
    assert_eq!(error.code(), "rpc/capability-table", "{error:?}");
    assert!(
        format!("{error}").contains("zero capability id"),
        "the reason names the zero id, got {error}"
    );
}

#[test]
fn a_read_only_flag_that_is_not_zero_or_one_is_a_table_fault() {
    let bytes = table(1, &descriptor_bytes([9u8; 16], 2));
    let error =
        active_rpc::wire::decode_capability_table(&bytes).expect_err("read_only must be 0 or 1");
    assert_eq!(error.code(), "rpc/capability-table", "{error:?}");
}

#[test]
fn a_delta_addition_with_a_zero_budget_is_refused() {
    let base: Vec<CapDescriptor> = Vec::new();
    let delta = CapTableDelta {
        base: cap_table_hash(&base).expect("hash"),
        removed: Vec::new(),
        added: vec![CapDescriptor {
            id: CapId([3u8; 16]),
            methods: ["echo".to_string()].into_iter().collect(),
            budget: Budget {
                max_calls: 0,
                ..Budget::default()
            },
            read_only: false,
            redact: false,
            path_scope: None,
        }],
    };
    let error = delta
        .apply_to(&base)
        .expect_err("a budget that disables a ceiling is invalid");
    assert_eq!(error.code(), "rpc/capability-table", "{error:?}");
}

/// A decoded `Float(NaN)` re-encodes to exactly the same bytes.
///
/// The nightly fuzz target crashed on this input (run 41437025560) because the
/// harness asserted `Envelope` equality, and `f64::NAN != f64::NAN`: the encoding
/// was stable, the oracle was not. The fixed-point oracle is the encoded bytes.
#[test]
fn a_nan_argument_re_encodes_to_the_same_bytes() {
    // The minimized crash input: a request with `Null, Null, Null, Float(NaN)`
    // and a four-byte payload.
    let input: [u8; 52] = [
        0x41, 0x52, 0x50, 0x31, 0x01, 0x01, 0x00, 0x00, 0x01, 0x69, 0x67, 0x00, 0x00, 0x6e, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03, 0x02, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let envelope = active_rpc::wire::Envelope::decode(&input).expect("the crash input decodes");
    assert!(
        envelope
            .args
            .iter()
            .any(|arg| matches!(arg, active_rpc::Arg::Value(active_rpc::Value::Float(value)) if value.is_nan())),
        "{envelope:?}"
    );
    let bytes = envelope.encode().expect("encode");
    assert_eq!(bytes, input, "the encoding is not a byte fixed point");
    let again = active_rpc::wire::Envelope::decode(&bytes).expect("re-decode");
    assert_eq!(again.encode().expect("re-encode"), bytes);
}
