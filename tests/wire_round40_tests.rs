//! R-01 wire, round 40: the writer bounds value shape, the method ceiling has
//! one number, and the reader refuses a delta that repeats a base id.

use std::collections::BTreeSet;

use active_rpc::cap::CapId;
use active_rpc::value::Value;
use active_rpc::wire::{CapDescriptor, CapTableDelta, Envelope, WireLimits};
use active_rpc::Budget;

fn descriptor(id: u8) -> CapDescriptor {
    CapDescriptor {
        id: CapId([id; 16]),
        methods: BTreeSet::from(["p".to_string()]),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    }
}

/// The decoder bounds the number of values a frame may materialise and the
/// width of one container; the writer must refuse the same images
/// (round 40, R-07-3).
#[test]
fn an_over_wide_value_is_refused_by_encode() {
    let limits = WireLimits::default();
    let too_wide = Value::list((0..=limits.max_array_len).map(|_| Value::Null));
    let error = Envelope::response(1, too_wide)
        .encode()
        .expect_err("a list wider than the ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");

    // The cumulative ceiling counts every value in the frame, not one list:
    // two lists that each fit are still over it together.
    let half = limits.max_values / 2 + 1;
    let two = Value::list(vec![
        Value::list((0..half).map(|_| Value::Null)),
        Value::list((0..half).map(|_| Value::Null)),
    ]);
    let error = Envelope::response(1, two)
        .encode()
        .expect_err("the value count is past the ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// A frame exactly at the width ceiling round-trips: the codec agrees at the
/// boundary in both directions (round 40, R-07-3).
#[test]
fn a_value_at_the_width_ceiling_round_trips() {
    let limits = WireLimits::default();
    // The widest value both ceilings allow: one element fewer than the width
    // ceiling, because the list itself is one value of the cumulative count.
    let exact = Value::list((0..limits.max_array_len - 1).map(|_| Value::Null));
    let bytes = Envelope::response(1, exact)
        .encode()
        .expect("exactly the ceilings is legal");
    let decoded = Envelope::decode(&bytes).expect("the decoder accepts it");
    match decoded.first_value() {
        Some(Value::List(items)) => assert_eq!(items.len() as u32, limits.max_array_len - 1),
        other => panic!("unexpected value {other:?}"),
    }
}

/// A method name the kernel may grant is a name every transport can encode: the
/// wire ceiling, the mint bound and the receipt bound are one number
/// (round 40, R-07-4).
#[test]
fn a_granted_method_name_fits_the_wire() {
    use active_rpc::kernel::MAX_GRANTED_METHOD_BYTES;

    assert_eq!(
        WireLimits::default().max_method as usize,
        MAX_GRANTED_METHOD_BYTES
    );
    let longest = "m".repeat(MAX_GRANTED_METHOD_BYTES);
    let bytes = Envelope::request(1, longest.clone(), Vec::new())
        .encode()
        .expect("the longest grantable name fits");
    assert_eq!(Envelope::decode(&bytes).expect("decode").method, longest);

    let too_long = "m".repeat(MAX_GRANTED_METHOD_BYTES + 1);
    let error = Envelope::request(1, too_long, Vec::new())
        .encode()
        .expect_err("past every ceiling");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// A delta addition that repeats an id the table already names makes the table
/// order-dependent; the reader refuses it as the writer does
/// (round 40, residual R-6).
#[test]
fn a_delta_addition_repeating_a_base_id_is_refused_by_decode() {
    let mut envelope = Envelope::request(1, "p", Vec::new()).with_caps(vec![descriptor(0xAA)]);
    envelope.cap_delta = Some(CapTableDelta {
        base: [0x11; 32],
        removed: Vec::new(),
        added: vec![descriptor(0xBB)],
    });
    let mut bytes = envelope.encode().expect("a legal table");
    let at = bytes
        .windows(16)
        .position(|window| window == [0xBB; 16])
        .expect("the added descriptor is in the frame");
    bytes[at..at + 16].copy_from_slice(&[0xAA; 16]);
    let error = Envelope::decode(&bytes).expect_err("the same id twice");
    assert_eq!(error.code(), "rpc/capability-table", "{error}");
}
