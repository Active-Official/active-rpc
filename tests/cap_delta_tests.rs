//! C-5.1 capability-table delta negotiation and fail-closed application.

use active_rpc::budget::Budget;
use active_rpc::cap::{CapAttrs, CapId};
use active_rpc::wire::{
    cap_table_hash, CapDescriptor, CapTableDelta, Envelope, FLAG_CAP_DELTA, FLAG_KNOWN,
};

fn descriptor(byte: u8, method: &str) -> CapDescriptor {
    CapDescriptor::from_attrs(
        CapId([byte; 16]),
        &CapAttrs::new(&[method]).with_budget(Budget::default()),
    )
}

#[test]
fn delta_applies_to_the_negotiated_base_and_rejects_wrong_bases() {
    let base = vec![descriptor(1, "echo"), descriptor(2, "evaluate")];
    let removed = vec![CapId([2u8; 16])];
    let added = vec![descriptor(3, "stats")];
    let delta = CapTableDelta::new(&base, removed.clone(), added.clone());
    let expected = vec![descriptor(1, "echo"), descriptor(3, "stats")];
    assert_eq!(delta.apply_to(&base).expect("apply"), expected);
    assert_eq!(delta.base, cap_table_hash(&base));

    let mut wrong = base.clone();
    wrong.push(descriptor(4, "why"));
    assert_eq!(
        delta.apply_to(&wrong).unwrap_err().code(),
        "rpc/capability-table"
    );

    let mut unknown_removal = delta.clone();
    unknown_removal.removed.push(CapId([9u8; 16]));
    assert_eq!(
        unknown_removal.apply_to(&base).unwrap_err().code(),
        "rpc/capability-table"
    );
}

#[test]
fn delta_survives_the_envelope_and_sets_the_negotiation_flag() {
    let base = vec![descriptor(1, "echo")];
    let delta = CapTableDelta::new(&base, vec![], vec![descriptor(2, "stats")]);
    let envelope = Envelope::request(7, "echo", vec![]).with_cap_delta(delta.clone());
    let bytes = envelope.encode().expect("encode");
    let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
    assert_ne!(flags & FLAG_CAP_DELTA, 0);
    assert_eq!(flags & !FLAG_KNOWN, 0);
    let decoded = Envelope::decode(&bytes).expect("decode");
    assert_eq!(decoded.cap_delta, Some(delta));
    let applied = decoded
        .cap_delta
        .expect("delta")
        .apply_to(&base)
        .expect("apply");
    assert_eq!(applied.len(), 2);
}

#[test]
fn a_full_table_envelope_has_no_delta() {
    let caps = vec![descriptor(1, "echo")];
    let envelope = Envelope::request(8, "echo", vec![]).with_caps(caps.clone());
    let decoded = Envelope::decode(&envelope.encode().expect("encode")).expect("decode");
    assert!(decoded.cap_delta.is_none());
    assert_eq!(decoded.caps, caps);
}

#[test]
fn delta_additions_cannot_reuse_an_existing_id() {
    let base = vec![descriptor(1, "echo")];
    let delta = CapTableDelta::new(&base, vec![], vec![descriptor(1, "ping")]);
    assert_eq!(
        delta.apply_to(&base).unwrap_err().code(),
        "rpc/capability-table"
    );
}

#[test]
fn delta_removals_are_order_independent_but_the_result_is_sorted() {
    let base = vec![descriptor(3, "c"), descriptor(1, "a"), descriptor(2, "b")];
    let delta = CapTableDelta::new(&base, vec![CapId([2u8; 16])], vec![]);
    let applied = delta.apply_to(&base).expect("apply");
    let ids: Vec<CapId> = applied.iter().map(|cap| cap.id).collect();
    assert_eq!(ids, vec![CapId([1u8; 16]), CapId([3u8; 16])]);
    assert!(applied.iter().all(|cap| !cap.methods.is_empty()));
}
