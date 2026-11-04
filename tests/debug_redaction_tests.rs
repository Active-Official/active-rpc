//! F-02/F-03: formatting an `Envelope` or a `Call` never dumps its payload.
//!
//! The payload is opaque bytes (an in-process provider may return a large
//! blob), so a derived `Debug` put it in every log line. Both formatters are
//! written by hand and show sizes and a bounded method label.

use active_rpc::value::Call;
use active_rpc::wire::{Envelope, Kind};

const MARKER: &[u8] = b"PAYLOAD-BYTES-MUST-NOT-APPEAR";

#[test]
fn an_envelope_debug_does_not_print_its_payload() {
    let envelope = Envelope::request(7, "stats", Vec::new()).with_payload(MARKER.to_vec());
    let text = format!("{envelope:?}");
    assert!(!text.contains("PAYLOAD"), "{text}");
    assert!(
        text.contains(&format!("payload: {} bytes", MARKER.len())),
        "{text}"
    );
    assert!(text.contains("stats"), "{text}");
    assert!(text.contains("request_id: 7"), "{text}");
}

#[test]
fn an_envelope_debug_bounds_a_long_method() {
    let method = "m".repeat(10_000);
    let envelope = Envelope::request(1, method, Vec::new());
    let text = format!("{envelope:?}");
    assert!(text.len() < 512, "the label is bounded: {}", text.len());
    assert!(text.contains('…'), "{text}");
}

#[test]
fn a_call_debug_does_not_print_its_payload() {
    let mut call = Call::new("run", Vec::new());
    call.payload = MARKER.to_vec();
    let text = format!("{call:?}");
    assert!(!text.contains("PAYLOAD"), "{text}");
    assert!(
        text.contains(&format!("payload: {} bytes", MARKER.len())),
        "{text}"
    );
    assert!(text.contains("run"), "{text}");
}

#[test]
fn the_envelope_kind_is_still_readable() {
    let text = format!("{:?}", Envelope::response(1, active_rpc::Value::Null));
    assert!(text.contains("kind: Response"), "{text}");
    assert!(text.contains("kind"), "{text}");
    let _ = Kind::Request;
}
