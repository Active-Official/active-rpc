//! The fixed positive controls the decoder fuzz targets assert, driven through
//! the same shipped API from a test CI runs on every push.
//!
//! A fuzz target's control only fails inside a campaign; these tests make the
//! same claim breakable by `scripts/negative_controls.py`, so a decoder that
//! regresses to "refuse every input" is caught immediately (R-20 round 5,
//! F3/F4/F7).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use active_rpc::receipts::{Decision, ReceiptLog};
use active_rpc::transport::connect::{grpc_frame, grpc_unframe};
use active_rpc::transport::shm::SharedSegment;
use active_rpc::Receipt;

fn scratch(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "active-rpc-fuzz-control-{}-{nanos}-{tag}.log",
        std::process::id()
    ))
}

/// The `ARRL` reader must accept a log the shipped writer produced and return
/// exactly the sealed records (the target's `fuzz_receipt_log` control).
#[test]
fn a_well_formed_receipt_log_reads_back() {
    let path = scratch("receipt");
    let _ = std::fs::remove_file(&path);
    let log = ReceiptLog::create(&path).expect("create");
    let first = Receipt {
        sequence: 1,
        cap: "0011223344556677".to_string(),
        method: "echo".to_string(),
        at_ms: 1,
        decision: Decision::Admitted,
        mac: [0u8; 32],
    };
    let second = Receipt {
        sequence: 2,
        cap: "8899aabbccddeeff".to_string(),
        method: "ping".to_string(),
        at_ms: 2,
        decision: Decision::Refused("rpc/unknown-capability".to_string()),
        mac: [1u8; 32],
    };
    log.append(&first).expect("append the first receipt");
    log.append(&second).expect("append the second receipt");
    let bytes = std::fs::read(&path).expect("read the log");
    let read = ReceiptLog::verify_bytes(&bytes).expect("the fixed log verifies");
    assert_eq!(read, vec![first, second]);
    let _ = std::fs::remove_file(&path);
}

/// A frame written into a shared-memory ring is readable, and advancing it
/// releases exactly the bytes written (the target's `fuzz_transport_framing`
/// ring control).
#[test]
fn a_written_shared_memory_frame_reads_back() {
    let ring = SharedSegment::new(1024);
    ring.write(b"frame").expect("the fixed frame fits");
    let read = ring.read().expect("read").expect("a frame");
    assert_eq!(read, b"frame");
    ring.advance().expect("advance");
    assert_eq!(ring.consumed(), ring.produced());
}

/// The gRPC length prefix round-trips (the target's framing control).
#[test]
fn a_framed_grpc_message_unframes_to_itself() {
    let framed = grpc_frame(b"hello").expect("frame");
    let (message, tail) = grpc_unframe(&framed).expect("unframe");
    assert_eq!(message, b"hello");
    assert!(tail.is_empty());
}
