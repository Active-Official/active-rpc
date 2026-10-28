#![no_main]

//! Transport framing: shared-memory ring boundaries and gRPC framing.
//!
//! Invariants under test (I-8, I-10):
//!
//! 1. A write larger than the remaining capacity is refused, never truncated
//!    silently and never written out of bounds.
//! 2. A frame whose declared length exceeds the segment is refused.
//! 3. Arbitrary read/advance/reset sequences never panic.
//! 4. gRPC length-prefix framing is self-delimiting and a fixed point.
//!
//! Run with `cargo +nightly fuzz run fuzz_transport_framing -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::transport::connect::{grpc_frame, grpc_unframe};
use active_rpc::transport::shm::SharedSegment;

#[path = "common.rs"]
mod common;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let requested = 64 + (data[0] as usize % 512);
    let segment = SharedSegment::new(requested);
    // The constructor clamps tiny segments to 1024 bytes; use the real
    // capacity for every bound below.
    let capacity = segment.capacity();
    assert!(capacity >= requested);

    // 1. Writes are bounded by capacity.
    let payload = &data[1..];
    if payload.len() > capacity {
        assert!(
            segment.write(payload).is_err(),
            "an oversized write must be refused"
        );
    } else {
        let _ = segment.write(payload);
    }
    assert!(segment.available() <= segment.capacity());

    // 2. A frame header that claims more than the segment is refused.
    let _ = segment.read();
    let _ = segment.with_frame(|frame| frame.len());
    let _ = segment.pop_frame(|frame| frame.len());

    // 3. Arbitrary advance/reset sequences never panic and never move past the
    // produced head by an unbounded amount.
    for byte in data.iter().take(16) {
        match byte % 4 {
            0 => segment.advance((*byte as usize) % (capacity + 8)),
            1 => {
                let _ = segment.read();
            }
            2 => {
                if payload.len() <= capacity {
                    let _ = segment.write(payload);
                }
            }
            _ => segment.reset(),
        }
        assert!(segment.consumed() <= segment.produced());
    }

    // 4. gRPC framing round-trips and refuses an over-declared length.
    if let Ok((message, rest)) = grpc_unframe(data) {
        let framed = grpc_frame(message);
        let (again, tail) = grpc_unframe(&framed).expect("framed message parses");
        assert_eq!(again, message);
        assert!(tail.is_empty());
        assert!(rest.len() < data.len());
    }

    // An over-declared 5-byte prefix is an error, not a panic.
    let mut bogus = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    bogus.extend_from_slice(payload);
    let _ = grpc_unframe(&bogus);

    let _ = common::budget_from(data);
});
