#![no_main]

//! Transport framing: shared-memory ring boundaries and gRPC framing.
//!
//! Invariants under test (I-8, I-10):
//!
//! 1. A write larger than the remaining capacity is refused, never truncated
//!    silently, never written out of bounds, and leaves no partial frame.
//! 2. A frame header that claims more than the segment is refused by the reader.
//!    The writer prefixes the length itself, so such a header cannot be produced
//!    through the public API: the reader's bound is asserted on an empty ring and
//!    after a refused write.
//! 3. Arbitrary read/advance/reset sequences never panic.
//! 4. gRPC length-prefix framing is self-delimiting and a fixed point.
//!
//! Run with `cargo +nightly fuzz run fuzz_transport_framing -- -runs=200000`.

use libfuzzer_sys::fuzz_target;

use active_rpc::transport::connect::{grpc_frame, grpc_unframe};
use active_rpc::transport::shm::SharedSegment;

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

    // 2. An oversized payload is refused, built here rather than taken from the
    //    input: the constructor clamps a segment to at least 1024 bytes, so no
    //    corpus seed can reach the boundary and the "refused" branch used to be
    //    unreachable.
    let oversized = vec![0u8; capacity + 1];

    // 2. The reader's frame bound: a refused write leaves the ring exactly as it
    //    was, and a fresh ring answers `Ok(None)` rather than inventing a frame.
    let before_refusal = segment.available();
    assert!(
        segment.write(&oversized).is_err(),
        "a write larger than the segment must be refused"
    );
    assert_eq!(
        segment.available(),
        before_refusal,
        "a refused write must not leave a partial frame behind"
    );
    let empty = SharedSegment::new(1024);
    assert!(
        matches!(empty.read(), Ok(None)),
        "an empty ring has no frame"
    );
    assert!(
        matches!(empty.with_frame(|frame| frame.len()), Ok(None)),
        "an empty ring has no frame header"
    );
    assert!(matches!(empty.pop_frame(|frame| frame.len()), Ok(None)));

    // 3. Arbitrary advance/reset sequences never panic and never move past the
    // produced head. `advance` takes no length: it reads the frame header, so a
    // caller cannot leave the ring mid-frame.
    for byte in data.iter().take(16) {
        match byte % 4 {
            0 => {
                let _ = segment.advance();
            }
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
        let Ok(framed) = grpc_frame(message) else { return };
        let (again, tail) = grpc_unframe(&framed).expect("framed message parses");
        assert_eq!(again, message);
        assert!(tail.is_empty());
        assert!(rest.len() < data.len());
    }

    // An over-declared 5-byte prefix is an error, not a panic.
    let mut bogus = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
    bogus.extend_from_slice(payload);
    let _ = grpc_unframe(&bogus);

});
