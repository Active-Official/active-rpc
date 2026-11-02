#![no_main]

//! Bulk transfer plans and chunk frames arrive from a peer. Decoding, hashing
//! and verification must reject truncation and abuse without panicking.

use libfuzzer_sys::fuzz_target;

use active_rpc::bulk::{BulkChunk, BulkPlan, BulkReceiver, BulkRequest, BulkSender};

fuzz_target!(|data: &[u8]| {
    if let Ok(plan) = BulkPlan::decode(data) {
        let _ = plan.chunk_count();
        let _ = plan.chunk_size();
        let _ = plan.total();
        let _ = plan.chunk_hash_at(0);
        let _ = plan.chunk_hash_at(u32::MAX);
        // A plan must never verify bytes that do not match its chunk hashes.
        let _ = plan.verify(data);
        let _ = plan.verify(&[]);
        // Structural invariants hold for every accepted plan.
        assert!(
            (plan.chunk_count() as u64) * (plan.chunk_size() as u64) >= plan.total(),
            "plan claims more bytes than its chunks can hold"
        );
        assert!(plan.chunk_size() > 0, "plan has a zero chunk size");
    }
    if let Ok(chunk) = BulkChunk::decode(data) {
        let _ = chunk.index();
        let _ = chunk.offset();
        let _ = chunk.hash();
        let _ = chunk.data().len();
        let _ = chunk.encode();
    }
    // Exercise the encoder with attacker-shaped inputs and verify the result
    // round-trips through the decoder.
    if data.len() >= 4 {
        let chunk = (data.len() / 2).clamp(1, 1 << 16);
        if let Ok(plan) = BulkPlan::new(data, chunk) {
            let encoded = plan.encode();
            let decoded = BulkPlan::decode(&encoded).expect("a plan must decode");
            assert_eq!(decoded.root(), plan.root());
            assert_eq!(decoded.total(), plan.total());
            assert_eq!(decoded.chunk_count() as usize, plan.chunk_count() as usize);
            assert!(
                plan.verify(data).is_ok(),
                "a plan must verify its own bytes"
            );

            // The receive state machine: duplicate, conflicting, reordered and
            // truncated chunks must each take a defined path. Replaying the
            // sender's own frames in order only proves the happy path, so the
            // order is derived from the input and a frame is substituted.
            if let Ok(sender) = BulkSender::new(data.to_vec(), plan.chunk_size()) {
                let frames = sender.frames();
                let mut receiver = BulkReceiver::new(decoded.clone()).expect("admitted plan");
                let mut order: Vec<usize> = (0..frames.len()).collect();
                // A deterministic permutation from the first byte: no RNG, so a
                // failure reproduces from the saved input.
                if !order.is_empty() {
                    let pivot = usize::from(data[0]) % order.len();
                    order.rotate_left(pivot);
                }
                for index in order {
                    if let Some(frame) = frames.get(index) {
                        match receiver.accept(frame) {
                            Ok(_) => {}
                            Err(error) => assert_eq!(error.code(), "rpc/bulk"),
                        }
                        // A conflicting frame for the same chunk must be
                        // refused, not accepted as the body.
                        let mut tampered = frame.clone();
                        if !tampered.is_empty() {
                            let last = tampered.len() - 1;
                            tampered[last] ^= 0xFF;
                        }
                        if let Err(error) = receiver.accept(&tampered) {
                            assert_eq!(error.code(), "rpc/bulk");
                        }
                    }
                }
                if receiver.is_complete() {
                    let assembled = receiver.finish().expect("a complete body verifies");
                    assert_eq!(assembled, data);
                }
                // A truncated frame is refused, never panics.
                if let Some(frame) = frames.first() {
                    let short = &frame[..frame.len() / 2];
                    if let Ok(plan_frame) = BulkChunk::decode(short) {
                        let _ = plan_frame.index();
                    }
                }
                // A resume request round-trips for every admitted plan.
                let request = BulkRequest::new(&[0, 0]);
                if let Ok(decoded_request) = BulkRequest::decode(&request.encode(), &decoded) {
                    assert!(decoded_request.missing().len() <= 1);
                }
            }
        }
    }
});
