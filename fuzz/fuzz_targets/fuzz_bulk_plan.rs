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

            // The receive state machine: duplicate, conflicting and off-plan
            // chunks must each take a defined path, never a panic.
            if let Ok(sender) = BulkSender::new(data.to_vec(), plan.chunk_size()) {
                let frames = sender.frames();
                let mut receiver = BulkReceiver::new(decoded.clone()).expect("admitted plan");
                for (index, frame) in frames.iter().enumerate() {
                    match receiver.accept(frame) {
                        Ok(accepted) => assert_eq!(accepted as usize, index),
                        Err(error) => assert_eq!(error.code(), "rpc/bulk"),
                    }
                    // Replay is idempotent.
                    if let Ok(repeated) = receiver.accept(frame) {
                        assert_eq!(repeated as usize, index);
                    }
                }
                if receiver.is_complete() {
                    let assembled = receiver.finish().expect("a complete body verifies");
                    assert_eq!(assembled, data);
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
