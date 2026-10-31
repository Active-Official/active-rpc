#![no_main]

//! Bulk transfer plans and chunk frames arrive from a peer. Decoding, hashing
//! and verification must reject truncation and abuse without panicking.

use libfuzzer_sys::fuzz_target;

use active_rpc::bulk::{BulkChunk, BulkPlan};

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
    }
    if let Ok(chunk) = BulkChunk::decode(data) {
        let _ = chunk.index();
        let _ = chunk.offset();
        let _ = chunk.hash();
        let _ = chunk.data().len();
        let _ = chunk.encode();
    }
});
