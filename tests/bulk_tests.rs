//! Bulk (carousel) transfer: plan integrity, chunk verification, resume.
//!
//! The end-to-end test moves a body over a real TCP socket, drops the
//! connection halfway, reconnects, and sends only the missing chunks. The server
//! verifies the root before it accepts the body.

use std::io::BufReader;
use std::net::{TcpListener, TcpStream};

use active_rpc::bulk::{BulkChunk, BulkPlan, BulkReceiver, BulkSender, MAX_CHUNK};
use active_rpc::transport::{read_frame, write_frame};
use active_rpc::WireLimits;

fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| ((index * 31 + 17) % 251) as u8)
        .collect()
}

#[test]
fn a_plan_round_trips_and_its_root_is_stable() {
    let bytes = body(300_000);
    let plan = BulkPlan::new(&bytes, 64 * 1024).expect("plan");
    assert_eq!(plan.chunk_count(), 5);
    assert_eq!(plan.total(), 300_000);
    let encoded = plan.encode();
    let decoded = BulkPlan::decode(&encoded).expect("decode");
    assert_eq!(decoded, plan);
    assert_eq!(decoded.root(), plan.root());
    assert_eq!(decoded.root_hex().len(), 64);
    decoded.verify(&bytes).expect("verify");

    let same = BulkPlan::new(&bytes, 64 * 1024).expect("plan again");
    assert_eq!(same.root(), plan.root(), "root is deterministic");
}

#[test]
fn chunks_reassemble_into_the_original_body() {
    let bytes = body(1_000_000);
    let sender = BulkSender::new(bytes.clone(), 128 * 1024).expect("sender");
    let mut receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");
    assert_eq!(receiver.missing().len(), 8);
    for frame in sender.frames() {
        receiver.accept(&frame).expect("accept");
    }
    assert!(receiver.is_complete());
    assert!(receiver.missing().is_empty());
    assert_eq!(receiver.bytes_received(), bytes.len() as u64);
    assert_eq!(receiver.finish().expect("finish"), bytes);
}

#[test]
fn an_empty_body_plans_to_zero_chunks_and_finishes_empty() {
    let sender = BulkSender::new(Vec::new(), 1024).expect("sender");
    assert_eq!(sender.plan().chunk_count(), 0);
    assert!(sender.frames().is_empty());
    let receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");
    assert!(receiver.is_complete());
    assert_eq!(receiver.finish().expect("finish"), Vec::<u8>::new());
}

#[test]
fn a_corrupted_or_truncated_chunk_is_refused() {
    let bytes = body(200_000);
    let sender = BulkSender::new(bytes, 64 * 1024).expect("sender");
    let mut receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");
    let frames = sender.frames();
    let frame = frames[0].clone();
    let mut corrupted = frame.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xff;
    let error = receiver.accept(&corrupted).expect_err("corrupt chunk");
    assert_eq!(error.code(), "rpc/bulk");

    let error = receiver
        .accept(&frame[..frame.len() - 1])
        .expect_err("truncated chunk");
    assert_eq!(error.code(), "rpc/bulk");

    // The good frame still works after the refusals.
    receiver.accept(&frame).expect("good chunk");
    assert_eq!(receiver.missing().len(), 3);
}

#[test]
fn a_chunk_cannot_claim_another_index_or_an_off_plan_hash() {
    let bytes = body(200_000);
    let sender = BulkSender::new(bytes, 64 * 1024).expect("sender");
    let mut receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");

    // Re-index a valid chunk: its offset no longer matches.
    let chunk = BulkChunk::new(0, 64 * 1024, &body(64 * 1024));
    let mut frame = chunk.encode();
    frame[5..9].copy_from_slice(&3u32.to_le_bytes());
    let error = receiver.accept(&frame).expect_err("offset mismatch");
    assert_eq!(error.code(), "rpc/bulk");

    // A frame with a valid shape but a hash the plan never announced.
    let foreign = BulkChunk::new(0, 64 * 1024, &vec![0x5a; 64 * 1024]);
    let error = receiver
        .accept(&foreign.encode())
        .expect_err("planned hash mismatch");
    assert_eq!(error.code(), "rpc/bulk");
}

#[test]
fn retransmission_is_idempotent_and_conflicts_are_refused() {
    let bytes = body(150_000);
    let sender = BulkSender::new(bytes, 64 * 1024).expect("sender");
    let mut receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");
    let frames = sender.frames();
    receiver.accept(&frames[0]).expect("first");
    receiver.accept(&frames[0]).expect("identical duplicate");

    let mut conflicting = frames[0].clone();
    let last = conflicting.len() - 1;
    conflicting[last] ^= 0x01;
    // A conflicting frame fails its own hash before it reaches the duplicate
    // comparison, which is the behaviour a receiver wants: never store it.
    let error = receiver.accept(&conflicting).expect_err("conflict");
    assert_eq!(error.code(), "rpc/bulk");
    assert_eq!(receiver.missing().len(), 2);
}

#[test]
fn resume_sends_only_the_missing_chunks() {
    let bytes = body(500_000);
    let sender = BulkSender::new(bytes.clone(), 64 * 1024).expect("sender");
    let mut receiver = BulkReceiver::new(sender.plan().clone()).expect("receiver");
    let all = sender.frames();
    for frame in all.iter().take(3) {
        receiver.accept(frame).expect("first three");
    }

    let missing = receiver.missing();
    let resumed = sender.frames_for(&missing);
    assert_eq!(resumed.len(), missing.len());
    for frame in resumed {
        receiver.accept(&frame).expect("resumed chunk");
    }
    assert!(receiver.is_complete());
    assert_eq!(receiver.finish().expect("finish"), bytes);
}

#[test]
fn a_receiver_refuses_a_body_over_its_ceiling() {
    let bytes = body(100_000);
    let plan = BulkPlan::new(&bytes, 64 * 1024).expect("plan");
    let error = BulkReceiver::with_ceiling(plan, 50_000).expect_err("ceiling");
    assert_eq!(error.code(), "rpc/bulk");
}

#[test]
fn a_plan_cannot_lie_about_its_root_or_its_hashes() {
    let bytes = body(200_000);
    let plan = BulkPlan::new(&bytes, 64 * 1024).expect("plan");
    let encoded = plan.encode();

    let mut bad_root = encoded.clone();
    bad_root[21] ^= 0xff;
    let error = BulkPlan::decode(&bad_root).expect_err("bad root");
    assert_eq!(error.code(), "rpc/bulk");

    let mut bad_hash = encoded.clone();
    let hash_offset = 53 + 5;
    bad_hash[hash_offset] ^= 0xff;
    let error = BulkPlan::decode(&bad_hash).expect_err("bad chunk hash");
    assert_eq!(error.code(), "rpc/bulk");

    let mut short = encoded.clone();
    short.truncate(encoded.len() - 1);
    let error = BulkPlan::decode(&short).expect_err("short plan");
    assert_eq!(error.code(), "rpc/bulk");
}

#[test]
fn chunk_size_is_bounded() {
    let bytes = body(10);
    assert_eq!(
        BulkPlan::new(&bytes, 0).expect_err("zero").code(),
        "rpc/bulk"
    );
    assert_eq!(
        BulkPlan::new(&bytes, MAX_CHUNK + 1)
            .expect_err("too large")
            .code(),
        "rpc/bulk"
    );
}

#[test]
fn a_bulk_transfer_over_tcp_resumes_after_a_dropped_connection() {
    let bytes = body(1_100_000);
    let sender = BulkSender::new(bytes.clone(), 128 * 1024).expect("sender");
    let plan = sender.plan().clone();
    let all = sender.frames();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr");
    let expected = bytes.clone();
    let expected_plan = plan.clone();

    let server = std::thread::spawn(move || {
        let mut receiver: Option<BulkReceiver> = None;
        let mut connections = 0;
        while connections < 2 {
            let (stream, _) = listener.accept().expect("accept");
            connections += 1;
            let mut reader = BufReader::new(stream);
            let plan_frame = read_frame(&mut reader, &WireLimits::default())
                .expect("read plan")
                .expect("plan frame");
            let decoded = BulkPlan::decode(&plan_frame).expect("plan");
            assert_eq!(decoded, expected_plan);
            if receiver.is_none() {
                receiver = Some(BulkReceiver::new(decoded).expect("receiver"));
            }
            let receiver = receiver.as_mut().expect("receiver");
            while let Some(frame) =
                read_frame(&mut reader, &WireLimits::default()).expect("read chunk")
            {
                receiver.accept(&frame).expect("accept chunk");
            }
            if receiver.is_complete() {
                break;
            }
        }
        receiver.expect("receiver").finish().expect("finish")
    });

    // First connection: plan plus the first three chunks, then drop.
    let mut first = TcpStream::connect(address).expect("connect");
    write_frame(&mut first, &plan.encode()).expect("write plan");
    for frame in all.iter().take(3) {
        write_frame(&mut first, frame).expect("write chunk");
    }
    drop(first);

    // Second connection: the plan again plus only the missing chunks.
    let mut second = TcpStream::connect(address).expect("connect");
    write_frame(&mut second, &plan.encode()).expect("write plan");
    let mut receiver = BulkReceiver::new(plan.clone()).expect("receiver");
    for frame in all.iter().take(3) {
        receiver.accept(frame).expect("replay");
    }
    for frame in sender.frames_for(&receiver.missing()) {
        write_frame(&mut second, &frame).expect("write resumed chunk");
    }
    drop(second);

    let received = server.join().expect("join");
    assert_eq!(received, expected, "the resumed body is byte-identical");
}
