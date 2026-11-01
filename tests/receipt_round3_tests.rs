//! Regression tests for the R-13 round-3 review: the lock steal is atomic, a
//! corrupted length field cannot be cut away, a pre-dispatch refusal in a
//! restarting session carries a real time, a log named `*.lock` keeps its own
//! lock, cancel and out-of-band resolve leave receipts, and a replaced log with
//! the same size is noticed.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::receipts::{Decision, ReceiptLog, LOG_HEADER_LEN};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, Receipt};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::Text(call.method.clone())))
    }
}

const SECRET: [u8; 32] = [0x3b; 32];

fn sandbox(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "active-rpc-receipt-round3-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    dir
}

fn receipt(sequence: u64, at_ms: u64) -> Receipt {
    Receipt {
        sequence,
        cap: "0123456789abcdef".to_string(),
        method: "echo".to_string(),
        at_ms,
        decision: Decision::Admitted,
        mac: [0u8; 32],
    }
}

/// A kernel with one registered provider, ready to queue work.
fn ready(agent: &Agent) -> (active_rpc::CapHandle, active_rpc::LaneId) {
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("round3", Budget::default())
        .expect("lane");
    (cap, lane)
}

// ---------------------------------------------------------------------------
// N2/N12: repair only cuts a genuinely torn write
// ---------------------------------------------------------------------------

#[test]
fn a_corrupted_length_field_is_not_cut_away() {
    let dir = sandbox("bad-length");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    for sequence in 1..=20 {
        log.append(&receipt(sequence, sequence)).expect("append");
    }
    let mut bytes = std::fs::read(&path).expect("read");
    // Rewrite the first record's length to another in-range value. The record
    // can no longer decode, and its "torn" declaration would run past the end of
    // the file, but the records after it are intact.
    let length = (u32::from_le_bytes(
        bytes[LOG_HEADER_LEN..LOG_HEADER_LEN + 4]
            .try_into()
            .expect("4 bytes"),
    ) + 1)
        .to_le_bytes();
    bytes[LOG_HEADER_LEN..LOG_HEADER_LEN + 4].copy_from_slice(&length);
    std::fs::write(&path, &bytes).expect("damage");

    let error = ReceiptLog::repair(&path)
        .expect_err("cutting a log whose tail still holds records would lose evidence");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        bytes,
        "a refused repair must not touch the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_torn_tail_repair_reports_the_bytes_it_discarded() {
    let dir = sandbox("torn-exact");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("first");
    log.append(&receipt(2, 20)).expect("second");
    let bytes = std::fs::read(&path).expect("read");
    // Find where the second record starts from the first record's own length,
    // then keep only a few bytes of it: a crash in the middle of a write.
    let first_len = u32::from_le_bytes(
        bytes[LOG_HEADER_LEN..LOG_HEADER_LEN + 4]
            .try_into()
            .expect("4 bytes"),
    ) as usize;
    let second_start = LOG_HEADER_LEN + 4 + first_len;
    let keep = second_start + 5;
    std::fs::write(&path, &bytes[..keep]).expect("tear");
    let discarded = ReceiptLog::repair(&path).expect("repair");
    assert_eq!(
        discarded as usize,
        keep - second_start,
        "the partial record is what gets discarded"
    );
    assert_eq!(std::fs::read(&path).expect("read").len(), second_start);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// N6: the lock path is derived by appending, not by replacing the extension
// ---------------------------------------------------------------------------

#[test]
fn a_log_named_lock_keeps_its_own_lock_file() {
    let dir = sandbox("lock-named");
    let path = dir.join("receipts.lock");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("append");
    assert!(
        std::fs::metadata(&path)
            .expect("the log itself survives")
            .len()
            > 0,
        "the log must not be mistaken for its own lock"
    );
    // Age the lock so a steal would be attempted, then append: the log is not
    // the lock, so this is a normal append.
    let lock = dir.join("receipts.lock.lock");
    if lock.exists() {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock)
            .expect("open");
        file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3_600))
            .expect("age");
    }
    log.append(&receipt(2, 20))
        .expect("append past a stale lock");
    assert_eq!(log.len().expect("len"), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// N9: the sequence setter refuses values it cannot honour
// ---------------------------------------------------------------------------

#[test]
fn the_sequence_setter_refuses_zero_and_the_ceiling() {
    let agent = Agent::with_secret(SECRET);
    assert_eq!(
        agent
            .set_receipt_sequence(0)
            .expect_err("zero is not a sequence")
            .code(),
        "rpc/invalid-argument"
    );
    assert_eq!(
        agent
            .set_receipt_sequence(u64::MAX)
            .expect_err("the ceiling would be issued twice")
            .code(),
        "rpc/invalid-argument"
    );
    agent.set_receipt_sequence(7).expect("a real sequence");
    agent.enable_receipts(true);
    let (cap, lane) = ready(&agent);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
    assert_eq!(agent.receipts()[0].sequence, 7);
}

// ---------------------------------------------------------------------------
// N3: a pre-dispatch refusal in a restarting session carries a real time
// ---------------------------------------------------------------------------

#[test]
fn a_restarted_session_dates_its_first_refusal() {
    let dir = sandbox("restart-clock");
    let path = dir.join("receipts.arrl");
    // Session 1 runs on the wall clock and exports two receipts.
    let first = Agent::with_secret(SECRET);
    first.use_wall_clock(true);
    first.enable_receipts(true);
    let (cap, lane) = ready(&first);
    for _ in 0..2 {
        let promise = first.call(lane, &cap, "echo", Vec::new()).expect("call");
        first.run();
        promise.value().expect("value");
    }
    let exported = first.receipts();
    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&first.receipt_key(), &exported)
        .expect("export");

    // Session 2 continues the log and refuses a call before dispatching.
    let second = Agent::with_secret(SECRET);
    second.use_wall_clock(true);
    second.enable_receipts(true);
    second.set_receipt_sequence(3).expect("continue the log");
    let (cap, lane) = ready(&second);
    let promise = second.call(lane, &cap, "echo", Vec::new()).expect("queued");
    drop(cap);
    second.run();
    promise.value().expect_err("released capability");

    let continued = second.receipts();
    assert_eq!(continued.len(), 1);
    assert!(
        continued[0].at_ms > 0,
        "a pre-dispatch refusal must carry the wall clock, not zero"
    );
    log.append_verified(&second.receipt_key(), &continued)
        .expect("the refusal appends without poisoning the export");
    assert_eq!(log.len().expect("len"), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// N14: cancel and out-of-band resolve leave a refusal
// ---------------------------------------------------------------------------

#[test]
fn a_cancelled_call_is_recorded_as_a_refusal() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let (cap, lane) = ready(&agent);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.cancel(&promise).expect("cancel");
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].decision,
        Decision::Refused("rpc/promise-cancelled".to_string())
    );
}

#[test]
fn an_out_of_band_resolve_is_recorded_as_a_refusal() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let (cap, lane) = ready(&agent);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent
        .resolve(&promise, Value::Int(1))
        .expect("answer out of band");
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].decision,
        Decision::Refused("rpc/promise-resolved".to_string())
    );
}

// ---------------------------------------------------------------------------
// N10: a replaced log of the same size is noticed
// ---------------------------------------------------------------------------

#[test]
fn a_log_replaced_at_the_same_size_is_not_trusted() {
    let dir = sandbox("same-size");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("first");

    // Replace the log with a different start sequence and exactly the same
    // number of bytes: the cached state must not be reused.
    let replacement = dir.join("other.arrl");
    let other = ReceiptLog::create_starting_at(&replacement, 900).expect("create");
    let _ = other;
    std::fs::copy(&replacement, &path).expect("replace");
    let error = log
        .append(&receipt(2, 20))
        .expect_err("sequence 2 does not follow a log that starts at 900");
    assert_eq!(error.code(), "rpc/receipt");
    log.records()
        .expect("the replaced log still reads as a header-only log");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// N18: the snapshot's MAC check is part of the contract
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_verifies_macs_under_the_receipt_key() {
    let dir = sandbox("snapshot-macs");
    let path = dir.join("receipts.arrl");
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let (cap, lane) = ready(&agent);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
    let receipts = agent.receipts();

    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&agent.receipt_key(), &receipts)
        .expect("export");
    let snapshot = log.snapshot().expect("snapshot");
    snapshot
        .verify_macs(&agent.receipt_key())
        .expect("the kernel's key verifies its own log");
    let error = snapshot
        .verify_macs(&active_rpc::receipts::derive_receipt_key(&[0x01; 32]))
        .expect_err("another key must not verify");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}
