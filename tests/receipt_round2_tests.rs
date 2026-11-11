//! Regression tests for the R-13 round-2 review: the receipt key is not the
//! kernel secret, a refusal before dispatch is still recorded, the writer and
//! reader agree on every field, a torn tail is repairable, a stale lock is
//! stolen, a create honours the writer lock, and a later session can continue an
//! existing log.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::receipts::{
    derive_receipt_key, Decision, ReceiptLog, MAX_LOG_RECORDS, MAX_RECEIPTS,
};
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

const SECRET: [u8; 32] = [0x7c; 32];

fn sandbox(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "active-rpc-receipt-round2-{name}-{}",
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
        caller: None,
    }
}

fn session(agent: &Agent, count: usize) {
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("round2", Budget::default())
        .expect("lane");
    for _ in 0..count {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("value");
    }
}

// ---------------------------------------------------------------------------
// B1: the receipt key is not the authority key
// ---------------------------------------------------------------------------

#[test]
fn a_receipt_is_sealed_with_a_derived_key_not_the_kernel_secret() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    session(&agent, 1);
    let key = agent.receipt_key();
    assert_ne!(
        key, SECRET,
        "the receipt key must not be the secret that mints capability ids"
    );
    assert_eq!(key, derive_receipt_key(&SECRET), "derivation is stable");

    let receipt = &agent.receipts()[0];
    assert!(receipt.verify(&key), "the derived key verifies the receipt");
    assert!(
        !receipt.verify(&SECRET),
        "the master secret must not verify a receipt"
    );
    assert!(agent.verify_receipt(receipt));
}

// ---------------------------------------------------------------------------
// B2: a refusal that never reaches dispatch is still recorded
// ---------------------------------------------------------------------------

#[test]
fn a_refusal_before_dispatch_is_recorded() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("predispatch", Budget::default())
        .expect("lane");

    // Queue the call, then drop the only handle: the capability is released, and
    // the kernel fails the queued job with `rpc/unknown-capability` without ever
    // dispatching it.
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    drop(cap);
    agent.run();
    let error = promise.value().expect_err("a released capability refuses");
    assert_eq!(error.code(), "rpc/unknown-capability");

    let receipts = agent.receipts();
    assert_eq!(
        receipts.len(),
        1,
        "a call failed before dispatch still took a decision"
    );
    assert_eq!(
        receipts[0].decision,
        Decision::Refused("rpc/unknown-capability".to_string())
    );
    assert!(agent.verify_receipt(&receipts[0]));
}

#[test]
fn a_destroyed_lane_records_the_calls_it_drops() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("doomed", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.destroy_lane(lane).expect("destroy");
    let error = promise.value().expect_err("the lane is gone");
    assert_eq!(error.code(), "rpc/unknown-lane");
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].decision,
        Decision::Refused("rpc/unknown-lane".to_string())
    );
}

// ---------------------------------------------------------------------------
// B3/B11: the writer applies every reader rule
// ---------------------------------------------------------------------------

#[test]
fn a_refused_code_the_reader_rejects_is_refused_by_the_writer() {
    let dir = sandbox("empty-code");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    let before = std::fs::read(&path).expect("read");

    let mut bad = receipt(1, 10);
    bad.decision = Decision::Refused(String::new());
    let error = log
        .append(&bad)
        .expect_err("an empty refusal code is not representable");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(std::fs::read(&path).expect("read"), before);
    log.records().expect("the log is still readable");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_start_too_close_to_the_sequence_ceiling_is_refused() {
    let dir = sandbox("ceiling");
    let error = ReceiptLog::create_starting_at(dir.join("late.arrl"), u64::MAX - 1)
        .expect_err("a start that could overflow is refused");
    assert_eq!(error.code(), "rpc/receipt");
    let log = ReceiptLog::create_starting_at(dir.join("ok.arrl"), u64::MAX - MAX_LOG_RECORDS)
        .expect("a start that can still be numbered");
    assert_eq!(
        log.start_sequence().expect("start"),
        u64::MAX - MAX_LOG_RECORDS
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_refuses_any_existing_content() {
    let dir = sandbox("tiny");
    let path = dir.join("tiny.arrl");
    std::fs::write(&path, b"junk").expect("write");
    let error = ReceiptLog::create(&path).expect_err("a truncated file is still evidence");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(std::fs::read(&path).expect("read"), b"junk", "bytes kept");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// B5: one snapshot answers every question
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_answers_records_start_and_head_from_one_read() {
    let dir = sandbox("snapshot");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create_starting_at(&path, 500).expect("create");
    log.append(&receipt(500, 10)).expect("first");
    log.append(&receipt(501, 20)).expect("second");

    let snapshot = log.snapshot().expect("snapshot");
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot.start_sequence(), 500);
    assert_eq!(snapshot.last_ms(), 20);
    assert_eq!(snapshot.receipts().len(), 2);
    assert_eq!(snapshot.head(), log.head_hash().expect("head"));
    snapshot.verify_macs(&[0u8; 32]).ok();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// B6: a torn trailing write is repairable
// ---------------------------------------------------------------------------

#[test]
fn a_torn_tail_is_repaired_and_the_surviving_chain_verifies() {
    let dir = sandbox("repair");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("first");
    log.append(&receipt(2, 20)).expect("second");
    log.append(&receipt(3, 30)).expect("third");

    // Simulate a crash in the middle of the third record's write.
    let bytes = std::fs::read(&path).expect("read");
    std::fs::write(&path, &bytes[..bytes.len() - 9]).expect("tear");
    let error = ReceiptLog::open(&path).expect_err("a torn log is refused");
    assert_eq!(error.code(), "rpc/receipt");

    let discarded = ReceiptLog::repair(&path).expect("repair");
    assert_eq!(
        discarded, 134,
        "the whole partial record is discarded, not only the bytes that were missing"
    );
    let repaired = ReceiptLog::open(&path).expect("the repaired log opens");
    assert_eq!(repaired.records().expect("records").len(), 2);
    repaired.verify_chain().expect("chain");

    // The next record continues the repaired chain.
    repaired
        .append(&receipt(3, 30))
        .expect("append after repair");
    assert_eq!(repaired.len().expect("len"), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repair_keeps_a_damaged_record_inside_the_log() {
    let dir = sandbox("repair-inside");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    for sequence in 1..=40 {
        log.append(&receipt(sequence, sequence)).expect("append");
    }
    // Flip a byte in the first record: the damage is not a torn tail, and
    // cutting it would silently drop the whole log.
    let mut bytes = std::fs::read(&path).expect("read");
    bytes[40] ^= 0x01;
    std::fs::write(&path, &bytes).expect("damage");
    let error = ReceiptLog::repair(&path).expect_err("repair refuses to cut into the log");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn repairing_an_intact_log_changes_nothing() {
    let dir = sandbox("repair-clean");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("append");
    let before = std::fs::read(&path).expect("read");
    assert_eq!(ReceiptLog::repair(&path).expect("repair"), 0);
    assert_eq!(std::fs::read(&path).expect("read"), before);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// B7/B8: the lock
// ---------------------------------------------------------------------------

#[test]
fn a_stale_lock_is_stolen_instead_of_blocking_forever() {
    let dir = sandbox("stale-lock");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("first");

    // A crashed writer leaves its lock behind; age it past the ceiling.
    let lock = path.with_extension("lock");
    // A real nonce and a pid no process can have: the first token is the
    // nonce, and `pid 1 started 0` would parse as the nonce `pid` with no
    // pid at all, so the liveness branch was never exercised (R-13 round 7,
    // #7).
    std::fs::write(&lock, b"999999-1 pid 4294967294 started 0").expect("lock");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&lock)
        .expect("open lock");
    file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3_600))
        .expect("age the lock");
    drop(file);

    log.append(&receipt(2, 20))
        .expect("a lock left by a dead process must not block the log");
    assert_eq!(log.len().expect("len"), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_honours_a_held_writer_lock() {
    let dir = sandbox("create-lock");
    let path = dir.join("receipts.arrl");
    // The lock name is the log name with `.lock` appended (not the extension
    // replaced), so a log named `*.lock` cannot collide with its own lock.
    std::fs::write(dir.join("receipts.arrl.lock"), b"held").expect("lock");
    let error = ReceiptLog::create(&path).expect_err("create must not truncate under a writer");
    assert_eq!(error.code(), "rpc/receipt");
    assert!(
        !path.exists(),
        "a refused create leaves no half-written log behind"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// B10: the event carries the running total
// ---------------------------------------------------------------------------

#[test]
fn the_drop_event_reports_the_running_total() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    session(&agent, MAX_RECEIPTS + 3);
    assert_eq!(agent.receipts_dropped(), 3);
    let marker = agent
        .events()
        .into_iter()
        .find_map(|event| match event {
            active_rpc::Event::ReceiptsDropped { count } => Some(count),
            _ => None,
        })
        .expect("a marker");
    assert_eq!(marker, 1, "the event fires when dropping begins");

    // Clearing adds to the same total, and the event reports that total.
    agent.enable_receipts(false);
    let total = agent.receipts_dropped();
    assert_eq!(total, 3 + MAX_RECEIPTS as u64);
    let last = agent
        .events()
        .into_iter()
        .filter_map(|event| match event {
            active_rpc::Event::ReceiptsDisabled { count } => Some(count),
            _ => None,
        })
        .next_back()
        .expect("a clear marker");
    assert_eq!(last, total, "the event reports the running total");
}

// ---------------------------------------------------------------------------
// B14: a later session continues an existing log
// ---------------------------------------------------------------------------

#[test]
fn a_second_session_continues_a_log() {
    let dir = sandbox("continue");
    let path = dir.join("receipts.arrl");
    // A restarted kernel adopts the log's next sequence and continues it. Both
    // sessions read the wall clock, because a log refuses a record older than
    // the one before it and a virtual clock restarts at zero.
    let first = Agent::with_secret(SECRET);
    first.enable_receipts(true);
    first.use_wall_clock(true);
    session(&first, 2);
    let receipts = first.receipts();
    assert_eq!(receipts.last().expect("receipt").sequence, 2);
    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&first.receipt_key(), &receipts)
        .expect("export");

    let second = Agent::with_secret(SECRET);
    second.enable_receipts(true);
    second.use_wall_clock(true);
    second.set_receipt_sequence(3).expect("continue the log");
    session(&second, 2);
    let continued = second.receipts();
    assert_eq!(continued[0].sequence, 3);
    log.append_verified(&second.receipt_key(), &continued)
        .expect("a second session continues the log");
    assert_eq!(log.len().expect("len"), 4);
    log.verify_macs(&first.receipt_key()).expect("macs");
    let _ = std::fs::remove_dir_all(&dir);
}
