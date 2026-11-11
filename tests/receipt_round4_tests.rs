//! R-13 round 4 (confirmation): the lock, the cached head, the decision a
//! receipt records, and a reader that must not call a live writer damage.
//!
//! The log is the real file-backed `ReceiptLog`; the writer and the reader are
//! real threads.

use std::path::PathBuf;

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::receipts::{Decision, Receipt, ReceiptLog};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget};

fn scratch(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "active-rpc-receipt-r4-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
    path
}

fn receipt(sequence: u64, method: &str) -> Receipt {
    Receipt {
        sequence,
        cap: "0123456789abcdef".to_string(),
        method: method.to_string(),
        at_ms: sequence,
        decision: Decision::Admitted,
        mac: [0u8; 32],
        caller: None,
    }
}

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
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        // A response past the grant's byte ceiling: the refusal is decided in
        // egress, after dispatch admitted the call.
        Ok(Response::Value(Value::list((0..64).map(Value::Int))))
    }
}

/// 3: a refusal decided after dispatch is receipted as a refusal.
#[test]
fn an_egress_refusal_is_receipted_as_an_egress_refusal() {
    let agent = Agent::with_secret([0x52; 32]);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget.max_bytes = 256;
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent.create_lane("r4", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.run();
    let error = promise.value().expect_err("the response is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded");

    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1, "one receipt per job");
    match &receipts[0].decision {
        Decision::Refused(code) => assert_eq!(code, "rpc/budget-exceeded"),
        other => panic!("an egress refusal was receipted as {other:?}"),
    }
    // The metric and the audit artifact agree.
    assert_eq!(agent.metrics().budget_exhaustions, 1);
}

/// 2: a same-size, same-start replacement is not trusted.
#[test]
fn a_replacement_at_the_same_size_and_start_is_not_trusted() {
    let path = scratch("replace");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, "echo")).expect("append");
    log.append(&receipt(2, "echo")).expect("append");
    let original_len = std::fs::metadata(&path).expect("stat").len();

    // A second handle to the same log: this one caches the head it will drive
    // the next append from.
    let live = ReceiptLog::open(&path).expect("open");

    // Replace the file with two records of exactly the same byte length but a
    // different second record: the size and the start match, so only the
    // trailing head tells the two files apart.
    let mut replacement_two = receipt(2, "echo");
    replacement_two.at_ms = 2_000;
    ReceiptLog::truncate(&path).expect("start over");
    let replaced = ReceiptLog::open(&path).expect("open the fresh log");
    replaced
        .append(&receipt(1, "echo"))
        .expect("first replacement");
    replaced
        .append(&replacement_two)
        .expect("second replacement");
    drop(replaced);
    assert_eq!(
        std::fs::metadata(&path).expect("stat").len(),
        original_len,
        "the replacement has the original shape"
    );

    // The live handle must not link to its stale head. Either it refuses, or it
    // re-reads and produces a log that walks: what must never happen is a write
    // that leaves a file nothing can read.
    let _ = live.append(&receipt(3, "echo"));
    let records = ReceiptLog::verify_bytes(&std::fs::read(&path).expect("read"))
        .expect("the log must still walk");
    assert!(!records.is_empty());
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
}

/// 6: a lock left with no nonce (a creator that died between `create_new` and
/// its write) is stolen rather than wedging the log for ever, and a lock path
/// that is not a regular file is refused instead of blocking (R-13 rounds 4-9).
#[test]
fn an_empty_lock_is_stolen_and_a_non_regular_lock_is_refused() {
    let path = scratch("lock");
    drop(ReceiptLog::create(&path).expect("create"));
    let lock = path.with_file_name(format!(
        "{}.lock",
        path.file_name().expect("name").to_string_lossy()
    ));
    // An empty lock, aged past the ceiling: the creator never wrote its nonce,
    // so no live writer can hold it.
    std::fs::write(&lock, b"").expect("lock");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
    filetime_set(&lock, old);

    let log = ReceiptLog::open(&path).expect("open");
    log.append(&receipt(1, "echo"))
        .expect("an unidentifiable lock is stolen, not a wedge");
    assert_eq!(
        ReceiptLog::verify_bytes(&std::fs::read(&path).expect("read"))
            .expect("walk")
            .len(),
        1
    );

    // A directory at the lock path is not a lock: the append is refused within
    // the documented budget instead of hanging on an open (R-13 round 9, F5).
    let _ = std::fs::remove_file(&lock);
    std::fs::create_dir_all(&lock).expect("directory at the lock path");
    let log = ReceiptLog::open(&path).expect("open");
    let started = std::time::Instant::now();
    let error = log
        .append(&receipt(2, "echo"))
        .expect_err("a directory is not a lock");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), "rpc/receipt");
    // The documented budget is 1.38 s; this test runs inside the parallel suite,
    // so it checks the order of magnitude (3 s catches a doubling) rather than
    // the exact figure.
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "the wait was {elapsed:?}, not the documented wait"
    );
    let _ = std::fs::remove_dir_all(&lock);
    let _ = std::fs::remove_file(&path);
}

/// 5: a reader that lands mid-append waits for the writer instead of calling the
/// log damaged.
#[test]
fn a_reader_does_not_call_an_in_progress_append_damage() {
    let path = scratch("live");
    // The file exists before either thread touches it, so `open` cannot race the
    // writer's `create`. The reader opens first: `open` refuses while a live
    // writer holds the lock, and the test's subject is a reader that polls
    // *during* an append, not the open race.
    let writer_path = path.clone();
    drop(ReceiptLog::create(&path).expect("create"));
    let reader = ReceiptLog::open(&path).expect("open");
    let writer = std::thread::spawn(move || {
        let log = ReceiptLog::open(&writer_path).expect("open for writing");
        for sequence in 1..=2_000u64 {
            log.append(&receipt(sequence, "echo")).expect("append");
        }
    });
    let mut failures = Vec::new();
    for _ in 0..40 {
        if let Err(error) = reader.records() {
            failures.push(error.to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    writer.join().expect("writer");
    // Every failure must name a live writer, never a damaged log.
    for failure in &failures {
        assert!(
            failure.contains("being written") || failure.contains("cannot read"),
            "a reader called an in-progress append damage: {failure}"
        );
    }
    let records = reader.records().expect("the finished log reads");
    assert_eq!(records.len(), 2_000);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
}

/// 4: the sequence setter cannot rewind, and cannot name a start no log can hold.
#[test]
fn the_sequence_setter_refuses_a_rewind_and_an_impossible_start() {
    let agent = Agent::with_secret([0x53; 32]);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent.create_lane("seq", Budget::default()).expect("lane");
    for _ in 0..3 {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
        agent.run();
        let _ = promise.value();
    }
    assert_eq!(agent.receipts().len(), 3);

    let error = agent
        .set_receipt_sequence(1)
        .expect_err("a rewind reuses a sequence");
    assert_eq!(error.code(), "rpc/invalid-argument");
    let error = agent
        .set_receipt_sequence(u64::MAX - 5)
        .expect_err("no log can hold that start");
    assert_eq!(error.code(), "rpc/invalid-argument");

    // Forward is fine, and the hole is counted: the six sequences that were
    // never issued plus the three sealed receipts the ring has to drop, because
    // a window cannot hold a gap and `append` would refuse it (R-13 round 5, #2).
    let before = agent.receipts_dropped();
    agent.set_receipt_sequence(10).expect("forward");
    assert_eq!(agent.receipts_dropped(), before + 9);
    assert!(
        agent.receipts().is_empty(),
        "the pre-gap window is not exportable and must not be offered"
    );
    // The next receipt continues at the adopted sequence, so the whole window is
    // a contiguous log from 10 onwards.
    let promise = agent
        .call(lane, &cap, "echo", Vec::new())
        .expect("queued after the adoption");
    agent.run();
    let _ = promise.value();
    let receipts = agent.receipts();
    assert_eq!(receipts.first().map(|receipt| receipt.sequence), Some(10));
    assert_eq!(receipts.len(), 1);
}

/// Set a file's modification time on every platform.
///
/// `FileTimes::set_modified` and `File::set_times` are stable in 1.75, so the
/// test stays inside the 1.88 floor; `FileTimesExt` (unix only) is a later
/// addition and must not be imported.
fn filetime_set(path: &std::path::Path, when: std::time::SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open");
    file.set_times(std::fs::FileTimes::new().set_modified(when))
        .expect("times");
}

/// R2-R13-01 (a), public API: a receipt dated beyond the 24 h skew bound is
/// refused at append, and the log still accepts a legitimate receipt after
/// the refusal.
#[test]
fn a_future_dated_receipt_is_refused_at_append() {
    let path = scratch("future-append-gate");
    let log = ReceiptLog::create(&path).expect("create");
    let at = |sequence: u64, at_ms: u64| Receipt {
        sequence,
        cap: "0123456789abcdef".to_string(),
        method: "echo".to_string(),
        at_ms,
        decision: Decision::Admitted,
        mac: [0u8; 32],
        caller: None,
    };
    log.append(&at(1, 100)).expect("append seq 1");
    let err = log
        .append(&at(2, u64::MAX))
        .expect_err("u64::MAX must be refused");
    assert!(
        err.to_string().contains("too far in the future"),
        "the refusal must name the skew bound: {err}"
    );
    assert_eq!(log.records().expect("records").len(), 1);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .expect("wall clock");
    log.append(&at(2, now_ms)).expect("append seq 2");
    assert_eq!(log.records().expect("records").len(), 2);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(path.with_extension("lock"));
}
