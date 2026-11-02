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
    let provider = agent.register(Box::new(Echo));
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

/// 6: a lock that cannot be identified is never stolen, and the wait is bounded.
#[test]
fn an_unidentifiable_lock_is_refused_within_a_bounded_time() {
    let path = scratch("lock");
    let log = ReceiptLog::create(&path).expect("create");
    drop(log);
    // An empty lock file: it has no nonce, so it cannot be judged stale safely.
    let lock = path.with_file_name(format!(
        "{}.lock",
        path.file_name().expect("name").to_string_lossy()
    ));
    std::fs::write(&lock, b"").expect("lock");
    // Age it past the stale ceiling.
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
    filetime_set(&lock, old);

    let log = ReceiptLog::open(&path).expect("open");
    let started = std::time::Instant::now();
    let error = log
        .append(&receipt(1, "echo"))
        .expect_err("a lock without a nonce cannot be stolen");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), "rpc/receipt");
    assert!(
        elapsed < std::time::Duration::from_secs(6),
        "the wait was {elapsed:?}, not the documented few seconds"
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&lock);
}

/// 5: a reader that lands mid-append waits for the writer instead of calling the
/// log damaged.
#[test]
fn a_reader_does_not_call_an_in_progress_append_damage() {
    let path = scratch("live");
    // The file exists before either thread touches it, so `open` cannot race the
    // writer's `create`.
    let writer_path = path.clone();
    drop(ReceiptLog::create(&path).expect("create"));
    let writer = std::thread::spawn(move || {
        let log = ReceiptLog::open(&writer_path).expect("open for writing");
        for sequence in 1..=2_000u64 {
            log.append(&receipt(sequence, "echo")).expect("append");
        }
    });
    let reader = ReceiptLog::open(&path).expect("open");
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
    let provider = agent.register(Box::new(Echo));
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

    // Forward is fine, and the gap is counted.
    let before = agent.receipts_dropped();
    agent.set_receipt_sequence(10).expect("forward");
    assert_eq!(agent.receipts_dropped(), before + 6);
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
