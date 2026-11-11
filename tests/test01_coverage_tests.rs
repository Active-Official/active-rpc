//! TEST-01: coverage of the receipt-log accessors and repair paths.
//!
//! The coverage measurement at HEAD `ba88305` showed `receipts.rs` at
//! 90.01% lines but only 76.65% functions: the snapshot/log accessors
//! (`Snapshot::is_empty`, `ReceiptLog::path`, `ReceiptLog::is_empty`),
//! `decision_label`, `repair_tail` (and through it `read_capped`) had no
//! test calling them at all, even though the log itself is heavily tested.
//! These tests pin those accessors' contracts directly.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::receipts::{decision_label, Decision};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, Receipt, ReceiptLog};

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
        Ok(Response::Value(Value::Text("ok".to_string())))
    }
}

const SECRET: [u8; 32] = [0x6d; 32];

/// A kernel with receipts enabled and three admitted calls.
fn session() -> (Agent, Vec<Receipt>) {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("receipts", Budget::default())
        .expect("lane");
    for _ in 0..3 {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("value");
    }
    let receipts = agent.receipts();
    (agent, receipts)
}

/// A sandbox that always removes itself, even when a test panics: the
/// `sandbox()` helpers elsewhere in this suite remove the directory only on
/// the success path, and a failed run used to leave the `Temp` pile behind.
struct Sandbox(std::path::PathBuf);

impl Sandbox {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("active-rpc-test01-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("sandbox");
        Sandbox(dir)
    }

    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn snapshot_accessors_describe_an_empty_and_a_full_log() {
    let dir = Sandbox::new("snapshot");
    let path = dir.path("receipts.arrl");
    let (_, receipts) = session();
    assert_eq!(receipts.len(), 3);

    let log = ReceiptLog::create(&path).expect("create");
    let empty = log.snapshot().expect("snapshot");
    assert!(empty.is_empty(), "a fresh log snapshots empty");
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.receipts().len(), 0);
    assert_eq!(empty.start_sequence(), 1);
    assert_eq!(empty.head(), [0u8; 32], "an empty log has a zero head");
    assert_eq!(empty.last_ms(), 0);

    log.append_all(&receipts).expect("append");
    let full = log.snapshot().expect("snapshot");
    assert!(!full.is_empty(), "three records are not empty");
    assert_eq!(full.len(), 3);
    assert_eq!(full.receipts(), receipts.as_slice());
    assert_eq!(full.start_sequence(), 1);
    assert_eq!(
        full.head(),
        log.head_hash().expect("head"),
        "the snapshot head is the log head"
    );
    assert_eq!(full.last_ms(), receipts[2].at_ms);
}

#[test]
fn path_returns_the_create_path() {
    let dir = Sandbox::new("path");
    let path = dir.path("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    assert_eq!(log.path(), path.as_path());
}

#[test]
fn is_empty_tracks_appends() {
    let dir = Sandbox::new("is-empty");
    let path = dir.path("receipts.arrl");
    let (_, receipts) = session();
    let log = ReceiptLog::create(&path).expect("create");
    assert!(log.is_empty().expect("is_empty"), "a fresh log is empty");
    assert_eq!(log.len().expect("len"), 0);
    log.append(&receipts[0]).expect("append");
    assert!(
        !log.is_empty().expect("is_empty"),
        "one record is not empty"
    );
    assert_eq!(log.len().expect("len"), 1);
}

#[test]
fn decision_label_names_both_decisions() {
    assert_eq!(decision_label(&Decision::Admitted), "admitted");
    assert_eq!(
        decision_label(&Decision::Refused("rpc/unknown-capability".to_string())),
        "refused"
    );
}

#[test]
fn repair_tail_keeps_a_healthy_log_and_cuts_a_torn_tail() {
    let dir = Sandbox::new("repair-tail");
    let path = dir.path("receipts.arrl");
    let (_, receipts) = session();
    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");

    assert_eq!(
        log.repair_tail().expect("repair a healthy log"),
        0,
        "a healthy log loses nothing"
    );
    assert_eq!(log.records().expect("records").len(), 3);

    // Tear the last record: drop its final 8 bytes (inside the stored hash).
    let bytes = std::fs::read(&path).expect("read");
    std::fs::write(&path, &bytes[..bytes.len() - 8]).expect("tear");
    assert!(
        log.records().is_err(),
        "the torn tail must be refused before repair"
    );
    let discarded = log.repair_tail().expect("repair the torn tail");
    assert!(
        discarded > 0,
        "repair must report the torn bytes, got {discarded}"
    );
    let kept = log.records().expect("records after repair");
    assert_eq!(kept.len(), 2, "only the two whole records survive");
    assert_eq!(kept, receipts[..2]);
    log.verify_chain().expect("the repaired log still verifies");

    // The repaired log accepts appends again: the chain continues.
    log.append(&receipts[2]).expect("append after repair");
    assert_eq!(log.records().expect("records").len(), 3);
}
