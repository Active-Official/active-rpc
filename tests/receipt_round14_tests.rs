//! R-13 round 14: the append fast path and the file identity it needs, the lock
//! magic that protects a sibling log, and the refusal code a receipt keeps.

use std::path::PathBuf;

use active_rpc::kernel::Provider;
use active_rpc::receipts::LOG_HEADER_LEN;
use active_rpc::receipts::{Decision, ReceiptLog};
use active_rpc::value::{Call, Response};
use active_rpc::Receipt;
use active_rpc::{Agent, Budget, CapAttrs, Error};

fn scratch(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "active-rpc-receipt-r14-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    path
}

fn receipt(sequence: u64) -> Receipt {
    Receipt {
        sequence,
        cap: "0011223344556677".to_string(),
        method: "echo".to_string(),
        at_ms: sequence,
        decision: Decision::Admitted,
        mac: [sequence as u8; 32],
    }
}

fn filetime_set(path: &std::path::Path, when: std::time::SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for times");
    file.set_times(std::fs::FileTimes::new().set_modified(when))
        .expect("times");
}

/// The fast path trusts length + header + trailing head; a same-length copy with
/// one interior byte changed keeps all three, and only the inode tells it apart
/// (R-13 round 14, F1). Off unix there is no identity, which ADR-0021 records.
#[cfg(unix)]
#[test]
fn an_interior_edit_behind_a_same_length_copy_is_not_trusted() {
    let path = scratch("interior");
    let log = ReceiptLog::create(&path).expect("create");
    for sequence in 1..=3 {
        log.append(&receipt(sequence)).expect("append");
    }
    let bytes = std::fs::read(&path).expect("read the log");
    let mut edited = bytes.clone();
    // Inside the first record, past its length field: its hash no longer
    // matches, so the chain is broken while every cached check still holds.
    edited[LOG_HEADER_LEN + 20] ^= 0xff;
    let staged = scratch("interior-staged");
    std::fs::write(&staged, &edited).expect("write the copy");
    std::fs::rename(&staged, &path).expect("replace the log");
    let outcome = log.append(&receipt(4));
    assert!(
        outcome.is_err(),
        "the fast path appended to a log it never walked"
    );
    let _ = std::fs::remove_file(&path);
}

/// A file at `<log>.lock` that this build did not write is not a lock: it is
/// left alone rather than judged, stolen and deleted (R-13 round 14, F4).
#[test]
fn a_foreign_file_at_the_lock_path_is_not_stolen() {
    let path = scratch("lock-sibling");
    let lock = path.with_file_name(format!(
        "{}.lock",
        path.file_name().expect("name").to_string_lossy()
    ));
    std::fs::write(&lock, b"ARRL a sibling log, not a lock").expect("plant");
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
    filetime_set(&lock, old);
    // The acquire refuses to judge it, so the log cannot be created while the
    // file is there (fail-closed), and the file survives unchanged.
    let outcome = ReceiptLog::create(&path);
    assert!(outcome.is_err(), "an unjudgeable lock was accepted");
    assert_eq!(
        std::fs::read(&lock).expect("the sibling survived"),
        b"ARRL a sibling log, not a lock"
    );
    let _ = std::fs::remove_file(&lock);
}

struct Trap;

impl Provider for Trap {
    fn name(&self) -> &'static str {
        "trap"
    }
    fn methods(&self) -> Vec<String> {
        vec!["trap".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        true
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Err(Error::Provider {
            code: "wasm/trap".to_string(),
        })
    }
}

/// A receipt is a local audit record: it keeps the provider's own code when the
/// format can carry it, so a trap in the log is attributable
/// (R-13 round 14, F5).
#[test]
fn a_receipt_records_the_providers_own_code() {
    let agent = Agent::new();
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Trap));
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["trap"]).with_budget(Budget::default()),
        )
        .expect("cap");
    let lane = agent.create_lane("trap", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "trap", Vec::new()).expect("queued");
    let _ = promise.value();
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1, "{receipts:?}");
    assert_eq!(
        receipts[0].decision,
        Decision::Refused("wasm/trap".to_string()),
        "the receipt collapsed the provider code"
    );
}

/// R-13 round 15, F1: an in-place edit keeps the inode, the length, the header
/// and the trailing head. The modification time does not, so the append
/// re-walks and refuses the broken chain.
#[test]
fn an_interior_edit_through_the_same_path_is_not_trusted() {
    let path = scratch("inplace");
    let log = ReceiptLog::create(&path).expect("create");
    for sequence in 1..=3 {
        log.append(&receipt(sequence)).expect("append");
    }
    let mut bytes = std::fs::read(&path).expect("read");
    bytes[LOG_HEADER_LEN + 20] ^= 0xff;
    std::fs::write(&path, &bytes).expect("rewrite in place");
    assert!(
        log.append(&receipt(4)).is_err(),
        "the fast path trusted an in-place edit"
    );
    let _ = std::fs::remove_file(&path);
}
