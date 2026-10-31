//! Durable receipt log (`ARRL`).
//!
//! The kernel's receipts are an in-memory ring. This file drives the real
//! kernel, exports its receipts to a log, and checks that the log detects every
//! edit without needing the secret — and that verification of the receipts
//! themselves needs the secret that produced them.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, Receipt, ReceiptLog};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "mutate".to_string()]
    }

    fn mutating(&self, method: &str) -> bool {
        method == "mutate"
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::Text(call.method.clone())))
    }
}

const SECRET: [u8; 32] = [0x6d; 32];

/// A kernel with receipts enabled and three admitted calls (plus one refusal,
/// which is not a receipt).
fn session() -> (Agent, Vec<Receipt>) {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo));
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
    // A refused call is not an admitted decision and must not produce a
    // receipt.
    let _ = agent.call(lane, &cap, "mutate", Vec::new());
    let receipts = agent.receipts();
    (agent, receipts)
}

fn sandbox(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "active-rpc-receipt-log-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    dir
}

#[test]
fn an_exported_log_round_trips_and_verifies() {
    let dir = sandbox("round-trip");
    let path = dir.join("receipts.arrl");
    let (agent, receipts) = session();
    assert_eq!(receipts.len(), 3, "three admitted calls, one refusal");
    assert!(receipts.iter().all(|receipt| agent.verify_receipt(receipt)));

    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");
    let read = log.records().expect("records");
    assert_eq!(read, receipts);
    log.verify_chain().expect("chain");
    log.verify_macs(&SECRET).expect("macs");
    assert_ne!(log.head_hash().expect("head"), [0u8; 32]);

    // Appending after a read continues the chain.
    let extra = Receipt {
        sequence: 4,
        cap: receipts[0].cap.clone(),
        method: "echo".to_string(),
        at_ms: 1,
        mac: receipts[0].mac,
    };
    log.append(&extra).expect("append one");
    assert_eq!(log.records().expect("records").len(), 4);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_empty_log_verifies() {
    let dir = sandbox("empty");
    let log = ReceiptLog::create(dir.join("empty.arrl")).expect("create");
    assert!(log.records().expect("records").is_empty());
    log.verify_chain().expect("chain");
    log.verify_macs(&SECRET).expect("macs");
    assert_eq!(log.head_hash().expect("head"), [0u8; 32]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_tampered_record_is_refused() {
    let dir = sandbox("tamper");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session();
    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");

    let mut bytes = std::fs::read(&path).expect("read");
    // Flip a byte inside the first record's method field.
    let middle = bytes.len() / 3;
    bytes[middle] ^= 0x01;
    std::fs::write(&path, &bytes).expect("write");
    let error = log
        .records()
        .expect_err("a tampered record must be refused");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_truncated_log_is_refused() {
    let dir = sandbox("truncate");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session();
    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");

    let bytes = std::fs::read(&path).expect("read");
    std::fs::write(&path, &bytes[..bytes.len() - 8]).expect("truncate");
    let error = log.records().expect_err("a partial record must be refused");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_reordered_log_is_refused() {
    let dir = sandbox("reorder");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session();
    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");

    // Split at record boundaries and swap the first two records.
    let bytes = std::fs::read(&path).expect("read");
    let mut cursor = 8usize;
    let mut boundaries = Vec::new();
    while cursor < bytes.len() {
        let length =
            u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().expect("4 bytes")) as usize;
        boundaries.push((cursor, cursor + 4 + length));
        cursor += 4 + length;
    }
    assert_eq!(boundaries.len(), 3);
    let mut reordered = bytes[..8].to_vec();
    reordered.extend_from_slice(&bytes[boundaries[1].0..boundaries[1].1]);
    reordered.extend_from_slice(&bytes[boundaries[0].0..boundaries[0].1]);
    reordered.extend_from_slice(&bytes[boundaries[2].0..boundaries[2].1]);
    std::fs::write(&path, &reordered).expect("write");
    let error = log.records().expect_err("a reordered log must be refused");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_foreign_secret_does_not_verify_the_macs() {
    let dir = sandbox("foreign");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session();
    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");
    // The chain is unkeyed: it verifies without the secret.
    log.verify_chain().expect("chain");
    // The receipts themselves are keyed.
    let error = log
        .verify_macs(&[0x6e; 32])
        .expect_err("another kernel's secret must not verify");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_invalid_receipt_is_refused_at_append() {
    let dir = sandbox("invalid");
    let log = ReceiptLog::create(dir.join("receipts.arrl")).expect("create");
    let mut receipt = Receipt {
        sequence: 1,
        cap: "not-hex".to_string(),
        method: "echo".to_string(),
        at_ms: 0,
        mac: [0u8; 32],
    };
    let error = log.append(&receipt).expect_err("bad correlation id");
    assert_eq!(error.code(), "rpc/receipt");

    receipt.cap = "0123456789abcdef".to_string();
    receipt.method.clear();
    let error = log.append(&receipt).expect_err("empty method");
    assert_eq!(error.code(), "rpc/receipt");

    receipt.method = "m".repeat(2_000);
    let error = log.append(&receipt).expect_err("method over the ceiling");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A log line must never contain argument bytes or a secret: the reader gets
/// correlation ids, methods and times only.
#[test]
fn the_log_carries_no_argument_or_secret_material() {
    let dir = sandbox("no-secrets");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session();
    let log = ReceiptLog::create(&path).expect("create");
    log.append_all(&receipts).expect("append");
    let bytes = std::fs::read(&path).expect("read");
    let text = String::from_utf8_lossy(&bytes);
    for forbidden in ["CANARY", "***SECRET***", "payload"] {
        assert!(!text.contains(forbidden), "log leaked {forbidden}");
    }
    // The fields that are present are exactly the allowed ones.
    for receipt in log.records().expect("records") {
        assert_eq!(receipt.cap.len(), 16);
        assert!(receipt.method == "echo" || receipt.method == "mutate");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
