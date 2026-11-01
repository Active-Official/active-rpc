//! Hardening of the receipt ring (`ARRL` v2) against the failures a hostile
//! reviewer found: a wrapped ring that writes a log it cannot read, a truncated
//! prefix that verifies, an unauthenticated append, a queue-time seal that
//! records a refusal as an authorization, concurrent writers, silent eviction,
//! an unbounded log, and records the writer accepts but the reader rejects.
//!
//! Every test drives the shipped API: `ReceiptLog`, `Agent`, and the sealed
//! receipts a real kernel produces.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::receipts::{
    Decision, ReceiptLog, LOG_HEADER_LEN, MAX_LOG_BYTES, MAX_METHOD_BYTES, MAX_RECEIPTS,
};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, Receipt};

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

/// A provider whose single method name is chosen by the test, so a grant can sit
/// exactly at the receipt ceiling.
struct LongEcho {
    method: String,
}

impl Provider for LongEcho {
    fn name(&self) -> &'static str {
        "long"
    }

    fn methods(&self) -> Vec<String> {
        vec![self.method.clone()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::Text(call.method.clone())))
    }
}

fn sandbox(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "active-rpc-receipt-hard-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    dir
}

/// A kernel whose cap admits `count` calls, with receipts enabled.
fn session(count: usize) -> (Agent, Vec<Receipt>) {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("receipts", Budget::default())
        .expect("lane");
    for _ in 0..count {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("value");
    }
    let receipts = agent.receipts();
    (agent, receipts)
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

// ---------------------------------------------------------------------------
// F1: a wrapped ring must not write a log its own reader refuses
// ---------------------------------------------------------------------------

#[test]
fn a_gap_in_the_sequence_is_refused_and_writes_nothing() {
    let dir = sandbox("gap");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("first record");
    let before = std::fs::read(&path).expect("read");

    let error = log
        .append(&receipt(3, 20))
        .expect_err("a gap must be refused");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "a refused append must not touch the file"
    );

    // The refusal did not wedge the log: the next record still lands.
    log.append(&receipt(2, 20)).expect("the missing record");
    assert_eq!(log.records().expect("records").len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrapped_ring_exports_the_window_it_holds() {
    let dir = sandbox("wrapped");
    let path = dir.join("receipts.arrl");
    // A ring that has wrapped starts above 1; the window is exported as its own
    // log, and the start sequence records where it begins.
    let log = ReceiptLog::create_starting_at(&path, 1_000).expect("create");
    log.append(&receipt(1_000, 10)).expect("first");
    log.append(&receipt(1_001, 20)).expect("second");
    assert_eq!(log.start_sequence().expect("start"), 1_000);
    assert_eq!(log.records().expect("records").len(), 2);
    log.verify_chain().expect("chain");

    // Starting at 0 is not a sequence.
    let error = ReceiptLog::create_starting_at(dir.join("zero.arrl"), 0)
        .expect_err("sequence 0 is not a record");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The real kernel path: after the ring wraps, the retained window appends to a
/// log whose first sequence is the oldest retained receipt.
#[test]
fn a_kernel_ring_that_wrapped_exports_cleanly() {
    let dir = sandbox("kernel-wrapped");
    let path = dir.join("receipts.arrl");
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("wrapped", Budget::default())
        .expect("lane");
    for _ in 0..MAX_RECEIPTS + 2 {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("value");
    }
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), MAX_RECEIPTS);
    assert_eq!(agent.receipts_dropped(), 2);
    assert_eq!(
        receipts[0].sequence, 3,
        "the retained window starts after the two evictions"
    );

    let log = ReceiptLog::create_starting_at(&path, receipts[0].sequence).expect("create");
    log.append_verified(&SECRET, &receipts)
        .expect("a wrapped ring exports its own window");
    assert_eq!(log.records().expect("records"), receipts);
    log.verify_macs(&SECRET).expect("macs");
    assert_eq!(log.start_sequence().expect("start"), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// F5: concurrent writers
// ---------------------------------------------------------------------------

#[test]
fn concurrent_writers_cannot_double_append() {
    let dir = sandbox("race");
    let path = dir.join("receipts.arrl");
    let log = std::sync::Arc::new(ReceiptLog::create(&path).expect("create"));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let log = std::sync::Arc::clone(&log);
        handles.push(std::thread::spawn(move || {
            log.append(&receipt(1, 10)).is_ok()
        }));
    }
    let accepted = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread"))
        .filter(|ok| *ok)
        .count();
    assert_eq!(accepted, 1, "exactly one writer wins sequence 1");
    assert_eq!(log.records().expect("records").len(), 1);
    log.verify_chain().expect("chain");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_out_of_order_batch_writes_nothing() {
    let dir = sandbox("batch");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 10)).expect("first");
    let before = std::fs::read(&path).expect("read");
    let error = log
        .append_all(&[receipt(2, 20), receipt(4, 30)])
        .expect_err("the batch skips a sequence");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        before,
        "a refused batch must not write its valid prefix"
    );
    log.append_all(&[receipt(2, 20), receipt(3, 30)])
        .expect("the batch that fits");
    assert_eq!(log.records().expect("records").len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// F2: a truncated prefix must not verify against a pinned head
// ---------------------------------------------------------------------------

#[test]
fn a_truncated_prefix_is_refused_against_the_pinned_head() {
    let dir = sandbox("prefix");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session(3);
    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&SECRET, &receipts).expect("append");
    let head = log.head_hash().expect("head");
    log.verify_against(head).expect("the whole log");

    // Keep the header and the first record: the chain is intact, so chain-only
    // verification still passes and only the pinned head catches the loss.
    let bytes = std::fs::read(&path).expect("read");
    let length = u32::from_le_bytes(
        bytes[LOG_HEADER_LEN..LOG_HEADER_LEN + 4]
            .try_into()
            .unwrap(),
    );
    std::fs::write(&path, &bytes[..LOG_HEADER_LEN + 4 + length as usize]).expect("truncate tail");
    log.verify_chain().expect("a prefix still chains");
    let error = log
        .verify_against(head)
        .expect_err("a truncated prefix must not match the pinned head");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// F3: an unauthenticated append / a forged record
// ---------------------------------------------------------------------------

#[test]
fn append_verified_refuses_a_forged_receipt() {
    let dir = sandbox("forged");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session(1);
    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&SECRET, &receipts)
        .expect("the real one");
    let before = std::fs::read(&path).expect("read");

    let mut forged = receipt(2, receipts[0].at_ms + 1);
    forged.mac = [0x11; 32];
    let error = log
        .append_verified(&SECRET, &[forged.clone()])
        .expect_err("a receipt this kernel did not produce");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(std::fs::read(&path).expect("read"), before);

    // The plain append is the writer's choice; the log still refuses a record
    // whose MAC is wrong when asked to authenticate it.
    log.append(&forged).expect("append without authentication");
    let error = log
        .verify_macs(&SECRET)
        .expect_err("the forged record is named");
    assert_eq!(error.code(), "rpc/receipt");
    assert!(
        format!("{error}").contains("receipt 2"),
        "the error names the offending sequence: {error}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// F4: the decision sealed is the one taken at dispatch
// ---------------------------------------------------------------------------

#[test]
fn a_dispatch_refusal_is_recorded_as_a_refusal() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent
        .create_lane("refusals", Budget::default())
        .expect("lane");

    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("admitted");

    // Queue the call while the capability is live, then revoke before the
    // kernel runs it: the queue accepts it and dispatch refuses it. This is the
    // window that used to seal an "admitted" receipt.
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.revoke(&cap).expect("revoke");
    agent.run();
    let error = promise
        .value()
        .expect_err("a revoked cap refuses at dispatch");
    assert_eq!(error.code(), "rpc/revoked");

    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 2, "the refusal is a decision");
    assert_eq!(receipts[0].decision, Decision::Admitted);
    assert_eq!(
        receipts[1].decision,
        Decision::Refused("rpc/revoked".to_string()),
        "a queued call that dispatch refused must not look authorized"
    );
    for receipt in &receipts {
        assert!(agent.verify_receipt(receipt));
    }
}

// ---------------------------------------------------------------------------
// F6: eviction and disable leave a marker
// ---------------------------------------------------------------------------

#[test]
fn evictions_are_counted_and_reported_once() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent.create_lane("evict", Budget::default()).expect("lane");
    for _ in 0..MAX_RECEIPTS + 3 {
        let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
        agent.run();
        promise.value().expect("value");
    }
    assert_eq!(agent.receipts().len(), MAX_RECEIPTS);
    assert_eq!(agent.receipts_dropped(), 3);
    assert_eq!(agent.receipts()[0].sequence, 4);
    let dropped = agent
        .events()
        .iter()
        .filter(|event| matches!(event, active_rpc::Event::ReceiptsDropped { .. }))
        .count();
    assert_eq!(dropped, 1, "one marker, not one per evicted receipt");
}

#[test]
fn disabling_receipts_counts_what_it_clears() {
    let (agent, receipts) = session(2);
    assert_eq!(receipts.len(), 2);
    agent.enable_receipts(false);
    assert!(agent.receipts().is_empty());
    assert_eq!(agent.receipts_dropped(), 2);
    let marker = agent
        .events()
        .into_iter()
        .find_map(|event| match event {
            active_rpc::Event::ReceiptsDropped { count } => Some(count),
            _ => None,
        })
        .expect("a marker for the cleared window");
    assert_eq!(marker, 2);
}

// ---------------------------------------------------------------------------
// F7: the log is bounded, and a large file is refused without reading it
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_log_is_refused_promptly() {
    let dir = sandbox("oversized");
    let path = dir.join("huge.arrl");
    let file = std::fs::File::create(&path).expect("create");
    file.set_len(MAX_LOG_BYTES + 1).expect("sparse file");
    drop(file);
    let started = std::time::Instant::now();
    let error = ReceiptLog::open(&path).expect_err("an oversized log is refused");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), "rpc/receipt");
    // A refusal that read the whole file would take far longer; the ceiling is
    // applied to the read itself.
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "an oversized log was read before it was refused: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// F8/F9/F13: the writer applies the reader's rules
// ---------------------------------------------------------------------------

#[test]
fn a_granted_method_the_log_cannot_hold_is_refused_at_mint() {
    let agent = Agent::with_secret(SECRET);
    let provider = agent.register(Box::new(Echo));
    let long = "m".repeat(MAX_METHOD_BYTES + 1);
    let error = agent
        .mint(provider, 0, CapAttrs::new(&[long.as_str()]))
        .expect_err("a method over the receipt ceiling");
    assert_eq!(error.code(), "rpc/invalid-argument");
    let error = agent
        .mint(provider, 0, CapAttrs::new(&["e\ncho"]))
        .expect_err("a control character in a method");
    assert_eq!(error.code(), "rpc/invalid-argument");
    // The bound itself is allowed.
    agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["m".repeat(MAX_METHOD_BYTES).as_str()]),
        )
        .expect("a method exactly at the ceiling");
}

#[test]
fn a_receipt_the_reader_would_reject_is_refused_at_append() {
    let dir = sandbox("writer-rules");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    let before = std::fs::read(&path).expect("read");

    let mut bad = receipt(1, 10);
    bad.method = "a\nb".to_string();
    assert_eq!(
        log.append(&bad).expect_err("a control character").code(),
        "rpc/receipt"
    );

    bad.method = "echo".to_string();
    bad.cap = "0123456789ABCDEF".to_string();
    assert_eq!(
        log.append(&bad).expect_err("uppercase id").code(),
        "rpc/receipt"
    );

    bad.cap = "0123456789abcdef".to_string();
    bad.decision = Decision::Refused("rpc/revoked\n".to_string());
    assert_eq!(
        log.append(&bad).expect_err("a code with a newline").code(),
        "rpc/receipt"
    );

    bad.decision = Decision::Refused("rpc/".to_string() + &"x".repeat(64));
    assert_eq!(
        log.append(&bad)
            .expect_err("a code over its ceiling")
            .code(),
        "rpc/receipt"
    );

    assert_eq!(std::fs::read(&path).expect("read"), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn time_that_runs_backwards_is_refused_on_both_sides() {
    let dir = sandbox("time");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, 100)).expect("first");
    let before = std::fs::read(&path).expect("read");
    let error = log
        .append(&receipt(2, 50))
        .expect_err("a record older than the previous one");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(std::fs::read(&path).expect("read"), before);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_refuses_to_overwrite_evidence() {
    let dir = sandbox("overwrite");
    let path = dir.join("receipts.arrl");
    let (_, receipts) = session(2);
    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&SECRET, &receipts).expect("append");
    let error = ReceiptLog::create(&path).expect_err("records already exist");
    assert_eq!(error.code(), "rpc/receipt");
    assert_eq!(log.records().expect("records").len(), 2, "nothing was lost");

    // Starting over is explicit, and says so.
    let fresh = ReceiptLog::truncate(&path).expect("explicit truncation");
    assert!(fresh.records().expect("records").is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_log_from_a_future_version_is_refused() {
    let dir = sandbox("version");
    let path = dir.join("future.arrl");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ARRL");
    bytes.push(3);
    bytes.extend_from_slice(&[0u8; 3]);
    bytes.extend_from_slice(&1u64.to_le_bytes());
    std::fs::write(&path, &bytes).expect("write");
    let error = ReceiptLog::verify_bytes(&bytes).expect_err("an unknown version");
    assert_eq!(error.code(), "rpc/receipt");
    let error = ReceiptLog::open(&path).expect_err("an unknown version");
    assert_eq!(error.code(), "rpc/receipt");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A refusal receipt survives a round trip through the log, code and all.
#[test]
fn a_refusal_round_trips_through_the_log() {
    let dir = sandbox("refusal-round-trip");
    let path = dir.join("receipts.arrl");
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent.create_lane("codes", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.revoke(&cap).expect("revoke");
    agent.run();
    promise.value().expect_err("refused at dispatch");
    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1);

    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&SECRET, &receipts).expect("append");
    let read = log.records().expect("records");
    assert_eq!(read, receipts);
    assert_eq!(
        read[0].decision,
        Decision::Refused("rpc/revoked".to_string())
    );
    log.verify_macs(&SECRET).expect("macs");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A grant at the receipt ceiling is recorded exactly: the method is not
/// truncated, so the log names what was authorized.
#[test]
fn a_long_granted_method_is_recorded_exactly() {
    let dir = sandbox("long-method");
    let path = dir.join("receipts.arrl");
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let method = "n".repeat(MAX_METHOD_BYTES);
    let provider = agent.register(Box::new(LongEcho {
        method: method.clone(),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&[method.as_str()]))
        .expect("a method exactly at the ceiling");
    let lane = agent
        .create_lane("labels", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, &method, Vec::new()).expect("queued");
    agent.run();
    promise.value().expect("admitted");

    let receipts = agent.receipts();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].method, method, "no truncation, no label");
    let log = ReceiptLog::create(&path).expect("create");
    log.append_verified(&SECRET, &receipts).expect("append");
    assert_eq!(log.records().expect("records"), receipts);
    log.verify_macs(&SECRET).expect("macs");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A call with a method the capability never granted is refused at the queue,
/// so no receipt exists for a name the log could not hold.
#[test]
fn an_ungranted_method_leaves_no_receipt() {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo));
    let lane = agent
        .create_lane("ungranted", Budget::default())
        .expect("lane");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let error = agent
        .call(lane, &cap, "e\ncho", Vec::new())
        .expect_err("not granted");
    assert_eq!(error.code(), "rpc/method-not-granted");
    assert!(agent.receipts().is_empty());
}

// ---------------------------------------------------------------------------
// F7: appends stay linear
// ---------------------------------------------------------------------------

/// The cached state makes a long append sequence linear: N appends do not
/// re-read and re-walk the file each time.
#[test]
fn many_appends_stay_linear() {
    let dir = sandbox("linear");
    let path = dir.join("receipts.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    const COUNT: u64 = 2_000;
    let started = std::time::Instant::now();
    for sequence in 1..=COUNT {
        log.append(&receipt(sequence, sequence)).expect("append");
    }
    let elapsed = started.elapsed();
    assert_eq!(log.len().expect("len"), COUNT);
    // A quadratic append (re-walking the whole file each time) is orders of
    // magnitude slower than this; the bound is loose enough for a loaded CI box.
    assert!(
        elapsed < std::time::Duration::from_secs(20),
        "{COUNT} appends took {elapsed:?}, which suggests a re-read per append"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
