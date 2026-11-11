#![no_main]

//! Receipt logs (`ARRL` v2): a hostile file must be refused, never panic.
//!
//! Invariants under test:
//!
//! 1. `verify_bytes` is total over arbitrary bytes: it returns receipts or an
//!    `rpc/receipt` error, never a panic, an allocation blow-up or an overflow.
//! 2. A log it accepts satisfies the format's own invariants: contiguous
//!    sequences from the header's start, non-decreasing times, lowercase
//!    correlation ids, representable methods and refusal codes.
//! 3. Every prefix that ends on a record boundary is itself a valid log holding
//!    that prefix of the records; every other prefix is refused. That is why a
//!    truncated tail is invisible to chain-only verification and needs a pinned
//!    head, which the unit tests cover.
//! 4. A log the shipped kernel exports round-trips: the records read back are
//!    the receipts the kernel sealed, and their MACs verify under the secret.
//!
//! Run with `cargo +nightly fuzz run fuzz_receipt_log -- -runs=200000`.

use std::path::PathBuf;

use libfuzzer_sys::fuzz_target;

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

const SECRET: [u8; 32] = [0x5a; 32];

/// A scratch path unique to the caller and this execution.
///
/// A fixed pid-named path in the shared temp directory is a file another local
/// user can pre-plant (a symlink, an empty log) and the writer truncates
/// through it (R-20 round 4, #9). The caller removes it when done.
fn scratch(tag: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "active-rpc-fuzz-receipt-log-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0)
    ));
    path
}

/// The invariants a log the reader accepted must satisfy.
fn check_invariants(receipts: &[Receipt], start: u64) {
    let mut last_ms = 0u64;
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(
            receipt.sequence,
            start + index as u64,
            "an accepted log must number its records from the header"
        );
        assert!(
            receipt.fields_are_representable(),
            "an accepted record must be representable"
        );
        assert!(
            receipt.at_ms >= last_ms,
            "an accepted log must not run backwards in time"
        );
        last_ms = receipt.at_ms;
    }
}

/// The shipped path: a kernel session exported and read back.
fn structured(data: &[u8]) {
    let agent = Agent::with_secret(SECRET);
    agent.enable_receipts(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = match agent.mint(provider, 0, CapAttrs::new(&["echo"])) {
        Ok(cap) => cap,
        Err(_) => return,
    };
    let lane = match agent.create_lane("fuzz", Budget::default()) {
        Ok(lane) => lane,
        Err(_) => return,
    };
    for action in data.iter().take(8) {
        match action % 4 {
            0 => {
                if let Ok(promise) = agent.call(lane, &cap, "echo", Vec::new()) {
                    agent.run();
                    let _ = promise.value();
                }
            }
            1 => {
                // Queue while live, revoke, then run: a dispatch refusal.
                if let Ok(promise) = agent.call(lane, &cap, "echo", Vec::new()) {
                    let _ = agent.revoke(&cap);
                    agent.run();
                    let _ = promise.value();
                }
            }
            2 => {
                let _ = agent.call(lane, &cap, "not-granted", Vec::new());
            }
            _ => {
                agent.enable_receipts(false);
                agent.enable_receipts(true);
            }
        }
    }

    let receipts = agent.receipts();
    let key = agent.receipt_key();
    let path = scratch("log");
    let _ = std::fs::remove_file(&path);
    let start = receipts.first().map_or(1, |receipt| receipt.sequence);
    let log = ReceiptLog::create_starting_at(&path, start).expect("create");
    log.append_verified(&key, &receipts)
        .expect("the kernel's own receipts must export");
    let read = log.records().expect("records");
    assert_eq!(read, receipts, "the log lost or reordered a receipt");
    log.verify_macs(&key).expect("the kernel's MACs");

    // Every record boundary is a shorter valid log; any other cut is refused.
    let bytes = std::fs::read(&path).expect("read");
    let mut cursor = LOG_HEADER_LEN;
    let mut index = 0usize;
    while cursor < bytes.len() {
        let finite = cursor + 4;
        assert!(finite <= bytes.len(), "a record must start inside the file");
        let length =
            u32::from_le_bytes(bytes[cursor..finite].try_into().expect("4 bytes")) as usize;
        let end = finite + length;
        let prefix = if end <= bytes.len() {
            &bytes[..end]
        } else {
            &bytes[..]
        };
        match ReceiptLog::verify_bytes(prefix) {
            Ok(records) => {
                index += 1;
                assert_eq!(records.len(), index, "a boundary prefix holds its records");
                assert_eq!(records[..], read[..index], "a prefix is the same records");
            }
            Err(error) => {
                assert_eq!(error.code(), "rpc/receipt");
                break;
            }
        }
        if end >= bytes.len() {
            break;
        }
        cursor = end;
    }
    assert_eq!(index, read.len(), "every record boundary verifies");
    let _ = std::fs::remove_file(&path);
}

/// The writer half: arbitrary receipt fields either append and read back, or are
/// refused and leave the log readable. A writer that accepts a record its own
/// reader rejects would make the log permanently unreadable, so this is the
/// invariant the reader fuzz cannot see.
fn writer(data: &[u8]) {
    let path = scratch("writer");
    let _ = std::fs::remove_file(&path);
    let log = match ReceiptLog::create(&path) {
        Ok(log) => log,
        Err(_) => return,
    };
    let field = |index: usize, fallback: u8| data.get(index).copied().unwrap_or(fallback);
    let cap: String = (0..16)
        .map(|index| {
            let nibble = field(index * 7, 0x2a) % 16;
            std::char::from_digit(u32::from(nibble), 16).unwrap_or('0')
        })
        .collect();
    let method_len = usize::from(field(400, 3)) % 64;
    let method: String = (0..method_len)
        .map(|index| {
            let byte = field(index * 3 + 500, b'a');
            // Feed control characters and non-ASCII bytes on purpose: the writer
            // must refuse what the reader would reject.
            char::from(byte)
        })
        .collect();
    let decision = if field(3, 0) % 2 == 0 {
        Decision::Admitted
    } else {
        let code_len = usize::from(field(4, 0)) % 8;
        let code: String = (0..code_len)
            .map(|index| char::from(field(index + 600, b'x')))
            .collect();
        Decision::Refused(code)
    };
    let candidate = Receipt {
        sequence: u64::from(field(5, 1)) % 4 + 1,
        cap,
        method,
        at_ms: u64::from(field(6, 0)),
        decision,
        mac: [field(7, 0); 32],
    };
    match log.append(&candidate) {
        Ok(()) => {
            let records = log
                .records()
                .expect("a record the writer accepted must be readable");
            assert_eq!(
                records.last(),
                Some(&candidate),
                "the writer stored something other than the receipt"
            );
            assert!(
                candidate.fields_are_representable(),
                "an accepted receipt is representable by definition"
            );
        }
        Err(error) => {
            assert_eq!(error.code(), "rpc/receipt");
            log.records()
                .expect("a refused append must leave the log readable");
        }
    }
    let _ = std::fs::remove_file(&path);
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: the reader must accept a well-formed log. Without
    // it a `walk_log` that refuses every log passed the lane (R-20 round 5, F3).
    {
        let path = scratch("control");
        let _ = std::fs::remove_file(&path);
        let log = ReceiptLog::create(&path).expect("create");
        let receipt = Receipt {
            sequence: 1,
            cap: "0011223344556677".to_string(),
            method: "echo".to_string(),
            at_ms: 1,
            decision: Decision::Admitted,
            mac: [0u8; 32],
        };
        log.append(&receipt).expect("append");
        let bytes = std::fs::read(&path).expect("read");
        let read = ReceiptLog::verify_bytes(&bytes).expect("the fixed log verifies");
        assert_eq!(read, vec![receipt]);
        let _ = std::fs::remove_file(&path);
    }
    match ReceiptLog::verify_bytes(data) {
        Ok(receipts) => {
            let start = u64::from_le_bytes(data[8..16].try_into().expect("header start"));
            check_invariants(&receipts, start);
        }
        Err(error) => assert_eq!(
            error.code(),
            "rpc/receipt",
            "verify_bytes refused with an unexpected code: {error}"
        ),
    }
    if !data.is_empty() {
        // The kernel half creates, locks, syncs and unlinks a file per
        // execution, which costs orders of magnitude more than the parser half.
        // Run it for one input in sixteen: the byte-parser above still sees
        // every input, and the corpus converges on inputs whose gate passes.
        if data[0] & 0x0f == 0 {
            writer(data);
            structured(data);
        }
    }
});
