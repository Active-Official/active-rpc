//! R-13 round 5: a contended stale-lock steal never corrupts the log, a hostile
//! nonce cannot steer the steal's claim out of the directory, a reader waits
//! while a writer holds a fresh lock, and a planted staging entry cannot redirect
//! the header write.
//!
//! The log is the real file-backed `ReceiptLog`; the writers are real threads and
//! a real lock file is aged with a real modification time.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use active_rpc::receipts::{Decision, Receipt, ReceiptLog};

fn scratch(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "active-rpc-receipt-r5-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(lock_of(&path));
    path
}

fn lock_of(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.lock",
        path.file_name().unwrap().to_string_lossy()
    ))
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

fn filetime_set(path: &Path, when: std::time::SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open");
    file.set_times(std::fs::FileTimes::new().set_modified(when))
        .expect("times");
}

/// A stale lock that several threads try to steal at once must never let two
/// appends run: the file that comes out still walks, and every refusal is a
/// clean one (R-13 round 5, #1).
#[test]
fn a_contended_steal_never_corrupts_the_log() {
    let path = scratch("contended");
    drop(ReceiptLog::create(&path).expect("create"));
    // A crashed writer's lock, aged past the steal ceiling.
    let lock = lock_of(&path);
    std::fs::write(&lock, b"999-1 pid 4294967294 started 1").expect("lock");
    filetime_set(
        &lock,
        std::time::SystemTime::now() - std::time::Duration::from_secs(600),
    );

    // Only the thread that wins the lock advances the sequence: a duplicate is
    // refused as a chain fault, which is the clean outcome this test tolerates.
    let next = std::sync::Arc::new(AtomicU64::new(1));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let path = path.clone();
        let next = std::sync::Arc::clone(&next);
        threads.push(std::thread::spawn(move || {
            let log = ReceiptLog::open(&path).expect("open");
            let mut refusals = 0;
            for _ in 0..20 {
                let sequence = next.load(Ordering::SeqCst);
                match log.append(&receipt(sequence, "echo")) {
                    Ok(()) => {
                        next.store(sequence + 1, Ordering::SeqCst);
                    }
                    Err(error) => {
                        assert_eq!(error.code(), "rpc/receipt", "a refusal is a lock refusal");
                        refusals += 1;
                    }
                }
            }
            refusals
        }));
    }
    for thread in threads {
        let _ = thread.join().expect("thread");
    }
    // Whatever the interleaving, the file must be a walkable chain: two appends
    // under one lock is what this test exists to rule out.
    let bytes = std::fs::read(&path).expect("read");
    let records = ReceiptLog::verify_bytes(&bytes).expect("the contended log still walks");
    assert!(!records.is_empty(), "at least one append won the lock");
    // Contiguous from the header's start: a torn write would break this.
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.sequence, records[0].sequence + index as u64);
    }
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&lock);
}

/// A lock is a file an attacker can plant: its nonce must not steer the steal's
/// claim file outside the log's directory (R-13 round 5, #1).
#[test]
fn a_hostile_nonce_cannot_steer_the_steal_claim() {
    let path = scratch("hostile");
    drop(ReceiptLog::create(&path).expect("create"));
    let lock = lock_of(&path);
    // A pid no process can have: a live pid is never stolen (round 6, M1), and
    // this test is about the nonce, not the liveness rule.
    std::fs::write(&lock, b"../../escaped pid 4294967294 started 1").expect("lock");
    filetime_set(
        &lock,
        std::time::SystemTime::now() - std::time::Duration::from_secs(600),
    );
    let directory = path.parent().expect("parent").to_path_buf();

    let log = ReceiptLog::open(&path).expect("open");
    log.append(&receipt(1, "echo"))
        .expect("the hostile lock is still stolen and the append lands");
    assert_eq!(
        ReceiptLog::verify_bytes(&std::fs::read(&path).expect("read"))
            .expect("walk")
            .len(),
        1
    );
    // Nothing was created under a name the lock's author chose.
    let escaped = directory.join("escaped");
    assert!(
        !escaped.exists(),
        "the claim escaped the log directory: {}",
        escaped.display()
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&lock);
}

/// A reader that lands while a writer holds a fresh lock waits for it instead of
/// returning a prefix of the batch (R-13 round 5, #5).
#[test]
fn a_reader_waits_while_a_fresh_lock_is_held() {
    let path = scratch("fresh");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(&receipt(1, "echo")).expect("append");
    drop(log);
    // A writer that has taken the lock and not yet released it.
    let lock = lock_of(&path);
    std::fs::write(&lock, b"1-1 pid 1 started 1").expect("lock");

    let reader_path = path.clone();
    let started = std::time::Instant::now();
    let reader = std::thread::spawn(move || {
        let log = ReceiptLog::open(&reader_path).expect("open");
        let records = log.records().expect("records");
        (records.len(), started.elapsed())
    });
    std::thread::sleep(std::time::Duration::from_millis(120));
    std::fs::remove_file(&lock).expect("release");
    let (count, elapsed) = reader.join().expect("reader");
    assert!(
        elapsed >= std::time::Duration::from_millis(100),
        "the reader did not wait for the writer: {elapsed:?}"
    );
    assert_eq!(count, 1, "the settled log holds the one record");
    let _ = std::fs::remove_file(&path);
}

/// The staging file a new log is written through is created fresh under a unique
/// name, so a planted entry at the old fixed name cannot redirect the header
/// write (R-13 round 5, #3).
#[test]
fn a_planted_staging_entry_does_not_redirect_the_header() {
    let path = scratch("staging");
    // The name `create` used to take, planted as a directory: `File::create`
    // would fail on it, and a symlink would have redirected the write.
    let planted = path.with_file_name(format!(
        "{}.writing",
        path.file_name().unwrap().to_string_lossy()
    ));
    std::fs::create_dir_all(&planted).expect("plant");
    let log = ReceiptLog::create(&path).expect("create ignores the planted entry");
    log.append(&receipt(1, "echo")).expect("append");
    assert_eq!(
        ReceiptLog::verify_bytes(&std::fs::read(&path).expect("read"))
            .expect("walk")
            .len(),
        1
    );
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&planted);
    let _ = std::fs::remove_file(lock_of(&path));
}

/// A lock that names a live writer is not abandoned however old it looks: a
/// stopped process or a slow batch still holds it, and stealing it writes a
/// second chain into the file (R-13 round 6, M1). The liveness check exists only
/// where the kernel exposes another process cheaply (`/proc`), so the assertion
/// is Linux-only.
#[cfg(target_os = "linux")]
#[test]
fn a_lock_whose_pid_is_alive_is_not_stolen() {
    let path = scratch("alive");
    drop(ReceiptLog::create(&path).expect("create"));
    let lock = lock_of(&path);
    std::fs::write(
        &lock,
        format!("424242 pid {} started 1", std::process::id()).as_bytes(),
    )
    .expect("lock");
    filetime_set(
        &lock,
        std::time::SystemTime::now() - std::time::Duration::from_secs(600),
    );

    let log = ReceiptLog::open(&path).expect("open");
    let started = std::time::Instant::now();
    let error = log
        .append(&receipt(1, "echo"))
        .expect_err("a live writer's lock is not stolen");
    assert_eq!(error.code(), "rpc/receipt");
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(1_000),
        "the caller waited the documented budget"
    );
    assert!(lock.exists(), "the live writer still holds its lock");
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&lock);
}
