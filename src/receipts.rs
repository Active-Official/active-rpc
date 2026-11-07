//! Capability receipts: an audit record of the authorization decision.
//!
//! A receipt answers "was this call authorized, under which capability, and
//! when" without carrying arguments, values or any secret material. Each
//! receipt is authenticated with a keyed hash under a key derived from the
//! kernel secret ([`derive_receipt_key`]), so a record cannot be edited or
//! transplanted between kernels without detection, and a verifier can be given
//! the receipt key without the authority to mint capability ids.
//!
//! A receipt records the decision that *matters*: the one taken at dispatch,
//! after the capability was re-checked for revocation, expiry and identity. A
//! call that was queued and then refused is recorded as a refusal, not as an
//! authorization.
//!
//! Receipts are opt-in (`Agent::enable_receipts`): a kernel that does not want
//! per-call bookkeeping pays nothing.

use crate::cap::CapId;
use crate::{Error, Result};

/// Longest receipt ring the kernel keeps.
pub const MAX_RECEIPTS: usize = 1 << 10;

/// Longest method name a receipt accepts, in bytes.
pub const MAX_METHOD_BYTES: usize = 1024;

/// Longest refusal code a receipt accepts, in bytes.
pub const MAX_CODE_BYTES: usize = 64;

/// The decision a receipt records.
///
/// A refusal carries an owned code rather than a `&'static str` so a reader can
/// rebuild any code the writer accepted; both sides validate with
/// [`valid_code`], so the reader and the writer cannot disagree about which
/// codes exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The call was admitted and dispatched.
    Admitted,
    /// The capability refused the call at dispatch; the code says why.
    Refused(String),
}

impl Decision {
    /// Wire flag: 0 is an admission, 1 a refusal.
    fn flag(&self) -> u8 {
        match self {
            Decision::Admitted => 0,
            Decision::Refused(_) => 1,
        }
    }

    /// The refusal code, or an empty string for an admission.
    fn code(&self) -> &str {
        match self {
            Decision::Admitted => "",
            Decision::Refused(code) => code,
        }
    }
}

/// One authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    /// Monotonic sequence within the kernel, starting at 1.
    pub sequence: u64,
    /// Non-reversible correlation id of the capability that authorized the call.
    pub cap: String,
    /// Method that was authorized.
    pub method: String,
    /// Kernel time of the decision, in milliseconds.
    pub at_ms: u64,
    /// What the kernel decided.
    pub decision: Decision,
    /// Keyed hash over the fields above.
    pub mac: [u8; 32],
}

/// Domain of the derived receipt key.
const RECEIPT_KEY_DOMAIN: &str = "active-rpc/receipt-key/v1";

/// Derive the key that seals receipts from a kernel secret.
///
/// The kernel secret mints capability ids, so it is the authority token itself
/// and must never leave the kernel. Receipts are sealed with a key derived from
/// it instead: a verifier needs that key and learns nothing that can mint a
/// capability. [`crate::Agent::receipt_key`] returns the derived key.
pub fn derive_receipt_key(secret: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key(RECEIPT_KEY_DOMAIN, secret)
}

impl Receipt {
    /// Build and seal a receipt for a decision.
    ///
    /// `key` is the derived receipt key, not the kernel secret.
    pub(crate) fn seal(
        key: &[u8; 32],
        sequence: u64,
        cap: CapId,
        method: &str,
        at_ms: u64,
        decision: Decision,
    ) -> Receipt {
        let mut receipt = Receipt {
            sequence,
            cap: cap.correlation_id(),
            method: method.to_string(),
            at_ms,
            decision,
            mac: [0u8; 32],
        };
        receipt.mac = receipt.compute(key);
        receipt
    }

    /// True when the receipt was produced by the kernel that owns `key` and its
    /// fields were not edited. `key` is the derived receipt key.
    pub fn verify(&self, key: &[u8; 32]) -> bool {
        let expected = self.compute(key);
        // Constant-time comparison; the mac is public, so this is hygiene.
        let mut difference = 0u8;
        for (left, right) in expected.iter().zip(self.mac.iter()) {
            difference |= left ^ right;
        }
        difference == 0
    }

    /// Whether every field is in the form the log format can hold.
    ///
    /// A receipt that fails this could be sealed by the kernel and then refused
    /// by its own log, which would leave an audit trail that cannot be written.
    pub fn fields_are_representable(&self) -> bool {
        valid_correlation_id(&self.cap)
            && valid_method(&self.method)
            && match &self.decision {
                Decision::Admitted => true,
                Decision::Refused(code) => valid_code(code),
            }
    }

    fn compute(&self, key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(b"active-rpc/receipt/v2");
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&(self.cap.len() as u32).to_le_bytes());
        hasher.update(self.cap.as_bytes());
        hasher.update(&(self.method.len() as u32).to_le_bytes());
        hasher.update(self.method.as_bytes());
        hasher.update(&self.at_ms.to_le_bytes());
        hasher.update(&[self.decision.flag()]);
        hasher.update(self.decision.code().as_bytes());
        *hasher.finalize().as_bytes()
    }
}

/// Whether a method name can travel in a receipt.
///
/// A control character would let a method name forge a line in a line-oriented
/// log or a terminal; the bound matches the log record field (a `u16`, but the
/// receipt format caps it lower so a reader and a writer agree).
pub fn valid_method(method: &str) -> bool {
    crate::security::valid_text(method, MAX_METHOD_BYTES)
}

/// Whether a refusal code can travel in a receipt.
///
/// The rule is a character set, not a list of codes this build happens to know:
/// a kernel that grows a new [`crate::Error`] code must still be able to export
/// its log, and a reader must still be able to read it. The set is the one
/// `rpc/...` codes already use, so a control character (a forged log line or a
/// terminal escape) cannot pass on either side.
pub fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_CODE_BYTES
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'/' | b'-' | b'_' | b'.')
        })
}

// ---------------------------------------------------------------------------
// Durable log (`ARRL`)
// ---------------------------------------------------------------------------

/// Magic of a receipt log file.
pub const LOG_MAGIC: &[u8; 4] = b"ARRL";
/// Version of the receipt log format.
///
/// Version 2 carries a start sequence in the header (so a ring that wrapped can
/// be exported as its own window) and a decision per record. Version 1 files are
/// refused: no deployment produced one, and reading them would need a second
/// parser for a format that never shipped.
pub const LOG_VERSION: u8 = 2;
/// Largest log record accepted, in bytes.
pub const MAX_LOG_RECORD: usize = 64 << 10;
/// Smallest record a log can carry.
///
/// `sequence u64 | at_ms u64 | decision u8 | code_len u16 | cap_len u16 |
/// method_len u16 | mac [32]` plus the chain link in the trailer: a shorter
/// record cannot be well formed, and subtracting its trailer used to underflow.
pub const MIN_LOG_RECORD: usize = 8 + 8 + 1 + 2 + 2 + 2 + 32 + 32;
/// Largest log file accepted, in bytes.
pub const MAX_LOG_BYTES: u64 = 64 << 20;
/// Largest number of records accepted.
pub const MAX_LOG_RECORDS: u64 = 100_000;

/// Domain separator for the log chain hash.
const LOG_DOMAIN: &[u8] = b"active-rpc/receipt-log/v2";

/// Header length: magic, version, flags, start sequence.
pub const LOG_HEADER_LEN: usize = 4 + 1 + 3 + 8;

/// What the log knows about its own tail, so an append is one write instead of a
/// full re-read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogState {
    bytes: u64,
    count: u64,
    start: u64,
    head: [u8; 32],
    /// `at_ms` of the last record, so a writer refuses a record the reader
    /// would reject for running backwards in time.
    last_ms: u64,
    /// The file identity the state was walked from.
    ///
    /// The append fast path trusted the length, the header and the trailing
    /// head, and a same-length copy with an edited middle record keeps all
    /// three: only the inode tells the copy from the log that was walked
    /// (R-13 round 14, F1). `None` means the walk did not come from a handle,
    /// and the fast path then re-walks.
    identity: Option<(u64, u64)>,
    /// The file's modification time when the walk happened.
    ///
    /// The inode is invariant under an in-place write, so an interior edit
    /// through the log's own path (or a hard link) kept length, header, tail
    /// and identity intact and the append kept trusting the cache. The mtime
    /// changes on that write; a writer who can set it back is the authenticity
    /// residual ADR-0021 records (R-13 round 15, F1).
    modified: Option<std::time::SystemTime>,
}

/// One read of a log: the records and the tail they end at.
///
/// A verifier that needs several of those (records, start, head, length) takes
/// one snapshot rather than reading the file once per question, and the answers
/// are then guaranteed to describe the same bytes even while a writer appends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    receipts: Vec<Receipt>,
    start: u64,
    head: [u8; 32],
    last_ms: u64,
}

impl Snapshot {
    /// Every record, oldest first.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Sequence of the first record.
    pub fn start_sequence(&self) -> u64 {
        self.start
    }

    /// Number of records.
    pub fn len(&self) -> u64 {
        self.receipts.len() as u64
    }

    /// True when the snapshot holds no records.
    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    /// Hash of the last record, or zeros for an empty log.
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// `at_ms` of the last record, or 0 for an empty log.
    pub fn last_ms(&self) -> u64 {
        self.last_ms
    }

    /// Verify every receipt's `mac` under the log's receipt key.
    pub fn verify_macs(&self, key: &[u8; 32]) -> Result<()> {
        for receipt in &self.receipts {
            if !receipt.verify(key) {
                return Err(Error::receipt(format!(
                    "receipt {} was not produced by this kernel",
                    receipt.sequence
                )));
            }
        }
        Ok(())
    }

    /// Refuse the snapshot unless it ends at the pinned head.
    pub fn verify_against(&self, expected: [u8; 32]) -> Result<()> {
        if self.head != expected {
            return Err(Error::receipt("the log does not end at the pinned head"));
        }
        Ok(())
    }
}

/// Exclusive access to one log file, held for the length of an append.
struct LogLock {
    path: std::path::PathBuf,
    /// Written into the lock file: the proof a non-unix host checks, and what an
    /// operator reads. On unix the held handle's `(dev, ino)` decides ownership
    /// (a copied text is not a file identity), so the field is write-only there.
    #[cfg_attr(unix, allow(dead_code))]
    nonce: String,
    /// The handle `create_new` returned.
    ///
    /// `touch` acts on this handle, not on the path: a lock path a local user
    /// replaced with a symlink or another file must not be the thing a live
    /// writer refreshes (R-13 round 8, L1).
    file: Option<std::fs::File>,
}

/// Age after which a lock file is treated as abandoned.
///
/// A writer holds the lock for one append (a `write_all` plus `sync_data`), so a
/// lock older than this cannot belong to a live writer. Without the ceiling a
/// crash leaves the log unappendable for good, and any local user who creates
/// that file stops the evidence pipeline.
const LOCK_STALE_MS: u64 = 120_000;

/// How long a lock that names a live pid is still honoured.
///
/// `judged_stale` refuses to steal a lock whose writer is alive, which is what
/// keeps a stopped process from losing its lock (R-13 round 6, M1). Without a
/// bound that rule is a denial of service: any user who can write the directory
/// plants a lock naming a live pid and the log is unappendable for ever. Past
/// this grace the age rule wins (R-13 round 7, #1).
const LOCK_LIVE_GRACE_MS: u64 = 10 * LOCK_STALE_MS;

/// Bytes written to the log between two refreshes of the lock's mtime.
///
/// A writer that keeps its lock fresh makes "older than the ceiling" mean "no
/// live writer is making progress" on every platform, without asking the
/// operating system about another process (R-13 round 7, #2).
const WRITE_CHUNK_BYTES: usize = 1 << 20;

/// How much of a lock file is read to find its nonce.
///
/// A lock is one short line. A lock is also a file an attacker can plant, and a
/// reader must not allocate a gigabyte to discover that it holds no nonce.
const MAX_LOCK_BYTES: u64 = 512;

impl LogLock {
    /// Take the log's lock, waiting for a concurrent writer.
    ///
    /// `create_new` is atomic on every supported platform: one writer wins. The
    /// others retry with backoff, which covers a normal append (including a
    /// large batch and its `sync_data`), then refuse rather than corrupt the
    /// chain.
    ///
    /// A lock older than `LOCK_STALE_MS` is stolen in two steps that cannot
    /// identify one file and act on another (R-13 round 5, #1). The judgement
    /// reads the age **and** the nonce through one open handle, so a writer that
    /// replaced the lock between two opens cannot make the stealer judge one lock
    /// and believe it identified another. The steal itself claims a
    /// `create_new` file named after the judged nonce, so exactly one stealer
    /// wins it, and the live lock is never moved: a loser cannot clobber a fresh
    /// lock, and the winner removes the lock only if its nonce is still the one
    /// it judged.
    /// Refresh the lock's modification time.
    ///
    /// A writer holds the lock for one append and keeps it fresh while it works,
    /// so the age rule means "no live writer is making progress" without a
    /// platform-specific liveness probe. A failure here is not fatal: the age
    /// rule is then the only guard, which is what it was before.
    fn touch(&self) {
        let Some(file) = &self.file else {
            return;
        };
        let _ =
            file.set_times(std::fs::FileTimes::new().set_modified(std::time::SystemTime::now()));
    }

    /// Whether the lock path still names this holder's lock.
    ///
    /// The mtime of a lock is advisory, but **ownership** is checked before
    /// every write: if the path no longer carries this nonce, another process
    /// displaced this lock and a second writer may hold the path, so this writer
    /// refuses rather than append a second chain into the file (R-13 round 8,
    /// M1). The check is one bounded read of the path.
    fn still_holds(&self) -> bool {
        // On unix the lock is a file identity: a local user with directory
        // write can read a live nonce, unlink the lock and recreate the same
        // text, so a text check alone let two writers append (R-13 round 11,
        // L-3). Everywhere else the nonce is the best available check.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let Some(held) = self.file.as_ref().and_then(|file| file.metadata().ok()) else {
                return false;
            };
            let Ok(current) = std::fs::symlink_metadata(&self.path) else {
                return false;
            };
            if current.file_type().is_symlink() {
                return false;
            }
            held.ino() != 0 && held.dev() == current.dev() && held.ino() == current.ino()
        }
        #[cfg(not(unix))]
        {
            nonce_of(&self.path).as_deref() == Some(self.nonce.as_str())
        }
    }

    fn acquire(log: &std::path::Path) -> Result<Self> {
        let path = lock_path(log);
        sweep_leftovers(&path);
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        );
        for attempt in 0..40u32 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write;
                    // The nonce proves ownership on drop; the pid and the start
                    // time are diagnostics for an operator who finds a lock.
                    let written = writeln!(
                        file,
                        "{LOCK_MAGIC}{nonce} pid {} started {}",
                        std::process::id(),
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|elapsed| elapsed.as_millis())
                            .unwrap_or(0)
                    );
                    if written.is_err() {
                        // An empty lock looks like an interrupted creator, wedges
                        // the log for the grace, and the writer's own
                        // `still_holds` would report a misleading "displaced"
                        // (R-13 round 10, E).
                        // Only the lock this call created may be removed:
                        // an unchecked unlink deleted whatever held the path
                        // after a displacement (R-13 round 14, F6).
                        let held = file.metadata().ok();
                        drop(file);
                        let ours = match &held {
                            Some(held) => {
                                #[cfg(not(unix))]
                                let _ = held;
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::MetadataExt;
                                    std::fs::symlink_metadata(&path).is_ok_and(|current| {
                                        !current.file_type().is_symlink()
                                            && current.dev() == held.dev()
                                            && current.ino() == held.ino()
                                    })
                                }
                                #[cfg(not(unix))]
                                {
                                    nonce_of(&path).as_deref() == Some(nonce.as_str())
                                }
                            }
                            None => false,
                        };
                        if ours {
                            let _ = std::fs::remove_file(&path);
                        }
                        return Err(Error::receipt("cannot write the receipt lock"));
                    }
                    return Ok(Self {
                        path,
                        nonce,
                        file: Some(file),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if attempt % 20 == 0 {
                        // `take_stale` moves the lock, verifies that the file it
                        // moved is the one that was judged, and preserves
                        // anything else (R-13 round 9, F1).
                        if let Some(judged) = judged_stale(&path) {
                            if take_stale(&path, &judged) {
                                continue;
                            }
                        }
                    }
                    // Backoff: 5 ms rising to 45 ms. A *failed* acquire sleeps
                    // on all 40 attempts, which is 1.38 s; a won steal skips its
                    // own sleep, so the successful path is shorter (R-13 round 7,
                    // #4). The wait only has to cover one append; a longer one is
                    // a lock a caller should see refused rather than a stall.
                    let step = u64::from(attempt.min(20));
                    std::thread::sleep(std::time::Duration::from_millis(5 + step * 2));
                }
                Err(_) => return Err(Error::receipt("cannot lock the receipt log")),
            }
        }
        Err(Error::receipt(
            "the receipt log is locked by another writer",
        ))
    }
}

/// The first token of a lock file's content.
///
/// A lock path is `<log>.lock`, which is also a legal log name, so a sibling
/// log was judged by reading its binary header as a nonce and then deleted by
/// the steal. A magic prefix makes a file that is not ours unjudgeable and
/// therefore preserved (R-13 round 14, F4).
const LOCK_MAGIC: &str = "active-rpc-lock v1 ";

/// Path of the lock that guards `log`.
///
/// Derived by appending `.lock` to the file name: `with_extension` would make a
/// log that is itself named `*.lock` collide with its own lock, and would make
/// `a.arrl` and `a.json` share one lock.
fn lock_path(log: &std::path::Path) -> std::path::PathBuf {
    let name = log
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "receipts".to_string());
    log.with_file_name(format!("{name}.lock"))
}

/// The nonce of a lock that is older than the stale ceiling, judged and read
/// through **one** open handle.
///
/// `None` when the lock is fresh, missing, or carries no readable nonce: a lock
/// that cannot be identified cannot be stolen safely. `metadata()` and the bytes
/// describe one file here, which is what makes the judgement trustworthy
/// (R-13 round 5, #1).
fn judged_stale(path: &std::path::Path) -> Option<String> {
    let (age_ms, nonce, pid) = lock_state(path)?;
    if lock_is_live(age_ms, pid) {
        return None;
    }
    Some(nonce)
}

/// The facts one open read gives: the lock's age, its nonce, and the pid it names
/// when its creator wrote one.
///
/// One handle, so the age and the identity describe the same file (R-13 round 5,
/// #1). Lossy text, so a lock with a stray non-UTF-8 byte is still identifiable
/// and can still be stolen (R-13 round 8, L5).
fn lock_state(path: &std::path::Path) -> Option<(u64, String, Option<u32>)> {
    // A FIFO or a device at the lock path would block `open` for ever, so the
    // type is checked without following a link and without blocking
    // (R-13 round 9, F5).
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let file = open_log_read(path).ok()?;
    let modified = file.metadata().ok()?.modified().ok()?;
    let age_ms = match modified.elapsed() {
        Ok(age) => age.as_millis() as u64,
        // A timestamp in the future is clock skew or a planted file. Reading the
        // age as zero made such a lock immortal, and reading it as the ceiling
        // kept it immortal while the pid it names is alive (the grace is longer
        // than the ceiling). Past the grace is the honest reading: no writer
        // writes its lock with a future timestamp (R-13 rounds 9-10, F2/B).
        Err(_) => LOCK_LIVE_GRACE_MS + 1,
    };
    let (nonce, pid) = read_lock(&file)?;
    Some((age_ms, nonce, pid))
}

/// Quarantine a lock that was judged stale, and only that lock.
///
/// The rename is atomic and only one stealer can win it. The moved file is then
/// checked against the nonce that was judged: a different nonce means a writer
/// created a new lock between the judgement and the move, and that lock was never
/// judged abandoned, so it is **preserved** — put back when the path is free,
/// otherwise kept under an orphan name — and the call reports failure rather than
/// deleting a live writer's lock (R-13 round 9, F1). A displaced writer fails
/// `still_holds` and refuses to write, so two writers never append.
///
/// Returns true when the lock that was judged was removed.
fn take_stale(path: &std::path::Path, judged: &str) -> bool {
    let safe = if judged.is_empty() {
        // No nonce: an interrupted creator. A fixed, valid name keeps the
        // quarantine path derivable without letting the file choose it.
        "unidentified".to_string()
    } else {
        // A nonce that no claim name can render is still `judged`: the match
        // below compares the raw text, and the quarantine name comes from a
        // fixed token, so returning `false` here wedged the log for ever
        // (R-13 round 10, D).
        claim_name(judged).unwrap_or_else(|| "unidentified".to_string())
    };
    let quarantine = path.with_file_name(format!("{}.stale-{safe}", file_name_text(path)));
    // A name a local user pre-planted (as a directory, or a file the rename
    // cannot replace) must not block the steal: the second attempt carries a
    // unique suffix the file's author cannot choose (R-13 round 9, L1).
    let quarantine = if std::fs::rename(path, &quarantine).is_ok() {
        quarantine
    } else {
        let unique = path.with_file_name(format!(
            "{}.stale-{safe}-{}",
            file_name_text(path),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        if std::fs::rename(path, &unique).is_err() {
            return false;
        }
        unique
    };
    let moved_nonce = nonce_of(&quarantine).unwrap_or_else(|| "missing".to_string());
    let matched = if judged.is_empty() {
        // The file that was judged had no nonce; it still has none, so it is the
        // same lock (R-13 round 9, F2).
        moved_nonce.is_empty()
    } else {
        moved_nonce == judged
    };
    if matched {
        let _ = std::fs::remove_file(&quarantine);
        return true;
    }
    // Not the file that was judged: never delete it.
    if !path.exists() {
        let _ = std::fs::rename(&quarantine, path);
    } else {
        let orphan = quarantine.with_file_name(format!(
            "{}.orphan-{}",
            file_name_text(&quarantine),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::rename(&quarantine, &orphan);
    }
    false
}

/// A refusal message that lets an operator tell a stale lock from damage.
///
/// The nonce is file text, so it is escaped and bounded like any other label
/// (R-13 round 12, F5).
fn writer_description(path: &std::path::Path) -> String {
    match lock_state(&lock_path(path)) {
        Some((age_ms, nonce, pid)) => format!(
            "the receipt log is being written by another process (lock {} ms old, owner {}, pid {})",
            age_ms,
            crate::observability::label(&nonce),
            pid.map_or_else(|| "unknown".to_string(), |pid| pid.to_string())
        ),
        None => "the receipt log is being written by another process".to_string(),
    }
}

/// Whether a lock of that age, naming that pid, still belongs to a live writer.
///
/// The one rule the stealer and the reader share: a lock is live while it is
/// younger than `LOCK_STALE_MS`, and it stays live past that while the pid it
/// names is alive, bounded by `LOCK_LIVE_GRACE_MS` so a planted lock naming a
/// live pid cannot stop the log for ever (R-13 rounds 6-8). A writer that is
/// making progress keeps its own lock fresh (`LogLock::touch`), so the grace only
/// covers a process that cannot touch.
fn lock_is_live(age_ms: u64, pid: Option<u32>) -> bool {
    age_ms <= LOCK_STALE_MS || (pid.is_some_and(process_is_alive) && age_ms <= LOCK_LIVE_GRACE_MS)
}

/// Whether `pid` names a live process.
///
/// Cheap only where the kernel exposes it as a directory; elsewhere the age rule
/// is the whole test, which is why `LOCK_STALE_MS` is generous.
#[cfg(target_os = "linux")]
fn process_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

/// See the Linux implementation: without a cheap existence check the age rule is
/// the whole test.
#[cfg(not(target_os = "linux"))]
fn process_is_alive(_pid: u32) -> bool {
    false
}

/// The nonce and (when the creator wrote one) the pid of an open lock file.
///
/// Bounded: a lock is one short line, and a hostile file must not make a reader
/// allocate megabytes to discover that. The format is
/// `{nonce} pid {pid} started {ms}`; a lock without a pid is still usable.
fn read_lock(file: &std::fs::File) -> Option<(String, Option<u32>)> {
    // (An empty lock yields an empty nonce: it is identifiable as "no owner",
    // which is a state a lock can be left in when a writer dies between
    // `create_new` and its write, and one that must not be unstealable.)
    use std::io::Read;
    let mut bytes = Vec::new();
    file.try_clone()
        .ok()?
        .take(MAX_LOCK_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    // Lossy: a lock with a stray non-UTF-8 byte in its first bytes is still
    // identifiable, so it can still be stolen instead of blocking for ever
    // (R-13 round 8, L5).
    let text = String::from_utf8_lossy(&bytes);
    let body = text.strip_prefix(LOCK_MAGIC).unwrap_or(&text);
    // A file that is neither magic-prefixed nor lock-shaped is not a lock this
    // build wrote or a build before it wrote: refuse to judge it, so a sibling
    // log at the lock path is never stolen and deleted (R-13 round 14, F4). An
    // empty file stays identifiable as "interrupted creator", and a legacy
    // `<nonce> pid <pid> started <ms>` line stays stealable, so a crashed writer
    // from an older build does not wedge the log for ever.
    if !body.trim().is_empty() && !looks_like_a_lock(body) {
        return None;
    }
    let mut words = body.split_whitespace();
    let nonce = words.next().unwrap_or_default().to_string();
    let mut pid = None;
    while let Some(word) = words.next() {
        if word == "pid" {
            pid = words.next().and_then(|value| value.parse().ok());
            break;
        }
    }
    Some((nonce, pid))
}

/// The nonce of the file at `path`, if it can be read.
fn nonce_of(path: &std::path::Path) -> Option<String> {
    if !std::fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    read_lock(&file).map(|(nonce, _)| nonce)
}

/// Whether a line is the shape every writer since the first build has written.
///
/// `<nonce> pid <pid> started <ms>`; the magic prefix is optional. Anything
/// else at the lock path is somebody else's file.
fn looks_like_a_lock(body: &str) -> bool {
    let mut words = body.split_whitespace();
    let Some(_nonce) = words.next() else {
        return false;
    };
    matches!(
        (words.next(), words.next(), words.next(), words.next()),
        (Some("pid"), Some(pid), Some("started"), Some(start))
            if pid.parse::<u32>().is_ok() && start.parse::<u64>().is_ok()
    )
}

/// A nonce rendered safe to use in a file name.
///
/// A lock is a file an attacker can plant: a nonce with a separator or a `..`
/// must not steer the claim path anywhere else.
/// Refuse a log path that is a symlink.
///
/// A link planted in the log's directory would make every append write through
/// it (and `repair` truncate through it), so the type is checked without
/// following it (R-13 round 9, L2).
/// Open the log for writing through a handle that is verified to be a regular
/// file.
///
/// The path check before an open cannot be atomic with it, so the open itself
/// refuses a symlink (`O_NOFOLLOW`) and the handle's own metadata decides
/// (R-13 round 13, F2). `read` adds `O_RDONLY`-style access for `repair`, which
/// walks and truncates the same inode.
fn open_log_write(path: &std::path::Path, append: bool, read: bool) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    if read {
        options.read(true);
    }
    if append {
        options.append(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| Error::receipt("cannot open the receipt log for writing"))?;
    let meta = file
        .metadata()
        .map_err(|_| Error::receipt("cannot inspect the receipt log"))?;
    if !meta.file_type().is_file() {
        return Err(Error::receipt("the receipt log is not a regular file"));
    }
    Ok(file)
}

/// Open a log for reading, refusing a symlink at the open.
///
/// The reader used a plain `File::open` and relied on a post-hoc identity
/// check, so a reparse point swapped in between the type check and the open
/// redirected it on every platform, and on unix the `O_NOFOLLOW` the manifest
/// claimed for "write and read opens" was missing (R-13 round 14, F2).
fn open_log_read(path: &std::path::Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| Error::receipt("cannot read the receipt log"))?;
    let meta = file
        .metadata()
        .map_err(|_| Error::receipt("cannot inspect the receipt log"))?;
    if !meta.file_type().is_file() {
        return Err(Error::receipt("the receipt log is not a regular file"));
    }
    Ok(file)
}

/// Refuse a log path that is not a regular file, before opening it for write.
///
/// A symlink check alone lets a FIFO or a device block the open; the type rule
/// is the one `read_capped` uses (R-13 round 11, L-5).
fn refuse_writable_regular(path: &std::path::Path) -> Result<()> {
    refuse_symlink(path)?;
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            return Err(Error::receipt("the receipt log is not a regular file"));
        }
    }
    Ok(())
}

fn refuse_symlink(path: &std::path::Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            Err(Error::receipt("the receipt log path is a symlink"))
        }
        _ => Ok(()),
    }
}

fn claim_name(nonce: &str) -> Option<String> {
    let cleaned: String = nonce
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '-')
        .take(64)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// The file name of `path`, as text, for deriving a sibling name.
/// Move a written header onto the log path.
///
/// Ownership is re-checked immediately before the rename: a creator suspended
/// past the grace can resume to find its lock stolen, and installing a fresh
/// header over a log the new owner is appending to destroys every record
/// (R-13 round 11, H-1). On unix the parent directory is flushed so `create`
/// does not return Ok for a name that a power loss forgets; that flush is
/// best-effort and has no Windows equivalent here, so the durability guarantee
/// is a unix one (L-6; round 12, F6).
fn install_staged(
    staging: &std::path::Path,
    path: &std::path::Path,
    lock: &LogLock,
    replacing: bool,
) -> Result<()> {
    if !lock.still_holds() {
        let _ = std::fs::remove_file(staging);
        return Err(Error::receipt(
            "the receipt log lock was displaced by another process",
        ));
    }
    if replacing {
        // `truncate` asked to replace the log: one atomic rename under the held
        // lock. Removing the old name first left a window with no log at all,
        // and a filesystem without hard links could never install (R-13 round
        // 13, F3).
        std::fs::rename(staging, path).map_err(|_| {
            let _ = std::fs::remove_file(staging);
            Error::receipt("cannot install the receipt log header")
        })?;
        sync_parent(path);
        return Ok(());
    }
    // A zero-length file is not evidence (the caller checked that); removing it
    // under the lock lets the exclusive link succeed, as the old rename did.
    if std::fs::metadata(path)
        .map(|metadata| metadata.len() == 0)
        .unwrap_or(false)
    {
        let _ = std::fs::remove_file(path);
    }
    // A `rename` *replaces* its destination: a creator that passes the check
    // and is descheduled before the rename installs a bare header over a log
    // another writer has created and appended to (R-13 round 12, F1). A hard
    // link is exclusive, so the two names can never both be the log.
    match std::fs::hard_link(staging, path) {
        Ok(()) => {
            let _ = std::fs::remove_file(staging);
            sync_parent(path);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(staging);
            Err(Error::receipt(
                "the receipt log was created by another writer",
            ))
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            let _ = std::fs::remove_file(staging);
            Err(Error::receipt(
                "this filesystem does not support an exclusive log install",
            ))
        }
        Err(_) => {
            let _ = std::fs::remove_file(staging);
            Err(Error::receipt("cannot install the receipt log header"))
        }
    }
}

fn sync_parent(path: &std::path::Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Remove aged claim, quarantine, orphan and staging files beside the lock.
///
/// A displaced drop, a crashed steal or a crash mid-header leaves one of each;
/// without a sweep the directory grows one file per attempt, and a local user
/// can make the writer add one per steal (R-13 round 12, F7). Best effort: an
/// entry that cannot be read or removed is left alone, and a live creator's
/// staging file is younger than the ceiling.
fn sweep_leftovers(lock: &std::path::Path) {
    let Some(parent) = lock.parent() else {
        return;
    };
    let Some(name) = lock
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return;
    };
    // The lock is `<log>.lock`; staging and claim files hang off the log stem,
    // so a sweep keyed on the lock name never matched them (R-13 round 13, F4).
    let stem = name
        .strip_suffix(".lock")
        .unwrap_or(name.as_str())
        .to_string();
    let Ok(entries) = std::fs::read_dir(parent) else {
        return;
    };
    let now = std::time::SystemTime::now();
    let mut budget = 32usize;
    for entry in entries.flatten() {
        if budget == 0 {
            break;
        }
        let file = entry.file_name();
        let file = file.to_string_lossy();
        let Some(rest) = file.strip_prefix(stem.as_str()) else {
            continue;
        };
        if !(rest.starts_with(".done-")
            || rest.starts_with(".stale-")
            || rest.starts_with(".orphan-")
            || rest.starts_with(".writing-")
            || rest.starts_with(".lock.done-")
            || rest.starts_with(".lock.stale-")
            || rest.starts_with(".lock.orphan-")
            || rest.starts_with(".lock.writing-"))
        {
            continue;
        }
        // A future mtime is a planted file, the same reading `lock_state`
        // gives it; treating it as fresh let one entry stall the sweep for good
        // (R-13 round 13, F8).
        let aged = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .is_some_and(|modified| match now.duration_since(modified) {
                Ok(age) => age.as_millis() as u64 >= LOCK_STALE_MS,
                Err(_) => true,
            });
        if aged && std::fs::remove_file(entry.path()).is_ok() {
            budget -= 1;
        }
    }
}

fn file_name_text(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "receipt-lock".to_string())
}

impl Drop for LogLock {
    fn drop(&mut self) {
        // Only the owner removes the lock. Moving it to a claim name first, then
        // verifying the moved file, is one winner: a check-then-unlink let a
        // stealer swap the path between the two and this holder delete the new
        // owner's live lock (R-13 round 11, L-4).
        if !self.still_holds() {
            return;
        }
        let claim = self.path.with_file_name(format!(
            "{}.done-{}-{}",
            file_name_text(&self.path),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        if std::fs::rename(&self.path, &claim).is_err() {
            return;
        }
        let ours = {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                match (
                    self.file.as_ref().and_then(|file| file.metadata().ok()),
                    std::fs::symlink_metadata(&claim),
                ) {
                    (Some(held), Ok(moved)) => {
                        held.dev() == moved.dev() && held.ino() == moved.ino()
                    }
                    _ => false,
                }
            }
            #[cfg(not(unix))]
            {
                nonce_of(&claim).as_deref() == Some(self.nonce.as_str())
            }
        };
        if ours {
            let _ = std::fs::remove_file(&claim);
        } else if !self.path.exists() {
            // Not ours: never destroy it, put it back when the path is free.
            let _ = std::fs::rename(&claim, &self.path);
        }
    }
}

/// An append-only receipt log on disk.
///
/// The file is `ARRL | version 2 | flags [3] | start_sequence u64` followed by
/// records. Each record carries its length, the receipt fields, its decision and
/// a chain hash over the previous record's hash and this record, so corruption,
/// reordering and a truncation *within* the chain are detectable without the
/// kernel secret.
///
/// The chain is **not** authenticated: a writer who can rewrite the file can
/// also recompute the links. Authenticity comes from the receipt `mac`, which
/// needs the derived receipt key ([`derive_receipt_key`],
/// [`ReceiptLog::verify_macs`]); truncation of the tail is caught by pinning the
/// head ([`ReceiptLog::verify_against`]).
///
/// The log holds correlation ids, method names, times and decisions: no
/// arguments, values or secret material.
#[derive(Debug, Clone)]
pub struct ReceiptLog {
    path: std::path::PathBuf,
    state: std::sync::Arc<std::sync::Mutex<LogState>>,
}

impl ReceiptLog {
    /// Create (or truncate) a log whose first record is sequence 1.
    ///
    /// Evidence is not overwritten silently: a path that already holds a
    /// non-empty log is refused. Use [`ReceiptLog::truncate`] when starting over
    /// is the intent.
    pub fn create(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        Self::create_starting_at(path, 1)
    }

    /// Create a log whose first record is `start_sequence`.
    ///
    /// A kernel ring that has wrapped exports its retained window this way: the
    /// window is honest about where it starts, and [`Decision`] plus
    /// `Agent::receipts_dropped` say what came before.
    pub fn create_starting_at(
        path: impl Into<std::path::PathBuf>,
        start_sequence: u64,
    ) -> Result<Self> {
        Self::create_locked(path.into(), start_sequence, false)
    }

    /// Create or truncate a log, discarding any existing evidence.
    ///
    /// This is the explicit "start over" entry point; [`ReceiptLog::create`]
    /// refuses to overwrite.
    pub fn truncate(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        Self::create_locked(path.into(), 1, true)
    }

    /// Create a log while holding the writer lock.
    ///
    /// The lock matters: `File::create` truncates, so a create that raced an
    /// append in another process would leave the appender writing into a fresh
    /// header and the log born corrupt.
    fn create_locked(
        path: std::path::PathBuf,
        start_sequence: u64,
        replacing: bool,
    ) -> Result<Self> {
        if start_sequence == 0 {
            return Err(Error::receipt("a log cannot start at sequence 0"));
        }
        // A start this close to the ceiling could not be numbered to the record
        // limit, and `walk_log` would refuse the result of its own writer.
        if start_sequence > u64::MAX - MAX_LOG_RECORDS {
            return Err(Error::receipt(
                "a log cannot start that close to the sequence ceiling",
            ));
        }
        let lock = LogLock::acquire(&path)?;
        if !lock.still_holds() {
            return Err(Error::receipt(
                "the receipt log lock was displaced by another process",
            ));
        }
        // Any existing content is refused, not just content that looks like
        // records: a truncated file is still evidence, and silently replacing it
        // is exactly what `truncate` exists for.
        if !replacing
            && std::fs::metadata(&path)
                .map(|metadata| metadata.len() > 0)
                .unwrap_or(false)
        {
            return Err(Error::receipt(
                "the receipt log already holds records; truncate it explicitly",
            ));
        }
        let log = Self {
            path: path.clone(),
            state: std::sync::Arc::new(std::sync::Mutex::new(LogState {
                bytes: LOG_HEADER_LEN as u64,
                count: 0,
                start: start_sequence,
                head: [0u8; 32],
                last_ms: 0,
                identity: None,
                modified: None,
            })),
        };
        let mut header = Vec::with_capacity(LOG_HEADER_LEN);
        header.extend_from_slice(LOG_MAGIC);
        header.push(LOG_VERSION);
        header.extend_from_slice(&[0u8; 3]);
        header.extend_from_slice(&start_sequence.to_le_bytes());
        // Write beside the target and rename: a crash mid-header must not leave
        // a file that `open`, `repair` and `create` all refuse. The staging name
        // is unique and created with `create_new`: a fixed name is a symlink an
        // attacker plants in the directory so the process truncates a privileged
        // file and leaves the log path pointing at it (R-13 round 5, #3).
        let staging = path.with_file_name(format!(
            "{}.writing-{}-{}",
            file_name_text(&path),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staging)
                .map_err(|_| Error::receipt("cannot create the receipt log"))?;
            let written = file.write_all(&header).and_then(|()| file.sync_all());
            if written.is_err() {
                let _ = std::fs::remove_file(&staging);
                return Err(Error::receipt("cannot write the receipt log header"));
            }
        }
        install_staged(&staging, &path, &lock, replacing)?;
        Ok(log)
    }

    /// Open an existing log without creating or truncating it.
    ///
    /// The header is checked and the state is read once; records are verified on
    /// every read.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let path = path.into();
        let (_, _, state) = read_stable(&path)?;
        Ok(Self {
            path,
            state: std::sync::Arc::new(std::sync::Mutex::new(state)),
        })
    }

    /// Path of the log file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Verify a log held in memory (used by tools and the fuzz target).
    pub fn verify_bytes(bytes: &[u8]) -> Result<Vec<Receipt>> {
        walk_log(bytes).map(|(receipts, _)| receipts)
    }

    /// Append one receipt **without** checking its MAC.
    ///
    /// The chain is integrity, not authenticity: a local writer can extend it.
    /// A deployment that needs the artifact to be evidence calls
    /// [`ReceiptLog::append_verified`], which refuses a record whose MAC is not
    /// the one this kernel's receipt key produces (R-13 round 12, F8).
    pub fn append(&self, receipt: &Receipt) -> Result<()> {
        self.append_all(std::slice::from_ref(receipt))
    }

    /// Append a batch of receipts without checking their `mac`.
    ///
    /// The unverified writer: see [`ReceiptLog::append`]. The tests use it to
    /// build logs with chosen fields; a deployment should use
    /// [`ReceiptLog::append_verified`].
    ///
    /// The sequence must continue the log exactly, every method must be
    /// representable, and the batch is refused before anything is written when
    /// one record would break a ceiling. For a batch that should also be
    /// authenticated, use [`ReceiptLog::append_verified`].
    pub fn append_all(&self, receipts: &[Receipt]) -> Result<()> {
        self.append_inner(receipts)
    }

    /// Append a batch after checking every receipt `mac` under `key`.
    ///
    /// `key` is the kernel's receipt key ([`derive_receipt_key`],
    /// [`crate::Agent::receipt_key`]), not the kernel secret. This is the owner
    /// path: the writer proves it is the kernel that produced the receipts, so
    /// the log cannot be extended with fabricated records by a party that has
    /// write access but not the key.
    pub fn append_verified(&self, key: &[u8; 32], receipts: &[Receipt]) -> Result<()> {
        for receipt in receipts {
            if !receipt.verify(key) {
                return Err(Error::receipt("a receipt was not produced by this kernel"));
            }
        }
        self.append_inner(receipts)
    }

    fn append_inner(&self, receipts: &[Receipt]) -> Result<()> {
        if receipts.is_empty() {
            return Ok(());
        }
        let lock = LogLock::acquire(&self.path)?;
        // The walk below can take a while (up to a full re-read); keep the lock
        // fresh so a slow walk is not read as an abandoned writer
        // (R-13 round 10, A).
        lock.touch();
        if !lock.still_holds() {
            // The path no longer carries our nonce: another process displaced
            // this lock, and a second writer may hold the path. Refusing keeps
            // one chain in the file (R-13 round 8, M1).
            return Err(Error::receipt(
                "the receipt log lock was displaced by another process",
            ));
        }
        // Re-read only when the file changed under us (a foreign writer appended
        // or replaced it); the common case is one stat and one write.
        let observed = std::fs::metadata(&self.path)
            .map_err(|_| Error::receipt("cannot stat the receipt log"))?
            .len();
        let mut state = {
            let cached = *self
                .state
                .lock()
                .map_err(|_| Error::receipt("the receipt log state is poisoned"))?;
            // Size alone is not enough: a replacement that happens to have the
            // same length (a fresh header of another start sequence, for
            // instance) would let the append write a sequence the header does
            // not number, producing a log nothing can walk.
            let usable = cached.bytes == observed
                // A copy swapped over the path keeps every other check: same
                // length, same header, same trailing head (its middle record
                // is the one edited). The inode is what a copy cannot keep
                // (R-13 round 14, F1).
                && identity_matches(&self.path, cached.identity)
                && cached.modified.is_some()
                && cached.modified == path_modified(&self.path)
                && read_header_start(&self.path) == Some(cached.start)
                // A replacement of exactly the same length would pass the two
                // checks above while its trailing head is another chain: the
                // append would link to a head the file does not carry, and
                // nothing could read the log again.
                && read_tail_head(&self.path) == Some(cached.head);
            if usable {
                cached
            } else {
                let (bytes, identity, modified) = read_capped_with_identity(&self.path)?;
                let (_, mut walked) = walk_log(&bytes)?;
                walked.identity = identity;
                walked.modified = modified;
                walked
            }
        };
        if state.count >= MAX_LOG_RECORDS {
            return Err(Error::receipt("the receipt log exceeds the record ceiling"));
        }
        let mut out = Vec::new();
        let mut previous = state.head;
        let mut count = state.count;
        let mut last_ms = state.last_ms;
        for receipt in receipts {
            // `checked_add`, like the reader: a sequence this close to the
            // ceiling must be refused here rather than written and unreadable.
            let expected = state
                .start
                .checked_add(count)
                .ok_or_else(|| Error::receipt("receipt sequence overflows"))?;
            if receipt.sequence != expected {
                return Err(Error::receipt(
                    "receipt sequence does not follow the log order",
                ));
            }
            if receipt.at_ms < last_ms {
                return Err(Error::receipt("receipt time runs backwards"));
            }
            let record = encode_record(receipt, &previous)?;
            previous.copy_from_slice(&record[record.len() - 32..]);
            out.extend_from_slice(&record);
            last_ms = receipt.at_ms;
            count += 1;
            // Apply both ceilings as they are crossed, so an oversized batch is
            // refused before the rest of it is encoded and allocated.
            let total = observed
                .checked_add(out.len() as u64)
                .ok_or_else(|| Error::receipt("the receipt log is too large"))?;
            if total > MAX_LOG_BYTES {
                return Err(Error::receipt("the receipt log exceeds the size ceiling"));
            }
            if count > MAX_LOG_RECORDS {
                return Err(Error::receipt("the receipt log exceeds the record ceiling"));
            }
        }
        let total = observed
            .checked_add(out.len() as u64)
            .ok_or_else(|| Error::receipt("the receipt log is too large"))?;
        self.write_all(&out, &lock)?;
        state.bytes = total;
        state.count = count;
        state.head = previous;
        state.last_ms = last_ms;
        if let Ok(mut cached) = self.state.lock() {
            *cached = state;
        }
        Ok(())
    }

    fn write_all(&self, bytes: &[u8], lock: &LogLock) -> Result<()> {
        use std::io::Write;
        // Ownership is re-checked **here**, immediately before the write: the
        // acquire-time check is followed by a state walk (and, on a repaired
        // log, a full read), so a writer displaced in between must not append a
        // second chain (R-13 round 10, A). Only an OS lock on the log handle
        // would close the window completely.
        if !lock.still_holds() {
            return Err(Error::receipt(
                "the receipt log lock was displaced by another process",
            ));
        }
        refuse_writable_regular(&self.path)?;
        let mut file = open_log_write(&self.path, true, false)?;
        // A batch larger than the stale ceiling on slow storage must not look
        // abandoned while it is being written: refresh the lock between bounded
        // chunks. The crash semantics are unchanged — a partial trailing record
        // is what the reader already refuses and `repair` cuts.
        let mut offset = 0;
        while offset < bytes.len() {
            // Per chunk, not once per batch: a displaced writer that keeps
            // appending interleaves a second chain inside the records, which
            // `repair` refuses to cut (R-13 round 13, F1).
            if !lock.still_holds() {
                return Err(Error::receipt(
                    "the receipt log lock was displaced by another process",
                ));
            }
            let end = (offset + WRITE_CHUNK_BYTES).min(bytes.len());
            file.write_all(&bytes[offset..end])
                .map_err(|_| Error::receipt("cannot append to the receipt log"))?;
            offset = end;
            lock.touch();
        }
        if !lock.still_holds() {
            return Err(Error::receipt(
                "the receipt log lock was displaced by another process",
            ));
        }
        file.sync_data()
            .map_err(|_| Error::receipt("cannot flush the receipt log"))?;
        Ok(())
    }

    /// Every receipt in the log, in order, with the chain verified.
    pub fn records(&self) -> Result<Vec<Receipt>> {
        read_stable(&self.path).map(|(_, receipts, _)| receipts)
    }

    /// One read of the whole log: records, start, head and last time.
    ///
    /// A verifier that needs more than one of those should use this rather than
    /// call four accessors: each accessor reads and walks the file again, and a
    /// writer appending in between would make the answers describe different
    /// bytes (a head the MAC check never covered, for instance).
    pub fn snapshot(&self) -> Result<Snapshot> {
        let (_, receipts, state) = read_stable(&self.path)?;
        Ok(Snapshot {
            receipts,
            start: state.start,
            head: state.head,
            last_ms: state.last_ms,
        })
    }

    /// Verify the chain only (no key needed).
    ///
    /// This detects corruption and reordering. It does **not** prove the log was
    /// produced by a particular kernel: that needs [`ReceiptLog::verify_macs`].
    pub fn verify_chain(&self) -> Result<()> {
        self.records().map(|_| ())
    }

    /// Verify the chain and every receipt's `mac` under the receipt key.
    pub fn verify_macs(&self, key: &[u8; 32]) -> Result<()> {
        self.snapshot()?.verify_macs(key)
    }

    /// Verify the chain and that the head is the pinned one.
    ///
    /// A verifier that learned the head out of band detects a truncated tail,
    /// which the per-record links alone cannot.
    pub fn verify_against(&self, expected: [u8; 32]) -> Result<()> {
        self.snapshot()?.verify_against(expected)
    }

    /// Repair a log whose last write was interrupted.
    ///
    /// A crash between the `write_all` and the `sync_data`, or a full disk,
    /// can leave a partial trailing record. The reader refuses it (correctly:
    /// the file is damaged), and every later append fails because the state
    /// cannot be walked, which would turn one crash into a permanent stop in the
    /// audit trail. This truncates the file back to the last complete record and
    /// reports how many bytes were discarded; the chain of the surviving records
    /// is verified before anything is cut, so a damaged record *inside* the log
    /// is refused rather than trimmed.
    pub fn repair_tail(&self) -> Result<u64> {
        let discarded = Self::repair(&self.path)?;
        if let Ok(bytes) = read_capped(&self.path) {
            if let Ok((_, state)) = walk_log(&bytes) {
                if let Ok(mut cached) = self.state.lock() {
                    *cached = state;
                }
            }
        }
        Ok(discarded)
    }

    /// Repair a damaged log file without opening it first.
    ///
    /// [`ReceiptLog::open`] refuses a damaged file, so a caller that wants to
    /// repair one needs an entry point that does not require a valid handle.
    /// Returns the number of bytes discarded.
    ///
    /// Only a genuinely interrupted write is cut: the tail must be a record
    /// whose declared length runs past the end of the file *and* must not
    /// contain a complete record at any offset. A length field corrupted to
    /// another in-range value looks torn by its own declaration, but the records
    /// after it still decode, so that case is refused rather than silently
    /// discarded.
    pub fn repair(path: impl Into<std::path::PathBuf>) -> Result<u64> {
        let path = path.into();
        let lock = LogLock::acquire(&path)?;
        if !lock.still_holds() {
            return Err(Error::receipt(
                "the receipt log lock was displaced by another process",
            ));
        }
        // One handle for the walk and the truncation. The bytes are read from
        // the very file `set_len` will act on, so a path swapped between a read
        // and a later open cannot be truncated (R-13 round 13, F2).
        refuse_writable_regular(&path)?;
        let mut file = open_log_write(&path, false, true)?;
        let mut bytes = Vec::new();
        {
            use std::io::Read;
            file.by_ref()
                .take(MAX_LOG_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)
                .map_err(|_| Error::receipt("cannot read the receipt log to repair it"))?;
        }
        if bytes.len() as u64 > MAX_LOG_BYTES {
            return Err(Error::receipt("the receipt log is too large"));
        }
        // A log that already walks is intact: repair has nothing to do.
        if walk_log(&bytes).is_ok() {
            return Ok(0);
        }
        verify_header(&bytes)?;
        let (_, good_end) = walk_prefix(&bytes);
        let tail = &bytes[good_end..];
        let declared_past_end = if tail.len() < 4 {
            true
        } else {
            let length = u32::from_le_bytes(tail[..4].try_into().expect("4 bytes")) as usize;
            (MIN_LOG_RECORD..=MAX_LOG_RECORD).contains(&length)
                && good_end + 4 + length > bytes.len()
        };
        if !declared_past_end || tail_holds_a_record(tail) {
            return Err(Error::receipt(
                "the log is damaged inside its records; repair cannot cut it",
            ));
        }
        let remaining = tail.len();
        // The prefix must itself be a valid log, or the cut would keep damage.
        let (_, state) = walk_log(&bytes[..good_end])?;
        // The same check as the append: a repair that lost its lock must not
        // truncate a log another writer now owns (R-13 round 10, A).
        if !lock.still_holds() {
            return Err(Error::receipt(
                "the receipt log lock was displaced by another process",
            ));
        }
        file.set_len(good_end as u64)
            .map_err(|_| Error::receipt("cannot truncate the damaged tail"))?;
        file.sync_all()
            .map_err(|_| Error::receipt("cannot flush the repaired log"))?;
        let _ = state;
        Ok(remaining as u64)
    }

    /// Hash of the last record (the chain head), or zeros for an empty log.
    pub fn head_hash(&self) -> Result<[u8; 32]> {
        read_stable(&self.path).map(|(_, _, state)| state.head)
    }

    /// Sequence of the first record.
    pub fn start_sequence(&self) -> Result<u64> {
        read_stable(&self.path).map(|(_, _, state)| state.start)
    }

    /// Number of records.
    pub fn len(&self) -> Result<u64> {
        read_stable(&self.path).map(|(_, _, state)| state.count)
    }

    /// True when the log holds no records.
    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|count| count == 0)
    }
}

/// Whether a correlation id is the form the reader accepts.
fn valid_correlation_id(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Read only the 16-byte header and return its start sequence.
///
/// Used to tell a cached state from a file that was replaced with the same
/// length, which a size comparison cannot see.
fn read_header_start(path: &std::path::Path) -> Option<u64> {
    use std::io::Read;
    // A non-regular file at the path would block `open`; the type check is not
    // atomic with the open, but it keeps a planted FIFO from hanging the writer
    // (R-13 round 10, C).
    if !std::fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    let mut header = [0u8; LOG_HEADER_LEN];
    let mut file = open_log_read(path).ok()?;
    file.read_exact(&mut header).ok()?;
    if &header[..4] != LOG_MAGIC {
        return None;
    }
    // The whole header decides which log this is: a version flip or a set
    // reserved flag is a different format that a cached state must not be
    // trusted against (R-13 round 14, F1).
    if header[4] != LOG_VERSION || header[5..8] != [0, 0, 0] {
        return None;
    }
    Some(u64::from_le_bytes(
        header[8..16].try_into().expect("8 bytes"),
    ))
}

/// The trailing head of a log: the record hash of its last complete record.
///
/// A record's hash is its last 32 bytes, so the last 32 bytes of
/// the file are the head an append links to.
fn read_tail_head(path: &std::path::Path) -> Option<[u8; 32]> {
    use std::io::{Read, Seek, SeekFrom};
    if !std::fs::symlink_metadata(path).ok()?.file_type().is_file() {
        return None;
    }
    let mut file = open_log_read(path).ok()?;
    let length = file.metadata().ok()?.len();
    if length < (LOG_HEADER_LEN + 32) as u64 {
        return None;
    }
    file.seek(SeekFrom::End(-32)).ok()?;
    let mut head = [0u8; 32];
    file.read_exact(&mut head).ok()?;
    Some(head)
}

/// Read a log file under the size ceiling, refusing a larger one without
/// allocating it.
fn read_capped(path: &std::path::Path) -> Result<Vec<u8>> {
    read_capped_with_identity(path).map(|(bytes, _, _)| bytes)
}

/// The identity of an open file on unix: `(dev, ino)`.
#[cfg(unix)]
fn file_identity(file: &std::fs::File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().ok()?;
    Some((meta.dev(), meta.ino()))
}

/// The identity of a path on unix, without following a link.
#[cfg(unix)]
fn path_identity(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    Some((meta.dev(), meta.ino()))
}

/// Off unix there is no stable inode at the MSRV: the fast path and the reader
/// fall back to the length and header checks, and the residual is stated in
/// ADR-0021 (R-13 round 14, F2).
#[cfg(not(unix))]
#[cfg_attr(not(unix), allow(dead_code))]
fn path_identity(_path: &std::path::Path) -> Option<(u64, u64)> {
    None
}

/// The path's modification time, without following a link.
fn path_modified(path: &std::path::Path) -> Option<std::time::SystemTime> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    meta.modified().ok()
}

/// Whether the path still names the file the state was walked from.
///
/// On unix a state with no recorded identity cannot be trusted, so the fast
/// path re-walks. Off unix there is nothing to compare, and the documented
/// residual applies (R-13 round 14, F1/F2).
fn identity_matches(path: &std::path::Path, identity: Option<(u64, u64)>) -> bool {
    #[cfg(unix)]
    {
        identity.is_some() && identity == path_identity(path)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, identity);
        true
    }
}

/// Whether the path still names the file that was read.
///
/// On unix `(dev, ino)` decides; elsewhere the read and the length check are
/// all that is available (the residual the ADR records).
fn same_identity(path: &std::path::Path, identity: Option<(u64, u64)>) -> bool {
    #[cfg(unix)]
    {
        identity.is_some() && path_identity(path) == identity
    }
    #[cfg(not(unix))]
    {
        let _ = (path, identity);
        true
    }
}

/// The bytes read, and the identity of the handle that read them.
type ReadLog = (Vec<u8>, Option<(u64, u64)>, Option<std::time::SystemTime>);

/// Read the log and report the identity of the handle that was read.
fn read_capped_with_identity(path: &std::path::Path) -> Result<ReadLog> {
    use std::io::Read;
    // Opening a FIFO or a device here would block for ever: refuse anything that
    // is not a regular file, without following a link (R-13 round 9, F5).
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            return Err(Error::receipt("the receipt log is not a regular file"));
        }
    }
    let file = open_log_read(path)?;
    let identity = {
        #[cfg(unix)]
        {
            file_identity(&file)
        }
        #[cfg(not(unix))]
        {
            None
        }
    };
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::receipt("cannot read the receipt log"))?;
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(Error::receipt("the receipt log exceeds the size ceiling"));
    }
    let modified = path_modified(path);
    Ok((bytes, identity, modified))
}

/// True when a writer is, or very recently was, appending.
fn writer_active(path: &std::path::Path) -> bool {
    // The stealer's own rule, so "not active" for a reader means "stealable" for
    // a writer. A separate short window made the two disagree: a 30-second-old
    // lock was final for a reader and live for a stealer, so a slow append read
    // as a damaged log (R-13 round 8, M2).
    let Some((age_ms, _nonce, pid)) = lock_state(&lock_path(path)) else {
        return false;
    };
    lock_is_live(age_ms, pid)
}

/// Read and walk a log, tolerating a read that lands mid-append.
///
/// A reader does not take the writer's lock, so a file system that writes a
/// large batch in more than one syscall can expose two shapes: a torn trailing
/// record (the walk fails) and a boundary-aligned prefix (the walk succeeds, but
/// the file holds fewer records than the writer has already appended). Both
/// settle when the writer finishes, so both wait — the second shape is what made
/// a snapshot report a head the file had already moved past (R-13 round 5, #5).
/// The wait is bounded, and a reader only waits while the lock is fresh: a
/// damaged file with a stale lock still fails.
fn read_stable(path: &std::path::Path) -> Result<(Vec<u8>, Vec<Receipt>, LogState)> {
    let mut last_error: Option<Error> = None;
    let mut previous_len = usize::MAX;
    for attempt in 0..11u32 {
        // Probe *before* the read as well as after: a writer that finished
        // between the read and the probe used to leave a boundary-aligned
        // prefix final (R-13 round 12, F4).
        if writer_active(path) {
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        let (bytes, identity, _) = read_capped_with_identity(path)?;
        let walked = walk_log(&bytes);
        let length_now = std::fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(u64::MAX);
        let active = writer_active(path);
        let same_file = same_identity(path, identity);
        match walked {
            // A complete walk is final only when no writer is appending, the
            // path still holds exactly the bytes that were walked, and it is
            // still the file that was read (a same-length replacement between
            // the read and the stat is a different log).
            Ok((receipts, state)) if !active && length_now == bytes.len() as u64 && same_file => {
                return Ok((bytes, receipts, state));
            }
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }
        let grew = bytes.len() != previous_len;
        previous_len = bytes.len();
        if attempt > 0 && !active && !grew && length_now == bytes.len() as u64 {
            // Nothing is being written and the bytes stopped changing: the file
            // is what it is.
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let (bytes, identity, _) = read_capped_with_identity(path)?;
    let length_now = std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(u64::MAX);
    let active = writer_active(path);
    let same_file = same_identity(path, identity);
    match walk_log(&bytes) {
        // The bound ran out while a writer was still working, or the file moved
        // under the read: a complete walk of the old bytes is a prefix of its
        // batch, and returning it would publish a head the file has already
        // moved past (R-13 round 7, #5; round 12, F4).
        Ok(_) if active || length_now != bytes.len() as u64 || !same_file => {
            Err(Error::receipt(writer_description(path)))
        }
        Ok((receipts, state)) => Ok((bytes, receipts, state)),
        Err(error) => {
            if active {
                Err(Error::receipt(writer_description(path)))
            } else {
                Err(last_error.unwrap_or(error))
            }
        }
    }
}

/// Encode one record: `len u32 | sequence u64 | at_ms u64 | decision u8 |
/// code_len u16 | code | cap_len u16 | cap | method_len u16 | method | mac [32]
/// | prev [32] | record_hash [32]`.
fn encode_record(receipt: &Receipt, previous: &[u8; 32]) -> Result<Vec<u8>> {
    // The writer applies the reader's rules, and it applies *all* of them: a
    // record this accepts and the reader rejects would make the whole log
    // unreadable, and nothing could be appended after it. `fields_are_
    // representable` is the reader's own predicate, so the two cannot drift.
    if !receipt.fields_are_representable() {
        return Err(Error::receipt(
            "a receipt is not representable in a log record",
        ));
    }
    let code = receipt.decision.code().as_bytes();
    let code_len =
        u16::try_from(code.len()).map_err(|_| Error::receipt("a decision code is too long"))?;
    let mut body = Vec::with_capacity(96 + receipt.method.len() + code.len());
    body.extend_from_slice(&receipt.sequence.to_le_bytes());
    body.extend_from_slice(&receipt.at_ms.to_le_bytes());
    body.push(receipt.decision.flag());
    body.extend_from_slice(&code_len.to_le_bytes());
    body.extend_from_slice(code);
    body.extend_from_slice(&(receipt.cap.len() as u16).to_le_bytes());
    body.extend_from_slice(receipt.cap.as_bytes());
    body.extend_from_slice(&(receipt.method.len() as u16).to_le_bytes());
    body.extend_from_slice(receipt.method.as_bytes());
    body.extend_from_slice(&receipt.mac);
    body.extend_from_slice(previous);

    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_DOMAIN);
    hasher.update(&body);
    let record_hash = *hasher.finalize().as_bytes();

    let mut out = Vec::with_capacity(4 + body.len() + 32);
    let total =
        u32::try_from(body.len() + 32).map_err(|_| Error::receipt("a record is too large"))?;
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(&body);
    out.extend_from_slice(&record_hash);
    Ok(out)
}

fn decode_record(bytes: &[u8], cursor: usize) -> Result<(Receipt, [u8; 32], [u8; 32], usize)> {
    let header = bytes
        .get(cursor..cursor + 4)
        .ok_or_else(|| Error::receipt("truncated record length"))?;
    let length = u32::from_le_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if !(MIN_LOG_RECORD..=MAX_LOG_RECORD).contains(&length) {
        return Err(Error::receipt("record length is out of range"));
    }
    let start = cursor + 4;
    let end = start
        .checked_add(length)
        .ok_or_else(|| Error::receipt("record length overflows"))?;
    let record = bytes
        .get(start..end)
        .ok_or_else(|| Error::receipt("truncated record"))?;
    let (body, stored_hash) = record.split_at(length - 32);

    let mut cursor = 0usize;
    let sequence = u64::from_le_bytes(
        body.get(..8)
            .ok_or_else(|| Error::receipt("truncated sequence"))?
            .try_into()
            .expect("8 bytes"),
    );
    cursor += 8;
    let at_ms = u64::from_le_bytes(
        body.get(cursor..cursor + 8)
            .ok_or_else(|| Error::receipt("truncated time"))?
            .try_into()
            .expect("8 bytes"),
    );
    cursor += 8;
    let flag = *body
        .get(cursor)
        .ok_or_else(|| Error::receipt("truncated decision"))?;
    cursor += 1;
    let code_len = u16::from_le_bytes(
        body.get(cursor..cursor + 2)
            .ok_or_else(|| Error::receipt("truncated decision length"))?
            .try_into()
            .expect("2 bytes"),
    ) as usize;
    cursor += 2;
    let code = body
        .get(cursor..cursor + code_len)
        .ok_or_else(|| Error::receipt("truncated decision code"))?;
    cursor += code_len;
    let cap_len = u16::from_le_bytes(
        body.get(cursor..cursor + 2)
            .ok_or_else(|| Error::receipt("truncated cap length"))?
            .try_into()
            .expect("2 bytes"),
    ) as usize;
    cursor += 2;
    let cap = body
        .get(cursor..cursor + cap_len)
        .ok_or_else(|| Error::receipt("truncated correlation id"))?;
    cursor += cap_len;
    let method_len = u16::from_le_bytes(
        body.get(cursor..cursor + 2)
            .ok_or_else(|| Error::receipt("truncated method length"))?
            .try_into()
            .expect("2 bytes"),
    ) as usize;
    cursor += 2;
    let method = body
        .get(cursor..cursor + method_len)
        .ok_or_else(|| Error::receipt("truncated method"))?;
    cursor += method_len;
    let mac: [u8; 32] = body
        .get(cursor..cursor + 32)
        .ok_or_else(|| Error::receipt("truncated mac"))?
        .try_into()
        .expect("32 bytes");
    cursor += 32;
    let previous: [u8; 32] = body
        .get(cursor..cursor + 32)
        .ok_or_else(|| Error::receipt("truncated chain link"))?
        .try_into()
        .expect("32 bytes");
    cursor += 32;
    if cursor != body.len() {
        return Err(Error::receipt("trailing bytes in a record"));
    }

    let cap = String::from_utf8(cap.to_vec())
        .map_err(|_| Error::receipt("correlation id is not text"))?;
    let method =
        String::from_utf8(method.to_vec()).map_err(|_| Error::receipt("method is not text"))?;
    if !valid_correlation_id(&cap) {
        return Err(Error::receipt(
            "correlation id is not 16 lowercase hex characters",
        ));
    }
    if !valid_method(&method) {
        return Err(Error::receipt(
            "a receipt method must be 1..=1024 bytes without control characters",
        ));
    }
    let code =
        std::str::from_utf8(code).map_err(|_| Error::receipt("decision code is not text"))?;
    let decision = match flag {
        0 if code.is_empty() => Decision::Admitted,
        // A refusal code is bounded text from a fixed character set, so it can
        // neither forge a log line nor grow a record without limit.
        1 if valid_code(code) => Decision::Refused(code.to_string()),
        _ => return Err(Error::receipt("malformed decision")),
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_DOMAIN);
    hasher.update(body);
    let expected = *hasher.finalize().as_bytes();
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(stored_hash.iter()) {
        difference |= left ^ right;
    }
    if difference != 0 {
        return Err(Error::receipt("record hash does not match its contents"));
    }
    Ok((
        Receipt {
            sequence,
            cap,
            method,
            at_ms,
            decision,
            mac,
        },
        previous,
        expected,
        end,
    ))
}

fn verify_header(bytes: &[u8]) -> Result<u64> {
    if bytes.len() < LOG_HEADER_LEN {
        return Err(Error::receipt("log is shorter than its header"));
    }
    if &bytes[..4] != LOG_MAGIC {
        return Err(Error::receipt("bad log magic"));
    }
    if bytes[4] != LOG_VERSION {
        return Err(Error::receipt("unsupported log version"));
    }
    if bytes[5..8] != [0u8; 3] {
        return Err(Error::receipt("reserved header bytes must be zero"));
    }
    let start = u64::from_le_bytes(bytes[8..16].try_into().expect("8 bytes"));
    if start == 0 {
        return Err(Error::receipt("a log cannot start at sequence 0"));
    }
    Ok(start)
}

/// Decode a whole log, verify every record hash, every chain link, the sequence
/// order (from the header's start) and the time order, and return the receipts
/// with the tail state.
fn walk_log(bytes: &[u8]) -> Result<(Vec<Receipt>, LogState)> {
    let start = verify_header(bytes)?;
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(Error::receipt("the receipt log exceeds the size ceiling"));
    }
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut cursor = LOG_HEADER_LEN;
    let mut expected_previous = [0u8; 32];
    let mut last_time: Option<u64> = None;
    while cursor < bytes.len() {
        if receipts.len() as u64 >= MAX_LOG_RECORDS {
            return Err(Error::receipt("the receipt log exceeds the record ceiling"));
        }
        let (receipt, previous, record_hash, next) = decode_record(bytes, cursor)?;
        if previous != expected_previous {
            // Name the sequence, not the index: an exported window can start
            // anywhere, so "record 2" is ambiguous evidence.
            return Err(Error::receipt(format!(
                "sequence {} does not link to the previous one",
                receipt.sequence
            )));
        }
        let expected = start
            .checked_add(receipts.len() as u64)
            .ok_or_else(|| Error::receipt("receipt sequence overflows"))?;
        if receipt.sequence != expected {
            return Err(Error::receipt(
                "receipt sequence does not follow the log order",
            ));
        }
        if last_time.is_some_and(|time| receipt.at_ms < time) {
            return Err(Error::receipt("receipt time runs backwards"));
        }
        last_time = Some(receipt.at_ms);
        expected_previous = record_hash;
        receipts.push(receipt);
        cursor = next;
    }
    if cursor != bytes.len() {
        return Err(Error::receipt("trailing bytes after the last record"));
    }
    let state = LogState {
        bytes: bytes.len() as u64,
        count: receipts.len() as u64,
        start,
        head: expected_previous,
        last_ms: last_time.unwrap_or(0),
        identity: None,
        modified: None,
    };
    Ok((receipts, state))
}

/// True when a tail that failed to walk still holds a complete record.
///
/// A corrupted length field can declare a record that runs past the end of the
/// file while the records after it are intact; cutting there would discard good
/// evidence. Scanning a bounded window (one record past the damage) for any
/// record that decodes is the cheap discriminator: a genuinely torn write holds
/// at most the bytes of one unfinished record, which decode to nothing.
fn tail_holds_a_record(tail: &[u8]) -> bool {
    let window = tail.len().min(MAX_LOG_RECORD);
    if window < MIN_LOG_RECORD {
        return false;
    }
    let bytes = &tail[..window];
    // A random offset almost never declares a length a record could have, and
    // the decoder hashes whatever it is handed: without this pre-filter `repair`
    // paid O(window^2) of hashing on a damaged tail (R-13 round 9, L5).
    for offset in 0..window.saturating_sub(4) {
        let declared = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]) as usize;
        if !(MIN_LOG_RECORD..=MAX_LOG_RECORD).contains(&declared) {
            continue;
        }
        if offset.saturating_add(declared) > window {
            continue;
        }
        if decode_record(bytes, offset).is_ok() {
            return true;
        }
    }
    false
}

/// Walk the records that decode, stopping at the first one that does not.
///
/// Returns the records and the offset just past the last good one, which is the
/// cut `repair_tail` uses. A caller that needs to know *why* the walk stopped
/// should use [`walk_log`], which reports the error.
fn walk_prefix(bytes: &[u8]) -> (Vec<Receipt>, usize) {
    let Ok(start) = verify_header(bytes) else {
        return (Vec::new(), 0);
    };
    let mut receipts: Vec<Receipt> = Vec::new();
    let mut cursor = LOG_HEADER_LEN;
    let mut expected_previous = [0u8; 32];
    let mut last_time = 0u64;
    while cursor < bytes.len() {
        let Ok((receipt, previous, record_hash, next)) = decode_record(bytes, cursor) else {
            break;
        };
        if previous != expected_previous {
            break;
        }
        if start.checked_add(receipts.len() as u64) != Some(receipt.sequence) {
            break;
        }
        if receipt.at_ms < last_time {
            break;
        }
        last_time = receipt.at_ms;
        expected_previous = record_hash;
        receipts.push(receipt);
        cursor = next;
    }
    (receipts, cursor)
}

/// What a decision looks like in a log line.
pub fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Admitted => "admitted",
        Decision::Refused(_) => "refused",
    }
}

#[cfg(test)]
mod claim_tests {
    use super::claim_name;

    /// A lock is a file an attacker can plant, and its nonce becomes part of the
    /// steal's file name: only alphanumerics and dashes may survive, or a nonce
    /// could steer the claim into another directory (R-13 round 5, #1).
    #[test]
    fn a_claim_name_never_carries_a_separator() {
        assert_eq!(claim_name("1234-5678"), Some("1234-5678".to_string()));
        assert_eq!(
            claim_name("../../escaped"),
            Some("escaped".to_string()),
            "the separators are dropped, not followed"
        );
        assert_eq!(claim_name("a/b\\c:d"), Some("abcd".to_string()));
        assert_eq!(claim_name("..."), None, "nothing usable is not a name");
        assert_eq!(claim_name(""), None);
        let long = claim_name(&"x".repeat(200)).expect("a long nonce still names a claim");
        assert_eq!(long.len(), 64, "the name is bounded");
    }
}

#[cfg(test)]
mod lock_tests {
    use super::LogLock;

    fn scratch(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "active-rpc-lock-unit-{}-{name}.log",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn lock_of(path: &std::path::Path) -> std::path::PathBuf {
        path.with_file_name(format!(
            "{}.lock",
            path.file_name().unwrap().to_string_lossy()
        ))
    }

    /// The steal removes only the lock it judged. A lock created between the
    /// judgement and the move was never judged abandoned, so `take_stale`
    /// preserves it and reports failure (R-13 round 9, F1).
    #[test]
    fn the_steal_never_removes_a_lock_it_did_not_judge() {
        let path = scratch("judged");
        let lock_path = lock_of(&path);
        std::fs::write(
            &lock_path,
            format!("{}fresh-1 pid 4294967294 started 1", super::LOCK_MAGIC),
        )
        .expect("lock");

        // `take_stale` takes the **lock** path, as `acquire` passes it.
        assert!(
            !super::take_stale(&lock_path, "judged-2"),
            "a lock with another nonce is not the one judged"
        );
        let kept = std::fs::read_to_string(&lock_path).expect("the unjudged lock survives");
        assert!(kept.contains("fresh-1"), "the live lock is intact: {kept}");

        // The lock that *was* judged is removed, so a real stale lock still goes.
        assert!(
            super::take_stale(&lock_path, "fresh-1"),
            "the judged nonce is the one removed"
        );
        assert!(!lock_path.exists(), "the judged lock is gone");

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// The write path checks ownership itself, not only the acquire path: a
    /// writer displaced during the state walk must not append a second chain
    /// (R-13 round 10, A). The check lives in `write_all`, so this drives the
    /// shipped function with a displaced lock.
    #[test]
    fn a_displaced_lock_cannot_write() {
        let path = scratch("displaced-write");
        drop(super::ReceiptLog::create(&path).expect("create"));
        let log = super::ReceiptLog::open(&path).expect("open");
        let lock = LogLock::acquire(&path).expect("the lock is free");
        let lock_path = lock_of(&path);

        // Displace the lock while this writer holds it.
        std::fs::remove_file(&lock_path).expect("remove");
        std::fs::write(&lock_path, b"other-1 pid 4294967294 started 1").expect("replacement");

        // The same `ReceiptLog::write_all` the append uses must refuse.
        let err = log
            .write_all(b"x", &lock)
            .expect_err("a displaced lock cannot write");
        assert_eq!(err.code(), "rpc/receipt", "{err}");
        assert!(err.to_string().contains("displaced"), "{err}");

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// Ownership is a property of the file the writer created: when the path is
    /// replaced, the writer knows it no longer holds the lock and refuses rather
    /// than append a second chain (R-13 round 8, M1). `touch` refreshes the
    /// writer's own file, never the replacement (L1).
    #[test]
    fn a_writer_that_lost_its_lock_refuses_and_never_refreshes_the_replacement() {
        let path = scratch("own");
        std::fs::write(&path, b"").expect("log");
        let lock = LogLock::acquire(&path).expect("the lock is free");
        let lock_path = lock_of(&path);
        assert!(lock.still_holds(), "a fresh lock owns the path");

        // A local user replaces the lock path with another file, and the
        // replacement's own mtime is the baseline the writer must not change.
        std::fs::remove_file(&lock_path).expect("remove");
        std::fs::write(&lock_path, b"foreign-1 pid 1 started 1").expect("replacement");
        assert!(
            !lock.still_holds(),
            "the writer must see that the path no longer carries its nonce"
        );
        let before = std::fs::metadata(&lock_path)
            .expect("stat")
            .modified()
            .expect("mtime");

        std::thread::sleep(std::time::Duration::from_millis(30));
        lock.touch();
        let after = std::fs::metadata(&lock_path)
            .expect("stat")
            .modified()
            .expect("mtime");
        assert_eq!(
            before, after,
            "touch followed the path and refreshed somebody else's file"
        );

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod round11_tests {
    use super::*;

    /// H-1: a creator whose lock was stolen while it wrote the header must not
    /// install that header over the new owner's log.
    #[test]
    fn a_displaced_creator_does_not_install_a_header() {
        let dir = std::env::temp_dir().join(format!(
            "arrl-displaced-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("log.arrl");
        let lock = LogLock::acquire(&path).expect("lock");
        let staging = dir.join("staging");
        std::fs::write(&staging, b"header").expect("staging");

        // Displace the lock: another writer now owns the path.
        std::fs::remove_file(lock_path(&path)).expect("remove");
        std::fs::write(lock_path(&path), "other-nonce pid 1 started 1").expect("foreign lock");

        let error = install_staged(&staging, &path, &lock, false).expect_err("displaced");
        assert_eq!(error.code(), "rpc/receipt");
        assert!(
            !path.exists(),
            "the header was installed over a lock the creator no longer held"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A competing log created between the ownership check and the install must
    /// survive: a hard link is exclusive, a rename would replace it (F1).
    #[test]
    fn a_competing_log_is_never_replaced_by_the_install() {
        let dir = scratch_dir("competing");
        let path = dir.join("log.arrl");
        let lock = LogLock::acquire(&path).expect("lock");
        let staging = dir.join("staging");
        std::fs::write(&staging, b"our header").expect("staging");
        // Another writer created the log after the check.
        std::fs::write(&path, b"their log").expect("competitor");

        let error = install_staged(&staging, &path, &lock, false).expect_err("refused");
        assert_eq!(error.code(), "rpc/receipt");
        assert_eq!(std::fs::read(&path).expect("read"), b"their log");
        assert!(!staging.exists(), "the staging file is removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A fresh lock is reported with its age and owner, so an operator can tell
    /// a stuck retry from damage (F5).
    #[test]
    fn a_live_lock_refusal_names_the_lock() {
        let dir = scratch_dir("live");
        let path = dir.join("log.arrl");
        drop(ReceiptLog::create(&path).expect("create"));
        let lock = LogLock::acquire(&path).expect("lock");
        let error = read_stable(&path).expect_err("a live writer is refused");
        let text = error.to_string();
        assert!(text.contains("ms old"), "{text}");
        assert!(
            text.contains(&format!("pid {}", std::process::id())),
            "{text}"
        );
        assert!(text.contains(&lock.nonce), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Aged claim, quarantine and staging files are swept on the next acquire;
    /// a live one is left alone (F7).
    #[test]
    fn acquisition_sweeps_aged_leftovers() {
        let dir = scratch_dir("sweep");
        let path = dir.join("log.arrl");
        let lock = lock_path(&path);
        let name = file_name_text(&lock);
        let aged = [
            dir.join(format!("{name}.done-1-2")),
            dir.join(format!("{name}.stale-x")),
            dir.join(format!("{name}.orphan-y")),
            dir.join(format!("{name}.writing-1-2")),
        ];
        for file in &aged {
            std::fs::write(file, b"leftover").expect("leftover");
            age(file, 600);
        }
        // The staging file production actually writes is `<log>.writing-…`,
        // not `<log>.lock.writing-…`: the sweep must match the log stem
        // (R-13 round 13, F4).
        let staging = dir.join(format!("{}.writing-7-8", file_name_text(&path)));
        std::fs::write(&staging, b"staged").expect("staging");
        age(&staging, 600);
        let fresh = dir.join(format!("{name}.writing-9-9"));
        std::fs::write(&fresh, b"live").expect("fresh");
        drop(LogLock::acquire(&path).expect("lock"));
        for file in aged.iter().chain(std::iter::once(&staging)) {
            assert!(!file.exists(), "{} survived the sweep", file.display());
        }
        assert!(fresh.exists(), "a live staging file is not swept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn age(file: &std::path::Path, seconds: u64) {
        let handle = std::fs::OpenOptions::new()
            .write(true)
            .open(file)
            .expect("open the leftover");
        handle
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::SystemTime::now() - std::time::Duration::from_secs(seconds),
            ))
            .expect("set the mtime");
    }

    /// `O_NOFOLLOW` is the only step that can be atomic with the open: the
    /// helper refuses a link on its own, without the path check (F2).
    #[cfg(unix)]
    #[test]
    fn the_write_open_refuses_a_symlink() {
        let dir = scratch_dir("nofollow");
        let target = dir.join("victim");
        std::fs::write(&target, b"keep").expect("victim");
        let link = dir.join("log.arrl");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let error = open_log_write(&link, true, false).expect_err("refused");
        assert_eq!(error.code(), "rpc/receipt");
        assert_eq!(std::fs::read(&target).expect("victim"), b"keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `repair` truncates the file it walked, never a link planted at the path
    /// (F2).
    #[cfg(unix)]
    #[test]
    fn repair_never_truncates_through_a_symlink() {
        let dir = scratch_dir("repair-link");
        let target = dir.join("victim");
        std::fs::write(&target, vec![0x41u8; 4096]).expect("victim");
        let link = dir.join("log.arrl");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert!(ReceiptLog::repair(&link).is_err());
        assert_eq!(
            std::fs::read(&target).expect("victim").len(),
            4096,
            "the victim was truncated through the link"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "arrl-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }
}
