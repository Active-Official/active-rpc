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
    /// Written into the lock file: the only proof that this holder may remove it.
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
        nonce_of(&self.path).as_deref() == Some(self.nonce.as_str())
    }

    fn acquire(log: &std::path::Path) -> Result<Self> {
        let path = lock_path(log);
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
                        "{nonce} pid {} started {}",
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
                        drop(file);
                        let _ = std::fs::remove_file(&path);
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
    let file = std::fs::File::open(path).ok()?;
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
    let mut words = text.split_whitespace();
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

/// A nonce rendered safe to use in a file name.
///
/// A lock is a file an attacker can plant: a nonce with a separator or a `..`
/// must not steer the claim path anywhere else.
/// Refuse a log path that is a symlink.
///
/// A link planted in the log's directory would make every append write through
/// it (and `repair` truncate through it), so the type is checked without
/// following it (R-13 round 9, L2).
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
fn file_name_text(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "receipt-lock".to_string())
}

impl Drop for LogLock {
    fn drop(&mut self) {
        // Only the owner removes the lock: a stealer replaces the file, and
        // deleting a stolen lock would free a writer that is still appending.
        // Bounded: after the kernel created its lock, a local user with
        // directory write can replace the path with a symlink to `/dev/zero`,
        // and an unbounded read would allocate without limit (R-13 round 7, #3).
        let owned = nonce_of(&self.path).as_deref() == Some(self.nonce.as_str());
        if owned {
            let _ = std::fs::remove_file(&self.path);
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
        std::fs::rename(&staging, &path).map_err(|_| {
            let _ = std::fs::remove_file(&staging);
            Error::receipt("cannot install the receipt log header")
        })?;
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

    /// Append one receipt.
    pub fn append(&self, receipt: &Receipt) -> Result<()> {
        self.append_all(std::slice::from_ref(receipt))
    }

    /// Append a batch of receipts without checking their `mac`.
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
                && read_header_start(&self.path) == Some(cached.start)
                // A replacement of exactly the same length would pass the two
                // checks above while its trailing head is another chain: the
                // append would link to a head the file does not carry, and
                // nothing could read the log again.
                && read_tail_head(&self.path) == Some(cached.head);
            if usable {
                cached
            } else {
                let bytes = read_capped(&self.path)?;
                let (_, walked) = walk_log(&bytes)?;
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
        refuse_symlink(&self.path)?;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| Error::receipt("cannot open the receipt log for append"))?;
        // A batch larger than the stale ceiling on slow storage must not look
        // abandoned while it is being written: refresh the lock between bounded
        // chunks. The crash semantics are unchanged — a partial trailing record
        // is what the reader already refuses and `repair` cuts.
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + WRITE_CHUNK_BYTES).min(bytes.len());
            file.write_all(&bytes[offset..end])
                .map_err(|_| Error::receipt("cannot append to the receipt log"))?;
            offset = end;
            lock.touch();
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
        let bytes = read_capped(&path)?;
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
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|_| Error::receipt("cannot open the receipt log to repair it"))?;
        refuse_symlink(&path)?;
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
    let mut file = std::fs::File::open(path).ok()?;
    file.read_exact(&mut header).ok()?;
    if &header[..4] != LOG_MAGIC {
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
    let mut file = std::fs::File::open(path).ok()?;
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
    use std::io::Read;
    // Opening a FIFO or a device here would block for ever: refuse anything that
    // is not a regular file, without following a link (R-13 round 9, F5).
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_file() {
            return Err(Error::receipt("the receipt log is not a regular file"));
        }
    }
    let file =
        std::fs::File::open(path).map_err(|_| Error::receipt("cannot read the receipt log"))?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::receipt("cannot read the receipt log"))?;
    if bytes.len() as u64 > MAX_LOG_BYTES {
        return Err(Error::receipt("the receipt log exceeds the size ceiling"));
    }
    Ok(bytes)
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
    let mut bytes = read_capped(path)?;
    let mut last_error: Option<Error> = None;
    let mut previous_len = 0usize;
    for attempt in 0..11u32 {
        let walked = walk_log(&bytes);
        let active = writer_active(path);
        match walked {
            // A complete walk is final only when no writer is appending: while
            // one is, the next record may already be on its way.
            Ok((receipts, state)) if !active => return Ok((bytes, receipts, state)),
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }
        let grew = bytes.len() != previous_len;
        previous_len = bytes.len();
        if attempt > 0 && !active && !grew {
            // Nothing is being written and the bytes stopped changing: the file
            // is what it is.
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        bytes = read_capped(path)?;
    }
    match walk_log(&bytes) {
        // The bound ran out while a writer was still working: a complete walk is
        // then a prefix of its batch, and returning it would publish a head the
        // file has already moved past (R-13 round 7, #5).
        Ok(_) if writer_active(path) => Err(Error::receipt(
            "the receipt log is being written by another process",
        )),
        Ok((receipts, state)) => Ok((bytes, receipts, state)),
        Err(error) => {
            if writer_active(path) {
                Err(Error::receipt(
                    "the receipt log is being written by another process",
                ))
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
        std::fs::write(&lock_path, b"fresh-1 pid 4294967294 started 1").expect("lock");

        // `take_stale` takes the **lock** path, as `acquire` passes it.
        assert!(
            !super::take_stale(&lock_path, "judged-2"),
            "a lock with another nonce is not the one judged"
        );
        let kept = std::fs::read_to_string(&lock_path).expect("the unjudged lock survives");
        assert!(
            kept.starts_with("fresh-1"),
            "the live lock is intact: {kept}"
        );

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
