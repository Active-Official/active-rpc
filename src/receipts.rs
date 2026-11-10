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
/// Longest receipt-log path accepted at `create`, in characters
/// (XPL-RPC-10, XPL-RPC-11).
///
/// Windows `MAX_PATH` is 260, including the terminating NUL, so a path of
/// 260 characters or more cannot be opened on a default Windows host
/// (`LongPathsEnabled` off). The ceiling is enforced on every platform so a
/// log created on Linux still opens on Windows; the count is UTF-16 code
/// units, the unit Windows counts. A path is refused at 260 characters, not
/// 259: 259 is the longest path a default Windows host can open.
pub const MAX_LOG_PATH_CHARS: usize = 260;
/// Longest final component (file name) of a receipt-log path accepted at
/// `create`, in bytes (XPL-RPC-11).
///
/// A filesystem component holds at most 255 bytes, and `create` installs the
/// header through a staging file named `<log>.writing-<pid>-<nanos>`, so the
/// log's own name must leave room for the longest that suffix can be:
/// `.writing-` (9 bytes) + pid (a `u32`, at most 10 digits) + `-` (1 byte) +
/// nanos (a `u64`, at most 20 digits) = 40 bytes. 255 - 40 = 215.
pub const MAX_LOG_NAME_BYTES: usize = 215;

/// Strata the append fast path samples from the log body on every append
/// (RPC-05). The record region is split into this many equal strata and one
/// window is read from each; see [`sample_windows`].
const FAST_PATH_SAMPLE_STRATA: usize = 8;
/// Bytes read from each sampled stratum (RPC-05).
///
/// Eight strata of 64 bytes cover a record region of 512 bytes end to end, so
/// every log that small is verified byte-for-byte on the fast path; above that
/// the sample is a tripwire and the periodic re-walk is the backstop.
const FAST_PATH_SAMPLE_WINDOW: usize = 64;
/// Fast-path appends between full re-walks (RPC-05).
///
/// A writer who evades the content sample can link at most this many appends
/// onto tampered history before the scheduled re-walk walks the whole chain
/// and refuses. The re-walk is amortised over the appends it separates, so the
/// linear-append property the hardening suite measures is kept.
const FAST_PATH_REWALK_EVERY: u32 = 32;

/// A receipt may not be dated more than this far ahead of the writer's wall
/// clock (R2-R13-01, RPC-14). Without the bound, one receipt with
/// `at_ms = u64::MAX` makes `last_ms` unreachable and bricks the log for
/// appends forever: no legitimate `at_ms` can ever be `>= u64::MAX`, and
/// `repair` finds nothing to cut in a log that walks cleanly. 24 h absorbs
/// real clock skew (NTP steps, a machine whose clock runs fast) while keeping
/// `last_ms` within reach of every future legitimate receipt.
pub const MAX_RECEIPT_SKEW_MS: u64 = 24 * 60 * 60 * 1000;

/// Wall-clock milliseconds since the Unix epoch; 0 when the clock is before
/// the epoch (a clock that far wrong cannot stamp a plausible receipt).
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The latest `at_ms` a receipt may carry: the writer's wall clock plus
/// [`MAX_RECEIPT_SKEW_MS`]. Computed once per operation, not once per
/// receipt, so a large batch does not pay a clock read per record.
fn future_horizon_ms() -> u64 {
    wall_ms().saturating_add(MAX_RECEIPT_SKEW_MS)
}

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
    ///
    /// On unix the identity is `(dev, ino)`; on Windows it is the volume
    /// serial plus file index from the `active-rpc-file-identity` helper
    /// (XPL-RPC-08). The identity is also the handle's pin: an append that
    /// finds a different file at the path is refused, never re-walked into
    /// (F1-NF-07) — the walk accepts any self-consistent chain, so a
    /// mismatch that only forced a re-walk would adopt a replacement chain,
    /// including a genuine backup with genuine MACs.
    identity: Option<(u64, u64)>,
    /// The file's modification time when the walk happened.
    ///
    /// The inode is invariant under an in-place write, so an interior edit
    /// through the log's own path (or a hard link) kept length, header, tail
    /// and identity intact and the append kept trusting the cache. The mtime
    /// changes on that write, but a writer who can set it back passed every
    /// check and the next append linked onto the forged chain (RPC-05): mtime
    /// is attacker-controllable metadata, not an integrity signal. It stays as
    /// a cheap tripwire for the non-adversarial writer; the content sample
    /// below is what the fast path now trusts.
    modified: Option<std::time::SystemTime>,
    /// Keyed hash of the sampled windows of the file at the last known-good
    /// state (RPC-05).
    ///
    /// The fast path used to admit an append on length, header, tail head,
    /// identity and mtime alone, and an in-place same-length interior edit
    /// whose mtime was set back passed every one of them. The sample binds the
    /// admission to file *content*: on every append the windows are re-read
    /// and re-hashed, and a mismatch falls through to the full re-walk, which
    /// fails on the broken chain link and refuses the append. `None` means no
    /// sample has been established for this state (fresh `create`/`open`, or a
    /// state refreshed by `repair_tail`), and the fast path then re-walks.
    /// The windows are chosen with the log's per-instance seed, so a writer
    /// with file access but no access to this process's memory cannot predict
    /// which bytes the next append will check. A log whose record region is
    /// at most `FAST_PATH_SAMPLE_STRATA * FAST_PATH_SAMPLE_WINDOW` bytes is
    /// covered end to end; above that the sample is probabilistic per append
    /// and the re-walk count below bounds the evasion.
    sample: Option<[u8; 32]>,
    /// Fast-path appends since the last full walk of the file (RPC-05).
    ///
    /// The sample can miss an edit in a large log, so the fast path is not
    /// trusted for ever: once this reaches [`FAST_PATH_REWALK_EVERY`] the
    /// next append re-walks the whole chain however clean the metadata looks.
    /// A state that comes from a walk starts at zero.
    appends_since_walk: u32,
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
    /// Written into the lock file: what an operator reads, and the name the
    /// steal's claim file is built from. It is not the proof of ownership:
    /// the nonce is plaintext, so a local user can read it and recreate the
    /// same text (XPL-RPC-08). Ownership is the file the held handle names —
    /// `(dev, ino)` on unix, volume serial plus file index on Windows — so
    /// the field is write-only on both.
    #[cfg_attr(any(unix, windows), allow(dead_code))]
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

/// The identity of a file the lock holder created, on Windows.
///
/// The held handle's volume serial plus file index, from
/// `GetFileInformationByHandle` through the `active-rpc-file-identity`
/// helper crate (XPL-RPC-08). Stable `std` cannot supply it:
/// `MetadataExt::file_index` needs the unstable `windows_by_handle`
/// feature, and this crate forbids `unsafe`, so the one call lives in the
/// helper, as the liveness probe does (XPL-RPC-02). A recreated file gets a
/// new file index — NTFS reuses the record number only with an incremented
/// sequence number, which is part of the 64-bit index — so a byte-identical
/// copy at the same path is a different file, as on unix.
#[cfg(windows)]
fn lock_held_identity(file: &std::fs::File) -> Option<(u64, u64)> {
    active_rpc_file_identity::file_identity(file)
}

/// The identity of the file at a lock path, on Windows.
///
/// The path is opened and the opened handle is identified, so the identity
/// describes the file that was actually opened. A symlink at the path is
/// refused outright: the link has its own file index, but a swapped-in link
/// must never pass by pointing at the original — and it cannot, since the
/// original was unlinked and no path names it any more.
#[cfg(windows)]
fn lock_path_identity(path: &std::path::Path) -> Option<(u64, u64)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    active_rpc_file_identity::file_identity(&file)
}

/// Whether the file at `path` is the file `judged` describes, on Windows.
///
/// The volume serial plus file index must match, and so must the
/// modification time: the identity alone is reusable (the Linux CI reuses an
/// inode for an immediate replacement, and NTFS likewise reuses a record
/// number), so the mtime is part of the identity and it survives the rename
/// that quarantines the judged file (R-13 round 16, F4 — the same rule the
/// unix branch applies).
#[cfg(windows)]
fn lock_file_is_judged(path: &std::path::Path, judged: FileIdentity) -> bool {
    let Some(identity) = lock_path_identity(path) else {
        return false;
    };
    identity == (judged.dev, judged.ino)
        && std::fs::symlink_metadata(path)
            .ok()
            .and_then(|meta| meta.modified().ok())
            == judged.modified
}

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
    /// every write: if the path no longer names this holder's file, another
    /// process displaced this lock and a second writer may hold the path, so
    /// this writer refuses rather than append a second chain into the file
    /// (R-13 round 8, M1). Ownership is the file, never the text in it: the
    /// nonce is plaintext, so a copy carrying the same nonce is not the
    /// holder's file (XPL-RPC-08).
    fn still_holds(&self) -> bool {
        // On unix the lock is a file identity: a local user with directory
        // write can read a live nonce, unlink the lock and recreate the same
        // text, so a text check alone let two writers append (R-13 round 11,
        // L-3). On Windows the same attack passed the text check too, so the
        // lock is a file identity there as well: the held handle's volume
        // serial plus file index against the path's. Anywhere else the nonce
        // is the best available check.
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
        #[cfg(windows)]
        {
            // Either side unavailable means the holder cannot prove the path
            // still names its file: fail closed, as on unix.
            let Some(held) = self.file.as_ref().and_then(lock_held_identity) else {
                return false;
            };
            lock_path_identity(&self.path) == Some(held)
        }
        #[cfg(not(any(unix, windows)))]
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
                        #[cfg(windows)]
                        let held_identity = lock_held_identity(&file);
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
                                #[cfg(windows)]
                                {
                                    held_identity
                                        .is_some_and(|id| lock_path_identity(&path) == Some(id))
                                }
                                #[cfg(not(any(unix, windows)))]
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
                        if let Some((judged, identity)) = judged_stale(&path) {
                            if take_stale(&path, &judged, identity) {
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
fn judged_stale(path: &std::path::Path) -> Option<(String, Option<FileIdentity>)> {
    let facts = lock_state(path)?;
    if lock_is_live(facts.age_ms, facts.pid) {
        return None;
    }
    Some((facts.nonce, facts.identity))
}

/// Identity of the lock file a judgement read.
///
/// `(dev, ino)` on unix, volume serial plus file index on Windows
/// (XPL-RPC-08). The identity alone is not enough: a filesystem may hand a
/// removed file's identity to its immediate replacement (the Linux CI does
/// with inodes). The modification time changes with the replacement and
/// survives the rename that quarantines the judged file (R-13 round 16, F4).
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    modified: Option<std::time::SystemTime>,
}

/// The facts one open read gives: the lock's age, its nonce, the pid it names
/// when its creator wrote one, and (on unix) the identity of the file read.
///
/// One handle, so the age and the identity describe the same file (R-13 round
/// 5, #1). Lossy text, so a lock with a stray non-UTF-8 byte is still
/// identifiable and can still be stolen (R-13 round 8, L5).
struct LockFacts {
    age_ms: u64,
    nonce: String,
    pid: Option<u32>,
    /// The file the judgement read (unix and Windows), so the steal can prove
    /// it moved the same file and not a replacement with the same text
    /// (R-13 round 16, F4).
    identity: Option<FileIdentity>,
}

fn lock_state(path: &std::path::Path) -> Option<LockFacts> {
    // A FIFO or a device at the lock path would block `open` for ever, so the
    // type is checked without following a link and without blocking
    // (R-13 round 9, F5).
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let file = open_log_read(path).ok()?;
    let metadata = file.metadata().ok()?;
    let modified = metadata.modified().ok()?;
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
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        Some(FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
            modified: metadata.modified().ok(),
        })
    };
    #[cfg(windows)]
    let identity = lock_held_identity(&file).map(|(dev, ino)| FileIdentity {
        dev,
        ino,
        modified: metadata.modified().ok(),
    });
    #[cfg(not(any(unix, windows)))]
    let identity = None;
    Some(LockFacts {
        age_ms,
        nonce,
        pid,
        identity,
    })
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
fn take_stale(path: &std::path::Path, judged: &str, identity: Option<FileIdentity>) -> bool {
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
    // Unix proves identity by inode, Windows by volume serial plus file
    // index: the text alone let a replacement that copied the judged nonce
    // be deleted (R-13 round 16, F4; XPL-RPC-08). Anywhere else the text is
    // compared, which is the best identity that platform's open gives.
    #[cfg(unix)]
    let matched = match identity {
        Some(judged) => {
            use std::os::unix::fs::MetadataExt;
            std::fs::symlink_metadata(&quarantine).is_ok_and(|meta| {
                // The inode alone is reusable (the Linux CI reuses it for an
                // immediate replacement), so the mtime is part of the identity
                // and it survives the rename (R-13 round 16, F4).
                !meta.file_type().is_symlink()
                    && meta.dev() == judged.dev
                    && meta.ino() == judged.ino
                    && meta.modified().ok() == judged.modified
            })
        }
        None => lock_text_matches(&moved_nonce, judged),
    };
    #[cfg(windows)]
    let matched = match identity {
        Some(judged) => lock_file_is_judged(&quarantine, judged),
        None => lock_text_matches(&moved_nonce, judged),
    };
    #[cfg(not(any(unix, windows)))]
    let matched = {
        let _ = identity;
        lock_text_matches(&moved_nonce, judged)
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
        Some(LockFacts {
            age_ms, nonce, pid, ..
        }) => format!(
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
/// Linux reads `/proc/{pid}` directly. Windows and macOS have no `/proc`, so
/// the probe there is one FFI call per platform (`OpenProcess` on Windows,
/// `kill(pid, 0)` on macOS) — and this crate forbids `unsafe`, so the call
/// lives in the `active-rpc-liveness` helper crate, which exposes it through
/// one safe function (XPL-RPC-02). Any other platform has no probe, so the
/// age rule is the whole test there, which is why `LOCK_STALE_MS` is generous.
#[cfg(target_os = "linux")]
fn process_is_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[cfg(not(target_os = "linux"))]
fn process_is_alive(pid: u32) -> bool {
    active_rpc_liveness::process_is_alive(pid)
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
    // The magic is proof this build wrote the file: a crash mid-write leaves a
    // partial line that starts with it, and the shape gate below would make
    // that line unjudgeable and wedge the log for ever (R-13 round 16, F2).
    let had_magic = text.starts_with(LOCK_MAGIC);
    let body = text.strip_prefix(LOCK_MAGIC).unwrap_or(&text);
    // A file that is neither magic-prefixed nor lock-shaped is not a lock this
    // build wrote or a build before it wrote: refuse to judge it, so a sibling
    // log at the lock path is never stolen and deleted (R-13 round 14, F4). An
    // empty file stays identifiable as "interrupted creator", and a full legacy
    // `<nonce> pid <pid> started <ms>` line stays stealable, so a crashed writer
    // from an older build does not wedge the log for ever. A *partial* legacy
    // line is refused: without the magic it is indistinguishable from a foreign
    // sibling, and only a pre-magic build could write one.
    if !had_magic && !body.trim().is_empty() && !looks_like_a_lock(body) {
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
    // The guarded reader, not `File::open`: a symlink at the path must not be
    // followed here either (R-13 round 16, F9).
    let file = open_log_read(path).ok()?;
    read_lock(&file).map(|(nonce, _)| nonce)
}

/// Whether a moved lock carries the nonce that was judged.
fn lock_text_matches(moved: &str, judged: &str) -> bool {
    if judged.is_empty() {
        // The file that was judged had no nonce; it still has none, so it is the
        // same lock (R-13 round 9, F2).
        moved.is_empty()
    } else {
        moved == judged
    }
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
/// Windows flags for refusing a reparse point at the open (XPL-RPC-01).
///
/// `FILE_FLAG_OPEN_REPARSE_POINT` makes the open return a handle to the link
/// itself instead of following it; `FILE_ATTRIBUTE_REPARSE_POINT` is the bit
/// the handle's own attributes carry when it is one. Both are stable Win32
/// values, spelled out here so the crate needs no `windows-sys` dependency
/// and no `unsafe` block (`#![forbid(unsafe_code)]`).
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Open the log for writing through a handle that is verified to be a regular
/// file.
///
/// The path check before an open cannot be atomic with it, so the open itself
/// refuses a symlink (`O_NOFOLLOW` on unix, `FILE_FLAG_OPEN_REPARSE_POINT`
/// plus a reparse-point check on the handle on Windows — XPL-RPC-01) and the
/// handle's own metadata decides (R-13 round 13, F2). `read` adds
/// `O_RDONLY`-style access for `repair`, which walks and truncates the same
/// inode.
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
    #[cfg(windows)]
    {
        // Open a reparse point itself instead of following it (XPL-RPC-01):
        // without this flag the open follows a symlink to its target and the
        // post-open `is_file()` check passes, because the target is a regular
        // file. The handle's own attributes are checked below, so the
        // refusal is atomic with the open — no check-then-open race.
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| Error::receipt("cannot open the receipt log for writing"))?;
    let meta = file
        .metadata()
        .map_err(|_| Error::receipt("cannot inspect the receipt log"))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::receipt("the receipt log path is a reparse point"));
        }
    }
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
/// claimed for "write and read opens" was missing (R-13 round 14, F2). On
/// Windows the same hole is closed with `FILE_FLAG_OPEN_REPARSE_POINT` plus
/// the handle's own reparse-point check (XPL-RPC-01).
fn open_log_read(path: &std::path::Path) -> Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        // As in `open_log_write`: open the link itself, then refuse it from
        // the handle's own attributes (XPL-RPC-01).
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| Error::receipt("cannot read the receipt log"))?;
    let meta = file
        .metadata()
        .map_err(|_| Error::receipt("cannot inspect the receipt log"))?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::receipt("the receipt log path is a reparse point"));
        }
    }
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
/// (R-13 round 11, H-1). The parent directory is flushed so `create` does
/// not return Ok for a name that a power loss forgets; that flush is
/// best-effort and is a directory flush on every OS (XPL-RPC-12) — on
/// Windows the directory handle is flushed with `FlushFileBuffers` — so
/// the durability guarantee is no longer a unix one (L-6; round 12, F6).
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

/// Sync the parent directory of `path`, so the directory entry of a just
/// installed log is durable and not just the file's bytes.
///
/// Best effort, as before: a parent that cannot be opened or flushed is
/// ignored, and the file's own `sync_all` is what orders the bytes. The
/// flush is a directory flush on every OS now (XPL-RPC-12): on Windows the
/// directory handle is opened with `FILE_FLAG_BACKUP_SEMANTICS` and
/// flushed with `FlushFileBuffers`, which `File::sync_all` cannot do —
/// the call lives in the `active-rpc-dir-sync` helper crate because this
/// crate forbids `unsafe`. On Unix the helper does the `File::open` +
/// `sync_all` this function used to do inline.
fn sync_parent(path: &std::path::Path) {
    let _ = active_rpc_dir_sync::sync_parent_dir(path);
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
        // A receipt log is never one of our leftovers, whatever its name: a
        // sibling log stored under a matching suffix must not be swept
        // (R-13 round 16, F6).
        if begins_with_receipt_log(&entry.path()) {
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

/// Whether a file starts with the receipt-log magic.
///
/// The sweep reads four bytes before it deletes a matching name: a receipt log
/// is never one of the writer's leftovers (R-13 round 16, F6).
fn begins_with_receipt_log(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && &magic == LOG_MAGIC
}

fn file_name_text(path: &std::path::Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "receipt-lock".to_string())
}

/// Longest single filesystem component, in bytes (NTFS, ext4, APFS).
const MAX_COMPONENT_BYTES: usize = 255;
/// Longest the staging suffix `.writing-<pid>-<nanos>` can be, in bytes:
/// `.writing-` (9) + pid (a `u32`, at most 10 digits) + `-` (1) + nanos (a
/// `u64`, at most 20 digits).
const STAGING_SUFFIX_MAX_BYTES: usize = 40;
/// Windows reserved device names: a final component whose stem is one of
/// these opens a device on Windows, not a file.
const RESERVED_DEVICE_STEMS: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The final component's stem with Windows' trailing-dot/space stripping
/// applied, uppercased for comparison: `CON.arrl` -> `CON`, `NUL.` -> `NUL`,
/// `CON ` -> `CON`, `com1.arrl` -> `COM1`. `None` when the path has no file
/// name or the stem is empty (`.arrl`).
fn reserved_device_stem(path: &std::path::Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let trimmed = name.trim_end_matches(['.', ' ']);
    let stem = trimmed.split('.').next().unwrap_or("");
    let stem = stem.trim_end_matches(['.', ' ']);
    if stem.is_empty() {
        return None;
    }
    Some(stem.to_ascii_uppercase())
}

/// A sibling in the same directory whose name differs from the requested log
/// name only by case, if one exists. `None` when the parent cannot be listed
/// (it does not exist yet, so there is no sibling) or no such sibling exists.
///
/// The comparison is Unicode lowercase, which is what the audit recommends
/// and what covers the realistic collision (same letters, different case).
/// A sibling that is byte-identical to the requested name is not a variant:
/// that is the same file, and the existing-content check reports it.
fn case_variant_sibling(path: &std::path::Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let lowered = name.to_lowercase();
    let entries = std::fs::read_dir(parent).ok()?;
    for entry in entries.flatten() {
        let sibling = entry.file_name();
        let sibling_text = sibling.to_string_lossy();
        if sibling_text.to_lowercase() == lowered && sibling_text != name {
            return Some(sibling_text.into_owned());
        }
    }
    None
}

/// The path as the operating system resolves it: a relative path is joined
/// onto the working directory, because that is the path the OS opens. `.`
/// and `..` are left in place — they only inflate the count, so the check
/// stays fail-closed.
fn absolute_log_path(path: &std::path::Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// The length Windows counts for `MAX_PATH`: UTF-16 code units of the path
/// as displayed. A non-UTF-8 name is measured through its lossy form, so the
/// count is approximate there; the names that carry a log are UTF-8 in
/// practice, and the approximation only ever moves the boundary by the
/// replacement characters.
fn path_len_utf16(path: &std::path::Path) -> usize {
    path.to_string_lossy().encode_utf16().count()
}

/// Refuse a log path that cannot name a log portably (XPL-RPC-10,
/// XPL-RPC-11), before the lock is taken or any file is created, so the
/// refusal names the rule instead of surfacing as a lock or staging error.
///
/// The checks are uniform on all platforms: a log created on Linux must open
/// on Windows and macOS, so the strictest platform's rules apply everywhere.
///
/// - a sibling that differs only by case (`log.arrl` vs `LOG.arrl`) is one
///   file on NTFS and default APFS: two audit logs silently become one;
/// - a final component whose stem is a Windows reserved device name (`CON`,
///   `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, after stripping
///   trailing dots and spaces) opens a device on Windows, not a file;
/// - a total path of 260 characters or more cannot be opened on a default
///   Windows host (`MAX_PATH` 260, including the terminating NUL);
/// - a final component longer than 215 bytes leaves no room for the staging
///   suffix `<log>.writing-<pid>-<nanos>` (at most 40 bytes) inside the
///   255-byte component limit, so `create` would fail at the staging step
///   with no cause named.
///
/// `open` and `repair` do not validate: they work on a log that already
/// exists, and refusing to open evidence created before this check (or on
/// another platform) would strand it. The collision can only be *created* by
/// `create` (and `truncate`, which funnels through the same `create_locked`),
/// so that is where it is refused.
fn validate_log_path(path: &std::path::Path) -> Result<()> {
    // Reserved device names first: the check needs no filesystem access, and
    // a device name must never reach the lock (W6 saw the lock errors
    // instead of a validation error).
    if let Some(stem) = reserved_device_stem(path) {
        if RESERVED_DEVICE_STEMS.contains(&stem.as_str()) {
            return Err(Error::receipt(format!(
                "the receipt log name {stem:?} is a reserved device name on Windows \
                 (CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9); choose another log name"
            )));
        }
    }
    // Case collision: a sibling that differs only by case.
    if let Some(sibling) = case_variant_sibling(path) {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        return Err(Error::receipt(format!(
            "a file named {sibling:?} already exists in this directory and differs \
             from {name:?} only by case; on a case-insensitive filesystem the two \
             names are one file, so the log cannot be created under this name"
        )));
    }
    // Total-path ceiling, measured on the absolute path: the path the OS opens.
    let absolute = absolute_log_path(path);
    let total = path_len_utf16(&absolute);
    if total >= MAX_LOG_PATH_CHARS {
        return Err(Error::receipt(format!(
            "the receipt log path is {total} characters; paths of {MAX_LOG_PATH_CHARS} \
             characters or more cannot be opened on a default Windows host (MAX_PATH \
             {MAX_LOG_PATH_CHARS}, including the terminating NUL); choose a shorter path"
        )));
    }
    // Final-component ceiling, in bytes: the filesystem component limit is in
    // bytes, and the staging suffix must fit beside the log name.
    let component = path
        .file_name()
        .map(|name| name.to_string_lossy().len())
        .unwrap_or(0);
    if component + STAGING_SUFFIX_MAX_BYTES > MAX_COMPONENT_BYTES {
        return Err(Error::receipt(format!(
            "the receipt log name is {component} bytes; with the staging suffix \
             `<log>.writing-<pid>-<nanos>` (up to {STAGING_SUFFIX_MAX_BYTES} bytes) it \
             would exceed the {MAX_COMPONENT_BYTES}-byte filesystem component limit; \
             choose a log name of at most {MAX_LOG_NAME_BYTES} bytes"
        )));
    }
    Ok(())
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
            #[cfg(windows)]
            {
                // The moved claim is the holder's file only if its identity
                // is still the held handle's: a copy carrying the same nonce
                // is not (XPL-RPC-08).
                self.file
                    .as_ref()
                    .and_then(lock_held_identity)
                    .is_some_and(|held| lock_path_identity(&claim) == Some(held))
            }
            #[cfg(not(any(unix, windows)))]
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
    /// Per-instance seed for the append fast-path content sample (RPC-05).
    ///
    /// Drawn from the operating system CSPRNG when the log is created or
    /// opened, held in memory only, and never written to the file: the sample
    /// windows it chooses are unpredictable to a writer that has file access
    /// but no access to this process's memory. Two handles to the same file
    /// hold different seeds and therefore check different bytes, which is
    /// safe because each handle establishes its own sample from a walk.
    /// Cloning a handle shares the seed, which is correct: the clone is the
    /// same writer.
    sample_seed: [u8; 32],
}

impl ReceiptLog {
    /// Create (or truncate) a log whose first record is sequence 1.
    ///
    /// Evidence is not overwritten silently: a path that already holds a
    /// non-empty log is refused. Use [`ReceiptLog::truncate`] when starting over
    /// is the intent.
    ///
    /// The log path is validated before anything is created (XPL-RPC-10,
    /// XPL-RPC-11): a name that collides case-insensitively with an existing
    /// file, a Windows reserved device name, a total path of
    /// [`MAX_LOG_PATH_CHARS`] characters or more, or a final component longer
    /// than [`MAX_LOG_NAME_BYTES`] bytes is refused with the rule named.
    pub fn create(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        Self::create_starting_at(path, 1)
    }

    /// Create a log whose first record is `start_sequence`.
    ///
    /// A kernel ring that has wrapped exports its retained window this way: the
    /// window is honest about where it starts, and [`Decision`] plus
    /// `Agent::receipts_dropped` say what came before.
    ///
    /// The log path is validated as [`ReceiptLog::create`] describes.
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
    ///
    /// The log path is validated as [`ReceiptLog::create`] describes.
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
        // The path is validated before the lock is taken or any file is
        // created (XPL-RPC-10, XPL-RPC-11): a refused path must never leave a
        // lock or staging file behind, and the refusal must name the rule.
        validate_log_path(&path)?;
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
                // No sample yet: the first append re-walks the header-only
                // file and establishes it (RPC-05).
                sample: None,
                appends_since_walk: 0,
            })),
            // The seed is drawn here so a log that cannot seed itself is
            // never created: without it the fast path could not sample
            // unpredictably, and silently falling back to fixed windows would
            // leave the hole RPC-05 closes (a reader of the source would know
            // exactly which bytes are never checked).
            sample_seed: new_sample_seed()?,
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
                .map_err(|_| {
                    // The staged path is longer than the log path by the
                    // suffix; on a default Windows host it can pass the
                    // log-path ceiling and still exceed MAX_PATH (a deep
                    // directory with short components), so name that cause
                    // instead of the generic refusal (XPL-RPC-11).
                    let staged = path_len_utf16(&staging);
                    if staged >= MAX_LOG_PATH_CHARS {
                        Error::receipt(format!(
                            "the staged receipt log path is {staged} characters; the \
                             staging suffix `<log>.writing-<pid>-<nanos>` pushes it past \
                             the {MAX_LOG_PATH_CHARS}-character Windows path limit; \
                             choose a shorter log path"
                        ))
                    } else {
                        Error::receipt("cannot create the receipt log")
                    }
                })?;
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
            // The walked state carries no sample, so the first append
            // re-walks and establishes one (RPC-05).
            sample_seed: new_sample_seed()?,
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

    /// The keyed hash of the sampled windows of the file on disk (RPC-05).
    ///
    /// Reads the same windows [`sample_bytes`] hashes for a log held in
    /// memory, so the two agree for the same seed and length. `None` means
    /// the file could not be read: the caller treats that as "not verified"
    /// and re-walks, never as "unchanged".
    fn read_sample(&self, total_len: u64) -> Option<[u8; 32]> {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = open_log_read(&self.path).ok()?;
        let mut hasher = blake3::Hasher::new_keyed(&self.sample_seed);
        let mut window = [0u8; FAST_PATH_SAMPLE_WINDOW];
        for (offset, len) in sample_windows(&self.sample_seed, total_len) {
            let len = len as usize;
            if len == 0 {
                continue;
            }
            file.seek(SeekFrom::Start(offset)).ok()?;
            file.read_exact(&mut window[..len]).ok()?;
            hasher.update(&window[..len]);
        }
        Some(*hasher.finalize().as_bytes())
    }

    /// Whether the file on disk still carries the content the cached state
    /// was sampled from (RPC-05).
    ///
    /// False when no sample was ever established, when the file cannot be
    /// read, and when any sampled byte differs. A false answer never refuses
    /// an append by itself: it sends the writer to the full re-walk, and the
    /// walk is what refuses a log whose chain link no longer verifies.
    fn sample_matches(&self, cached: &LogState) -> bool {
        match cached.sample {
            None => false,
            Some(expected) => self.read_sample(cached.bytes) == Some(expected),
        }
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
        let mut used_fast_path = false;
        let mut state = {
            let cached = *self
                .state
                .lock()
                .map_err(|_| Error::receipt("the receipt log state is poisoned"))?;
            // Size alone is not enough: a replacement that happens to have the
            // same length (a fresh header of another start sequence, for
            // instance) would let the append write a sequence the header does
            // not number, producing a log nothing can walk.
            //
            // None of the checks below reads file content except the last,
            // and that is the hole RPC-05 closes: an in-place same-length
            // interior edit whose mtime was set back passed length, identity,
            // mtime, header and tail head alike, because every one of those
            // is metadata the editor controls or bytes the edit never
            // touched. A keyed MAC over (length, head, mtime) would not have
            // closed it either — the attack leaves all three inputs exactly
            // as cached, so the MAC still verifies. The admission is
            // therefore bound to content: the sample re-reads bytes spread
            // over the whole log (every byte of a small log), and a mismatch
            // sends the writer to the re-walk, which fails on the broken
            // chain link. The re-walk count bounds how long the sample is
            // trusted for a large log, where it is probabilistic.
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
                && read_tail_head(&self.path) == Some(cached.head)
                && cached.appends_since_walk < FAST_PATH_REWALK_EVERY
                && self.sample_matches(&cached);
            if usable {
                used_fast_path = true;
                cached
            } else {
                let (bytes, identity, modified) = read_capped_with_identity(&self.path)?;
                // An open handle never adopts a different file at its path
                // (F1-NF-07). The walk below accepts any self-consistent
                // chain, so a mismatch that only forced this re-walk would
                // ratify the replacement: the next receipt would link onto
                // a history the handle never wrote, including a genuine
                // backup whose MACs are genuine under the same key (no MAC
                // check, at walk time or anywhere else, can tell a backup
                // from the log it backs up). Refuse instead, before the
                // walk, and touch nothing: the cached state is left intact,
                // so if the original file returns the handle appends again,
                // and the remedy for a deliberate replacement is to reopen
                // the log, which is what the error says. Only a pinned
                // identity can refuse: `None` on either side means no
                // baseline was ever established (a fresh `open` or `create`,
                // or a state refreshed by `repair_tail`), and the walk then
                // establishes one, exactly as a fresh handle would.
                if let (Some(pinned), Some(fresh)) = (cached.identity, identity) {
                    if pinned != fresh {
                        return Err(Error::receipt(
                            "the receipt log file was replaced since this handle opened it; reopen the log before appending",
                        ));
                    }
                }
                let (_, mut walked) = walk_log(&bytes)?;
                walked.identity = identity;
                walked.modified = modified;
                // The walk verified every byte, so this state is the one the
                // next sample is taken from.
                walked.sample = Some(sample_bytes(&self.sample_seed, &bytes));
                walked.appends_since_walk = 0;
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
        // The skew bound is checked against one horizon for the whole batch,
        // so a receipt dated beyond it is refused before anything is written.
        let horizon = future_horizon_ms();
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
            if receipt.at_ms > horizon {
                return Err(Error::receipt("receipt time is too far in the future"));
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
        // Our own append moved the mtime the fast path compares: refresh it
        // here, or every later append re-walks the whole log (the linearity
        // test caught exactly that).
        state.modified = path_modified(&self.path);
        // The file grew by the batch, so the sample must cover the new bytes:
        // refresh it from disk, and advance the re-walk count only when this
        // append trusted the fast path (a walk has just happened, so its
        // count restarts at zero). A refresh that cannot read the file leaves
        // no sample, and the next append re-walks instead of trusting stale
        // bytes (RPC-05).
        if used_fast_path {
            state.appends_since_walk = state.appends_since_walk.saturating_add(1);
        } else {
            state.appends_since_walk = 0;
        }
        state.sample = self.read_sample(total);
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
        // A log that already walks is intact -- unless its tail is dated
        // beyond the skew bound (R2-R13-01): one future-dated receipt bricks
        // appends forever, and the walk alone cannot see it, so `repair`
        // used to report 0 bytes cut for a log that could never be appended
        // to again. Cut back to the last record within the bound; the suffix
        // is exactly the records no legitimate writer could have produced,
        // and the prefix is a valid log (a prefix of a walking log still
        // walks). `encode_record` is deterministic, so re-encoding the
        // walked receipts reproduces the exact record boundaries.
        if let Ok((receipts, _)) = walk_log(&bytes) {
            let horizon = future_horizon_ms();
            let mut previous = [0u8; 32];
            let mut offset = LOG_HEADER_LEN;
            let mut cut_at: Option<usize> = None;
            for receipt in &receipts {
                if receipt.at_ms > horizon {
                    cut_at = Some(offset);
                    break;
                }
                let record = encode_record(receipt, &previous)?;
                previous.copy_from_slice(&record[record.len() - 32..]);
                offset += record.len();
            }
            let cut_at = match cut_at {
                Some(at) => at,
                None => return Ok(0),
            };
            // The prefix must itself be a valid log, or the cut would keep
            // damage.
            let _ = walk_log(&bytes[..cut_at])?;
            // The same check as the append: a repair that lost its lock must
            // not truncate a log another writer now owns (R-13 round 10, A).
            if !lock.still_holds() {
                return Err(Error::receipt(
                    "the receipt log lock was displaced by another process",
                ));
            }
            file.set_len(cut_at as u64)
                .map_err(|_| Error::receipt("cannot truncate the future-dated tail"))?;
            file.sync_all()
                .map_err(|_| Error::receipt("cannot flush the repaired log"))?;
            return Ok((bytes.len() - cut_at) as u64);
        }
        verify_header(&bytes)?;
        let good_end = walk_prefix(&bytes);
        let tail = &bytes[good_end..];
        let declared_past_end = if tail.len() < 4 {
            true
        } else {
            let length = u32::from_le_bytes(tail[..4].try_into().expect("4 bytes")) as usize;
            // An out-of-range length is a zeroed or flooded tail, not a record
            // that begins inside the tail: cut it only if no record survives
            // there (the `tail_holds_a_record` guard below keeps the
            // in-range-but-truncated case honest). Refusing it wedged a
            // filesystem zero-fill behind manual surgery (R-13 round 16, F3).
            !(MIN_LOG_RECORD..=MAX_LOG_RECORD).contains(&length)
                || good_end + 4 + length > bytes.len()
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

/// One per-instance seed for the append fast-path content sample (RPC-05).
///
/// The operating system CSPRNG is the same source the kernel seeds itself
/// from; a log that cannot draw one is not created at all, rather than
/// running with predictable sample windows.
fn new_sample_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|_| Error::receipt("the operating system CSPRNG must be available"))?;
    Ok(seed)
}

/// The windows of the log body the fast path samples on every append
/// (RPC-05): one `(offset, length)` pair per stratum, in file order.
///
/// The record region (everything past the header) is split into
/// [`FAST_PATH_SAMPLE_STRATA`] equal strata — the first strata hold one byte
/// more when the region does not divide evenly, so every byte belongs to
/// exactly one stratum — and one window of at most [`FAST_PATH_SAMPLE_WINDOW`]
/// bytes is taken from each. Where the window sits inside its stratum is
/// derived from the per-instance seed, the stratum index and the file length,
/// so the checked bytes change as the log grows and are unpredictable to a
/// writer that has file access but no access to this process's memory. A
/// stratum no larger than the window is covered end to end, which is what
/// makes a small log's fast path verify every byte.
///
/// The offsets depend on the total length, so a sample is only meaningful for
/// the length it was computed over: the caller must have checked the length
/// first, which the fast-path gate does.
fn sample_windows(seed: &[u8; 32], total_len: u64) -> [(u64, u64); FAST_PATH_SAMPLE_STRATA] {
    let mut windows = [(0u64, 0u64); FAST_PATH_SAMPLE_STRATA];
    let region_len = total_len.saturating_sub(LOG_HEADER_LEN as u64);
    if region_len == 0 {
        return windows;
    }
    let base = region_len / FAST_PATH_SAMPLE_STRATA as u64;
    let extra = region_len % FAST_PATH_SAMPLE_STRATA as u64;
    let mut start = LOG_HEADER_LEN as u64;
    for (index, window) in windows.iter_mut().enumerate() {
        let stratum_len = base + u64::from((index as u64) < extra);
        let take = stratum_len.min(FAST_PATH_SAMPLE_WINDOW as u64);
        let slack = stratum_len - take;
        let shift = if slack == 0 {
            0
        } else {
            let mut hasher = blake3::Hasher::new_keyed(seed);
            hasher.update(&(index as u64).to_le_bytes());
            hasher.update(&total_len.to_le_bytes());
            hasher.update(&slack.to_le_bytes());
            let derived = hasher.finalize();
            u64::from_le_bytes(
                derived.as_bytes()[..8]
                    .try_into()
                    .expect("8 bytes of a hash"),
            ) % (slack + 1)
        };
        *window = (start + shift, take);
        start += stratum_len;
    }
    windows
}

/// The keyed hash of the sampled windows of a whole log held in memory
/// (RPC-05).
///
/// `bytes` is the complete file, header included; only the record region is
/// sampled. The windows come from [`sample_windows`], so this agrees with
/// [`ReceiptLog::read_sample`] for the same seed and length by construction.
fn sample_bytes(seed: &[u8; 32], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    for (offset, len) in sample_windows(seed, bytes.len() as u64) {
        let offset = offset as usize;
        let len = len as usize;
        // The windows are derived from this very length, so they lie inside
        // the bytes by construction; the slice is the contract, not a guess.
        hasher.update(&bytes[offset..offset + len]);
    }
    *hasher.finalize().as_bytes()
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

/// The identity of a path on Windows: volume serial plus file index.
///
/// The path is opened and the opened handle is identified, so the identity
/// describes the file that was actually opened — the same shape as
/// [`lock_path_identity`] (XPL-RPC-08), which does this for the lock file. A
/// symlink at the path is refused outright: the link has its own file index,
/// but a swapped-in link must never pass by pointing at the original. A
/// recreated file gets a new file index even when its bytes are identical,
/// so a byte-identical copy at the same path is a different file, as on
/// unix. `None` when the filesystem supplies no file IDs (a zero file
/// index — FAT/exFAT — where treating zero as an identity would equate
/// every file on the volume); `create` already fails there (the header
/// install needs a hard link), so no working log exists there to break.
#[cfg(windows)]
fn path_identity(path: &std::path::Path) -> Option<(u64, u64)> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    active_rpc_file_identity::file_identity(&file)
}

/// Off unix and Windows there is no stable inode at the MSRV: the fast path
/// and the reader fall back to the length and header checks, and the
/// residual is stated in ADR-0021 (R-13 round 14, F2). The append handle
/// cannot pin a file it cannot identify there, so a replacement is adopted
/// by the walk (F1-NF-07) — the same residual, now narrowed to platforms
/// with no identity primitive.
#[cfg(not(any(unix, windows)))]
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
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
/// On unix and Windows a state with no recorded identity cannot be trusted,
/// so the fast path re-walks. Where there is no identity primitive the
/// documented residual applies (R-13 round 14, F1/F2; F1-NF-07).
fn identity_matches(path: &std::path::Path, identity: Option<(u64, u64)>) -> bool {
    #[cfg(any(unix, windows))]
    {
        identity.is_some() && identity == path_identity(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, identity);
        true
    }
}

/// Whether the path still names the file that was read.
///
/// On unix and Windows `(dev, ino)` — or the volume serial plus file index
/// — decides; elsewhere the read and the length check are all that is
/// available (the residual the ADR records).
fn same_identity(path: &std::path::Path, identity: Option<(u64, u64)>) -> bool {
    #[cfg(any(unix, windows))]
    {
        identity.is_some() && path_identity(path) == identity
    }
    #[cfg(not(any(unix, windows)))]
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
        #[cfg(windows)]
        {
            // The identity of the handle that was read, not of a second
            // open: the bytes below come from this handle, so the identity
            // must describe it (F1-NF-07).
            active_rpc_file_identity::file_identity(&file)
        }
        #[cfg(not(any(unix, windows)))]
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
    let Some(LockFacts { age_ms, pid, .. }) = lock_state(&lock_path(path)) else {
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
        // A bare walk knows no seed, so it establishes no sample: the
        // caller that owns the seed sets it from the walked bytes, and any
        // other consumer re-walks on its next append (RPC-05).
        sample: None,
        appends_since_walk: 0,
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

/// Offset just past the last record that decodes, stopping at the first one
/// that does not.
///
/// Returns only the offset: `repair` needs the cut point, and materialising
/// every record let a crafted 64 MiB log allocate hundreds of megabytes of
/// `Receipt`s it discarded (R-13 round 16, F5). The walk also stops at
/// [`MAX_LOG_RECORDS`], which a writer never exceeds.
fn walk_prefix(bytes: &[u8]) -> usize {
    let Ok(start) = verify_header(bytes) else {
        return 0;
    };
    let mut count: u64 = 0;
    let mut cursor = LOG_HEADER_LEN;
    let mut expected_previous = [0u8; 32];
    let mut last_time = 0u64;
    while cursor < bytes.len() {
        if count >= MAX_LOG_RECORDS {
            break;
        }
        let Ok((receipt, previous, record_hash, next)) = decode_record(bytes, cursor) else {
            break;
        };
        if previous != expected_previous {
            break;
        }
        if start.checked_add(count) != Some(receipt.sequence) {
            break;
        }
        if receipt.at_ms < last_time {
            break;
        }
        last_time = receipt.at_ms;
        expected_previous = record_hash;
        count += 1;
        cursor = next;
    }
    cursor
}

/// What a decision looks like in a log line.
pub fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Admitted => "admitted",
        Decision::Refused(_) => "refused",
    }
}

#[cfg(test)]
mod walk_tests {
    use super::*;

    /// The prefix walk stops at the record ceiling and allocates nothing per
    /// record: a crafted log larger than a writer can produce must not build
    /// hundreds of megabytes of discarded `Receipt`s (R-13 round 16, F5).
    #[test]
    fn a_walk_stops_at_the_record_ceiling() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(LOG_MAGIC);
        bytes.push(2);
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        assert_eq!(bytes.len(), LOG_HEADER_LEN);
        let mut previous = [0u8; 32];
        for index in 0..=MAX_LOG_RECORDS {
            let receipt = Receipt {
                sequence: 1 + index,
                cap: "0011223344556677".to_string(),
                method: "echo".to_string(),
                at_ms: index,
                decision: Decision::Admitted,
                mac: [0u8; 32],
            };
            let encoded = encode_record(&receipt, &previous).expect("record");
            previous = encoded[encoded.len() - 32..]
                .try_into()
                .expect("32-byte hash");
            bytes.extend_from_slice(&encoded);
        }
        let offset = walk_prefix(&bytes);
        assert!(
            offset < bytes.len(),
            "the walk stopped before the extra record"
        );
        let mut records = 0u64;
        let mut cursor = LOG_HEADER_LEN;
        while cursor < offset {
            let (_, _, _, next) = decode_record(&bytes, cursor).expect("record decodes");
            records += 1;
            cursor = next;
        }
        assert_eq!(records, MAX_LOG_RECORDS, "the ceiling is the stop");
    }
}

#[cfg(test)]
mod sample_tests {
    use super::*;

    /// The sample windows of a small log cover every byte of it, so the fast
    /// path verifies a small log byte-for-byte and no interior edit can hide
    /// between windows (RPC-05). Above the coverage limit the windows are
    /// still in order, in bounds and disjoint, and sample the full budget.
    #[test]
    fn small_logs_are_sampled_end_to_end() {
        let seed = [0x5au8; 32];
        // An empty record region samples nothing.
        assert!(
            sample_windows(&seed, LOG_HEADER_LEN as u64)
                .iter()
                .all(|&(_, len)| len == 0),
            "an empty region has no windows"
        );
        for region in 1..=600usize {
            let total = (LOG_HEADER_LEN + region) as u64;
            let windows = sample_windows(&seed, total);
            let mut covered = 0u64;
            let mut cursor = LOG_HEADER_LEN as u64;
            for (offset, len) in windows {
                assert!(
                    offset >= cursor && offset + len <= total,
                    "window {offset}+{len} escapes its stratum in a {region}-byte region"
                );
                covered += len;
                cursor = offset + len;
            }
            if region <= FAST_PATH_SAMPLE_STRATA * FAST_PATH_SAMPLE_WINDOW {
                assert_eq!(
                    covered, region as u64,
                    "a {region}-byte region must be covered end to end"
                );
            } else {
                assert_eq!(
                    covered,
                    (FAST_PATH_SAMPLE_STRATA * FAST_PATH_SAMPLE_WINDOW) as u64,
                    "a large region samples the full window budget"
                );
            }
        }
        // Same seed and length, same windows: the sample a walk establishes
        // is the sample the next append checks.
        assert_eq!(
            sample_windows(&seed, 300),
            sample_windows(&seed, 300),
            "the windows are deterministic"
        );
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
    /// Age a lock file past the stale ceiling. A write handle is needed:
    /// on Windows `set_times` through a read-only handle is refused
    /// (XPL-RPC-02 probe shape).
    fn age_lock(lock_path: &std::path::Path, seconds: u64) {
        let handle = std::fs::OpenOptions::new()
            .write(true)
            .open(lock_path)
            .expect("open for set_times");
        handle
            .set_times(std::fs::FileTimes::new().set_modified(
                std::time::SystemTime::now() - std::time::Duration::from_secs(seconds),
            ))
            .expect("age the lock");
    }

    /// A crash mid-write leaves a partial line that still starts with the lock
    /// magic. The magic is proof of origin, so the shape gate must not apply:
    /// otherwise the file is unjudgeable and wedges the log for ever
    /// (R-13 round 16, F2).
    #[test]
    fn a_partial_magic_lock_is_still_stealable() {
        let path = scratch("partial-magic");
        let lock_path = lock_of(&path);
        let shapes = [
            format!("{}1234-5678", super::LOCK_MAGIC),
            format!("{}1234-5678 pid", super::LOCK_MAGIC),
            format!("{}1234-5678 pid 999", super::LOCK_MAGIC),
        ];
        for body in shapes {
            std::fs::write(&lock_path, body.as_bytes()).expect("partial lock");
            let handle = std::fs::OpenOptions::new()
                .write(true)
                .open(&lock_path)
                .expect("open");
            handle
                .set_times(std::fs::FileTimes::new().set_modified(
                    // Past the 20-minute live grace, so a partial line naming a
                    // pid that is alive on this host is still judged stale
                    // (Linux CI has a live pid 999).
                    std::time::SystemTime::now() - std::time::Duration::from_secs(1_300),
                ))
                .expect("age the lock");
            drop(handle);
            let (nonce, identity) = super::judged_stale(&lock_path)
                .unwrap_or_else(|| panic!("a stale partial lock is judged: {body}"));
            assert_eq!(nonce, "1234-5678", "the nonce is the first word: {body}");
            assert!(
                super::take_stale(&lock_path, &nonce, identity),
                "the judged partial lock is stolen: {body}"
            );
            assert!(!lock_path.exists(), "the wedge is gone: {body}");
        }
        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// `nonce_of` must use the guarded reader: a symlink at the lock path is
    /// not followed (unix; off unix the residual is in ADR-0021)
    /// (R-13 round 16, F9).
    #[cfg(unix)]
    #[test]
    fn a_lock_symlink_is_not_read_through() {
        let dir = std::env::temp_dir().join(format!("active-rpc-lock-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let target = dir.join("target");
        std::fs::write(
            &target,
            format!("{}abc-1 pid 1 started 1", super::LOCK_MAGIC),
        )
        .expect("target");
        let link = dir.join("receipts.arrl.lock");
        std::os::unix::fs::symlink(&target, &link).expect("link");
        assert!(
            super::nonce_of(&link).is_none(),
            "the guarded reader refuses a symlink"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The steal proves it moved the file it judged. A replacement that copies
    /// the judged nonce is preserved, because on unix identity is the inode
    /// (R-13 round 16, F4).
    #[cfg(unix)]
    #[test]
    fn the_steal_uses_the_judged_inode_not_its_text() {
        let dir =
            std::env::temp_dir().join(format!("active-rpc-lock-inode-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let lock_path = dir.join("receipts.arrl.lock");
        let body = format!("{}abc-1 pid 1 started 1", super::LOCK_MAGIC);
        std::fs::write(&lock_path, &body).expect("lock");
        let facts = super::lock_state(&lock_path).expect("state");
        let nonce = facts.nonce;
        let identity = facts.identity;
        assert!(identity.is_some(), "unix identity is available");

        // Same text, new inode: a steal must not delete this file.
        std::fs::remove_file(&lock_path).expect("remove");
        std::fs::write(&lock_path, &body).expect("replacement");
        assert!(
            !super::take_stale(&lock_path, &nonce, identity),
            "a replacement with the same text is not the judged file"
        );
        assert!(lock_path.exists(), "the replacement is preserved");
        let _ = std::fs::remove_dir_all(&dir);
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
            !super::take_stale(&lock_path, "judged-2", None),
            "a lock with another nonce is not the one judged"
        );
        let kept = std::fs::read_to_string(&lock_path).expect("the unjudged lock survives");
        assert!(kept.contains("fresh-1"), "the live lock is intact: {kept}");

        // The lock that *was* judged is removed, so a real stale lock still goes.
        assert!(
            super::take_stale(&lock_path, "fresh-1", None),
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

    /// A byte-identical copy of a live lock is not the holder's lock
    /// (XPL-RPC-08): the nonce is plaintext, so on Windows the text check
    /// could not tell the copy from the original and the displaced writer
    /// kept appending. Ownership is the file, not the text — a recreated
    /// file, however identical its bytes, is a different file.
    #[test]
    fn a_copied_lock_nonce_does_not_keep_a_live_lock() {
        let path = scratch("copied-nonce");
        std::fs::write(&path, b"").expect("log");
        let lock = LogLock::acquire(&path).expect("the lock is free");
        let lock_path = lock_of(&path);
        assert!(lock.still_holds(), "a fresh lock owns the path");

        // The attack: a local user reads the plaintext nonce, unlinks the
        // lock and recreates the same text.
        let bytes = std::fs::read(&lock_path).expect("read the live lock");
        std::fs::remove_file(&lock_path).expect("remove");
        std::fs::write(&lock_path, &bytes).expect("replacement");
        assert_eq!(
            std::fs::read(&lock_path).expect("read the copy"),
            bytes,
            "the copy is byte-identical: the attack's premise"
        );
        assert!(
            !lock.still_holds(),
            "a byte-identical copy of the lock is not the holder's lock"
        );

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// The `Drop` half of the same hole (XPL-RPC-08): a displaced holder
    /// must not delete the replacement lock when it finishes. Before the
    /// fix the drop's nonce check passed on the copy and removed a file
    /// the holder did not own.
    #[test]
    fn a_displaced_holders_drop_does_not_delete_the_replacement_lock() {
        let path = scratch("drop-copy");
        std::fs::write(&path, b"").expect("log");
        let lock = LogLock::acquire(&path).expect("the lock is free");
        let lock_path = lock_of(&path);
        let bytes = std::fs::read(&lock_path).expect("read the live lock");
        std::fs::remove_file(&lock_path).expect("remove");
        std::fs::write(&lock_path, &bytes).expect("replacement");
        drop(lock);
        let kept = std::fs::read(&lock_path).expect("the replacement survives the holder's drop");
        assert_eq!(kept, bytes, "the replacement is intact");

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// The steal half of the same hole (XPL-RPC-08, and XPL-RPC-03's
    /// Windows side): a replacement carrying the judged nonce is not the
    /// judged file, so the steal must preserve it. On unix the judged
    /// inode decides (R-13 round 16, F4); on Windows the judged file
    /// index must decide the same way.
    #[test]
    fn the_steal_uses_the_judged_identity_not_its_text() {
        let path = scratch("steal-copy");
        let lock_path = lock_of(&path);
        let body = format!("{}stale-1 pid 4294967294 started 1", super::LOCK_MAGIC);
        std::fs::write(&lock_path, &body).expect("lock");
        age_lock(&lock_path, 130);
        let (nonce, identity) =
            super::judged_stale(&lock_path).expect("a lock naming a dead pid is judged stale");
        assert_eq!(nonce, "stale-1");

        // Same text, new file: the steal must not delete this file.
        std::fs::remove_file(&lock_path).expect("remove");
        std::fs::write(&lock_path, &body).expect("replacement");
        assert!(
            !super::take_stale(&lock_path, &nonce, identity),
            "a replacement carrying the judged nonce is not the judged file"
        );
        assert!(lock_path.exists(), "the replacement is preserved");

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// The attack as audited (XPL-RPC-08): the copy is made by another
    /// process, not by this test. The holder's `still_holds` inspects only
    /// the filesystem, so the process boundary is the attack's shape, not a
    /// timing race — each child is awaited before the assertion runs, and
    /// no sleep or retry is involved.
    #[cfg(windows)]
    #[test]
    fn a_lock_nonce_copied_by_another_process_does_not_keep_the_lock() {
        let path = scratch("copied-by-child");
        std::fs::write(&path, b"").expect("log");
        let lock = LogLock::acquire(&path).expect("the lock is free");
        let lock_path = lock_of(&path);
        assert!(lock.still_holds(), "a fresh lock owns the path");
        let bytes = std::fs::read(&lock_path).expect("read the live lock");

        let lock_text = lock_path.to_str().expect("the temp path is UTF-8");
        let copy_path = lock_path.with_file_name(format!(
            "{}.copy",
            lock_path.file_name().unwrap().to_string_lossy()
        ));
        let copy_text = copy_path.to_str().expect("the temp path is UTF-8");
        // One `cmd` per step, each awaited: copy the live lock aside, unlink
        // the lock, move the copy back. The lock path then carries the same
        // bytes from a file another process wrote.
        let run = |args: &[&str]| {
            let output = std::process::Command::new("cmd")
                .arg("/C")
                .args(args)
                .output()
                .expect("spawn cmd");
            assert!(
                output.status.success(),
                "cmd {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run(&["copy", "/Y", lock_text, copy_text]);
        run(&["del", lock_text]);
        run(&["move", "/Y", copy_text, lock_text]);
        assert_eq!(
            std::fs::read(&lock_path).expect("read the copy"),
            bytes,
            "the copy another process made is byte-identical"
        );
        assert!(
            !lock.still_holds(),
            "a copy another process made is not the holder's lock"
        );

        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// A lock naming a live pid is not stolen past the stale ceiling
    /// (XPL-RPC-02): on Windows `process_is_alive` always returned `false`,
    /// so a live holder's lock was stolen 130 s in, while Linux honours it
    /// until the 20-minute grace. The mirror of the W6 verification probe,
    /// which plants exactly this lock and watches the append go through.
    #[test]
    fn a_lock_naming_a_live_pid_is_not_stolen_past_the_stale_ceiling() {
        let path = scratch("live-pid");
        let lock_path = lock_of(&path);
        std::fs::write(
            &lock_path,
            format!(
                "{}live-1 pid {} started 1",
                super::LOCK_MAGIC,
                std::process::id()
            ),
        )
        .expect("lock");
        age_lock(&lock_path, 130);
        assert!(
            super::judged_stale(&lock_path).is_none(),
            "a lock naming a live pid is live until the grace, not stealable at 130 s"
        );
        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    /// The other direction of the same rule (XPL-RPC-02): a lock naming a
    /// pid that does not exist is still stolen past the ceiling, or a
    /// liveness fix that never reports dead would wedge the log for ever.
    /// 4294967294 is the dead pid the steal tests already use: no host
    /// hands it out.
    #[test]
    fn a_lock_naming_a_dead_pid_is_stolen_past_the_stale_ceiling() {
        let path = scratch("dead-pid");
        let lock_path = lock_of(&path);
        std::fs::write(
            &lock_path,
            format!("{}dead-1 pid 4294967294 started 1", super::LOCK_MAGIC),
        )
        .expect("lock");
        age_lock(&lock_path, 130);
        let (nonce, identity) =
            super::judged_stale(&lock_path).expect("a lock naming a dead pid is judged stale");
        assert_eq!(nonce, "dead-1");
        assert!(
            super::take_stale(&lock_path, &nonce, identity),
            "the judged dead-pid lock is stolen"
        );
        assert!(!lock_path.exists(), "the stolen lock is gone");
        let _ = std::fs::remove_file(&path);
    }

    /// `process_is_alive` is the primitive the steal rule stands on
    /// (XPL-RPC-02): the caller's own pid is alive on every platform, and
    /// a pid no host hands out is not.
    #[test]
    fn process_is_alive_reports_the_callers_own_pid_and_rejects_an_impossible_one() {
        assert!(
            super::process_is_alive(std::process::id()),
            "the test process itself is alive"
        );
        assert!(
            !super::process_is_alive(u32::MAX),
            "no host hands out pid u32::MAX"
        );
    }

    /// The corruption case behind XPL-RPC-02, not just the planted-lock
    /// probe: a writer that really holds the lock (its file open, its pid
    /// live) but has not touched it for 130 s must not lose it to a
    /// stealer. `touch` is what a progressing writer calls; a stalled one
    /// is covered by the pid, up to the grace.
    #[test]
    fn a_live_holders_lock_is_not_stolen_while_it_is_held() {
        let path = scratch("live-holder");
        std::fs::write(&path, b"").expect("log");
        let lock = LogLock::acquire(&path).expect("the lock is free");
        let lock_path = lock_of(&path);
        age_lock(&lock_path, 130);
        assert!(
            super::judged_stale(&lock_path).is_none(),
            "a lock its holder still holds is live, however old its mtime"
        );
        drop(lock);
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

    /// A receipt log is never one of the writer's leftovers, whatever its
    /// name: the sweep reads the magic before it deletes a matching entry
    /// (R-13 round 16, F6).
    #[test]
    fn the_sweep_spares_a_sibling_receipt_log() {
        let dir = scratch_dir("sweep-sibling");
        let path = dir.join("log.arrl");
        let sibling = dir.join("log.arrl.stale-operator-1");
        std::fs::write(&sibling, b"ARRL\x02\0\0\0").expect("sibling log");
        age(&sibling, 600);
        drop(LogLock::acquire(&path).expect("lock"));
        assert!(sibling.exists(), "a sibling receipt log survived the sweep");
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

    /// On Windows the open itself must refuse a reparse point (XPL-RPC-01):
    /// `O_NOFOLLOW` is unix-only, and the post-open `is_file()` check follows
    /// the link to a regular file, so without the refusal the open hands back
    /// a handle to the attacker's target. The mirror of
    /// `the_write_open_refuses_a_symlink` above.
    #[cfg(windows)]
    #[test]
    fn the_write_open_refuses_a_reparse_point_on_windows() {
        let dir = scratch_dir("nofollow-win");
        let target = dir.join("victim");
        std::fs::write(&target, b"keep").expect("victim");
        let link = dir.join("log.arrl");
        std::os::windows::fs::symlink_file(&target, &link).expect("symlink");
        let error = open_log_write(&link, true, false).expect_err("refused");
        assert_eq!(error.code(), "rpc/receipt");
        assert_eq!(std::fs::read(&target).expect("victim"), b"keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The read open is the same hole (XPL-RPC-01): the reader has no
    /// pre-open check of its own, so a link at the path is followed and the
    /// target's bytes are read as the log's.
    #[cfg(windows)]
    #[test]
    fn the_read_open_refuses_a_reparse_point_on_windows() {
        let dir = scratch_dir("nofollow-read-win");
        let target = dir.join("victim");
        std::fs::write(&target, b"keep").expect("victim");
        let link = dir.join("log.arrl");
        std::os::windows::fs::symlink_file(&target, &link).expect("symlink");
        let error = open_log_read(&link).expect_err("refused");
        assert_eq!(error.code(), "rpc/receipt");
        assert_eq!(std::fs::read(&target).expect("victim"), b"keep");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `repair` truncates the file it walked, never a link planted at the path
    /// — on Windows too (XPL-RPC-01).
    #[cfg(windows)]
    #[test]
    fn repair_never_truncates_through_a_symlink_on_windows() {
        let dir = scratch_dir("repair-link-win");
        let target = dir.join("victim");
        std::fs::write(&target, vec![0x41u8; 4096]).expect("victim");
        let link = dir.join("log.arrl");
        std::os::windows::fs::symlink_file(&target, &link).expect("symlink");
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

#[cfg(test)]
mod future_tests {
    use super::*;

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "active-rpc-receipt-future-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
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

    /// R2-R13-01 (a): a receipt dated beyond the skew bound is refused at
    /// append, and the refusal spends nothing -- the log keeps its one
    /// record and still accepts a legitimate receipt afterwards.
    #[test]
    fn a_future_dated_receipt_is_refused_at_append() {
        let dir = scratch_dir("append-gate");
        let path = dir.join("log.arrl");
        let log = ReceiptLog::create(&path).expect("create");
        log.append(&receipt(1, 100)).expect("append seq 1");
        let err = log
            .append(&receipt(2, u64::MAX))
            .expect_err("u64::MAX must be refused");
        assert!(
            err.to_string().contains("too far in the future"),
            "the refusal must name the skew bound, not the backwards rule: {err}"
        );
        assert_eq!(log.records().expect("records").len(), 1);
        // A receipt stamped with the real wall clock still appends.
        log.append(&receipt(2, wall_ms())).expect("append seq 2");
        assert_eq!(log.records().expect("records").len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R2-R13-01 (b): a log bricked before the fix -- one future-dated
    /// record at the tail -- is cut back to the last in-bound record by
    /// repair, and appends resume at the sequence that follows the
    /// surviving records.
    #[test]
    fn repair_cuts_a_future_dated_suffix_and_appends_resume() {
        let dir = scratch_dir("repair-cut");
        let path = dir.join("log.arrl");
        // Build the bricked log by hand: the append gate (a) now refuses the
        // future record, so a log bricked before the fix can only be
        // constructed from encoded records.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(LOG_MAGIC);
        bytes.push(LOG_VERSION);
        bytes.extend_from_slice(&[0, 0, 0]);
        bytes.extend_from_slice(&1u64.to_le_bytes());
        let mut previous = [0u8; 32];
        let first = encode_record(&receipt(1, 100), &previous).expect("record 1");
        previous.copy_from_slice(&first[first.len() - 32..]);
        bytes.extend_from_slice(&first);
        let future = encode_record(&receipt(2, u64::MAX), &previous).expect("record 2");
        bytes.extend_from_slice(&future);
        std::fs::write(&path, &bytes).expect("write bricked log");

        let log = ReceiptLog::open(&path).expect("open walks the bricked log");
        assert_eq!(log.records().expect("records").len(), 2);
        let err = log
            .append(&receipt(3, wall_ms()))
            .expect_err("the bricked log must refuse appends");
        assert!(err.to_string().contains("backwards"), "{err}");

        let cut = ReceiptLog::repair(&path).expect("repair runs");
        assert_eq!(
            cut,
            future.len() as u64,
            "repair must cut exactly the future record"
        );
        assert_eq!(log.records().expect("records").len(), 1);
        log.append(&receipt(2, wall_ms()))
            .expect("appends resume at the sequence after the surviving records");
        assert_eq!(log.records().expect("records").len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod path_validation_tests {
    use super::*;

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "active-rpc-path-validation-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
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

    /// XPL-RPC-10: `log.arrl` and `LOG.arrl` are two files on Linux and one
    /// file on NTFS and default APFS. Creating the second must be refused
    /// with the case collision named, not with "already holds records"
    /// (which is what the same file says through a differently-cased name),
    /// and the first log must be untouched afterwards.
    #[test]
    fn a_case_variant_of_an_existing_log_is_refused_at_create() {
        let dir = scratch_dir("case");
        let lower = dir.join("log.arrl");
        let upper = dir.join("LOG.arrl");
        let log = ReceiptLog::create(&lower).expect("create lower");
        log.append(&receipt(1, 100)).expect("append lower");
        let len_before = std::fs::metadata(&lower).expect("metadata").len();

        let error = ReceiptLog::create(&upper).expect_err("case variant refused");
        assert!(
            error.to_string().contains("only by case"),
            "the refusal must name the case collision: {error}"
        );

        assert_eq!(
            std::fs::metadata(&lower).expect("metadata").len(),
            len_before,
            "the refused create must not touch the existing log"
        );
        assert_eq!(
            log.records().expect("records").len(),
            1,
            "the existing log keeps its one receipt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// XPL-RPC-10: the refusal is the validation, not the install step. A
    /// zero-length file at the case-variant name would otherwise reach the
    /// hard link and come back as "created by another writer".
    #[test]
    fn a_case_variant_of_an_empty_existing_file_is_refused_at_create() {
        let dir = scratch_dir("case-empty");
        let lower = dir.join("log.arrl");
        std::fs::write(&lower, b"").expect("empty file");
        let error = ReceiptLog::create(dir.join("LOG.arrl")).expect_err("refused");
        assert!(
            error.to_string().contains("only by case"),
            "the refusal must name the case collision: {error}"
        );
        assert_eq!(
            std::fs::metadata(&lower).expect("metadata").len(),
            0,
            "the empty file is untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// XPL-RPC-10: `truncate` is the dangerous direction — on NTFS it would
    /// rename a fresh header over the differently-cased name, wiping the
    /// log it names. It must be refused the same way `create` is.
    #[test]
    fn truncate_refuses_a_case_variant_of_an_existing_log() {
        let dir = scratch_dir("case-truncate");
        let lower = dir.join("log.arrl");
        let log = ReceiptLog::create(&lower).expect("create lower");
        log.append(&receipt(1, 100)).expect("append lower");

        let error = ReceiptLog::truncate(dir.join("LOG.arrl")).expect_err("truncate refused");
        assert!(
            error.to_string().contains("only by case"),
            "the refusal must name the case collision: {error}"
        );
        assert_eq!(
            log.records().expect("records").len(),
            1,
            "the existing log survives the refused truncate"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// XPL-RPC-11: every legacy device stem is refused at `create` with the
    /// rule named — including lowercase spellings and the trailing-dot /
    /// trailing-space variants Windows strips — and the refusal happens
    /// before the lock is taken, so no lock or staging file is left behind.
    #[test]
    fn a_reserved_device_name_is_refused_at_create() {
        let dir = scratch_dir("reserved");
        for name in [
            "CON.arrl",
            "NUL.arrl",
            "COM1.arrl",
            "AUX.arrl",
            "PRN.arrl",
            "LPT1.arrl",
            "COM9.arrl",
            "LPT9.arrl",
            "con.arrl",
            "nul.arrl",
            "NUL.",
            "CON ",
            "COM1.",
        ] {
            let error = ReceiptLog::create(dir.join(name)).expect_err("refused");
            assert!(
                error.to_string().contains("reserved device name"),
                "{name}: the refusal must name the reserved device rule: {error}"
            );
        }
        assert_eq!(
            std::fs::read_dir(&dir).expect("read dir").count(),
            0,
            "a refused create must not leave a lock or staging file behind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// XPL-RPC-11: a total path of 260 characters or more cannot be opened
    /// on a default Windows host, so `create` refuses it on every platform
    /// with the ceiling named. The parent directories are deliberately not
    /// created: the validation runs before any filesystem touch, so the
    /// refusal must fire even for a path whose parents do not exist yet.
    /// The depth adapts to the machine's temp prefix (a short pid in a
    /// container shortens it), so the total is over the ceiling on any
    /// machine.
    #[test]
    fn a_log_path_of_260_or_more_characters_is_refused_at_create() {
        let dir = scratch_dir("long");
        let mut path = dir.clone();
        let mut i = 0;
        while path.to_string_lossy().len() + 1 + 8 < 260 {
            path = path.join(format!("{}{}", "a".repeat(50), i));
            i += 1;
        }
        let path = path.join("log.arrl");
        let total = path.to_string_lossy().len();
        assert!(
            total >= 260,
            "the test path must be over the ceiling: {total}"
        );

        let error = ReceiptLog::create(&path).expect_err("long path refused");
        assert!(
            error.to_string().contains("260"),
            "the refusal must name the 260-character ceiling: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// XPL-RPC-11: a component longer than 215 bytes leaves no room for the
    /// staging suffix inside the 255-byte component limit. `create` must
    /// refuse it with the staging suffix named, not fail at the staging
    /// step with "cannot create the receipt log".
    ///
    /// No subdirectory: the temp prefix plus the component must stay under
    /// the 260-character total ceiling, or the total-path rule fires first
    /// (a 235-byte component under an 80-character prefix is over both
    /// ceilings, and the total is reported first). The name carries the pid
    /// so parallel runs cannot collide in the shared temp directory, and the
    /// component is 219–221 bytes whatever the pid's length, so the
    /// component rule — not the pid — decides the outcome.
    #[test]
    fn a_log_name_too_long_for_the_staging_suffix_is_refused_at_create() {
        let dir = std::env::temp_dir();
        let name = format!("{}{}.arrl", "a".repeat(210), std::process::id());
        assert!(
            name.len() > 215,
            "the test name must be over the component ceiling: {}",
            name.len()
        );
        let path = dir.join(&name);
        assert!(
            path.to_string_lossy().len() < 260,
            "the test path must stay under the total ceiling"
        );
        let error = ReceiptLog::create(&path).expect_err("long name refused");
        assert!(
            error.to_string().contains("staging"),
            "the refusal must name the staging suffix: {error}"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// XPL-RPC-11 (control): a long name that fits the staging suffix still
    /// creates. The length adapts to the machine's temp prefix so the total
    /// path stays under the 260-character ceiling; the floor keeps the test
    /// meaningful on any machine.
    #[test]
    fn a_long_log_name_that_fits_the_staging_suffix_is_created() {
        let dir = std::env::temp_dir().join(format!("r10-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("short temp dir");
        let prefix = dir.to_string_lossy().len();
        let stem_len = 200.min(250usize.saturating_sub(prefix + 1 + 5));
        assert!(
            stem_len >= 150,
            "temp prefix too long to test a long log name: {prefix}"
        );
        let name = format!("{}.arrl", "a".repeat(stem_len));
        let path = dir.join(&name);
        assert!(
            path.to_string_lossy().len() < 260,
            "the control path must stay under the total ceiling"
        );
        let log = ReceiptLog::create(&path).expect("a fitting long name creates");
        log.append(&receipt(1, 100)).expect("append");
        assert_eq!(log.records().expect("records").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// XPL-RPC-11 (unit): the reserved-stem rule is a property of the final
    /// component's stem, case-insensitively, after trailing dots and spaces
    /// are stripped. `COM10` is not a legacy device, and a stem that merely
    /// starts with a device name is not one.
    #[test]
    fn a_reserved_device_stem_is_refused_by_path_validation() {
        let dir = std::env::temp_dir().join(format!("v10-{}", std::process::id()));
        for name in ["CON.arrl", "con.arrl", "NUL.", "CON ", "COM1.arrl", "LPT9"] {
            let error = validate_log_path(&dir.join(name)).expect_err("reserved stem refused");
            assert!(
                error.to_string().contains("reserved device name"),
                "{name}: {error}"
            );
        }
        for name in ["log.arrl", "COM10.arrl", "auxiliary.arrl", "console.arrl"] {
            assert!(
                validate_log_path(&dir.join(name)).is_ok(),
                "{name} is not a reserved device name"
            );
        }
    }

    /// XPL-RPC-11 (unit): the total-path ceiling is exact — 259 characters
    /// are accepted, 260 are refused. The path is built from short
    /// components so the component ceiling cannot fire first, and the
    /// lengths are computed from the machine's temp prefix so the boundary
    /// is exact on any machine.
    #[test]
    fn a_path_of_260_characters_is_refused_by_path_validation_and_259_is_accepted() {
        let mut dir = std::env::temp_dir().join(format!("v10-{}", std::process::id()));
        while dir.to_string_lossy().len() + 51 + 9 <= 240 {
            dir = dir.join("d".repeat(50));
        }
        let current = dir.to_string_lossy().len();
        let stem_len = 259usize.saturating_sub(current + 1 + 5);
        assert!(
            (9..=215).contains(&stem_len),
            "temp prefix too long to pin the total-path boundary: {current}"
        );
        let accepted = dir.join(format!("{}.arrl", "n".repeat(stem_len)));
        assert_eq!(accepted.to_string_lossy().len(), 259);
        assert!(
            validate_log_path(&accepted).is_ok(),
            "a 259-character path must be accepted"
        );
        let refused = dir.join(format!("{}.arrl", "n".repeat(stem_len + 1)));
        assert_eq!(refused.to_string_lossy().len(), 260);
        let error = validate_log_path(&refused).expect_err("260 refused");
        assert!(
            error.to_string().contains("260"),
            "the refusal must name the 260-character ceiling: {error}"
        );
    }

    /// XPL-RPC-11 (unit): the component ceiling is exact — a 215-byte final
    /// component leaves room for the longest staging suffix (40 bytes)
    /// inside the 255-byte limit, a 216-byte one does not. The total path
    /// is asserted short so the total-path ceiling cannot fire first.
    #[test]
    fn a_component_of_216_bytes_is_refused_by_path_validation_and_215_is_accepted() {
        // A one-letter base keeps the total path short: the temp prefix plus
        // a 215-byte component must stay under the 260-character ceiling, or
        // the total-path rule would fire first.
        let dir = std::env::temp_dir().join("q");
        let accepted = dir.join(format!("{}.arrl", "a".repeat(210)));
        assert_eq!(accepted.file_name().unwrap().len(), 215);
        assert!(
            accepted.to_string_lossy().len() < 260,
            "the accepted path must stay under the total ceiling"
        );
        assert!(
            validate_log_path(&accepted).is_ok(),
            "a 215-byte component must be accepted"
        );
        let refused = dir.join(format!("{}.arrl", "a".repeat(211)));
        assert_eq!(refused.file_name().unwrap().len(), 216);
        assert!(
            refused.to_string_lossy().len() < 260,
            "the refused path must stay under the total ceiling"
        );
        let error = validate_log_path(&refused).expect_err("216 refused");
        assert!(
            error.to_string().contains("staging"),
            "the refusal must name the staging suffix: {error}"
        );
    }
}
