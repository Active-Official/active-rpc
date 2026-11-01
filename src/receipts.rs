//! Capability receipts: an audit record of the authorization decision.
//!
//! A receipt answers "was this call authorized, under which capability, and
//! when" without carrying arguments, values or any secret material. Each
//! receipt is authenticated with a keyed hash under the kernel secret, so a
//! record cannot be edited or transplanted between kernels without detection.
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

impl Receipt {
    /// Build and seal a receipt for a decision.
    pub(crate) fn seal(
        secret: &[u8; 32],
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
        receipt.mac = receipt.compute(secret);
        receipt
    }

    /// True when the receipt was produced by the kernel that owns `secret` and
    /// its fields were not edited.
    pub fn verify(&self, secret: &[u8; 32]) -> bool {
        let expected = self.compute(secret);
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

    fn compute(&self, secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(secret);
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
    !method.is_empty() && method.len() <= MAX_METHOD_BYTES && !method.chars().any(char::is_control)
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

/// Exclusive access to one log file, held for the length of an append.
struct LogLock {
    path: std::path::PathBuf,
}

impl LogLock {
    /// Take the log's lock, waiting briefly for a concurrent writer.
    ///
    /// `create_new` is atomic on every supported platform: one writer wins. The
    /// others retry for about a second, which covers a normal append, then
    /// refuse rather than corrupt the chain. A lock left behind by a crashed
    /// process is reported by the append and can be removed by hand; the log
    /// itself is still readable.
    fn acquire(log: &std::path::Path) -> Result<Self> {
        let path = log.with_extension("lock");
        for _ in 0..200 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => return Err(Error::receipt("cannot lock the receipt log")),
            }
        }
        Err(Error::receipt(
            "the receipt log is locked by another writer",
        ))
    }
}

impl Drop for LogLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
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
/// needs the kernel secret ([`ReceiptLog::verify_macs`]); truncation of the tail
/// is caught by pinning the head ([`ReceiptLog::verify_against`]).
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
        let path = path.into();
        if start_sequence == 0 {
            return Err(Error::receipt("a log cannot start at sequence 0"));
        }
        if std::fs::metadata(&path)
            .map(|metadata| metadata.len() > LOG_HEADER_LEN as u64)
            .unwrap_or(false)
        {
            return Err(Error::receipt(
                "the receipt log already holds records; truncate it explicitly",
            ));
        }
        let log = Self {
            path,
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
        {
            use std::io::Write;
            let mut file = std::fs::File::create(&log.path)
                .map_err(|_| Error::receipt("cannot create the receipt log"))?;
            file.write_all(&header)
                .map_err(|_| Error::receipt("cannot write the receipt log header"))?;
            file.sync_all()
                .map_err(|_| Error::receipt("cannot flush the receipt log header"))?;
        }
        Ok(log)
    }

    /// Create or truncate a log, discarding any existing evidence.
    ///
    /// This is the explicit "start over" entry point; [`ReceiptLog::create`]
    /// refuses to overwrite.
    pub fn truncate(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let path = path.into();
        std::fs::write(&path, []).map_err(|_| Error::receipt("cannot create the receipt log"))?;
        Self::create_starting_at(path, 1)
    }

    /// Open an existing log without creating or truncating it.
    ///
    /// The header is checked and the state is read once; records are verified on
    /// every read.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let path = path.into();
        let bytes = read_capped(&path)?;
        let (_, state) = walk_log(&bytes)?;
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

    /// Append a batch after checking every receipt `mac` under `secret`.
    ///
    /// This is the owner path: the writer proves it is the kernel that produced
    /// the receipts, so the log cannot be extended with fabricated records by a
    /// party that has write access but not the secret.
    pub fn append_verified(&self, secret: &[u8; 32], receipts: &[Receipt]) -> Result<()> {
        for receipt in receipts {
            if !receipt.verify(secret) {
                return Err(Error::receipt("a receipt was not produced by this kernel"));
            }
        }
        self.append_inner(receipts)
    }

    fn append_inner(&self, receipts: &[Receipt]) -> Result<()> {
        if receipts.is_empty() {
            return Ok(());
        }
        let _lock = LogLock::acquire(&self.path)?;
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
            if cached.bytes == observed {
                cached
            } else {
                let bytes = read_capped(&self.path)?;
                let (_, walked) = walk_log(&bytes)?;
                walked
            }
        };
        let mut out = Vec::new();
        let mut previous = state.head;
        let mut count = state.count;
        let mut last_ms = state.last_ms;
        for receipt in receipts {
            let expected = state.start.saturating_add(count);
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
        }
        let total = observed
            .checked_add(out.len() as u64)
            .ok_or_else(|| Error::receipt("the receipt log is too large"))?;
        if total > MAX_LOG_BYTES {
            return Err(Error::receipt("the receipt log exceeds the size ceiling"));
        }
        if count > MAX_LOG_RECORDS {
            return Err(Error::receipt("the receipt log exceeds the record ceiling"));
        }
        self.write_all(&out)?;
        state.bytes = total;
        state.count = count;
        state.head = previous;
        state.last_ms = last_ms;
        if let Ok(mut cached) = self.state.lock() {
            *cached = state;
        }
        Ok(())
    }

    fn write_all(&self, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| Error::receipt("cannot open the receipt log for append"))?;
        file.write_all(bytes)
            .map_err(|_| Error::receipt("cannot append to the receipt log"))?;
        file.sync_data()
            .map_err(|_| Error::receipt("cannot flush the receipt log"))?;
        Ok(())
    }

    /// Every receipt in the log, in order, with the chain verified.
    pub fn records(&self) -> Result<Vec<Receipt>> {
        let bytes = read_capped(&self.path)?;
        walk_log(&bytes).map(|(receipts, _)| receipts)
    }

    /// Verify the chain only (no key needed).
    ///
    /// This detects corruption and reordering. It does **not** prove the log was
    /// produced by a particular kernel: that needs [`ReceiptLog::verify_macs`].
    pub fn verify_chain(&self) -> Result<()> {
        self.records().map(|_| ())
    }

    /// Verify the chain and every receipt's `mac` under the kernel secret.
    pub fn verify_macs(&self, secret: &[u8; 32]) -> Result<()> {
        let records = self.records()?;
        for receipt in &records {
            if !receipt.verify(secret) {
                return Err(Error::receipt(format!(
                    "receipt {} was not produced by this kernel",
                    receipt.sequence
                )));
            }
        }
        Ok(())
    }

    /// Verify the chain and that the head is the pinned one.
    ///
    /// A verifier that learned the head out of band detects a truncated tail,
    /// which the per-record links alone cannot.
    pub fn verify_against(&self, expected: [u8; 32]) -> Result<()> {
        let head = self.head_hash()?;
        if head != expected {
            return Err(Error::receipt("the log does not end at the pinned head"));
        }
        Ok(())
    }

    /// Hash of the last record (the chain head), or zeros for an empty log.
    pub fn head_hash(&self) -> Result<[u8; 32]> {
        let bytes = read_capped(&self.path)?;
        walk_log(&bytes).map(|(_, state)| state.head)
    }

    /// Sequence of the first record.
    pub fn start_sequence(&self) -> Result<u64> {
        let bytes = read_capped(&self.path)?;
        walk_log(&bytes).map(|(_, state)| state.start)
    }

    /// Number of records.
    pub fn len(&self) -> Result<u64> {
        let bytes = read_capped(&self.path)?;
        walk_log(&bytes).map(|(_, state)| state.count)
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

/// Read a log file under the size ceiling, refusing a larger one without
/// allocating it.
fn read_capped(path: &std::path::Path) -> Result<Vec<u8>> {
    use std::io::Read;
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

/// Encode one record: `len u32 | sequence u64 | at_ms u64 | decision u8 |
/// code_len u16 | code | cap_len u16 | cap | method_len u16 | method | mac [32]
/// | prev [32] | record_hash [32]`.
fn encode_record(receipt: &Receipt, previous: &[u8; 32]) -> Result<Vec<u8>> {
    // The writer applies the reader's rules. A record the writer accepts and the
    // reader rejects would make the whole log unreadable, so the checks here and
    // in `decode_record` are the same predicates.
    if !valid_correlation_id(&receipt.cap) {
        return Err(Error::receipt(
            "a receipt correlation id must be 16 lowercase hex characters",
        ));
    }
    if !valid_method(&receipt.method) {
        return Err(Error::receipt(
            "a receipt method must be 1..=1024 bytes without control characters",
        ));
    }
    if !valid_code(receipt.decision.code()) && receipt.decision.code() != "" {
        return Err(Error::receipt(
            "a decision code must be 1..=64 characters from [a-z0-9/-_.]",
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
            return Err(Error::receipt(format!(
                "record {} does not link to the previous one",
                receipts.len() + 1
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

/// What a decision looks like in a log line.
pub fn decision_label(decision: &Decision) -> &'static str {
    match decision {
        Decision::Admitted => "admitted",
        Decision::Refused(_) => "refused",
    }
}
