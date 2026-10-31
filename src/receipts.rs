//! Capability receipts: an audit record of the authorization decision.
//!
//! A receipt answers "was this call authorized, under which capability, and
//! when" without carrying arguments, values or any secret material. Each
//! receipt is authenticated with a keyed hash under the kernel secret, so a
//! record cannot be edited or transplanted between kernels without detection.
//!
//! Receipts are opt-in (`Agent::enable_receipts`): a kernel that does not want
//! per-call bookkeeping pays nothing.

use crate::cap::CapId;
use crate::{Error, Result};

/// Longest receipt ring the kernel keeps.
pub const MAX_RECEIPTS: usize = 1 << 10;

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
    /// Keyed hash over the fields above.
    pub mac: [u8; 32],
}

impl Receipt {
    /// Build and seal a receipt for an admitted call.
    pub(crate) fn seal(
        secret: &[u8; 32],
        sequence: u64,
        cap: CapId,
        method: &str,
        at_ms: u64,
    ) -> Receipt {
        let mut receipt = Receipt {
            sequence,
            cap: cap.correlation_id(),
            method: method.to_string(),
            at_ms,
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

    fn compute(&self, secret: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(secret);
        hasher.update(b"active-rpc/receipt/v1");
        hasher.update(&self.sequence.to_le_bytes());
        hasher.update(&(self.cap.len() as u32).to_le_bytes());
        hasher.update(self.cap.as_bytes());
        hasher.update(&(self.method.len() as u32).to_le_bytes());
        hasher.update(self.method.as_bytes());
        hasher.update(&self.at_ms.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Durable log (`ARRL`)
// ---------------------------------------------------------------------------

/// Magic of a receipt log file.
pub const LOG_MAGIC: &[u8; 4] = b"ARRL";
/// Version of the receipt log format.
pub const LOG_VERSION: u8 = 1;
/// Largest log record accepted, in bytes.
pub const MAX_LOG_RECORD: usize = 64 << 10;

/// Domain separator for the log chain hash.
const LOG_DOMAIN: &[u8] = b"active-rpc/receipt-log/v1";

/// An append-only receipt log on disk.
///
/// The file is `ARRL | version u8 | reserved u8 u16` followed by records. Each
/// record carries its length, the receipt fields, and a chain hash over the
/// previous record's hash and this record, so truncation, reordering and edits
/// are detectable without the kernel secret. The receipt's own `mac` still
/// proves the kernel produced it, and verifying that needs the secret
/// ([`ReceiptLog::verify_macs`]).
///
/// The log holds correlation ids, method names and times: no arguments, values
/// or secret material.
#[derive(Debug, Clone)]
pub struct ReceiptLog {
    path: std::path::PathBuf,
}

impl ReceiptLog {
    /// Create (or truncate) a log file.
    pub fn create(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let log = Self { path: path.into() };
        let mut header = Vec::with_capacity(8);
        header.extend_from_slice(LOG_MAGIC);
        header.push(LOG_VERSION);
        header.extend_from_slice(&[0u8; 3]);
        std::fs::write(&log.path, &header)
            .map_err(|_| Error::receipt("cannot create the receipt log"))?;
        Ok(log)
    }

    /// Open an existing log without creating or truncating it.
    ///
    /// The header is checked; the records are verified on read.
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let log = Self { path: path.into() };
        let bytes =
            std::fs::read(&log.path).map_err(|_| Error::receipt("cannot read the receipt log"))?;
        verify_header(&bytes)?;
        Ok(log)
    }

    /// Path of the log file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Append one receipt.
    pub fn append(&self, receipt: &Receipt) -> Result<()> {
        self.append_all(std::slice::from_ref(receipt))
    }

    /// Append a batch of receipts.
    ///
    /// The chain is walked once and the whole batch is written with a single
    /// `write_all`, so a crash can leave a partial *trailing* record (refused on
    /// read) but never a record with a broken link in the middle.
    pub fn append_all(&self, receipts: &[Receipt]) -> Result<()> {
        if receipts.is_empty() {
            return Ok(());
        }
        let bytes =
            std::fs::read(&self.path).map_err(|_| Error::receipt("cannot read the receipt log"))?;
        let (_, mut previous) = walk_log(&bytes)?;
        let mut out = Vec::new();
        for receipt in receipts {
            let record = encode_record(receipt, &previous)?;
            previous.copy_from_slice(&record[record.len() - 32..]);
            out.extend_from_slice(&record);
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|_| Error::receipt("cannot open the receipt log for append"))?;
        file.write_all(&out)
            .map_err(|_| Error::receipt("cannot append to the receipt log"))?;
        file.sync_data()
            .map_err(|_| Error::receipt("cannot flush the receipt log"))?;
        Ok(())
    }

    /// Every receipt in the log, in order, with the chain verified.
    pub fn records(&self) -> Result<Vec<Receipt>> {
        let bytes =
            std::fs::read(&self.path).map_err(|_| Error::receipt("cannot read the receipt log"))?;
        walk_log(&bytes).map(|(receipts, _)| receipts)
    }

    /// Verify the chain only (no key needed).
    pub fn verify_chain(&self) -> Result<()> {
        self.records().map(|_| ())
    }

    /// Verify the chain and every receipt's `mac` under the kernel secret.
    pub fn verify_macs(&self, secret: &[u8; 32]) -> Result<()> {
        let records = self.records()?;
        for (index, receipt) in records.iter().enumerate() {
            if !receipt.verify(secret) {
                return Err(Error::receipt(format!(
                    "receipt {index} was not produced by this kernel"
                )));
            }
        }
        Ok(())
    }

    /// Hash of the last record (the chain head), or zeros for an empty log.
    ///
    /// A verifier that pins a head hash out of band can detect truncation of
    /// the whole tail, which the per-record links alone cannot.
    pub fn head_hash(&self) -> Result<[u8; 32]> {
        let bytes =
            std::fs::read(&self.path).map_err(|_| Error::receipt("cannot read the receipt log"))?;
        walk_log(&bytes).map(|(_, hash)| hash)
    }
}

/// Encode one record: `len u32 | sequence u64 | at_ms u64 | cap | method | mac
/// | prev [32] | record_hash [32]`.
fn encode_record(receipt: &Receipt, previous: &[u8; 32]) -> Result<Vec<u8>> {
    if receipt.cap.len() != 16 || !receipt.cap.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::receipt(
            "a receipt correlation id must be 16 hex characters",
        ));
    }
    if receipt.method.is_empty() || receipt.method.len() > 1024 {
        return Err(Error::receipt("a receipt method must be 1..=1024 bytes"));
    }
    let mut body = Vec::with_capacity(64 + receipt.method.len());
    body.extend_from_slice(&receipt.sequence.to_le_bytes());
    body.extend_from_slice(&receipt.at_ms.to_le_bytes());
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
    let total = (body.len() + 32) as u32;
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
    if length == 0 || length > MAX_LOG_RECORD {
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
    if cap.len() != 16 || !cap.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::receipt("correlation id is not 16 hex characters"));
    }
    if method.is_empty() {
        return Err(Error::receipt("empty method"));
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(LOG_DOMAIN);
    hasher.update(body);
    let expected = *hasher.finalize().as_bytes();
    if expected != stored_hash {
        return Err(Error::receipt("record hash does not match its contents"));
    }
    Ok((
        Receipt {
            sequence,
            cap,
            method,
            at_ms,
            mac,
        },
        previous,
        expected,
        end,
    ))
}

fn verify_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < 8 {
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
    Ok(())
}

/// Decode a whole log, verify every record hash and every chain link, and
/// return the receipts with the last record's hash.
fn walk_log(bytes: &[u8]) -> Result<(Vec<Receipt>, [u8; 32])> {
    verify_header(bytes)?;
    let mut receipts = Vec::new();
    let mut cursor = 8usize;
    let mut expected_previous = [0u8; 32];
    while cursor < bytes.len() {
        let (receipt, previous, record_hash, next) = decode_record(bytes, cursor)?;
        if previous != expected_previous {
            return Err(Error::receipt(format!(
                "record {} does not link to the previous one",
                receipts.len() + 1
            )));
        }
        if receipt.sequence != receipts.len() as u64 + 1 {
            return Err(Error::receipt(
                "receipt sequence does not follow the log order",
            ));
        }
        expected_previous = record_hash;
        receipts.push(receipt);
        cursor = next;
    }
    if cursor != bytes.len() {
        return Err(Error::receipt("trailing bytes after the last record"));
    }
    Ok((receipts, expected_previous))
}
