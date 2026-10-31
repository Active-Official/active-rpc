//! Bulk (carousel) transfer for large Infinity bodies.
//!
//! An ARP1 envelope carries a payload bounded by [`crate::transport::MAX_FRAME_BYTES`]
//! (64 MiB). Active Infinity images can be larger than that, and a single
//! oversized frame is the wrong shape for a flaky link in any case: one lost TCP
//! segment or QUIC retransmission stalls the whole body.
//!
//! This module defines a resume-friendly chunk protocol on top of any byte
//! transport:
//!
//! 1. The sender sends a **plan**: chunk size, total length, per-chunk Blake3
//!    hashes and a root hash over the plan itself.
//! 2. The receiver asks for whatever is missing (initially everything). Each
//!    chunk frame carries its index, offset and hash, so it is self-verifying.
//! 3. After a disconnect, either side reconstructs the receiver from the plan
//!    and only the missing indexes travel again. A duplicate chunk is accepted
//!    when it is byte-identical and refused when it is not.
//! 4. `finish` requires every chunk, checks the total length, and recomputes the
//!    root. A corrupted or truncated body never becomes a valid image.
//!
//! The root is a hash of the chunk hashes, not of the bytes: the sender can
//! hash once while streaming, and a receiver can verify a chunk without holding
//! the rest of the body. Hashing is domain-separated (`bulk-chunk`, `bulk-root`)
//! so a chunk digest can never be confused with an Infinity content hash.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Magic prefix of a bulk plan.
pub const PLAN_MAGIC: [u8; 4] = *b"ARBL";
/// Magic prefix of a bulk chunk frame.
pub const CHUNK_MAGIC: [u8; 4] = *b"ARBC";
/// Protocol version for both frame kinds.
pub const VERSION: u8 = 1;
/// Default chunk size (256 KiB): large enough to amortize framing, small enough
/// that one retransmission is cheap.
pub const DEFAULT_CHUNK: usize = 256 * 1024;
/// Largest chunk a receiver accepts.
pub const MAX_CHUNK: usize = 8 << 20;
/// Default ceiling on the body a receiver will assemble.
pub const MAX_TOTAL: u64 = 1 << 30;

const CHUNK_DOMAIN: &[u8] = b"active-rpc/bulk-chunk/v1\0";
const ROOT_DOMAIN: &[u8] = b"active-rpc/bulk-root/v1\0";

/// Hash of one chunk's bytes.
pub fn chunk_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHUNK_DOMAIN);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Root hash over a plan's shape and chunk hashes.
fn root_hash(chunk: usize, total: u64, hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROOT_DOMAIN);
    hasher.update(&[VERSION]);
    hasher.update(&(chunk as u32).to_le_bytes());
    hasher.update(&total.to_le_bytes());
    hasher.update(&(hashes.len() as u32).to_le_bytes());
    for hash in hashes {
        hasher.update(hash);
    }
    *hasher.finalize().as_bytes()
}

/// The shape and integrity metadata of a body split into chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkPlan {
    chunk: usize,
    total: u64,
    chunks: u32,
    hashes: Vec<[u8; 32]>,
    root: [u8; 32],
}

impl BulkPlan {
    /// Plan a body.
    pub fn new(bytes: &[u8], chunk: usize) -> Result<Self> {
        check_chunk_size(chunk)?;
        let hashes: Vec<[u8; 32]> = bytes.chunks(chunk).map(chunk_hash).collect();
        let chunks = hashes.len() as u32;
        let total = bytes.len() as u64;
        let root = root_hash(chunk, total, &hashes);
        Ok(Self {
            chunk,
            total,
            chunks,
            hashes,
            root,
        })
    }

    /// Rebuild a plan from the hashes a sender transmitted.
    ///
    /// The root is recomputed from the hashes, so a plan cannot claim a root it
    /// does not match.
    pub fn from_hashes(chunk: usize, total: u64, hashes: Vec<[u8; 32]>) -> Result<Self> {
        check_chunk_size(chunk)?;
        let expected = expected_chunks(total, chunk)?;
        if hashes.len() as u32 != expected {
            return Err(Error::Bulk("plan chunk count does not match the total"));
        }
        let root = root_hash(chunk, total, &hashes);
        Ok(Self {
            chunk,
            total,
            chunks: expected,
            hashes,
            root,
        })
    }

    /// Chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        self.chunk
    }

    /// Total body length.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Number of chunks.
    pub fn chunk_count(&self) -> u32 {
        self.chunks
    }

    /// Root hash over the plan.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Hex root, for logs and manifests.
    pub fn root_hex(&self) -> String {
        hex(&self.root)
    }

    /// Hash of one chunk, when the index exists.
    pub fn chunk_hash_at(&self, index: u32) -> Option<[u8; 32]> {
        self.hashes.get(index as usize).copied()
    }

    /// Encoded plan bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + 8 + 4 + 32 + self.hashes.len() * 32);
        out.extend_from_slice(&PLAN_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&(self.chunk as u32).to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&self.chunks.to_le_bytes());
        out.extend_from_slice(&self.root);
        for hash in &self.hashes {
            out.extend_from_slice(hash);
        }
        out
    }

    /// Decode and verify a plan.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        const HEADER: usize = 4 + 1 + 4 + 8 + 4 + 32;
        if bytes.len() < HEADER {
            return Err(Error::Bulk("plan is shorter than its header"));
        }
        if bytes[0..4] != PLAN_MAGIC {
            return Err(Error::Bulk("plan magic mismatch"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Bulk("unsupported bulk plan version"));
        }
        let chunk = u32::from_le_bytes(bytes[5..9].try_into().expect("4 bytes")) as usize;
        check_chunk_size(chunk)?;
        let total = u64::from_le_bytes(bytes[9..17].try_into().expect("8 bytes"));
        let chunks = u32::from_le_bytes(bytes[17..21].try_into().expect("4 bytes"));
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[21..53]);
        let count = chunks as usize;
        let expected_len = HEADER
            .checked_add(
                count
                    .checked_mul(32)
                    .ok_or(Error::Bulk("plan is too large"))?,
            )
            .ok_or(Error::Bulk("plan is too large"))?;
        if bytes.len() != expected_len {
            return Err(Error::Bulk("plan length does not match its chunk count"));
        }
        if chunks != expected_chunks(total, chunk)? {
            return Err(Error::Bulk("plan chunk count does not match the total"));
        }
        let mut hashes = Vec::with_capacity(count);
        for index in 0..count {
            let start = HEADER + index * 32;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes[start..start + 32]);
            hashes.push(hash);
        }
        let recomputed = root_hash(chunk, total, &hashes);
        if recomputed != root {
            return Err(Error::Bulk("plan root does not match its chunk hashes"));
        }
        Ok(Self {
            chunk,
            total,
            chunks,
            hashes,
            root,
        })
    }

    /// Verify a whole body against the plan.
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.total {
            return Err(Error::Bulk("body length does not match the plan"));
        }
        for (index, part) in bytes.chunks(self.chunk).enumerate() {
            let expected = self.hashes[index];
            if chunk_hash(part) != expected {
                return Err(Error::Bulk("chunk hash mismatch"));
            }
        }
        Ok(())
    }
}

/// One self-verifying chunk frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkChunk {
    index: u32,
    offset: u64,
    data: Vec<u8>,
}

impl BulkChunk {
    /// Build the chunk at `index` from a body.
    pub fn new(index: u32, chunk_size: usize, data: &[u8]) -> Self {
        Self {
            index,
            offset: index as u64 * chunk_size as u64,
            data: data.to_vec(),
        }
    }

    /// Chunk index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Byte offset in the body.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Chunk bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Hash of the chunk bytes.
    pub fn hash(&self) -> [u8; 32] {
        chunk_hash(&self.data)
    }

    /// Encoded frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + 8 + 4 + 32 + self.data.len());
        out.extend_from_slice(&CHUNK_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.hash());
        out.extend_from_slice(&self.data);
        out
    }

    /// Decode a frame and verify its hash and internal consistency.
    pub fn decode(frame: &[u8]) -> Result<Self> {
        const HEADER: usize = 4 + 1 + 4 + 8 + 4 + 32;
        if frame.len() < HEADER {
            return Err(Error::Bulk("chunk frame is shorter than its header"));
        }
        if frame[0..4] != CHUNK_MAGIC {
            return Err(Error::Bulk("chunk magic mismatch"));
        }
        if frame[4] != VERSION {
            return Err(Error::Bulk("unsupported bulk chunk version"));
        }
        let index = u32::from_le_bytes(frame[5..9].try_into().expect("4 bytes"));
        let offset = u64::from_le_bytes(frame[9..17].try_into().expect("8 bytes"));
        let len = u32::from_le_bytes(frame[17..21].try_into().expect("4 bytes")) as usize;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&frame[21..53]);
        let end = HEADER
            .checked_add(len)
            .ok_or(Error::Bulk("chunk length overflows"))?;
        if frame.len() != end {
            return Err(Error::Bulk("chunk length does not match the frame"));
        }
        if len > MAX_CHUNK {
            return Err(Error::Bulk("chunk exceeds the ceiling"));
        }
        let data = frame[HEADER..].to_vec();
        if chunk_hash(&data) != hash {
            return Err(Error::Bulk("chunk hash mismatch"));
        }
        Ok(Self {
            index,
            offset,
            data,
        })
    }
}

/// Splits a body into frames and supports resuming from any index.
#[derive(Debug, Clone)]
pub struct BulkSender {
    plan: BulkPlan,
    bytes: Vec<u8>,
}

impl BulkSender {
    /// Plan and retain a body for sending.
    pub fn new(bytes: Vec<u8>, chunk: usize) -> Result<Self> {
        let plan = BulkPlan::new(&bytes, chunk)?;
        Ok(Self { plan, bytes })
    }

    /// The plan to send before any chunk.
    pub fn plan(&self) -> &BulkPlan {
        &self.plan
    }

    /// Every frame for every chunk, in order.
    pub fn frames(&self) -> Vec<Vec<u8>> {
        self.frames_from(0)
    }

    /// Frames for the chunks at or after `from`.
    pub fn frames_from(&self, from: u32) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for (index, part) in self.bytes.chunks(self.plan.chunk).enumerate() {
            if index as u32 >= from {
                out.push(BulkChunk::new(index as u32, self.plan.chunk, part).encode());
            }
        }
        out
    }

    /// Frames for exactly the indexes a receiver reports as missing.
    ///
    /// An index outside the plan is an error rather than a silently dropped
    /// frame: a resume request that asks for a chunk this body never had is a
    /// protocol bug, and answering with silence would stall the transfer.
    pub fn frames_for(&self, missing: &[u32]) -> Result<Vec<Vec<u8>>> {
        for index in missing {
            if *index >= self.plan.chunks {
                return Err(Error::Bulk("requested chunk is outside the plan"));
            }
        }
        Ok(missing
            .iter()
            .filter_map(|index| {
                let start = *index as usize * self.plan.chunk;
                if start >= self.bytes.len() {
                    return None;
                }
                let end = (start + self.plan.chunk).min(self.bytes.len());
                Some(BulkChunk::new(*index, self.plan.chunk, &self.bytes[start..end]).encode())
            })
            .collect())
    }
}

/// Receives chunks, tolerates retransmission, and verifies the root at the end.
#[derive(Debug, Clone)]
pub struct BulkReceiver {
    plan: BulkPlan,
    received: BTreeMap<u32, Vec<u8>>,
    ceiling: u64,
}

impl BulkReceiver {
    /// A receiver for a plan with the default body ceiling.
    pub fn new(plan: BulkPlan) -> Result<Self> {
        Self::with_ceiling(plan, MAX_TOTAL)
    }

    /// A receiver that refuses a plan larger than `ceiling` bytes.
    pub fn with_ceiling(plan: BulkPlan, ceiling: u64) -> Result<Self> {
        if plan.total > ceiling {
            return Err(Error::Bulk("body exceeds the receiver ceiling"));
        }
        Ok(Self {
            plan,
            received: BTreeMap::new(),
            ceiling,
        })
    }

    /// The plan being received.
    pub fn plan(&self) -> &BulkPlan {
        &self.plan
    }

    /// Accept one chunk frame and return its index.
    ///
    /// A duplicate with identical bytes is accepted (idempotent retransmission);
    /// a duplicate with different bytes is refused.
    pub fn accept(&mut self, frame: &[u8]) -> Result<u32> {
        let chunk = BulkChunk::decode(frame)?;
        let index = chunk.index;
        if index >= self.plan.chunks {
            return Err(Error::Bulk("chunk index is outside the plan"));
        }
        let expected_offset = index as u64 * self.plan.chunk as u64;
        if chunk.offset != expected_offset {
            return Err(Error::Bulk("chunk offset does not match its index"));
        }
        let expected_len = self.expected_len(index);
        if chunk.data.len() as u64 != expected_len {
            return Err(Error::Bulk("chunk length does not match the plan"));
        }
        let planned = self.plan.hashes[index as usize];
        if chunk.hash() != planned {
            return Err(Error::Bulk("chunk does not match the planned hash"));
        }
        if let Some(existing) = self.received.get(&index) {
            if existing == &chunk.data {
                return Ok(index);
            }
            return Err(Error::Bulk("conflicting duplicate chunk"));
        }
        self.received.insert(index, chunk.data);
        Ok(index)
    }

    /// Indexes not yet received, in order.
    pub fn missing(&self) -> Vec<u32> {
        (0..self.plan.chunks)
            .filter(|index| !self.received.contains_key(index))
            .collect()
    }

    /// Bytes accepted so far.
    pub fn bytes_received(&self) -> u64 {
        self.received.values().map(|data| data.len() as u64).sum()
    }

    /// True when every chunk is present.
    pub fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.plan.chunks
    }

    /// Assemble and verify the body.
    pub fn finish(self) -> Result<Vec<u8>> {
        if !self.is_complete() {
            return Err(Error::Bulk("body is incomplete"));
        }
        if self.plan.total > self.ceiling {
            return Err(Error::Bulk("body exceeds the receiver ceiling"));
        }
        let mut out = Vec::with_capacity(self.plan.total as usize);
        for index in 0..self.plan.chunks {
            let data = self
                .received
                .get(&index)
                .ok_or(Error::Bulk("body is incomplete"))?;
            out.extend_from_slice(data);
        }
        if out.len() as u64 != self.plan.total {
            return Err(Error::Bulk("body length does not match the plan"));
        }
        self.plan.verify(&out)?;
        Ok(out)
    }

    fn expected_len(&self, index: u32) -> u64 {
        let start = index as u64 * self.plan.chunk as u64;
        (self.plan.total - start).min(self.plan.chunk as u64)
    }
}

fn check_chunk_size(chunk: usize) -> Result<()> {
    if chunk == 0 || chunk > MAX_CHUNK {
        return Err(Error::Bulk("chunk size is outside the supported range"));
    }
    Ok(())
}

fn expected_chunks(total: u64, chunk: usize) -> Result<u32> {
    if total == 0 {
        return Ok(0);
    }
    let chunk = chunk as u64;
    let count = total.div_ceil(chunk);
    if count > u32::MAX as u64 {
        return Err(Error::Bulk("too many chunks"));
    }
    Ok(count as u32)
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
