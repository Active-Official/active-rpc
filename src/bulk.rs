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
//! 2. The receiver asks for whatever is missing ([`BulkRequest`]). Each chunk
//!    frame carries its index, offset and hash, so it is self-verifying.
//! 3. After a disconnect, either side reconstructs the receiver from the plan
//!    and only the missing indexes travel again. A duplicate chunk is accepted
//!    when it is byte-identical and refused when it is not.
//! 4. [`BulkFinish`] closes the transfer: it names the root and the total so a
//!    receiver can refuse a body from another transfer, and `finish` requires
//!    every chunk and checks the total length.
//!
//! The root is a hash of the chunk hashes, not of the bytes: the sender can
//! hash once while streaming, and a receiver can verify a chunk without holding
//! the rest of the body. Hashing is domain-separated (`bulk-chunk`, `bulk-root`)
//! so a chunk digest can never be confused with an Infinity content hash.
//!
//! ## What the root does and does not prove
//!
//! The root proves the body is internally consistent with the plan that
//! described it. It does **not** prove who chose the plan: a peer that can
//! replace the plan can replace the body with it and every check still passes.
//! Authority comes from the ARP1 envelope that opened the transfer, so a caller
//! must pin the root it expects — [`BulkReceiver::with_expected_root`], or a
//! `context` that folds the envelope's request id and capability id into the
//! root ([`BulkPlan::new_with_context`]). With neither, a transfer is
//! integrity-checked against corruption only.

use std::collections::{BTreeMap, BTreeSet};

use crate::budget::{Budget, BudgetMeter};
use crate::error::{Error, Result};
use crate::value::{Call, Response, Value};

/// Magic prefix of a bulk plan.
pub const PLAN_MAGIC: [u8; 4] = *b"ARBL";
/// Magic prefix of a bulk chunk frame.
pub const CHUNK_MAGIC: [u8; 4] = *b"ARBC";
/// Magic prefix of a resume request.
pub const REQUEST_MAGIC: [u8; 4] = *b"ARBM";
/// Magic prefix of a finish marker.
pub const FINISH_MAGIC: [u8; 4] = *b"ARBF";
/// Protocol version for every frame kind.
pub const VERSION: u8 = 1;
/// Default chunk size (256 KiB): large enough to amortize framing, small enough
/// that one retransmission is cheap.
pub const DEFAULT_CHUNK: usize = 256 * 1024;
/// Largest chunk a receiver accepts.
pub const MAX_CHUNK: usize = 8 << 20;
/// Default ceiling on the body a receiver will assemble.
pub const MAX_TOTAL: u64 = 1 << 30;
/// Most chunks a plan may declare.
///
/// The plan frame names one hash per chunk, so an unbounded count turns a small
/// frame into a huge allocation. 65 536 chunks with the smallest useful chunk
/// still describes a 1 GiB body at 16 KiB per chunk.
pub const MAX_CHUNKS: u32 = 65_536;

const CHUNK_DOMAIN: &[u8] = b"active-rpc/bulk-chunk/v1\0";
const ROOT_DOMAIN: &[u8] = b"active-rpc/bulk-root/v1\0";

/// Hash of one chunk's bytes.
pub fn chunk_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHUNK_DOMAIN);
    hasher.update(data);
    *hasher.finalize().as_bytes()
}

/// Root hash over a plan's shape, chunk hashes and transfer context.
///
/// `context` is not transmitted: both sides derive it from the exchange that
/// opened the transfer (for example the request id and capability id), so a plan
/// cannot float free of the envelope that authorized it.
fn root_hash(chunk: usize, total: u64, hashes: &[[u8; 32]], context: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ROOT_DOMAIN);
    hasher.update(&[VERSION]);
    hasher.update(&(chunk as u32).to_le_bytes());
    hasher.update(&total.to_le_bytes());
    hasher.update(&(hashes.len() as u32).to_le_bytes());
    for hash in hashes {
        hasher.update(hash);
    }
    hasher.update(&(context.len() as u32).to_le_bytes());
    hasher.update(context);
    *hasher.finalize().as_bytes()
}

/// The shape and integrity metadata of a body split into chunks.
#[derive(Clone, PartialEq, Eq)]
pub struct BulkPlan {
    chunk: usize,
    total: u64,
    chunks: u32,
    hashes: Vec<[u8; 32]>,
    root: [u8; 32],
    context: Vec<u8>,
}

impl std::fmt::Debug for BulkPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the hashes: a 65 536-chunk plan would print two megabytes.
        f.debug_struct("BulkPlan")
            .field("chunk", &self.chunk)
            .field("total", &self.total)
            .field("chunks", &self.chunks)
            .field("root", &hex(&self.root))
            .field("context_bytes", &self.context.len())
            .finish()
    }
}

impl BulkPlan {
    /// Plan a body.
    pub fn new(bytes: &[u8], chunk: usize) -> Result<Self> {
        Self::new_with_context(bytes, chunk, &[])
    }

    /// Plan a body bound to a transfer context.
    ///
    /// The context is folded into the root and never transmitted: a receiver
    /// must derive the same bytes or its root check fails.
    pub fn new_with_context(bytes: &[u8], chunk: usize, context: &[u8]) -> Result<Self> {
        check_chunk_size(chunk)?;
        let hashes: Vec<[u8; 32]> = bytes.chunks(chunk).map(chunk_hash).collect();
        let total = bytes.len() as u64;
        let chunks = expected_chunks(total, chunk)?;
        debug_assert_eq!(chunks as usize, hashes.len());
        let root = root_hash(chunk, total, &hashes, context);
        Ok(Self {
            chunk,
            total,
            chunks,
            hashes,
            root,
            context: context.to_vec(),
        })
    }

    /// Rebuild a plan from the hashes a sender transmitted.
    ///
    /// The root is recomputed from the hashes, so a plan cannot claim a root it
    /// does not match.
    pub fn from_hashes(chunk: usize, total: u64, hashes: Vec<[u8; 32]>) -> Result<Self> {
        Self::from_hashes_with_context(chunk, total, hashes, &[])
    }

    /// Rebuild a plan bound to a transfer context.
    pub fn from_hashes_with_context(
        chunk: usize,
        total: u64,
        hashes: Vec<[u8; 32]>,
        context: &[u8],
    ) -> Result<Self> {
        check_chunk_size(chunk)?;
        let expected = expected_chunks(total, chunk)?;
        if hashes.len() as u32 != expected {
            return Err(Error::Bulk("plan chunk count does not match the total"));
        }
        let root = root_hash(chunk, total, &hashes, context);
        Ok(Self {
            chunk,
            total,
            chunks: expected,
            hashes,
            root,
            context: context.to_vec(),
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

    /// Refuse a plan whose root is not the pinned one.
    ///
    /// This is the check that binds a plan to the transfer the caller
    /// authorized; see the module note on what the root does not prove.
    pub fn require_root(&self, expected: [u8; 32]) -> Result<()> {
        if self.root != expected {
            return Err(Error::Bulk("plan root does not match the expected root"));
        }
        Ok(())
    }

    /// Hash of one chunk, when the index exists.
    pub fn chunk_hash_at(&self, index: u32) -> Option<[u8; 32]> {
        self.hashes.get(index as usize).copied()
    }

    /// Encoded plan bytes. The transfer context is not written.
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

    /// Decode and verify a plan under the default ceiling.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::decode_for(bytes, MAX_TOTAL, &[])
    }

    /// Decode and verify a plan that is bound to a transfer context.
    pub fn decode_with_context(bytes: &[u8], context: &[u8]) -> Result<Self> {
        Self::decode_for(bytes, MAX_TOTAL, context)
    }

    /// Decode and verify a plan, refusing a body above `max_total`.
    ///
    /// The total and the chunk count are checked before the hash vector is
    /// allocated: a small frame must not be able to declare a body the receiver
    /// would never admit.
    pub fn decode_with_ceiling(bytes: &[u8], max_total: u64) -> Result<Self> {
        Self::decode_for(bytes, max_total, &[])
    }

    /// Decode with both a ceiling and a transfer context.
    pub fn decode_for(bytes: &[u8], max_total: u64, context: &[u8]) -> Result<Self> {
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
        if total > max_total {
            return Err(Error::Bulk("body exceeds the receiver ceiling"));
        }
        if total > MAX_TOTAL {
            return Err(Error::Bulk("body exceeds the protocol ceiling"));
        }
        let chunks = u32::from_le_bytes(bytes[17..21].try_into().expect("4 bytes"));
        if chunks > MAX_CHUNKS {
            return Err(Error::Bulk("plan declares too many chunks"));
        }
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
        let recomputed = root_hash(chunk, total, &hashes, context);
        if recomputed != root {
            return Err(Error::Bulk("plan root does not match its chunk hashes"));
        }
        Ok(Self {
            chunk,
            total,
            chunks,
            hashes,
            root,
            context: context.to_vec(),
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
#[derive(Clone, PartialEq, Eq)]
pub struct BulkChunk {
    index: u32,
    offset: u64,
    hash: [u8; 32],
    data: Vec<u8>,
}

impl std::fmt::Debug for BulkChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body may be anything, including a secret: print its shape only.
        f.debug_struct("BulkChunk")
            .field("index", &self.index)
            .field("offset", &self.offset)
            .field("len", &self.data.len())
            .finish()
    }
}

impl BulkChunk {
    /// Build the chunk at `index` from a body.
    ///
    /// `data` is trusted to be at most [`MAX_CHUNK`]; use [`BulkChunk::try_new`]
    /// when it comes from anywhere else.
    pub fn new(index: u32, chunk_size: usize, data: &[u8]) -> Self {
        Self {
            index,
            offset: index as u64 * chunk_size as u64,
            hash: chunk_hash(data),
            data: data.to_vec(),
        }
    }

    /// Build a chunk, refusing data the frame format cannot carry.
    pub fn try_new(index: u32, chunk_size: usize, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_CHUNK {
            return Err(Error::Bulk("chunk exceeds the ceiling"));
        }
        if chunk_size == 0 {
            return Err(Error::Bulk("chunk size is outside the supported range"));
        }
        Ok(Self::new(index, chunk_size, data))
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

    /// Hash of the chunk bytes, computed once.
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Encoded frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + 8 + 4 + 32 + self.data.len());
        out.extend_from_slice(&CHUNK_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.offset.to_le_bytes());
        out.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.hash);
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
            hash,
            data,
        })
    }
}

/// A resume request: the chunk indexes a receiver still wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkRequest {
    missing: Vec<u32>,
}

impl BulkRequest {
    /// Build a request from a missing list. Duplicates are removed.
    pub fn new(missing: &[u32]) -> Self {
        let mut unique: BTreeSet<u32> = BTreeSet::new();
        unique.extend(missing.iter().copied());
        Self {
            missing: unique.into_iter().collect(),
        }
    }

    /// The indexes asked for, ascending and unique.
    pub fn missing(&self) -> &[u32] {
        &self.missing
    }

    /// Encoded request.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + self.missing.len() * 4);
        out.extend_from_slice(&REQUEST_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&(self.missing.len() as u32).to_le_bytes());
        for index in &self.missing {
            out.extend_from_slice(&index.to_le_bytes());
        }
        out
    }

    /// Decode a request, refusing one that asks for more chunks than exist.
    pub fn decode(bytes: &[u8], plan: &BulkPlan) -> Result<Self> {
        const HEADER: usize = 4 + 1 + 4;
        if bytes.len() < HEADER {
            return Err(Error::Bulk("request is shorter than its header"));
        }
        if bytes[0..4] != REQUEST_MAGIC {
            return Err(Error::Bulk("request magic mismatch"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Bulk("unsupported bulk request version"));
        }
        let count = u32::from_le_bytes(bytes[5..9].try_into().expect("4 bytes")) as usize;
        let expected = HEADER
            .checked_add(
                count
                    .checked_mul(4)
                    .ok_or(Error::Bulk("request is too large"))?,
            )
            .ok_or(Error::Bulk("request is too large"))?;
        if bytes.len() != expected {
            return Err(Error::Bulk("request length does not match its count"));
        }
        if count > plan.chunk_count() as usize {
            return Err(Error::Bulk("request asks for more chunks than the plan"));
        }
        let mut missing = Vec::with_capacity(count);
        for slot in 0..count {
            let start = HEADER + slot * 4;
            let index = u32::from_le_bytes(bytes[start..start + 4].try_into().expect("4 bytes"));
            if index >= plan.chunk_count() {
                return Err(Error::Bulk("requested chunk is outside the plan"));
            }
            missing.push(index);
        }
        Ok(Self::new(&missing))
    }
}

/// The finish marker: which transfer the sender believes it completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkFinish {
    root: [u8; 32],
    total: u64,
}

impl BulkFinish {
    /// Build the marker for a plan.
    pub fn new(plan: &BulkPlan) -> Self {
        Self {
            root: plan.root(),
            total: plan.total(),
        }
    }

    /// The root the sender claims.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// The body length the sender claims.
    pub fn total(&self) -> u64 {
        self.total
    }

    /// Encoded marker.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 8 + 32);
        out.extend_from_slice(&FINISH_MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&self.root);
        out
    }

    /// Decode a marker and check it against the plan being received.
    pub fn decode(bytes: &[u8], plan: &BulkPlan) -> Result<Self> {
        const LEN: usize = 4 + 1 + 8 + 32;
        if bytes.len() != LEN {
            return Err(Error::Bulk("finish marker has the wrong length"));
        }
        if bytes[0..4] != FINISH_MAGIC {
            return Err(Error::Bulk("finish magic mismatch"));
        }
        if bytes[4] != VERSION {
            return Err(Error::Bulk("unsupported bulk finish version"));
        }
        let total = u64::from_le_bytes(bytes[5..13].try_into().expect("8 bytes"));
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[13..45]);
        if total != plan.total() || root != plan.root() {
            return Err(Error::Bulk("finish marker does not match the plan"));
        }
        Ok(Self { root, total })
    }
}

/// Splits a body into frames and supports resuming from any index.
#[derive(Clone)]
pub struct BulkSender {
    plan: BulkPlan,
    bytes: Vec<u8>,
}

impl std::fmt::Debug for BulkSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The body itself is never printed.
        f.debug_struct("BulkSender")
            .field("plan", &self.plan)
            .field("len", &self.bytes.len())
            .finish()
    }
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
    ///
    /// Holds one copy of the body a second time; [`BulkSender::frame_at`] is the
    /// streaming path.
    pub fn frames(&self) -> Vec<Vec<u8>> {
        (0..self.plan.chunks)
            .filter_map(|index| self.frame_at(index).ok())
            .collect()
    }

    /// Frames for the chunks at or after `from`.
    pub fn frames_from(&self, from: u32) -> Result<Vec<Vec<u8>>> {
        if from > self.plan.chunks {
            return Err(Error::Bulk("resume point is outside the plan"));
        }
        let mut out = Vec::new();
        for (index, part) in self.bytes.chunks(self.plan.chunk).enumerate() {
            if index as u32 >= from {
                out.push(BulkChunk::new(index as u32, self.plan.chunk, part).encode());
            }
        }
        Ok(out)
    }

    /// One frame, for a streaming sender.
    pub fn frame_at(&self, index: u32) -> Result<Vec<u8>> {
        if index >= self.plan.chunks {
            return Err(Error::Bulk("requested chunk is outside the plan"));
        }
        let start = index as usize * self.plan.chunk;
        let end = (start + self.plan.chunk).min(self.bytes.len());
        Ok(BulkChunk::new(index, self.plan.chunk, &self.bytes[start..end]).encode())
    }

    /// Frames for exactly the indexes a receiver reports as missing.
    ///
    /// The list is deduplicated and bounded by the plan: it comes from the peer,
    /// and an unbounded list would let a small request ask for an unbounded
    /// allocation. An index outside the plan is an error rather than a silently
    /// dropped frame.
    pub fn frames_for(&self, missing: &[u32]) -> Result<Vec<Vec<u8>>> {
        if missing.len() > self.plan.chunks as usize {
            return Err(Error::Bulk("request asks for more chunks than the plan"));
        }
        let mut unique: BTreeSet<u32> = BTreeSet::new();
        for index in missing {
            if *index >= self.plan.chunks {
                return Err(Error::Bulk("requested chunk is outside the plan"));
            }
            unique.insert(*index);
        }
        unique
            .into_iter()
            .map(|index| self.frame_at(index))
            .collect()
    }
}

/// Receives chunks, tolerates retransmission, and verifies the root at the end.
#[derive(Clone)]
pub struct BulkReceiver {
    plan: BulkPlan,
    received: BTreeMap<u32, Vec<u8>>,
    ceiling: u64,
    meter: Option<BudgetMeter>,
    expected_root: Option<[u8; 32]>,
}

impl std::fmt::Debug for BulkReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The chunk bodies are never printed.
        f.debug_struct("BulkReceiver")
            .field("plan", &self.plan)
            .field("received", &self.received.len())
            .field("bytes", &self.bytes_received())
            .field("ceiling", &self.ceiling)
            .finish()
    }
}

impl BulkReceiver {
    /// A receiver for a plan with the default body ceiling.
    pub fn new(plan: BulkPlan) -> Result<Self> {
        Self::with_ceiling(plan, MAX_TOTAL)
    }

    /// A receiver that refuses a plan larger than `ceiling` bytes.
    pub fn with_ceiling(plan: BulkPlan, ceiling: u64) -> Result<Self> {
        let ceiling = ceiling.min(MAX_TOTAL);
        if plan.total > ceiling {
            return Err(Error::Bulk("body exceeds the receiver ceiling"));
        }
        Ok(Self {
            plan,
            received: BTreeMap::new(),
            ceiling,
            meter: None,
            expected_root: None,
        })
    }

    /// A receiver that charges every chunk against `budget`.
    ///
    /// The charge is the frame's wire size and happens before the chunk is
    /// stored, so a refused chunk costs the receiver nothing but the read. The
    /// ceiling becomes the budget's `max_bytes`, so the plan itself is refused
    /// when it announces more than the grant allows.
    pub fn with_budget(plan: BulkPlan, budget: Budget) -> Result<Self> {
        let ceiling = budget.max_bytes.min(MAX_TOTAL);
        let mut receiver = Self::with_ceiling(plan, ceiling)?;
        receiver.meter = Some(BudgetMeter::new(budget));
        Ok(receiver)
    }

    /// A receiver that refuses any plan but the one with `expected` as its root.
    ///
    /// This is the binding to the transfer the caller authorized: a substituted
    /// plan has a different root and is refused before a chunk is accepted.
    pub fn with_expected_root(plan: BulkPlan, expected: [u8; 32]) -> Result<Self> {
        plan.require_root(expected)?;
        let mut receiver = Self::with_ceiling(plan, MAX_TOTAL)?;
        receiver.expected_root = Some(expected);
        Ok(receiver)
    }

    /// The plan being received.
    pub fn plan(&self) -> &BulkPlan {
        &self.plan
    }

    /// Bytes charged so far, when the receiver has a budget.
    pub fn charged_bytes(&self) -> u64 {
        self.meter.as_ref().map(BudgetMeter::bytes).unwrap_or(0)
    }

    /// Accept one chunk frame and return its index.
    ///
    /// A duplicate with identical bytes is accepted (idempotent retransmission);
    /// a duplicate with different bytes is refused. With a budget, the frame is
    /// charged before it is stored.
    pub fn accept(&mut self, frame: &[u8]) -> Result<u32> {
        let (index, data, duplicate) = validate_chunk(&self.plan, &self.received, frame)?;
        if duplicate {
            return Ok(index);
        }
        if let Some(meter) = self.meter.as_mut() {
            meter.charge_bytes(frame.len() as u64)?;
        }
        self.received.insert(index, data);
        Ok(index)
    }

    /// Accept one chunk frame, charging it through `charge` first.
    ///
    /// The callback is the integration point for a caller that meters bytes
    /// somewhere else (a kernel lane, a capability). It runs after validation
    /// and before the chunk is stored, so a refused charge leaves no state.
    pub fn accept_charged(
        &mut self,
        frame: &[u8],
        charge: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<u32> {
        let (index, data, duplicate) = validate_chunk(&self.plan, &self.received, frame)?;
        if duplicate {
            return Ok(index);
        }
        charge(frame.len() as u64)?;
        self.received.insert(index, data);
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
    ///
    /// Each chunk is moved out of the map as it is appended, so peak memory is
    /// the body plus one chunk rather than twice the body.
    pub fn finish(self) -> Result<Vec<u8>> {
        let Self {
            plan,
            mut received,
            ceiling,
            expected_root,
            ..
        } = self;
        if let Some(expected) = expected_root {
            plan.require_root(expected)?;
        }
        if received.len() as u32 != plan.chunks {
            return Err(Error::Bulk("body is incomplete"));
        }
        if plan.total > ceiling {
            return Err(Error::Bulk("body exceeds the receiver ceiling"));
        }
        let mut out = Vec::with_capacity(plan.total as usize);
        for index in 0..plan.chunks {
            let data = received
                .remove(&index)
                .ok_or(Error::Bulk("body is incomplete"))?;
            out.extend_from_slice(&data);
        }
        if out.len() as u64 != plan.total {
            return Err(Error::Bulk("body length does not match the plan"));
        }
        plan.verify(&out)?;
        Ok(out)
    }
}

/// Validate a chunk frame against a plan and what is already stored.
///
/// Returns `(index, data, duplicate)`. Validation happens before any charge or
/// store, so a malformed frame cannot cost the receiver budget or memory.
fn validate_chunk(
    plan: &BulkPlan,
    received: &BTreeMap<u32, Vec<u8>>,
    frame: &[u8],
) -> Result<(u32, Vec<u8>, bool)> {
    let chunk = BulkChunk::decode(frame)?;
    let index = chunk.index;
    if index >= plan.chunks {
        return Err(Error::Bulk("chunk index is outside the plan"));
    }
    let expected_offset = index as u64 * plan.chunk as u64;
    if chunk.offset != expected_offset {
        return Err(Error::Bulk("chunk offset does not match its index"));
    }
    let start = index as u64 * plan.chunk as u64;
    let expected_len = (plan.total - start).min(plan.chunk as u64);
    if chunk.data.len() as u64 != expected_len {
        return Err(Error::Bulk("chunk length does not match the plan"));
    }
    let planned = plan.hashes[index as usize];
    if chunk.hash != planned {
        return Err(Error::Bulk("chunk does not match the planned hash"));
    }
    if let Some(existing) = received.get(&index) {
        if existing == &chunk.data {
            return Ok((index, chunk.data, true));
        }
        return Err(Error::Bulk("conflicting duplicate chunk"));
    }
    Ok((index, chunk.data, false))
}

/// A provider that receives a bulk body through ordinary calls.
///
/// The plan, each chunk, the resume request and the finish marker travel as the
/// **payload** of an ARP1 call (`plan`, `put`, `missing`, `finish`). That is
/// what binds a transfer to authority and to the byte budget: the kernel charges
/// an envelope payload on ingress and the capability grants the methods, so a
/// chunk costs the caller its grant and a peer without `put` cannot push one.
///
/// The receiver here is deliberately unmetered: the bytes were charged when the
/// envelope arrived, and charging again would double-count. A caller that feeds
/// [`BulkReceiver`] directly uses [`BulkReceiver::with_budget`] or
/// [`BulkReceiver::accept_charged`] instead.
pub struct BulkProvider {
    expected_root: Option<[u8; 32]>,
    ceiling: u64,
    transfer: Option<(BulkPlan, BulkReceiver)>,
    completed: Option<(Vec<u8>, [u8; 32])>,
    calls: u64,
}

impl std::fmt::Debug for BulkProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkProvider")
            .field("pinned_root", &self.expected_root.is_some())
            .field("ceiling", &self.ceiling)
            .field("active", &self.transfer.is_some())
            .field(
                "completed",
                &self.completed.as_ref().map(|(body, _)| body.len()),
            )
            .finish()
    }
}

impl Default for BulkProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl BulkProvider {
    /// A provider that accepts any internally consistent plan.
    ///
    /// A transfer admitted this way is checked against corruption, not against
    /// substitution: pin a root with [`BulkProvider::with_expected_root`] when
    /// the plan arrives over a channel that is not already authenticated.
    pub fn new() -> Self {
        Self {
            expected_root: None,
            ceiling: MAX_TOTAL,
            transfer: None,
            completed: None,
            calls: 0,
        }
    }

    /// A provider that only admits the transfer whose root is `root`.
    pub fn with_expected_root(root: [u8; 32]) -> Self {
        let mut provider = Self::new();
        provider.expected_root = Some(root);
        provider
    }

    /// Cap the body this provider assembles.
    pub fn with_ceiling(mut self, ceiling: u64) -> Self {
        self.ceiling = ceiling.min(MAX_TOTAL);
        self
    }

    /// Take the last completed body and its content hash.
    pub fn take_body(&mut self) -> Option<(Vec<u8>, [u8; 32])> {
        self.completed.take()
    }

    /// The transfer in progress, if any.
    pub fn active_root(&self) -> Option<[u8; 32]> {
        self.transfer.as_ref().map(|(plan, _)| plan.root())
    }

    fn plan_method(&mut self, call: &Call) -> Result<Response> {
        let plan = BulkPlan::decode_for(&call.payload, self.ceiling, &[])?;
        if let Some(expected) = self.expected_root {
            plan.require_root(expected)?;
        }
        if let Some((active, receiver)) = &self.transfer {
            // A second plan mid-transfer is either a retry of the same transfer
            // or a substitution, which is refused. A retry must not reset the
            // chunks already received: the caller paid for them, and a
            // retransmitted plan frame is ordinary on a flaky link.
            if active.root() != plan.root() {
                return Err(Error::Bulk("a different transfer is already active"));
            }
            let plan = active.clone();
            let missing = receiver.missing().len() as u64;
            return Ok(Response::Value(Value::map([
                ("total", Value::Int(plan.total() as i64)),
                ("chunk", Value::Int(plan.chunk_size() as i64)),
                ("chunks", Value::Int(plan.chunk_count() as i64)),
                ("root", Value::text(plan.root_hex())),
                ("missing", Value::Int(missing as i64)),
            ])));
        }
        let receiver = BulkReceiver::with_ceiling(plan.clone(), self.ceiling)?;
        let missing = receiver.missing().len() as u64;
        self.transfer = Some((plan.clone(), receiver));
        Ok(Response::Value(Value::map([
            ("total", Value::Int(plan.total() as i64)),
            ("chunk", Value::Int(plan.chunk_size() as i64)),
            ("chunks", Value::Int(plan.chunk_count() as i64)),
            ("root", Value::text(plan.root_hex())),
            ("missing", Value::Int(missing as i64)),
        ])))
    }

    fn put_method(&mut self, call: &Call) -> Result<Response> {
        let (_, receiver) = self
            .transfer
            .as_mut()
            .ok_or(Error::Bulk("no transfer is active"))?;
        let index = receiver.accept(&call.payload)?;
        let received = receiver.bytes_received();
        let missing = receiver.missing().len() as u64;
        Ok(Response::Value(Value::map([
            ("index", Value::Int(index as i64)),
            ("received", Value::Int(received as i64)),
            ("missing", Value::Int(missing as i64)),
        ])))
    }

    fn missing_method(&mut self) -> Result<Response> {
        let (plan, receiver) = self
            .transfer
            .as_ref()
            .ok_or(Error::Bulk("no transfer is active"))?;
        let missing: Vec<Value> = receiver
            .missing()
            .into_iter()
            .map(|index| Value::Int(index as i64))
            .collect();
        Ok(Response::Value(Value::map([
            ("total", Value::Int(plan.total() as i64)),
            ("missing", Value::list(missing)),
        ])))
    }

    fn finish_method(&mut self, call: &Call) -> Result<Response> {
        // Validate before taking: a marker for another transfer, or a finish
        // that arrives before the last chunk, must not destroy the chunks the
        // caller has already paid for. Only a successful finish consumes the
        // transfer.
        {
            let (plan, receiver) = self
                .transfer
                .as_ref()
                .ok_or(Error::Bulk("no transfer is active"))?;
            // The marker names the root and length the sender believes it sent;
            // a marker for another transfer must not settle this one.
            BulkFinish::decode(&call.payload, plan)?;
            if !receiver.is_complete() {
                return Err(Error::Bulk("body is incomplete"));
            }
        }
        let (_, receiver) = self
            .transfer
            .take()
            .ok_or(Error::Bulk("no transfer is active"))?;
        let body = receiver.finish()?;
        let hash = *blake3::hash(&body).as_bytes();
        let length = body.len() as u64;
        self.completed = Some((body, hash));
        Ok(Response::Value(Value::map([
            ("length", Value::Int(length as i64)),
            ("hash", Value::text(hex(&hash))),
        ])))
    }
}

impl crate::kernel::Provider for BulkProvider {
    fn name(&self) -> &'static str {
        "bulk"
    }

    fn methods(&self) -> Vec<String> {
        ["plan", "put", "missing", "finish"]
            .iter()
            .map(|method| method.to_string())
            .collect()
    }

    fn has_method(&self, method: &str) -> bool {
        matches!(method, "plan" | "put" | "missing" | "finish")
    }

    fn mutating(&self, method: &str) -> bool {
        // `missing` only reads the receiver's state.
        method != "missing"
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> Result<Response> {
        self.calls = self.calls.saturating_add(1);
        match call.method.as_str() {
            "plan" => self.plan_method(call),
            "put" => self.put_method(call),
            "missing" => self.missing_method(),
            "finish" => self.finish_method(call),
            other => Err(Error::MethodNotGranted {
                method: other.to_string(),
            }),
        }
    }
}

/// A body split into frames, for a caller that drives the transfer itself.
pub struct BulkTransfer {
    sender: BulkSender,
}

impl BulkTransfer {
    /// Plan a body for sending.
    pub fn new(body: Vec<u8>, chunk: usize) -> Result<Self> {
        Ok(Self {
            sender: BulkSender::new(body, chunk)?,
        })
    }

    /// The plan frame, which opens the transfer.
    pub fn plan_frame(&self) -> Vec<u8> {
        self.sender.plan().encode()
    }

    /// One chunk frame.
    pub fn chunk_frame(&self, index: u32) -> Result<Vec<u8>> {
        self.sender.frame_at(index)
    }

    /// The finish marker.
    pub fn finish_frame(&self) -> Vec<u8> {
        BulkFinish::new(self.sender.plan()).encode()
    }

    /// The plan.
    pub fn plan(&self) -> &BulkPlan {
        self.sender.plan()
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
    if count > MAX_CHUNKS as u64 {
        return Err(Error::Bulk("plan declares too many chunks"));
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
