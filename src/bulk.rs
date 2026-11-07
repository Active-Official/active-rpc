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
/// frame into a huge allocation. The bound is the size of the plan *envelope*
/// under `WireLimits::strict()`: that profile caps the whole frame at 1 MiB
/// (`max_bytes`, not only `max_payload`), so the header and 32 bytes per chunk
/// must leave room for the envelope framing as well, and for a capability
/// descriptor with a `max_path`-length scope plus a one-entry cap delta (about
/// 1.6 kB together). A full 1 GiB body therefore needs a chunk of at least
/// 32 837 bytes: `ceil(2^30 / 32 836)` is 32 701, one more than the ceiling
/// (round 3, F8; round 4, L-2; round 5, F5; round 6, L4; round 7, L4). A test
/// encodes and decodes the maximal plan under the strict profile with such a
/// descriptor and a delta attached.
pub const MAX_CHUNKS: u32 = 32_700;

/// Wire overhead of one chunk frame: magic, version, index, offset, length and
/// hash.
///
/// A grant carries frames, not body bytes, so a body of `total` bytes needs
/// `total + CHUNK_OVERHEAD * chunks` of grant to arrive at all
/// (round 3, F9).
pub const CHUNK_OVERHEAD: u64 = 4 + 1 + 4 + 8 + 4 + 32;

/// How many missing indexes a `missing` reply lists.
///
/// `Budget::strict()` allows 1 024 elements in one list, and a
/// [`MAX_CHUNKS`]-chunk plan cannot be resumed from a single unbounded reply,
/// so the reply is a window and the caller repeats it (round 3, F8).
pub const MISSING_PAGE: usize = 1_024;

/// Wire overhead of a plan frame: magic, version, chunk size, total length,
/// chunk count and the root hash.
pub const PLAN_OVERHEAD: u64 = 4 + 1 + 4 + 8 + 4 + 32;

/// Wire length of a finish marker: magic, version, total and root.
pub const FINISH_LEN: u64 = 4 + 1 + 8 + 32;

/// Per-call allowance for the provider's replies when a caller sizes a grant.
///
/// A place, put, missing or finish reply is a small map; 128 bytes covers every
/// fixed shape with room to spare (a missing page is larger, but a caller that
/// pages a [`MAX_CHUNKS`]-chunk plan also needs the grant for those replies and
/// [`BulkPlan::required_grant`] is the conservative bound).
pub const REPLY_ALLOWANCE: u64 = 128;

/// Throughput the wall-sizing formula assumes for one `finish` pass.
///
/// Measured at about 700 MiB/s on the reference host (256 MiB finishes in 372 ms,
/// see `docs/spec/performance.md`); the formula assumes 128 MiB/s, a 5x margin
/// (round 8, M1).
pub const FINISH_BYTES_PER_MS: u64 = 128 * 1024 * 1024 / 1000;

/// Under-resourced `finish` attempts a transfer tolerates before it freezes.
///
/// Each one may assemble, verify and classify the whole body, so the budget is
/// what stops a 53-byte frame from buying a body-sized copy over and over
/// (R-10 round 13). Three is the number the spec states.
pub const WALL_REFUSAL_LIMIT: u8 = 3;

/// What the wall throttle decides for one `finish` attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Throttle {
    /// The attempt may run. `funded` says its grant is wider than any grant that
    /// has already run out of wall, so it is a price this transfer has not
    /// refused and it clears the failure count.
    Run { funded: bool },
    /// The wall attempts are spent: refuse before any work.
    Frozen,
}

/// Whether a `finish` attempt runs, given the caller's grant, the widest grant
/// that has run out of wall, and the failures already counted.
///
/// Every wall failure counts, whatever its grant: an attempt that presents the
/// body's own wall and still expires is evidence that the estimate is wrong for
/// this host, not a payment that must be forgotten (R-10 round 16, #1). The only
/// way to clear the count is a grant *strictly wider* than one that has already
/// failed, which is a price the transfer has not refused. A transfer that keeps
/// failing at the same grant freezes after [`WALL_REFUSAL_LIMIT`] failures and
/// has the two documented ways out: a wider grant, or `abort`.
fn throttle(grant_wall_ms: u64, failed_at_ms: u64, refusals: u8) -> Throttle {
    if grant_wall_ms > failed_at_ms {
        Throttle::Run { funded: true }
    } else if refusals >= WALL_REFUSAL_LIMIT {
        Throttle::Frozen
    } else {
        Throttle::Run { funded: false }
    }
}

/// How long a finished, untaken body is retained before its memory is released.
///
/// Longer than [`TRANSFER_IDLE_MS`] because the host polls for a completed body,
/// and bounded so a capability that expires by TTL without being dropped cannot
/// hold a gigabyte for the process lifetime (round 4, L-5). The digest reply
/// stays answerable after the bytes are released.
pub const COMPLETED_IDLE_MS: u64 = 600_000;

/// An absolute lifetime for one transfer, whatever its refreshes.
///
/// A peer that keeps polling `plan` or `missing` renews the idle window; this
/// bound is anchored at the opening call, so a transfer cannot be held forever
/// (round 5, F2).
pub const MAX_TRANSFER_LIFETIME_MS: u64 = 3_600_000;

/// How long a transfer may sit idle before its slot is released.
///
/// The kernel stamps `Call::now_ms`, so expiry is deterministic and a peer that
/// opens a transfer and sends nothing cannot hold the slot forever
/// (round 3, F1).
pub const TRANSFER_IDLE_MS: u64 = 60_000;

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
        let total = bytes.len() as u64;
        if total > MAX_TOTAL {
            // A sender must not build a plan its own decoder refuses
            // (round 3, F7).
            return Err(Error::Bulk("body exceeds the protocol ceiling"));
        }
        // The count is checked before the hash vector is built: a body of a
        // gigabyte at a one-byte chunk used to allocate 34 GB of hashes and
        // then refuse (round 4, M-4).
        let chunks = expected_chunks(total, chunk)?;
        let hashes: Vec<[u8; 32]> = bytes.chunks(chunk).map(chunk_hash).collect();
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
        if total > MAX_TOTAL {
            return Err(Error::Bulk("body exceeds the protocol ceiling"));
        }
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

    /// The byte grant a whole transfer needs through a kernel.
    ///
    /// The kernel charges ingress and egress against one meter, so this covers
    /// the plan frame, every chunk frame, the finish marker and a per-call reply
    /// allowance. `total + CHUNK_OVERHEAD * chunks` covers the chunk frames
    /// only: a transfer started with exactly that grant spends it on the plan
    /// and the chunks and then cannot pay for a reply (round 4, M-2).
    pub fn required_grant(&self) -> u64 {
        let chunks = self.chunks as u64;
        self.total
            .saturating_add(CHUNK_OVERHEAD.saturating_mul(chunks))
            .saturating_add(PLAN_OVERHEAD.saturating_add(32u64.saturating_mul(chunks)))
            .saturating_add(FINISH_LEN)
            .saturating_add(REPLY_ALLOWANCE.saturating_mul(chunks.saturating_add(3)))
    }

    /// The call grant a whole transfer needs through a kernel, including a full
    /// resume.
    ///
    /// `plan`, one `put` per chunk and `finish` (`chunks + 2`), plus one
    /// `missing` page per 1 024 chunks for the gaps-only resume the module
    /// advertises: a caller that sizes its grant from this accessor can lose the
    /// connection, ask what is missing and finish rather than be refused
    /// mid-resume. A caller that re-sends every chunk instead uses
    /// [`BulkPlan::required_calls_with_resume`]. `Budget::default()`
    /// `.max_calls` is 10 000, which a large body with small chunks exceeds; the
    /// caller raises it with the grant (round 5, F3; round 6, L8).
    pub fn required_calls(&self) -> u64 {
        let chunks = self.chunks as u64;
        let pages = chunks.div_ceil(MISSING_PAGE as u64);
        chunks.saturating_add(2).saturating_add(pages)
    }

    /// The call grant a transfer needs if the sender re-sends every chunk.
    ///
    /// Two `plan` frames, two `put` per chunk and one `finish`: the resume
    /// [`BulkPlan::required_grant_with_resume`] pays for in bytes
    /// (round 7, M2).
    pub fn required_calls_with_resume(&self) -> u64 {
        (self.chunks as u64).saturating_mul(2).saturating_add(4)
    }

    /// The lane's wall grant a transfer needs.
    ///
    /// The kernel meters a call against the narrower of the capability and the
    /// lane on every axis, so the lane's `max_wall_ms` must carry the same bound
    /// as the capability's; a default lane (5 s) silently truncates it
    /// (round 9, M1).
    pub fn required_lane_wall_ms(&self) -> u64 {
        self.required_wall_ms()
    }

    /// The lane's cumulative byte ceiling a transfer needs.
    ///
    /// The kernel meters a call against the narrower of the capability and the
    /// lane, and a lane's `max_bytes` is cumulative over its life, so a lane
    /// created with `Budget::default()` (64 MiB) cannot carry a larger body
    /// whatever the capability says (round 8, M2). This is the no-resume bound;
    /// add [`BulkPlan::required_grant_with_resume`] when a resume is expected.
    pub fn required_lane_bytes(&self) -> u64 {
        self.required_grant()
    }

    /// The byte grant a transfer needs if it may have to resume.
    ///
    /// A resume re-sends the plan and the chunk frames, and every payload is
    /// charged on ingress again, so the worst case is two passes over the plan
    /// and the chunk frames plus the marker and the replies (round 7, M2). The
    /// plain [`BulkPlan::required_grant`] is the no-resume bound; this one is
    /// not the default because it roughly doubles what a caller must reserve.
    pub fn required_grant_with_resume(&self) -> u64 {
        let chunks = self.chunks as u64;
        let pass = self
            .total
            .saturating_add(CHUNK_OVERHEAD.saturating_mul(chunks))
            .saturating_add(PLAN_OVERHEAD)
            .saturating_add(32u64.saturating_mul(chunks));
        self.required_grant()
            .saturating_add(pass)
            .saturating_add(REPLY_ALLOWANCE.saturating_mul(chunks.saturating_add(2)))
    }

    /// The wall the body can be assembled, verified and classified under, in
    /// milliseconds.
    ///
    /// `finish` is linear in the body: the assembly hashes every chunk, the
    /// verification pass re-hashes it, and the content address adds the
    /// redaction pass. [`FINISH_BYTES_PER_MS`] is a 5x margin under the measured
    /// full-finish rate, so one pass at this rate covers all three. The bound
    /// carries 100 ms of slack for the scheduling around them.
    ///
    /// This is the *reachable* bound: the provider throttles repeated attempts
    /// whose grant is below it, and a caller that can obtain it always finishes
    /// (R-10 round 15, #2).
    pub fn assembly_wall_ms(&self) -> u64 {
        // The per-chunk term is not decoration: the verification pass builds and
        // finalises one hash per chunk and both passes read the clock per chunk,
        // so a maximal-chunk-count body measured 1.3-1.7x the byte-only estimate
        // (R-10 round 16, #4). Four microseconds per chunk keeps a ~4x margin on
        // top of the measured cost.
        let per_chunk = u64::from(self.chunks).div_ceil(250);
        self.total
            .div_ceil(FINISH_BYTES_PER_MS)
            .saturating_add(per_chunk)
            .saturating_add(100)
    }

    /// The wall grant a `finish` should be sized for, in milliseconds.
    ///
    /// A grant below this bound makes a large transfer permanently unfinishable,
    /// since attenuation can only narrow it (round 8, M1). It never asks for
    /// less than the default grant, because a deployment that mints capabilities
    /// with the default expects every transfer to fit: [`Self::assembly_wall_ms`]
    /// is the hard floor, this is the recommended sizing.
    pub fn required_wall_ms(&self) -> u64 {
        self.assembly_wall_ms().max(Budget::default().max_wall_ms)
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

    /// Verify a whole body against the plan, inside `deadline`.
    ///
    /// The pass re-hashes the whole body, so it is charged to the wall grant
    /// like the assembly is: the deadline is checked before the first chunk,
    /// between chunks and after the last one. A single check before the pass
    /// left a caller with an expired grant paying one full body hash with no
    /// bound at all (R-10 round 15, #1).
    pub fn verify_within(&self, bytes: &[u8], deadline: Option<std::time::Instant>) -> Result<()> {
        if bytes.len() as u64 != self.total {
            return Err(Error::Bulk("body length does not match the plan"));
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(Error::BudgetExceeded("wall"));
        }
        for (index, part) in bytes.chunks(self.chunk).enumerate() {
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err(Error::BudgetExceeded("wall"));
            }
            // A body of the planned length always has this many hashes; the
            // lookup is fallible so a plan built by hand cannot panic here.
            let Some(expected) = self.hashes.get(index) else {
                return Err(Error::Bulk("chunk hash mismatch"));
            };
            if chunk_hash(part) != *expected {
                return Err(Error::Bulk("chunk hash mismatch"));
            }
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(Error::BudgetExceeded("wall"));
        }
        Ok(())
    }

    /// Verify a whole body against the plan, unbounded.
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        self.verify_within(bytes, None)
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
            // A pair whose product is past `u64` names no plan position, so it
            // becomes `u64::MAX`, which `validate_chunk` refuses. Panicking in
            // a infallible constructor was the alternative (round 6, L3).
            offset: (index as u64).saturating_mul(chunk_size as u64),
            hash: chunk_hash(data),
            data: data.to_vec(),
        }
    }

    /// Build a chunk whose hash is already known (the sender's plan holds it).
    ///
    /// The receiver still validates the hash against the plan, so a wrong value
    /// here is refused at the other end rather than trusted.
    fn with_hash(index: u32, chunk_size: usize, data: &[u8], hash: [u8; 32]) -> Self {
        Self {
            index,
            offset: (index as u64).saturating_mul(chunk_size as u64),
            hash,
            data: data.to_vec(),
        }
    }

    /// Build a chunk, refusing data the frame format cannot carry.
    pub fn try_new(index: u32, chunk_size: usize, data: &[u8]) -> Result<Self> {
        if data.len() > MAX_CHUNK {
            return Err(Error::Bulk("chunk exceeds the ceiling"));
        }
        // The same range `new` relies on: a chunk past `MAX_CHUNK` names no
        // wire-legal plan (round 12, L-5).
        check_chunk_size(chunk_size)?;
        // The refusing constructor must not panic on a pair whose product is
        // past `u64` (round 5, F6).
        let offset = (index as u64)
            .checked_mul(chunk_size as u64)
            .ok_or(Error::Bulk("chunk offset overflows"))?;
        Ok(Self {
            index,
            offset,
            hash: chunk_hash(data),
            data: data.to_vec(),
        })
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

    /// Decode a marker and check it against a root and total, without a plan.
    ///
    /// The provider keeps the digest reply of a finished transfer as an O(1)
    /// record, so it must be able to validate a retried marker without holding
    /// the plan (round 5, F1).
    pub fn decode_for(bytes: &[u8], expected_total: u64, expected_root: [u8; 32]) -> Result<Self> {
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
        if total != expected_total || root != expected_root {
            return Err(Error::Bulk("finish marker does not match the plan"));
        }
        Ok(Self { root, total })
    }

    /// Decode a marker and check it against the plan being received.
    pub fn decode(bytes: &[u8], plan: &BulkPlan) -> Result<Self> {
        Self::decode_for(bytes, plan.total(), plan.root())
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
    /// streaming path. A frame that cannot be built is an error, never a
    /// silently short batch (round 5, F7).
    pub fn frames(&self) -> Result<Vec<Vec<u8>>> {
        (0..self.plan.chunks)
            .map(|index| self.frame_at(index))
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
    ///
    /// The frame carries the hash the plan already holds: a retransmission or a
    /// resume does not re-hash the body (round 7, L8).
    pub fn frame_at(&self, index: u32) -> Result<Vec<u8>> {
        if index >= self.plan.chunks {
            return Err(Error::Bulk("requested chunk is outside the plan"));
        }
        let start = index as usize * self.plan.chunk;
        let end = (start + self.plan.chunk).min(self.bytes.len());
        let planned = self.plan.hashes[index as usize];
        Ok(BulkChunk::with_hash(index, self.plan.chunk, &self.bytes[start..end], planned).encode())
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
    /// Bytes stored, maintained on insert so a status reply is O(1) rather
    /// than a sum over every chunk (round 3, F2).
    stored: u64,
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
            .field("bytes", &self.stored)
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
            stored: 0,
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
    /// charged **before** it is validated: decoding and hashing it is the work
    /// the charge pays for, so a wrong-hash frame is not free
    /// (round 7, L6; round 10, M-2).
    pub fn accept(&mut self, frame: &[u8]) -> Result<u32> {
        if let Some(meter) = self.meter.as_mut() {
            meter.charge_bytes(frame.len() as u64)?;
        }
        let (index, data, duplicate) = validate_chunk(&self.plan, &self.received, frame)?;
        if duplicate {
            return Ok(index);
        }
        self.stored = self.stored.saturating_add(data.len() as u64);
        self.received.insert(index, data);
        Ok(index)
    }

    /// Accept one chunk frame, charging it through `charge` before the work.
    ///
    /// The callback is the integration point for a caller that meters bytes
    /// somewhere else (a kernel lane, a capability). It runs before validation,
    /// because decoding and hashing the frame is the work it pays for; a
    /// refused charge still leaves no state (round 10, M-2).
    pub fn accept_charged(
        &mut self,
        frame: &[u8],
        charge: &mut dyn FnMut(u64) -> Result<()>,
    ) -> Result<u32> {
        charge(frame.len() as u64)?;
        let (index, data, duplicate) = validate_chunk(&self.plan, &self.received, frame)?;
        if duplicate {
            return Ok(index);
        }
        self.stored = self.stored.saturating_add(data.len() as u64);
        self.received.insert(index, data);
        Ok(index)
    }

    /// Indexes not yet received, in order.
    ///
    /// The whole list; a status reply on the provider path uses the bounded
    /// [`BulkReceiver::missing_page`] instead.
    pub fn missing(&self) -> Vec<u32> {
        (0..self.plan.chunks)
            .filter(|index| !self.received.contains_key(index))
            .collect()
    }

    /// At most `page` indexes not yet received, lowest first.
    ///
    /// A resumed transfer of a plan with tens of thousands of chunks needs more
    /// than one reply, and `Budget::strict()` allows 1 024 elements
    /// (round 3, F8).
    pub fn missing_page(&self, page: usize) -> Vec<u32> {
        (0..self.plan.chunks)
            .filter(|index| !self.received.contains_key(index))
            .take(page)
            .collect()
    }

    /// Whether `index` is still missing.
    pub fn missing_contains(&self, index: u32) -> bool {
        index < self.plan.chunks && !self.received.contains_key(&index)
    }

    /// How many chunks are still missing. O(1): the count is derived from the
    /// stored indexes, not from a scan (round 3, F2).
    pub fn missing_count(&self) -> u64 {
        self.plan.chunks as u64 - self.received.len() as u64
    }

    /// Bytes accepted so far. O(1): maintained on insert (round 3, F2).
    pub fn bytes_received(&self) -> u64 {
        self.stored
    }

    /// True when every chunk is present.
    pub fn is_complete(&self) -> bool {
        self.received.len() as u32 == self.plan.chunks
    }

    /// Assemble and verify the body.
    ///
    /// Every refusal leaves the stored chunks intact: a finish that cannot
    /// succeed must not destroy bytes the caller already paid for
    /// (round 3, F6). A successful finish releases them, and peak memory is the
    /// assembled body plus the stored chunks.
    pub fn finish(&mut self) -> Result<Vec<u8>> {
        Ok(self.finish_within(None)?.0)
    }

    /// Assemble and verify under an optional deadline, returning the body and
    /// its raw Blake3 digest.
    ///
    /// The digest is fed while the body is assembled, so the provider does not
    /// re-hash a gigabyte after verification. A deadline that has already
    /// passed is `rpc/budget-exceeded("wall")` before any work, and the deadline
    /// is re-checked between chunks and inside the verification pass, chunk by
    /// chunk (round 5, F4; round 6, L6; R-10 round 15). The assembly allocation
    /// is fallible: a body
    /// the process cannot hold is a refusal, not an abort. The content address
    /// of a valid image allocates a second body-sized projection inside
    /// `finish_method`, which is optional and skippable when the grant is spent.
    ///
    /// This is the one place a bulk provider reads the wall clock. Every other
    /// lifetime is measured from `Call::now_ms`, but the grant is a *duration*
    /// (`max_wall_ms`) that a timestamp cannot express, so the deadline is
    /// derived from `Instant::now()`; a replay with the same timestamps can
    /// therefore refuse on a loaded machine where it succeeded on an idle one
    /// (round 6, L9).
    pub fn finish_within(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        if let Some(expected) = self.expected_root {
            self.plan.require_root(expected)?;
        }
        if self.received.len() as u32 != self.plan.chunks {
            return Err(Error::Bulk("body is incomplete"));
        }
        if self.plan.total > self.ceiling {
            return Err(Error::Bulk("body exceeds the receiver ceiling"));
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(Error::BudgetExceeded("wall"));
        }
        let mut out = Vec::new();
        out.try_reserve_exact(self.plan.total as usize)
            .map_err(|_| Error::Bulk("the body cannot be allocated"))?;
        let mut hasher = blake3::Hasher::new();
        for index in 0..self.plan.chunks {
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err(Error::BudgetExceeded("wall"));
            }
            let data = self
                .received
                .get(&index)
                .ok_or(Error::Bulk("body is incomplete"))?;
            out.extend_from_slice(data);
            hasher.update(data);
        }
        if out.len() as u64 != self.plan.total {
            return Err(Error::Bulk("body length does not match the plan"));
        }
        // The verification pass re-hashes the whole body, so it is inside the
        // deadline too, chunk by chunk (round 6, L6; R-10 round 15, #1).
        self.plan.verify_within(&out, deadline)?;
        self.received.clear();
        self.stored = 0;
        Ok((out, *hasher.finalize().as_bytes()))
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
    // A plan constructor makes `start < total`, but this is the one arithmetic
    // check behind a caller-side invariant: a subtraction that panics is not a
    // refusal (round 7, L5).
    let expected_len = plan.total.saturating_sub(start).min(plan.chunk as u64);
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

/// A completed bulk body and the digests computed for it.
///
/// `body_hash` is the raw Blake3 digest of the bytes: a transfer-integrity
/// value, never a content address. For a body that is a canonical Active
/// Infinity image, [`BulkBody::content_hash`] is the redacted content address
/// the domain provider serves, so a relay that republishes a location does not
/// re-create the offline-guessing oracle a raw digest is (round 3, F4).
pub struct BulkBody {
    body: Vec<u8>,
    body_hash: [u8; 32],
    content: Option<[u8; 32]>,
    /// Why the canonical address is missing, when it could have been computed
    /// (`"wall"` for a spent grant, `"parser"` for a body that decodes as an
    /// image but cannot be redacted). `None` alongside an absent `content`
    /// means the body is not an image (round 10, M-4).
    content_error: Option<&'static str>,
}

impl std::fmt::Debug for BulkBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The raw digest is the value a redacting capability withholds: it is
        // an offline equality oracle over the un-redacted bytes, so a host that
        // logged a taken body with `{:?}` would republish it (round 15, #4).
        // The reply carries it where the contract allows it.
        f.debug_struct("BulkBody")
            .field("len", &self.body.len())
            .field("content", &self.content.as_ref().map(hex))
            .field("content_error", &self.content_error)
            .finish()
    }
}

impl BulkBody {
    /// The assembled bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Take the assembled bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// Raw Blake3 digest of the bytes. Never a content address.
    pub fn body_hash(&self) -> [u8; 32] {
        self.body_hash
    }

    /// The canonical, redacted content address, when the body is an Active
    /// Infinity image.
    pub fn content_hash(&self) -> Option<[u8; 32]> {
        self.content
    }

    /// Why [`BulkBody::content_hash`] is absent for an image that should have
    /// one: `"wall"` (the grant was spent) or `"parser"` (the body decodes but
    /// cannot be redacted). `None` with no address means the body is not an
    /// image (round 10, M-4).
    pub fn content_error(&self) -> Option<&'static str> {
        self.content_error
    }
}

/// A transfer in progress for one object.
struct ActiveTransfer {
    plan: BulkPlan,
    receiver: BulkReceiver,
    last_ms: u64,
    /// When the transfer opened: the idle window can be refreshed, this bound
    /// cannot (round 5, F2).
    created_ms: u64,
    /// Finishes refused by the wall grant. Each one re-assembles the body, so a
    /// caller cannot buy CPU with a 45-byte frame (round 9, M4).
    wall_refusals: u8,
    /// The widest wall grant that has run out of wall. A grant above it is a
    /// price this transfer has not refused, and it clears the count
    /// (R-10 round 16, #1).
    wall_failed_at_ms: u64,
}

/// A body that finished and has not been taken by the host yet.
///
/// The plan is not retained: a marker check needs the root and the total, and a
/// maximal plan would outweigh the body it describes (round 6, L2).
struct CompletedTransfer {
    body: BulkBody,
    root: [u8; 32],
    total: u64,
    at_ms: u64,
    /// Whether a `wall`-degraded content address has already been recomputed
    /// once. A replay may pay for one recomputation, never for a loop of them
    /// (R-10 round 16, #5).
    recomputed: bool,
}

/// The digest reply for a finished body, kept after the host takes the bytes so
/// a retransmitted finish marker is still answered (round 4, L-4).
///
/// O(1): the root and total are all a marker check needs, so the record never
/// retains a plan's chunk hashes (round 5, F1).
struct FinishedTransfer {
    root: [u8; 32],
    total: u64,
    length: u64,
    body_hash: [u8; 32],
    content: Option<[u8; 32]>,
    content_error: Option<&'static str>,
    /// When the reply was recorded: the record is released with the same window
    /// as an untaken body (round 6, L7).
    at_ms: u64,
}

/// The content address of a body, if the body has one.
///
/// `(None, Some("wall"))` means the grant was spent before the classification
/// started; `(None, None)` means the body is not an image;
/// `(None, Some("parser"))` means it is an image the redaction refuses. A panic
/// in the Infinity parser must not leave the object without a digest reply: the
/// content address is optional, the record is not (round 8, L2). The probe runs
/// inside `catch_unwind` because the caller releases the chunks, so an unwind
/// would leave a transfer that can never finish (round 11, L-3).
fn classify_body(body: &[u8]) -> (Option<[u8; 32]>, Option<&'static str>) {
    let classified = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match crate::security::redact_module(body) {
            Ok(redacted) => match active_infinity::content_hash(&redacted) {
                Ok(address) => Ok(Some(address)),
                // The image redacted but its address failed: a parser fault
                // unless it does not even claim to be an image (R-16 round 6, #4).
                Err(_) => Err(crate::security::claims_infinity_image(body)),
            },
            Err(_) => Err(crate::security::claims_infinity_image(body)),
        }
    }));
    match classified {
        Ok(Ok(Some(address))) => (Some(address), None),
        Ok(Ok(None)) => (None, None),
        Ok(Err(true)) => (None, Some("parser")),
        Ok(Err(false)) => (None, None),
        Err(_) => (None, Some("parser")),
    }
}

/// A provider that receives a bulk body through ordinary calls.
///
/// The plan, each chunk, the resume request and the finish marker travel as the
/// **payload** of an ARP1 call (`plan`, `put`, `missing`, `finish`). That is
/// what binds a transfer to authority and to the byte budget: the kernel charges
/// an envelope payload on ingress and the capability grants the methods, so a
/// chunk costs the caller its grant and a peer without `put` cannot push one.
///
/// State is keyed by the capability's **object**, which is what
/// `Provider::invoke` carries, and the kernel's drop notification releases it:
/// revoking the last capability cannot leave a gigabyte of chunks resident
/// (round 3, F1). Attenuation preserves the object, so two capabilities derived
/// from the same grant share one slot: the object is expected to have one
/// principal. An incomplete transfer is released after [`TRANSFER_IDLE_MS`] of
/// inactivity and a finished, untaken body after [`COMPLETED_IDLE_MS`], both
/// measured against the kernel's `Call::now_ms`.
///
/// The receiver here is deliberately unmetered: the bytes were charged when the
/// envelope arrived, and charging again would double-count. A caller that feeds
/// [`BulkReceiver`] directly uses [`BulkReceiver::with_budget`] or
/// [`BulkReceiver::accept_charged`] instead.
pub struct BulkProvider {
    expected_root: Option<[u8; 32]>,
    context: Vec<u8>,
    ceiling: u64,
    /// Provider-wide ceiling on the bytes held across every object; `0` means
    /// no aggregate bound beyond the cap count (round 8, L5).
    max_live_bytes: u64,
    transfers: BTreeMap<u64, ActiveTransfer>,
    completed: BTreeMap<u64, CompletedTransfer>,
    last_finished: BTreeMap<u64, FinishedTransfer>,
    calls: u64,
}

impl std::fmt::Debug for BulkProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulkProvider")
            .field("pinned_root", &self.expected_root.is_some())
            .field("context_bytes", &self.context.len())
            .field("ceiling", &self.ceiling)
            .field("active", &self.transfers.keys().collect::<Vec<_>>())
            .field("completed", &self.completed.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for BulkProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// The `plan` reply for a transfer.
fn plan_reply(plan: &BulkPlan, missing: u64) -> Response {
    Response::Value(Value::map([
        ("total", Value::Int(plan.total() as i64)),
        ("chunk", Value::Int(plan.chunk_size() as i64)),
        ("chunks", Value::Int(plan.chunk_count() as i64)),
        ("root", Value::text(plan.root_hex())),
        ("missing", Value::Int(missing as i64)),
    ]))
}

/// The `finish` reply, and the same reply for a repeated marker.
fn finished_reply(
    length: u64,
    body_hash: [u8; 32],
    content: Option<[u8; 32]>,
    content_error: Option<&'static str>,
    redact: bool,
) -> Response {
    let mut entries = BTreeMap::new();
    entries.insert("length".to_string(), Value::Int(length as i64));
    if !redact {
        entries.insert("body_hash".to_string(), Value::text(hex(&body_hash)));
    }
    // A client that keys on `content` must be able to tell "not an image" from
    // "the address could not be computed now", because the reply is recorded
    // and replayed: a spent grant would otherwise degrade it silently and
    // permanently (round 10, M-4).
    entries.insert("canonical".to_string(), Value::Bool(content.is_some()));
    if let Some(content) = content {
        entries.insert("content".to_string(), Value::text(hex(&content)));
    }
    if let Some(error) = content_error {
        entries.insert("content_error".to_string(), Value::text(error));
    }
    Response::Value(Value::Map(entries))
}

impl BulkProvider {
    /// A provider that accepts any internally consistent plan.
    ///
    /// Without a context or a pinned root a transfer is checked against
    /// corruption only: any peer that can reach `plan` chooses the body. Pin a
    /// root with [`BulkProvider::with_expected_root`] or bind the plan to the
    /// opening exchange with [`BulkProvider::with_context`].
    pub fn new() -> Self {
        Self {
            expected_root: None,
            context: Vec::new(),
            ceiling: MAX_TOTAL,
            max_live_bytes: 0,
            transfers: BTreeMap::new(),
            completed: BTreeMap::new(),
            last_finished: BTreeMap::new(),
            calls: 0,
        }
    }

    /// A provider that only admits the transfer whose root is `root`.
    pub fn with_expected_root(root: [u8; 32]) -> Self {
        let mut provider = Self::new();
        provider.expected_root = Some(root);
        provider
    }

    /// Bind every plan to `context` (for example the request id and capability
    /// id of the exchange that opened the transfer).
    ///
    /// The context is never transmitted: both sides derive it, so a plan cannot
    /// float free of the envelope that authorized it. This is the provider-side
    /// half of [`BulkPlan::new_with_context`], which the capability kernel cannot
    /// supply on its own because `Provider::invoke` carries no request id
    /// (round 3, F5).
    ///
    /// One context per provider instance: a provider that serves several objects
    /// binds them all to the same context, so an exchange that needs its own
    /// context uses its own provider (round 4, L-3).
    pub fn with_context(mut self, context: Vec<u8>) -> Self {
        self.context = context;
        self
    }

    /// Cap the body this provider assembles.
    pub fn with_ceiling(mut self, ceiling: u64) -> Self {
        self.ceiling = ceiling.min(MAX_TOTAL);
        self
    }

    /// Bound the bytes held across every object (`0` keeps no aggregate bound).
    ///
    /// N objects each hold up to the protocol ceiling; a host that mints per
    /// upload wants a provider-wide limit rather than one per object
    /// (round 8, L5). The check runs when a transfer opens, so a transfer that
    /// fits is never evicted mid-flight.
    pub fn with_max_live_bytes(mut self, limit: u64) -> Self {
        self.max_live_bytes = limit;
        self
    }

    /// Bytes the provider is committed to hold: the announced total of every
    /// open transfer plus every completed body.
    ///
    /// An open transfer reserves its plan's total, so the bound holds before a
    /// chunk arrives (round 8, L5).
    pub fn live_bytes(&self) -> u64 {
        // An open transfer reserves the bytes it has stored, the assembly
        // buffer a `finish` allocates and the plan's own hash vector
        // (round 9, M5; round 10, M-1; round 18, #1).
        let pending: u64 = self
            .transfers
            .values()
            .map(|active| reserved_bytes(&active.plan, active.receiver.bytes_received()))
            .sum();
        let done: u64 = self
            .completed
            .values()
            .map(|done| done.body.len() as u64)
            .sum();
        pending.saturating_add(done)
    }

    /// Take the completed body for `object`, if the host has not taken it.
    pub fn take_body(&mut self, object: u64) -> Option<BulkBody> {
        self.completed.remove(&object).map(|done| done.body)
    }

    /// Whether a completed body is waiting for the host.
    pub fn has_body(&self, object: u64) -> bool {
        self.completed.contains_key(&object)
    }

    /// The transfer in progress for `object`, if any.
    pub fn active_root(&self, object: u64) -> Option<[u8; 32]> {
        self.transfers.get(&object).map(|active| active.plan.root())
    }

    /// Calls admitted by this provider, for observability.
    pub fn calls(&self) -> u64 {
        self.calls
    }

    /// Release an incomplete transfer, or a finished body, that has been idle
    /// past its window.
    ///
    /// A released body keeps its digest reply in `last_finished`, so a retried
    /// finish marker is answered even after the bytes are gone. The idle window
    /// is refreshable; [`MAX_TRANSFER_LIFETIME_MS`] is anchored at the opening
    /// call and cannot be (round 5, F2).
    fn expire(&mut self, object: u64, now_ms: u64) {
        let stale = |stamp: u64, window: u64| now_ms.saturating_sub(stamp) > window;
        if let Some(active) = self.transfers.get(&object) {
            if stale(active.last_ms, TRANSFER_IDLE_MS)
                || stale(active.created_ms, MAX_TRANSFER_LIFETIME_MS)
            {
                self.transfers.remove(&object);
            }
        }
        if let Some(done) = self.completed.get(&object) {
            if stale(done.at_ms, COMPLETED_IDLE_MS) {
                self.completed.remove(&object);
            }
        }
        if let Some(done) = self.last_finished.get(&object) {
            if stale(done.at_ms, COMPLETED_IDLE_MS) {
                self.last_finished.remove(&object);
            }
        }
    }

    /// Release every object whose state has been idle past its window.
    ///
    /// `expire` is per object, so without a sweep an abandoned transfer stays
    /// resident until its own object is called again. A host with its own clock
    /// calls this; `plan` calls it too, so a new transfer sweeps the provider
    /// (round 5, F2).
    pub fn expire_idle(&mut self, now_ms: u64) {
        let objects: Vec<u64> = self
            .transfers
            .keys()
            .chain(self.completed.keys())
            .chain(self.last_finished.keys())
            .copied()
            .collect();
        for object in objects {
            self.expire(object, now_ms);
        }
    }

    /// Refuse a new plan while a finished body waits to be taken.
    ///
    /// Replacing it would silently drop bytes the caller paid to transfer
    /// (round 3, F3).
    fn require_taken(&self, object: u64) -> Result<()> {
        if self.completed.contains_key(&object) {
            return Err(Error::Bulk("the completed body has not been taken"));
        }
        Ok(())
    }

    fn plan_method(&mut self, object: u64, call: &Call) -> Result<Response> {
        let plan = BulkPlan::decode_for(&call.payload, self.ceiling, &self.context)?;
        if let Some(expected) = self.expected_root {
            plan.require_root(expected)?;
        }
        // A new transfer is the moment to sweep every object: an abandoned
        // transfer on another object would otherwise wait for its own call.
        self.expire_idle(call.now_ms);
        // The state refusals come before the byte ceiling: the same plan must
        // not answer "not taken" or "another transfer" as a budget fault just
        // because other objects hold bytes (round 10, L-1).
        self.require_taken(object)?;
        if let Some(active) = self.transfers.get_mut(&object) {
            // A second plan mid-transfer is either a retry of the same transfer
            // or a substitution, which is refused. A retry must not reset the
            // chunks already received: the caller paid for them, and a
            // retransmitted plan frame is ordinary on a flaky link.
            if active.plan.root() != plan.root() {
                return Err(Error::Bulk("a different transfer is already active"));
            }
            // The attempt budget is kept: the same chunks are still stored, so
            // this is the same transfer (round 12, M-1). Only an exhausted
            // transfer is released, and a re-plan after that is a new one.
            active.last_ms = call.now_ms;
            return Ok(plan_reply(&active.plan, active.receiver.missing_count()));
        }
        if self.max_live_bytes != 0 {
            let held = self.live_bytes();
            // A new transfer has stored nothing yet, so it reserves its plan
            // vector; the chunks it receives reserve more as they arrive
            // (R-10 round 18, #1).
            if held.saturating_add(reserved_bytes(&plan, 0)) > self.max_live_bytes {
                // A budget class, like every other ceiling (round 9, L3).
                return Err(Error::BudgetExceeded("byte"));
            }
        }
        let receiver = BulkReceiver::with_ceiling(plan.clone(), self.ceiling)?;
        let missing = receiver.missing_count();
        self.transfers.insert(
            object,
            ActiveTransfer {
                plan,
                receiver,
                last_ms: call.now_ms,
                created_ms: call.now_ms,
                wall_refusals: 0,
                wall_failed_at_ms: 0,
            },
        );
        // A new transfer is a new exchange: the previous body's digest reply is
        // no longer this object's answer.
        self.last_finished.remove(&object);
        let plan = &self.transfers[&object].plan;
        Ok(plan_reply(plan, missing))
    }

    /// Abandon whatever this object holds.
    ///
    /// A refusal must never destroy a body the caller paid to transfer, so the
    /// caller needs its own way out: without one, a transfer whose finish cannot
    /// be granted holds the object's slot, its reserved bytes in the provider's
    /// live ceiling and its chunks until the idle or absolute window expires
    /// (R-10 round 15, #2). An explicit `abort` is that party saying so, and it
    /// is idempotent: an object with nothing to drop answers the same constant
    /// shape as one that dropped a body (`aborted: true`), so a capability that
    /// grants only `abort` learns nothing about another principal's state
    /// (R-10 rounds 17-18).
    ///
    /// It drops a completed body the host has not taken as well: the caller paid
    /// for the transfer and the reply for it, and asking to abandon it is a
    /// decision the provider cannot overrule.
    fn abort_method(&mut self, object: u64, call: &Call) -> Result<Response> {
        self.expire(object, call.now_ms);
        self.transfers.remove(&object);
        self.completed.remove(&object);
        self.last_finished.remove(&object);
        // The reply is one constant shape. `dropped: true/false` told a
        // capability that grants only `abort` whether another principal held a
        // transfer or an untaken body on the object — a one-bit view of somebody
        // else's state, the same family as RPC-11 (R-10 round 17).
        Ok(Response::Value(Value::map([(
            "aborted",
            Value::Bool(true),
        )])))
    }

    fn put_method(&mut self, object: u64, call: &Call) -> Result<Response> {
        self.expire(object, call.now_ms);
        if self.max_live_bytes != 0 {
            // A chunk grows the reservation by twice its stored bytes; the
            // ceiling is charged before the bytes are stored, like every other
            // budget (R-10 round 18, #1).
            // The stored bytes are the frame without its header, which is what
            // live_bytes counts; a malformed short frame reserves nothing and
            // accept refuses it below.
            let stored = (call.payload.len() as u64).saturating_sub(CHUNK_OVERHEAD);
            let growth = stored.saturating_mul(2);
            if self.live_bytes().saturating_add(growth) > self.max_live_bytes {
                return Err(Error::BudgetExceeded("byte"));
            }
        }
        let active = self
            .transfers
            .get_mut(&object)
            .ok_or(Error::Bulk("no transfer is active"))?;
        let index = active.receiver.accept(&call.payload)?;
        active.last_ms = call.now_ms;
        let received = active.receiver.bytes_received();
        let missing = active.receiver.missing_count();
        Ok(Response::Value(Value::map([
            ("index", Value::Int(index as i64)),
            ("received", Value::Int(received as i64)),
            ("missing", Value::Int(missing as i64)),
        ])))
    }

    fn missing_method(&mut self, object: u64, call: &Call) -> Result<Response> {
        // A live resume poll keeps the idle window alive, and a read-only caller
        // cannot destroy another capability's chunks by idleness (round 4,
        // L-1). The absolute lifetime is different: polling must not hold a
        // transfer past `MAX_TRANSFER_LIFETIME_MS` (round 6, M1).
        let expired = self.transfers.get(&object).is_some_and(|active| {
            call.now_ms.saturating_sub(active.created_ms) > MAX_TRANSFER_LIFETIME_MS
        });
        if expired {
            self.transfers.remove(&object);
        }
        let active = self
            .transfers
            .get_mut(&object)
            .ok_or(Error::Bulk("no transfer is active"))?;
        // A resume request names the gaps the sender wants; the reply is that
        // set (page-capped), or the authoritative window when the frame is
        // empty. An index outside the plan is refused (round 8, L1;
        // round 9, M3).
        let requested = if call.payload.is_empty() {
            None
        } else {
            Some(BulkRequest::decode(&call.payload, &active.plan)?)
        };
        active.last_ms = call.now_ms;
        let page: Vec<u32> = match requested {
            Some(request) => request
                .missing()
                .iter()
                .copied()
                .filter(|index| active.receiver.missing_contains(*index))
                .take(MISSING_PAGE)
                .collect(),
            None => active.receiver.missing_page(MISSING_PAGE),
        };
        let more = active.receiver.missing_count() > page.len() as u64;
        let missing: Vec<Value> = page
            .into_iter()
            .map(|index| Value::Int(index as i64))
            .collect();
        Ok(Response::Value(Value::map([
            ("total", Value::Int(active.plan.total() as i64)),
            ("missing", Value::list(missing)),
            ("more", Value::Bool(more)),
            (
                "remaining",
                Value::Int(active.receiver.missing_count() as i64),
            ),
        ])))
    }

    fn finish_method(&mut self, object: u64, call: &Call) -> Result<Response> {
        // Expiry runs before the idempotent fast paths: a peer that retried the
        // marker every window kept an untaken body resident forever and, with
        // `require_taken`, wedged the object (round 7, M1).
        self.expire(object, call.now_ms);
        // A repeated marker answers with the same reply: the effect landed, the
        // caller cannot tell a lost answer from a lost request, and a retry must
        // not be receipted as a refusal (round 3, F3). The digest summary
        // outlives the bytes, so the answer survives `take_body` and the
        // completed window (round 4, L-4, L-5).
        if let Some(done) = self.completed.get_mut(&object) {
            BulkFinish::decode_for(&call.payload, done.total, done.root)?;
            // A reply degraded by a spent grant is not final while the body is
            // still resident: one replay that can pay recomputes the address
            // once, and the record then says it did (R-10 round 16, #5).
            if !done.recomputed
                && done.body.content_hash().is_none()
                && done.body.content_error() == Some("wall")
                && call.budget.max_wall_ms > 0
            {
                let (content, content_error) = classify_body(done.body.body());
                done.recomputed = true;
                done.body.content = content;
                done.body.content_error = content_error;
                if let Some(last) = self.last_finished.get_mut(&object) {
                    last.content = content;
                    last.content_error = content_error;
                }
            }
            let reply = finished_reply(
                done.body.len() as u64,
                done.body.body_hash(),
                done.body.content_hash(),
                done.body.content_error(),
                call.redact,
            );
            return Ok(reply);
        }
        if let Some(done) = self.last_finished.get(&object) {
            BulkFinish::decode_for(&call.payload, done.total, done.root)?;
            return Ok(finished_reply(
                done.length,
                done.body_hash,
                done.content,
                done.content_error,
                call.redact,
            ));
        }
        // Validate before taking: a marker for another transfer, or a finish
        // that arrives before the last chunk, must not destroy the chunks the
        // caller has already paid for.
        let (root, total) = {
            let active = self
                .transfers
                .get(&object)
                .ok_or(Error::Bulk("no transfer is active"))?;
            // The marker names the root and length the sender believes it sent;
            // a marker for another transfer must not settle this one.
            BulkFinish::decode(&call.payload, &active.plan)?;
            if !active.receiver.is_complete() {
                return Err(Error::Bulk("body is incomplete"));
            }
            (active.plan.root(), active.plan.total())
        };
        // The transfer stays in the map until the reply is built: the chunks are
        // released by `finish_within` on success, but a panic in the parser
        // below must not leave the object with no record at all (round 7, L7).
        // The wall grant bounds the assembly, the verification and the
        // redaction: a grant that has run out refuses before the work, and a
        // spent grant after assembly skips the content address instead of
        // running an unbounded pass (round 5, F4; round 7, L3).
        // A wall grant that cannot be added (u64::MAX) must fail closed rather
        // than disable the check (round 9, L1). The instant is the same one the
        // attempt counter compares below, so "did this attempt have time to
        // work" is deterministic rather than a sub-millisecond race
        // (round 12, L-4).
        let entered = std::time::Instant::now();
        let deadline = entered
            .checked_add(std::time::Duration::from_millis(
                call.budget.max_wall_ms.min(MAX_TRANSFER_LIFETIME_MS),
            ))
            // `checked_add` cannot fail after the clamp on any sane clock, but
            // a `None` here used to mean "no deadline at all": fall back to the
            // absolute lifetime instead (round 10, L-2).
            .or_else(|| {
                std::time::Instant::now()
                    .checked_add(std::time::Duration::from_millis(MAX_TRANSFER_LIFETIME_MS))
            })
            // A None deadline would mean no bound at all: an already-passed
            // deadline fails closed instead (round 11, L-5).
            .unwrap_or_else(std::time::Instant::now);
        // A transfer that keeps running out of wall gets three assemblies and
        // then only refusals: a cheap frame must not buy repeated CPU. Every
        // failure counts, whatever its grant — an attempt that presents the
        // body's own wall and still expires is evidence that the estimate is
        // wrong for this host, not a payment to forget — and the only way to
        // clear the count is a grant strictly wider than one that has already
        // failed (R-10 round 13/15/16). The chunks are never released by a
        // refusal: a refusal must not destroy a body the caller paid to
        // transfer.
        let (refusals, failed_at) = self.transfers.get(&object).map_or((0, 0), |active| {
            (active.wall_refusals, active.wall_failed_at_ms)
        });
        let funded = match throttle(call.budget.max_wall_ms, failed_at, refusals) {
            // A state refusal, not a budget class: the transfer will not take
            // another attempt at a grant it has already refused, and the same
            // frame is refused identically. The message names both ways out.
            Throttle::Frozen => {
                return Err(Error::Bulk(
                    "finish is frozen after three attempts at a refused wall grant: grant more wall or abort",
                ))
            }
            Throttle::Run { funded } => funded,
        };
        if funded {
            // A wider grant is a price the transfer has not refused, so three
            // cheap failures must not make a body unfinishable once the host
            // widens it (round 15, #3).
            if let Some(active) = self.transfers.get_mut(&object) {
                active.wall_refusals = 0;
            }
        }
        // The instant the assembly starts, not the instant the deadline was
        // built: `entered < deadline` held for every positive grant and turned
        // the documented "did no work" exemption into dead code
        // (R-10 round 16, #3).
        let started = std::time::Instant::now();
        let (body, body_hash) = {
            let active = self
                .transfers
                .get_mut(&object)
                .ok_or(Error::Bulk("no transfer is active"))?;
            match active.receiver.finish_within(Some(deadline)) {
                Ok(pair) => pair,
                Err(error) => {
                    // Every wall failure that did work counts, and the widest
                    // one is remembered. A refusal that never started (the
                    // deadline was already spent) did no work and is not
                    // evidence about the grant (round 11, M-2; round 16, #1).
                    if matches!(&error, Error::BudgetExceeded("wall")) && started < deadline {
                        active.wall_refusals = active.wall_refusals.saturating_add(1);
                        active.wall_failed_at_ms =
                            active.wall_failed_at_ms.max(call.budget.max_wall_ms);
                    }
                    return Err(error);
                }
            }
        };
        let length = body.len() as u64;
        // The canonical content address is computed over the *redacted* image.
        // The raw hash covers the secret heap, so serving it would be the
        // offline equality oracle the domain provider refuses to publish
        // (round 4, H-1).
        // A body that is not an image has no address, and saying so is not a
        // degradation. A spent grant or a parser fault are, and the reply says
        // which (round 10, M-4).
        let spent = std::time::Instant::now() >= deadline;
        let (content, content_error) = if spent {
            (None, Some("wall"))
        } else {
            classify_body(&body)
        };
        self.transfers.remove(&object);
        // A raw digest over a secret-bearing body is the value the domain
        // provider withholds from a redacting capability; `content` is the
        // redacted address and is enough (round 5 residual).
        let reply = finished_reply(length, body_hash, content, content_error, call.redact);
        self.last_finished.insert(
            object,
            FinishedTransfer {
                root,
                total,
                length,
                body_hash,
                content,
                content_error,
                at_ms: call.now_ms,
            },
        );
        self.completed.insert(
            object,
            CompletedTransfer {
                body: BulkBody {
                    body,
                    body_hash,
                    content,
                    content_error,
                },
                root,
                total,
                at_ms: call.now_ms,
                // The reply this record is built from already ran the
                // classification inside its grant, so a replay must not run it
                // again (round 16, #5).
                recomputed: false,
            },
        );
        Ok(reply)
    }
}

impl crate::kernel::Provider for BulkProvider {
    fn name(&self) -> &'static str {
        "bulk"
    }

    fn methods(&self) -> Vec<String> {
        ["plan", "put", "missing", "finish", "abort"]
            .iter()
            .map(|method| method.to_string())
            .collect()
    }

    fn has_method(&self, method: &str) -> bool {
        matches!(method, "plan" | "put" | "missing" | "finish" | "abort")
    }

    fn mutating(&self, method: &str) -> bool {
        // `missing` reads the receiver's state and refreshes the liveness stamp;
        // it never consumes a chunk or a body, so a read-only capability may call
        // it (round 4, L-1).
        method != "missing"
    }

    /// A revoked capability must not leave state behind: the chunks (up to the
    /// protocol ceiling), a completed body and the digest reply would stay
    /// resident for the life of the process (round 3, F1; round 5, F1).
    fn on_drop(&mut self, object: u64, _cap: crate::cap::CapId) {
        self.transfers.remove(&object);
        self.completed.remove(&object);
        self.last_finished.remove(&object);
    }

    fn invoke(&mut self, object: u64, call: &Call) -> Result<Response> {
        self.calls = self.calls.saturating_add(1);
        match call.method.as_str() {
            "plan" => self.plan_method(object, call),
            "put" => self.put_method(object, call),
            "missing" => self.missing_method(object, call),
            "finish" => self.finish_method(object, call),
            "abort" => self.abort_method(object, call),
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

/// Bytes one open transfer reserves: the body, the assembly buffer and the
/// plan's hash vector.
///
/// The plan is retained for the whole transfer (32 bytes per chunk plus the
/// header), so a bound that counts only the body under-reports a
/// maximal-chunk-count plan by up to 16x (round 10, M-1).
fn reserved_bytes(plan: &BulkPlan, received: u64) -> u64 {
    // The footprint is what is stored plus the assembly buffer a `finish`
    // allocates, and the assembly can only ever hold a complete body: reserving
    // `2 x received` is exact at the finish and never under-counts. Charging
    // `2 x total` from the plan instead let an announced-but-unpaid plan hold the
    // provider-wide bound for the whole idle window (R-10 round 18, #1).
    received
        .saturating_mul(2)
        .saturating_add(PLAN_OVERHEAD)
        .saturating_add(32u64.saturating_mul(plan.chunk_count() as u64))
}

fn check_chunk_size(chunk: usize) -> Result<()> {
    if chunk == 0 || chunk > MAX_CHUNK {
        return Err(Error::Bulk("chunk size is outside the supported range"));
    }
    Ok(())
}

fn expected_chunks(total: u64, chunk: usize) -> Result<u32> {
    // This is the division sink for every ceiling check: a zero chunk panicked
    // here, and the guard had been left to each caller (round 3, F10).
    check_chunk_size(chunk)?;
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

#[cfg(test)]
mod throttle_tests {
    use super::{
        throttle, BulkBody, BulkFinish, BulkPlan, BulkProvider, CompletedTransfer, Throttle,
        WALL_REFUSAL_LIMIT,
    };
    use crate::kernel::Provider;
    use crate::value::{Call, Response, Value};

    /// Every failure counts, whatever its grant, and only a *strictly wider*
    /// grant clears the count: repeating an attempt at a grant the transfer has
    /// already refused must freeze, which is what a "reaches the bound" reset
    /// got wrong on a host slower than the estimate (R-10 round 13/15/16).
    #[test]
    fn the_wall_throttle_counts_every_failure_and_needs_a_wider_grant_to_clear() {
        // A price the transfer has not refused always runs, however many
        // failures came before it.
        assert_eq!(throttle(8_000, 0, 0), Throttle::Run { funded: true });
        assert_eq!(throttle(8_000, 1, 3), Throttle::Run { funded: true });
        assert_eq!(throttle(8_001, 8_000, 9), Throttle::Run { funded: true });
        // The same grant that already failed is counted, then frozen.
        assert_eq!(throttle(132, 132, 0), Throttle::Run { funded: false });
        assert_eq!(throttle(132, 132, 2), Throttle::Run { funded: false });
        assert_eq!(throttle(132, 132, WALL_REFUSAL_LIMIT), Throttle::Frozen);
        // So is a narrower one, and a zero grant on a fresh transfer is not a
        // payment at all (it runs, does no work, and is not counted by the
        // caller of this function).
        assert_eq!(throttle(100, 132, 0), Throttle::Run { funded: false });
        assert_eq!(throttle(100, 132, 3), Throttle::Frozen);
        assert_eq!(throttle(0, 0, 0), Throttle::Run { funded: false });
        assert_eq!(throttle(0, 132, 3), Throttle::Frozen);
    }

    /// A `wall`-degraded reply is not final while the body is resident: one
    /// replay that can pay recomputes the address, and the record then refuses
    /// to run the pass again, so a replay loop cannot buy repeated redactions
    /// (R-10 round 16, #5). The fixture is the recorded state a spent grant
    /// leaves behind; the entry point is the real `finish` method.
    #[test]
    fn a_wall_degraded_reply_is_recomputed_once() {
        let module =
            crate::domain::module_from_source("[app]\nname = \"bulk-r16\"\n", "bulk-r16.active")
                .expect("module");
        let image = active_infinity::encode(&module).expect("encode");
        let plan = BulkPlan::new(&image, 4_096).expect("plan");
        let mut provider = BulkProvider::new();
        provider.completed.insert(
            0,
            CompletedTransfer {
                body: BulkBody {
                    body_hash: *blake3::hash(&image).as_bytes(),
                    body: image,
                    // The state a spent grant records: the address was never
                    // computed, and the reply says why.
                    content: None,
                    content_error: Some("wall"),
                },
                root: plan.root(),
                total: plan.total(),
                at_ms: 0,
                recomputed: false,
            },
        );
        let marker = BulkFinish::new(&plan).encode();
        let mut request = Call::new("finish", Vec::new()).with_payload(marker.clone());
        request.now_ms = 1;

        let reply = provider.invoke(0, &request).expect("the replay answers");
        let Response::Value(Value::Map(entries)) = reply else {
            panic!("a map reply");
        };
        assert!(
            entries.contains_key("content"),
            "the replay that can pay recomputes the address: {entries:?}"
        );
        assert!(
            !entries.contains_key("content_error"),
            "a recomputed address has no error: {entries:?}"
        );
        let recomputed = provider
            .completed
            .get(&0)
            .expect("the record survives the replay")
            .body
            .content;
        assert!(recomputed.is_some(), "the address is recorded");

        // Break the body and mark the reply degraded again without clearing the
        // one-shot flag: the shipped fast path must not run the pass again.
        {
            let done = provider.completed.get_mut(&0).expect("record");
            done.body.body = vec![0u8; 8];
            done.body.content = None;
            done.body.content_error = Some("wall");
        }
        let reply = provider.invoke(0, &request).expect("the second replay");
        let Response::Value(Value::Map(entries)) = reply else {
            panic!("a map reply");
        };
        assert_eq!(
            entries.get("content_error"),
            Some(&Value::text("wall")),
            "one recomputation per transfer, not one per replay"
        );
    }
}
