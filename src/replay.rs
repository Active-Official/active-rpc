//! Deterministic replay packages.
//!
//! A package records a session's *inputs* (operations against a kernel) and the
//! decision trace they produced. Replaying the package against a fresh kernel
//! must reproduce the same trace entry for entry; a tampered package, an
//! unknown operation, or a session whose decisions no longer match is refused.
//!
//! Values never enter a package. A call records its method and argument wire
//! size, not the argument text, so a recorded session cannot leak the secrets
//! it exercised. Capability ids are recorded as ordinals in first-seen order,
//! which keeps the trace stable across kernels with different secrets.

use std::collections::BTreeMap;

use crate::cap::{CapAttrs, CapHandle, CapId};
use crate::error::{Error, Result};
use crate::kernel::{Event, Provider};
use crate::value::{Arg, Call, Response, Value};
use crate::{Agent, Budget, LaneId};

/// Package magic: Active RPC Replay Package.
pub const MAGIC: &[u8; 4] = b"ARRP";
/// Format version.
pub const VERSION: u8 = 1;
/// Longest operation list a package may carry.
pub const MAX_OPS: usize = 100_000;
/// Longest trace a package may carry.
pub const MAX_TRACES: usize = 1_000_000;
/// Longest string a package may carry (method or event name).
pub const MAX_STRING: usize = 1 << 20;
/// Largest synthesized argument a replay call may carry.
pub const MAX_ARG_BYTES: u64 = 1 << 20;

/// Most methods one operation may grant.
///
/// The decoder refuses a larger set, so the recorder and the encoder do too:
/// a package that cannot be read back is not a package. A capability with more
/// than 64 methods is outside what a replay artifact can describe.
pub const MAX_METHODS: usize = 64;

/// Largest package the decoder accepts, in bytes.
///
/// The per-field ceilings (operation count, trace count, string length) do not
/// bound the body: a package can be arbitrarily large while every field is
/// legal. The whole body is held in memory and hashed before decoding, so the
/// total needs its own ceiling.
pub const MAX_PACKAGE_BYTES: usize = 64 << 20;

/// Ceiling on the decoded heap a package may describe, in bytes.
///
/// The body ceiling bounds the bytes on the wire, not the objects they
/// describe: a 19 MB package of one-byte strings expands to ~370 MB of `Op`,
/// `Trace`, `String` and method-vector allocations (R-12 round 6, L2). The
/// decoder charges every object it builds against this ceiling and refuses a
/// package that would expand past it.
pub const MAX_DECODE_BYTES: usize = 128 << 20;

/// Heap one method string costs beyond its bytes: the `String` header and the
/// vector element (48 bytes on a 64-bit target), which the earlier charge
/// missed by 16 bytes per method (R-12 round 8, F4).
const METHOD_HEAP: usize = 48;

/// Heap one trace event costs beyond its bytes: the `Trace` record and the
/// `String` header.
const TRACE_HEAP: usize = 48;

/// The decoded heap one operation describes.
fn op_decoded_bytes(op: &Op) -> usize {
    let base = std::mem::size_of::<Op>();
    match op {
        Op::Mint { methods, .. } | Op::Attenuate { methods, .. } => {
            base + methods
                .iter()
                .map(|method| method.len().saturating_add(METHOD_HEAP))
                .sum::<usize>()
        }
        Op::Call { method, .. } => base
            .saturating_add(method.len())
            .saturating_add(METHOD_HEAP),
        Op::SetLatency(_) | Op::Revoke { .. } => base,
    }
}

/// The decoded heap one trace entry describes.
fn trace_decoded_bytes(event: &str) -> usize {
    std::mem::size_of::<Trace>()
        .saturating_add(event.len())
        .saturating_add(TRACE_HEAP)
}

/// Largest sum of declared argument sizes in one package, in bytes.
///
/// Replay synthesizes an argument of the declared size for each call, so the
/// per-call ceiling alone would allow 100k × 1 MiB of transient allocation.
pub const MAX_ARG_TOTAL_BYTES: u64 = 16 << 20;

/// Fixed demo secret: replay ordinals are secret-independent, but a fixed
/// secret keeps the recorded package bytes reproducible for tests and CI.
const DEMO_SECRET: [u8; 32] = [0x6b; 32];

/// One recorded operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Set the simulated provider latency (milliseconds per batch).
    SetLatency(u64),
    /// Mint a capability for the demo provider.
    Mint {
        /// Granted methods.
        methods: Vec<String>,
        /// Optional lifetime in milliseconds.
        ttl_ms: Option<u64>,
    },
    /// Attenuate an existing capability.
    Attenuate {
        /// Parent ordinal.
        parent: u32,
        /// Granted methods.
        methods: Vec<String>,
        /// Optional lifetime in milliseconds.
        ttl_ms: Option<u64>,
    },
    /// Call a capability.
    Call {
        /// Capability ordinal.
        cap: u32,
        /// Method name.
        method: String,
        /// Bytes of the text value replay synthesizes for this argument.
        ///
        /// This is the synthesized text length, not the charged wire size: the
        /// kernel charges the value's encoded size, which the trace records
        /// separately as `call.queued:<method>:<bytes>`. The two are different
        /// numbers by design, and no argument value is recorded.
        arg_bytes: u64,
    },
    /// Revoke a capability.
    Revoke {
        /// Capability ordinal.
        cap: u32,
    },
}

/// One decision in the trace: an event name and, when the event names a
/// capability, its ordinal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trace {
    /// Stable event name (`cap.minted`, `call.refused:rpc/revoked`, ...).
    pub event: String,
    /// Capability ordinal, when the event names one.
    pub cap: Option<u32>,
}

/// A recorded session: inputs plus the decision trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayPackage {
    /// Simulated provider latency.
    pub latency_ms: u64,
    /// Recorded operations, in order.
    pub ops: Vec<Op>,
    /// Decision trace produced by those operations.
    pub trace: Vec<Trace>,
}

impl ReplayPackage {
    /// Encode the package as canonical little-endian bytes with a Blake3
    /// checksum over everything before it.
    ///
    /// Fails when the package cannot be represented: the counts are `u32` and
    /// each method length is `u16`, so a session that outgrew a ceiling is
    /// refused here instead of silently truncated into a package that re-frames
    /// its own op stream.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_with_ceiling(MAX_DECODE_BYTES)
    }

    /// [Self::encode] with the decoded-heap ceiling the caller supplies.
    ///
    /// The decoder refuses a package whose objects expand past
    /// [`MAX_DECODE_BYTES`]; an encoder that wrote one anyway produced an
    /// artifact this crate cannot read, so the same charge runs here
    /// (R-12 round 9, F2). The test drives a one-byte ceiling.
    fn encode_with_ceiling(&self, decode_ceiling: usize) -> Result<Vec<u8>> {
        let decoded = self
            .ops
            .iter()
            .map(op_decoded_bytes)
            .fold(0usize, usize::saturating_add)
            .saturating_add(
                self.trace
                    .iter()
                    .map(|entry| trace_decoded_bytes(&entry.event))
                    .fold(0usize, usize::saturating_add),
            );
        if decoded > decode_ceiling {
            return Err(Error::Replay(
                "the package expands beyond the decode ceiling".into(),
            ));
        }
        // The format's first operation carries the header rate; a package that
        // does not is one `replay` refuses, so `encode` must not write it.
        if self.ops.first() != Some(&Op::SetLatency(self.latency_ms)) {
            return Err(Error::Replay(
                "the package does not begin with its header latency".into(),
            ));
        }
        if self.ops.len() > MAX_OPS {
            return Err(Error::Replay("too many operations".into()));
        }
        if self.trace.len() > MAX_TRACES {
            return Err(Error::Replay("trace is too long".into()));
        }
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.latency_ms.to_le_bytes());
        out.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        check_body(&out)?;
        let mut arg_total: u64 = 0;
        for op in &self.ops {
            match op {
                Op::SetLatency(ms) => {
                    out.push(1);
                    out.extend_from_slice(&ms.to_le_bytes());
                }
                Op::Mint { methods, ttl_ms } => {
                    out.push(2);
                    write_attrs(&mut out, methods, *ttl_ms)?;
                }
                Op::Attenuate {
                    parent,
                    methods,
                    ttl_ms,
                } => {
                    out.push(3);
                    out.extend_from_slice(&parent.to_le_bytes());
                    write_attrs(&mut out, methods, *ttl_ms)?;
                }
                Op::Call {
                    cap,
                    method,
                    arg_bytes,
                } => {
                    if *arg_bytes > MAX_ARG_BYTES {
                        return Err(Error::Replay("argument size exceeds the ceiling".into()));
                    }
                    arg_total = arg_total.saturating_add(*arg_bytes);
                    if arg_total > MAX_ARG_TOTAL_BYTES {
                        return Err(Error::Replay(
                            "declared argument sizes exceed the package ceiling".into(),
                        ));
                    }
                    out.push(4);
                    out.extend_from_slice(&cap.to_le_bytes());
                    write_str(&mut out, method)?;
                    out.extend_from_slice(&arg_bytes.to_le_bytes());
                }
                Op::Revoke { cap } => {
                    out.push(5);
                    out.extend_from_slice(&cap.to_le_bytes());
                }
            }
            check_body(&out)?;
        }
        out.extend_from_slice(&(self.trace.len() as u32).to_le_bytes());
        check_body(&out)?;
        for trace in &self.trace {
            out.push(u8::from(trace.cap.is_some()));
            write_str(&mut out, &trace.event)?;
            if let Some(cap) = trace.cap {
                out.extend_from_slice(&cap.to_le_bytes());
            }
            check_body(&out)?;
        }
        let checksum = blake3::hash(&out);
        out.extend_from_slice(checksum.as_bytes());
        Ok(out)
    }

    /// Decode and verify a package.
    pub fn decode(bytes: &[u8]) -> Result<ReplayPackage> {
        Self::decode_with_ceiling(bytes, MAX_DECODE_BYTES)
    }

    /// [Self::decode] with the decoded-heap ceiling the caller supplies.
    ///
    /// The test drives the real parser with a small ceiling; production calls
    /// [`Self::decode`] with [`MAX_DECODE_BYTES`].
    fn decode_with_ceiling(bytes: &[u8], decode_ceiling: usize) -> Result<ReplayPackage> {
        const MIN: usize = 4 + 1 + 2 + 8 + 4 + 4 + 32;
        if bytes.len() < MIN {
            return Err(Error::Replay("package is shorter than its header".into()));
        }
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(Error::Replay("package exceeds the size ceiling".into()));
        }
        let body_len = bytes.len() - 32;
        let (body, checksum) = bytes.split_at(body_len);
        if blake3::hash(body).as_bytes() != checksum {
            return Err(Error::Replay("checksum does not match".into()));
        }
        if &body[..4] != MAGIC {
            return Err(Error::Replay("bad magic".into()));
        }
        if body[4] != VERSION {
            return Err(Error::Replay("unsupported version".into()));
        }
        if u16::from_le_bytes([body[5], body[6]]) != 0 {
            return Err(Error::Replay("reserved flags must be zero".into()));
        }
        let mut reader = Reader::new(&body[7..]);
        let latency_ms = reader.u64()?;
        let op_count = reader.u32()? as usize;
        if op_count > MAX_OPS {
            return Err(Error::Replay("too many operations".into()));
        }
        let mut ops = Vec::with_capacity(op_count.min(1024));
        let mut arg_total: u64 = 0;
        // The decoded heap this package describes, charged as it is built.
        let mut decoded_bytes: usize = 0;
        for _ in 0..op_count {
            let tag = reader.u8()?;
            let op = match tag {
                1 => Op::SetLatency(reader.u64()?),
                2 => {
                    let (methods, ttl_ms) = read_attrs(&mut reader)?;
                    Op::Mint { methods, ttl_ms }
                }
                3 => {
                    let parent = reader.u32()?;
                    let (methods, ttl_ms) = read_attrs(&mut reader)?;
                    Op::Attenuate {
                        parent,
                        methods,
                        ttl_ms,
                    }
                }
                4 => {
                    let cap = reader.u32()?;
                    let method = reader.string()?;
                    let arg_bytes = reader.u64()?;
                    if arg_bytes > MAX_ARG_BYTES {
                        return Err(Error::Replay("argument size exceeds the ceiling".into()));
                    }
                    arg_total = arg_total.saturating_add(arg_bytes);
                    if arg_total > MAX_ARG_TOTAL_BYTES {
                        return Err(Error::Replay(
                            "declared argument sizes exceed the package ceiling".into(),
                        ));
                    }
                    Op::Call {
                        cap,
                        method,
                        arg_bytes,
                    }
                }
                5 => Op::Revoke { cap: reader.u32()? },
                other => {
                    return Err(Error::Replay(format!("unknown operation tag {other}")));
                }
            };
            decoded_bytes = decoded_bytes.saturating_add(op_decoded_bytes(&op));
            if decoded_bytes > decode_ceiling {
                return Err(Error::Replay(
                    "the package expands beyond the decode ceiling".into(),
                ));
            }
            ops.push(op);
        }
        let trace_count = reader.u32()? as usize;
        if trace_count > MAX_TRACES {
            return Err(Error::Replay("trace is too long".into()));
        }
        let mut trace = Vec::with_capacity(trace_count.min(1024));
        for _ in 0..trace_count {
            let flags = reader.u8()?;
            if flags > 1 {
                return Err(Error::Replay("unknown trace flags".into()));
            }
            let event = reader.string()?;
            let cap = if flags == 1 {
                Some(reader.u32()?)
            } else {
                None
            };
            decoded_bytes = decoded_bytes.saturating_add(trace_decoded_bytes(&event));
            if decoded_bytes > decode_ceiling {
                return Err(Error::Replay(
                    "the package expands beyond the decode ceiling".into(),
                ));
            }
            trace.push(Trace { event, cap });
        }
        if !reader.is_empty() {
            return Err(Error::Replay("trailing bytes after the package".into()));
        }
        // The format's first operation carries the header rate, and both
        // `encode` and `replay_trace` refuse a package that disagrees. A
        // parser that accepted one handed the caller a package this crate
        // could never re-encode or run (R-20 round 3, M5).
        if ops.first() != Some(&Op::SetLatency(latency_ms)) {
            return Err(Error::Replay(
                "the package does not begin with its header latency".into(),
            ));
        }
        Ok(ReplayPackage {
            latency_ms,
            ops,
            trace,
        })
    }

    /// Replay the package against a fresh kernel and compare the trace.
    ///
    /// Operation errors are part of the recorded decision (the trace carries the
    /// refusal), so they do not abort the replay; a mismatch aborts with the
    /// first differing entry.
    ///
    /// The trace pins the inputs: every operation appends an `op.*` entry
    /// derived from its own fields, so a package edited without re-running the
    /// replay no longer matches its own trace. Comparing the replayed operation
    /// list would prove nothing, because `replay_trace` builds that list from
    /// the very operations it reads.
    pub fn replay(&self) -> Result<()> {
        let trace = self.replay_trace_inner()?;
        if self.trace.len() != trace.len() {
            return Err(Error::Replay(format!(
                "trace length differs: recorded {}, replayed {}",
                self.trace.len(),
                trace.len()
            )));
        }
        for (index, (expected, actual)) in self.trace.iter().zip(trace.iter()).enumerate() {
            if expected != actual {
                // The ordinal is part of the entry, so a message that prints only
                // the event cannot explain a package edited in its cap ids
                // (round 4, L-4).
                return Err(Error::Replay(format!(
                    "trace mismatch at entry {index}: recorded {} (cap {:?}), replayed {} (cap {:?})",
                    summary(&expected.event),
                    expected.cap,
                    summary(&actual.event),
                    actual.cap
                )));
            }
        }
        Ok(())
    }

    /// Execute the package and return the trace the kernel produced together
    /// with the operations the replay actually ran.
    ///
    /// This is the diagnostic half of [`ReplayPackage::replay`]: it lets a
    /// caller inspect where a package diverges instead of only learning that it
    /// did. It refuses the same malformed header `replay` does: a package whose
    /// first operation is not its header latency would otherwise run every
    /// operation except the one the header describes.
    pub fn replay_trace(&self) -> Result<(Vec<Trace>, Vec<Op>)> {
        // The operations this replay ran are the package's own, in order: the
        // recorder no longer keeps a second list, so the diagnostic path
        // returns the package's (R-12 round 10, F3). `replay()` takes the
        // trace directly and avoids this copy.
        let trace = self.replay_trace_inner()?;
        Ok((trace, self.ops.clone()))
    }

    /// The trace a replay produces, without the diagnostic operation list.
    fn replay_trace_inner(&self) -> Result<Vec<Trace>> {
        // The header latency is the *initial* rate; the recording always emits
        // it as the first operation, and a package that does not is using the
        // field for something else.
        if self.ops.first() != Some(&Op::SetLatency(self.latency_ms)) {
            return Err(Error::Replay(
                "the package does not begin with its header latency".into(),
            ));
        }
        // Replay through the same recorder code path the original session used,
        // so handle lifetimes (retain/release events) are identical by
        // construction.
        let mut recorder = Recorder::replaying(self.latency_ms)?;
        // The first op is the header latency, which `Recorder::new` already
        // applied and recorded; replaying it would duplicate the entry.
        for op in self.ops.iter().skip(1) {
            match op {
                Op::SetLatency(ms) => recorder.set_latency(*ms),
                Op::Mint { methods, ttl_ms } => {
                    ignore_refusal(recorder.mint(&method_refs(methods), *ttl_ms))?;
                    Ok(())
                }
                Op::Attenuate {
                    parent,
                    methods,
                    ttl_ms,
                } => {
                    ignore_refusal(recorder.attenuate(*parent, &method_refs(methods), *ttl_ms))?;
                    Ok(())
                }
                Op::Call {
                    cap,
                    method,
                    arg_bytes,
                } => {
                    // A hand-built package on a 32-bit target could carry an `arg_bytes`
                    // that truncates; the ceiling check below reads the full value
                    // (R-12 round 8, F10).
                    let arg_bytes = usize::try_from(*arg_bytes)
                        .map_err(|_| Error::Replay("argument size exceeds the ceiling".into()))?;
                    ignore_refusal(recorder.call(*cap, method, arg_bytes))?;
                    Ok(())
                }
                Op::Revoke { cap } => {
                    ignore_refusal(recorder.revoke(*cap))?;
                    Ok(())
                }
            }?;
        }
        // A capture that lost events leaves a truncated trace; returning it
        // as `Ok` would verify a package crafted to match that truncation
        // (R-12 round 11, F1).
        if recorder.poisoned {
            return Err(Error::Replay(
                "the replay lost events; the trace is incomplete".into(),
            ));
        }
        Ok(recorder.trace)
    }
}

/// A bounded, escaped rendering of a trace event for an error message.
///
/// The event text comes from the package: up to a megabyte of valid UTF-8,
/// including newlines and terminal escapes. Rendering it raw would let a hostile
/// package forge log lines inside the one message that is supposed to be
/// trustworthy.
fn summary(event: &str) -> String {
    const LIMIT: usize = 64;
    let truncated: String = event.chars().take(LIMIT).collect();
    format!("{truncated:?}")
}

/// A kernel refusal is part of the recorded decision; only a malformed package
/// (`rpc/replay`) aborts a replay.
fn ignore_refusal<T>(result: Result<T>) -> Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(error @ Error::Replay(_)) => Err(error),
        Err(_) => Ok(()),
    }
}

fn method_refs(methods: &[String]) -> Vec<&str> {
    methods.iter().map(String::as_str).collect()
}

/// Records a live session into a [`ReplayPackage`].
pub struct Recorder {
    agent: Agent,
    provider: crate::ProviderId,
    lane: LaneId,
    caps: Vec<CapHandle>,
    ordinals: BTreeMap<CapId, u32>,
    ops: Vec<Op>,
    trace: Vec<Trace>,
    /// Events ever captured, including ones the bounded tape has evicted.
    seen_total: u64,
    latency_ms: u64,
    /// The rate the session started at. The package header carries this, not the
    /// current rate: replay needs the initial clock to reproduce the first
    /// expiry boundary, and the recorded `SetLatency` operations move it from
    /// there.
    initial_latency_ms: u64,
    /// Set when a capture failed. The op list and the trace no longer line up,
    /// so the recorder refuses to produce a package rather than emit one that
    /// cannot replay.
    poisoned: bool,
    /// Whether this recorder keeps its own op list.
    ///
    /// A replay drives the recorder to reproduce handle lifetimes and the
    /// trace, but it never packages: keeping a second op list (with a second
    /// copy of every method string) doubled the peak for no consumer
    /// (R-12 round 10, F3).
    record_ops: bool,
    /// The decoded heap this session describes: every operation plus every
    /// trace entry, charged with the same helpers the decoder uses.
    ///
    /// The decoder refuses a package past [`MAX_DECODE_BYTES`]; a recorder that
    /// did not charge the same objects could write an artifact this crate
    /// cannot read (R-12 round 9, F2).
    decoded: usize,
    /// The ceiling `decoded` is checked against.
    decode_ceiling: usize,
    /// Declared argument bytes across every recorded call.
    ///
    /// The decoder refuses a package whose sum exceeds
    /// [`MAX_ARG_TOTAL_BYTES`], so the recorder counts as it records and refuses
    /// before the artifact exists.
    arg_total: u64,
    /// Bytes the encoded package would take, excluding the checksum.
    ///
    /// `encode` and `decode` share the body ceiling, so the recorder tracks the
    /// same number as it records. A session that reaches the ceiling is refused
    /// while it is being recorded instead of retaining a body that cannot be
    /// written.
    body: usize,
}

impl Recorder {
    /// Start a recorded session with the given simulated latency.
    pub fn new(latency_ms: u64) -> Result<Recorder> {
        Self::with_record_ops(latency_ms, true)
    }

    /// A recorder that reproduces a session without keeping its own op list.
    ///
    /// [`ReplayPackage::replay_trace`] drives this path: it already owns the
    /// operations it executes, and a second op list (with a second copy of
    /// every method string) only raised the peak (R-12 round 10, F3).
    pub(crate) fn replaying(latency_ms: u64) -> Result<Self> {
        Self::with_record_ops(latency_ms, false)
    }

    fn with_record_ops(latency_ms: u64, record_ops: bool) -> Result<Self> {
        let agent = Agent::with_secret(DEMO_SECRET);
        let provider = agent.register(Box::new(Demo));
        agent.set_latency(latency_ms);
        let lane = agent.create_lane("replay", Budget::default())?;
        let mut recorder = Recorder {
            agent,
            provider,
            lane,
            caps: Vec::new(),
            ordinals: BTreeMap::new(),
            ops: if record_ops {
                vec![Op::SetLatency(latency_ms)]
            } else {
                Vec::new()
            },
            trace: Vec::new(),
            seen_total: 0,
            latency_ms,
            initial_latency_ms: latency_ms,
            poisoned: false,
            record_ops,
            decoded: 0,
            decode_ceiling: MAX_DECODE_BYTES,
            arg_total: 0,
            // magic, version, flags, latency, op_count, and the trace count that
            // follows the operations.
            body: 4 + 1 + 2 + 8 + 4 + 4,
        };
        recorder.capture()?;
        recorder.note(&Op::SetLatency(latency_ms))?;
        Ok(recorder)
    }

    /// Whether a capture failed, so the session can no longer be packaged.
    pub fn poisoned(&self) -> bool {
        self.poisoned
    }

    /// Simulated provider latency, in milliseconds per batch.
    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Change the simulated latency and record the change.
    pub fn set_latency(&mut self, latency_ms: u64) -> Result<()> {
        let op = Op::SetLatency(latency_ms);
        self.reserve_op(&op)?;
        self.latency_ms = latency_ms;
        self.agent.set_latency(latency_ms);
        if self.record_ops {
            self.ops.push(op.clone());
        }
        self.note(&op)?;
        // The kernel does not emit an event for a clock change today, so this
        // usually captures nothing; a future clock that does emit one must not
        // leave it for the next operation's trace.
        self.capture()?;
        Ok(())
    }

    /// The decisions recorded so far.
    pub fn trace(&self) -> &[Trace] {
        &self.trace
    }

    /// Refuse a session that would produce a package its own decoder rejects.
    ///
    /// The body estimate runs as the session is recorded, not at `encode`, so a
    /// long or large session fails before it retains the bytes. A refusal here
    /// leaves the recorder usable: the operations before it are still a valid,
    /// encodable transcript, so only a lost capture poisons a session.
    fn reserve_op(&mut self, op: &Op) -> Result<()> {
        if self.poisoned {
            return Err(Error::Replay(
                "the recorder lost events; the session cannot be packaged".into(),
            ));
        }
        if self.record_ops && self.ops.len() >= MAX_OPS {
            return Err(Error::Replay(
                "the session exceeds the operation ceiling".into(),
            ));
        }
        // Every operation adds at least its own trace entry, so the ceiling is
        // predictable here: refusing keeps the session usable, where poisoning
        // on the push destroyed a transcript that was still valid
        // (round 4, L-2).
        if self.trace.len() + 1 > MAX_TRACES {
            return Err(Error::Replay("the trace exceeds the ceiling".into()));
        }
        let addition = op_len(op)?
            .checked_add(trace_len(&input_event(op))?)
            .ok_or_else(|| Error::Replay("the package size overflows".into()))?;
        // The header and the trace count are already counted in `body`; the
        // checksum is reserved here.
        if self.body.saturating_add(addition) > MAX_PACKAGE_BYTES - 32 {
            return Err(Error::Replay("package exceeds the size ceiling".into()));
        }
        // The same decoded-heap ceiling `encode` and `decode` apply, charged as
        // each operation is recorded so the session fails early rather than at
        // write time (R-12 round 9, F2). Trace entries are charged by
        // `capture` as they arrive, so this counts the op alone.
        let decoded = self.decoded.saturating_add(op_decoded_bytes(op));
        if decoded > self.decode_ceiling {
            return Err(Error::Replay(
                "the session expands beyond the decode ceiling".into(),
            ));
        }
        self.decoded = decoded;
        Ok(())
    }

    /// Refuse a method set the package format cannot encode.
    ///
    /// The wire stores a method count and each length as `u16`, while the
    /// decoder accepts at most [`MAX_METHODS`]; recording something larger would
    /// make `encode` produce an artifact `decode` refuses, so the limit is
    /// enforced here, at the only place a caller can reach it. A method name
    /// beyond `u16::MAX` bytes is refused for the same reason.
    fn check_methods(methods: &[&str]) -> Result<()> {
        if methods.len() > MAX_METHODS {
            return Err(Error::Replay("too many methods for a package".into()));
        }
        if methods
            .iter()
            .any(|method| method.len() > u16::MAX as usize)
        {
            return Err(Error::Replay(
                "a method name is too long for a package".into(),
            ));
        }
        Ok(())
    }

    /// Record one operation's input in the trace.
    ///
    /// The kernel's events name a capability, never the grant, the TTL, the
    /// method text or the argument size, so a trace built only from events
    /// cannot tell an edited package from the original: swapping a grant or a
    /// refused call's method and re-checksumming replayed clean. The input entry
    /// is derived from the *package's* fields at replay time and from the live
    /// arguments at record time, so a package edited without re-running the
    /// replay no longer matches its own trace.
    ///
    /// The entry carries a digest rather than the text: a method name is
    /// caller-chosen and may be a megabyte long.
    fn note(&mut self, op: &Op) -> Result<()> {
        // `note` appends the `op.*` input entry outside `capture`, so it must
        // charge that entry itself; otherwise `package()` could succeed while
        // `encode`/`decode` at the same ceiling refuse the same package
        // (R-12 round 11, F3).
        let entry = input_event(op);
        self.decoded = self.decoded.saturating_add(trace_decoded_bytes(&entry));
        if self.decoded > self.decode_ceiling {
            self.poisoned = true;
            return Err(Error::Replay(
                "the session expands beyond the decode ceiling".into(),
            ));
        }
        let event = input_event(op);
        // The operation's own bytes plus its input entry: the same sum
        // `reserve_op` predicted, and `encode` writes exactly this.
        let addition = op_len(op)
            .unwrap_or(usize::MAX)
            .saturating_add(trace_len(&event).unwrap_or(usize::MAX));
        self.body = self.body.saturating_add(addition);
        self.trace.push(Trace { event, cap: None });
        if self.trace.len() > MAX_TRACES {
            self.poisoned = true;
            return Err(Error::Replay("the trace exceeds the ceiling".into()));
        }
        Ok(())
    }

    /// Capture after the kernel already acted.
    ///
    /// A refused capture means the trace lost events, so `package()` refuses;
    /// the operation itself succeeded or failed for its own reasons and its
    /// answer must not be replaced by `rpc/replay`, which would make a caller
    /// believe a revocation did not happen.
    fn capture_acted(&mut self) {
        let _ = self.capture();
    }

    fn capture(&mut self) -> Result<()> {
        let before = self.trace.len();
        let result = capture(
            &self.agent,
            &mut self.seen_total,
            &mut self.trace,
            &mut self.ordinals,
            &mut self.body,
        );
        // Every entry this capture appended is decoded heap a reader will
        // build (R-12 round 9, F2).
        for entry in &self.trace[before..] {
            self.decoded = self
                .decoded
                .saturating_add(trace_decoded_bytes(&entry.event));
        }
        if result.is_ok() && self.decoded > self.decode_ceiling {
            self.poisoned = true;
            return Err(Error::Replay(
                "the session expands beyond the decode ceiling".into(),
            ));
        }
        if result.is_err() {
            self.poisoned = true;
        }
        // The trace is bounded by the decoder too; a session that outgrows it
        // must fail here rather than at read-back.
        if result.is_ok() && self.trace.len() > MAX_TRACES {
            self.poisoned = true;
            return Err(Error::Replay("the trace exceeds the ceiling".into()));
        }
        result
    }

    /// Mint a capability and return its ordinal.
    ///
    /// The attempt is recorded even when the kernel refuses it: a refusal that
    /// emits an event must be reproducible by replay, and a refused mint is a
    /// legitimate input.
    pub fn mint(&mut self, methods: &[&str], ttl_ms: Option<u64>) -> Result<u32> {
        Self::check_methods(methods)?;
        let attrs = attrs_for(
            &methods
                .iter()
                .map(|method| method.to_string())
                .collect::<Vec<_>>(),
            ttl_ms,
        );
        let op = Op::Mint {
            methods: methods.iter().map(|method| method.to_string()).collect(),
            ttl_ms,
        };
        self.reserve_op(&op)?;
        if self.record_ops {
            self.ops.push(op.clone());
        }
        self.note(&op)?;
        let cap = match self.agent.mint(self.provider, 0, attrs) {
            Ok(cap) => cap,
            Err(error) => {
                // A refusal emits events (`cap.expired`, retention churn); they
                // belong to the recorded session even though the op failed.
                self.capture_acted();
                return Err(error);
            }
        };
        let ordinal = self.caps.len() as u32;
        self.caps.push(cap);
        self.capture_acted();
        Ok(ordinal)
    }

    /// Attenuate a capability and return the child ordinal.
    ///
    /// The parent is cloned and the attempt is recorded *before* the kernel
    /// decides. A refused attenuation still retains and releases the parent
    /// handle, so those events are part of the trace; recording the attempt is
    /// what lets replay reproduce them. An ordinal that does not exist is a
    /// recorder bug, not a decision, and is refused before anything is
    /// recorded.
    pub fn attenuate(&mut self, parent: u32, methods: &[&str], ttl_ms: Option<u64>) -> Result<u32> {
        Self::check_methods(methods)?;
        // The ordinal is checked before anything is recorded (a missing one is
        // a recorder bug), but the handle is cloned only after the fallible
        // recording steps. A clone made first and dropped by an early return
        // leaves its retain/release events for the next operation's capture,
        // and no recorded op produces them, so the package fails its own
        // replay (R-12 round 7, F1).
        if self.caps.get(parent as usize).is_none() {
            return Err(Error::Replay(format!(
                "capability ordinal {parent} does not exist"
            )));
        }
        let attrs = attrs_for(
            &methods
                .iter()
                .map(|method| method.to_string())
                .collect::<Vec<_>>(),
            ttl_ms,
        );
        let op = Op::Attenuate {
            parent,
            methods: methods.iter().map(|method| method.to_string()).collect(),
            ttl_ms,
        };
        self.reserve_op(&op)?;
        if self.record_ops {
            self.ops.push(op.clone());
        }
        self.note(&op)?;
        // Nothing below can fail before the handle is dropped, so its
        // retain/release events are captured with this operation.
        let handle = self.caps[parent as usize].clone();
        let outcome = self.agent.attenuate(&handle, attrs);
        // The borrowed handle's `cap.released` is a decision of this operation:
        // drop it before the capture that closes the operation, or the trace
        // ends on an unmatched retain.
        drop(handle);
        match outcome {
            Ok(child) => {
                let ordinal = self.caps.len() as u32;
                self.caps.push(child);
                self.capture_acted();
                Ok(ordinal)
            }
            Err(error) => {
                self.capture_acted();
                Err(error)
            }
        }
    }

    /// Issue a call. Refusals are recorded in the trace, not returned.
    pub fn call(&mut self, cap: u32, method: &str, arg_bytes: usize) -> Result<()> {
        let arg_bytes = u64::try_from(arg_bytes)
            .map_err(|_| Error::Replay("argument size exceeds the ceiling".into()))?;
        // Both ceilings are the decoder's: a package that cannot be read back
        // is not a package. The check also keeps a caller-chosen size away from
        // `String::repeat`, which would otherwise abort on allocation failure.
        if arg_bytes > MAX_ARG_BYTES {
            return Err(Error::Replay("argument size exceeds the ceiling".into()));
        }
        let arg_total = self.arg_total.saturating_add(arg_bytes);
        if arg_total > MAX_ARG_TOTAL_BYTES {
            return Err(Error::Replay(
                "declared argument sizes exceed the package ceiling".into(),
            ));
        }
        // `encode` refuses a string over `MAX_STRING`; a method the package
        // cannot carry must be refused here, not at read-back.
        if method.len() > MAX_STRING {
            return Err(Error::Replay("string exceeds the ceiling".into()));
        }
        if self.caps.get(cap as usize).is_none() {
            return Err(Error::Replay(format!(
                "capability ordinal {cap} does not exist"
            )));
        }
        let op = Op::Call {
            cap,
            method: method.to_string(),
            arg_bytes,
        };
        self.reserve_op(&op)?;
        if self.record_ops {
            self.ops.push(op.clone());
        }
        self.note(&op)?;
        self.arg_total = arg_total;
        // Cloned after the fallible steps, so a refusal above cannot leave a
        // retain/release pair for the next operation (R-12 round 7, F1).
        let handle = self.caps[cap as usize].clone();
        let args = if arg_bytes == 0 {
            Vec::new()
        } else {
            vec![Arg::text("x".repeat(arg_bytes as usize))]
        };
        let outcome = self.agent.call(self.lane, &handle, method, args);
        drop(handle);
        if let Ok(promise) = outcome {
            self.agent.run();
            let _ = promise.value();
        } else {
            self.agent.run();
        }
        self.capture_acted();
        Ok(())
    }

    /// Revoke a capability.
    pub fn revoke(&mut self, cap: u32) -> Result<()> {
        if self.caps.get(cap as usize).is_none() {
            return Err(Error::Replay(format!(
                "capability ordinal {cap} does not exist"
            )));
        }
        let op = Op::Revoke { cap };
        self.reserve_op(&op)?;
        if self.record_ops {
            self.ops.push(op.clone());
        }
        self.note(&op)?;
        // Cloned after the fallible steps (R-12 round 7, F1).
        let handle = self.caps[cap as usize].clone();
        let outcome = self.agent.revoke(&handle);
        drop(handle);
        // A refused revoke still produced a decision, and a successful one must
        // be reported as a success even when the capture that follows lost
        // events: `package()` is where that loss is refused.
        self.capture_acted();
        outcome
    }

    /// The recorded package.
    ///
    /// A recorder that lost events refuses: the op list and the trace no longer
    /// line up, so the artifact could not replay.
    pub fn package(&self) -> Result<ReplayPackage> {
        if !self.record_ops {
            return Err(Error::Replay(
                "a replay recorder has no op list to package".into(),
            ));
        }
        if self.poisoned {
            return Err(Error::Replay(
                "the recorder lost events; the session cannot be packaged".into(),
            ));
        }
        if self.body.saturating_add(32) > MAX_PACKAGE_BYTES {
            return Err(Error::Replay("package exceeds the size ceiling".into()));
        }
        if self.decoded > self.decode_ceiling {
            return Err(Error::Replay(
                "the package expands beyond the decode ceiling".into(),
            ));
        }
        Ok(ReplayPackage {
            // The header is the initial rate; each `SetLatency` op moves it from
            // there, so replay starts where the recording did.
            latency_ms: self.initial_latency_ms,
            ops: self.ops.clone(),
            trace: self.trace.clone(),
        })
    }
}

fn attrs_for(methods: &[String], ttl_ms: Option<u64>) -> CapAttrs {
    let refs: Vec<&str> = methods.iter().map(String::as_str).collect();
    let attrs = CapAttrs::new(&refs);
    match ttl_ms {
        Some(ttl) => attrs.with_ttl_ms(ttl),
        None => attrs,
    }
}

/// Append the events the tape gained since `seen_total`.
///
/// The kernel tape is bounded (`MAX_EVENTS`). If it wrapped between two
/// captures, events the session produced were evicted before they could be
/// recorded, and a package built from what is left would not replay. That is
/// a refusal (`rpc/replay`), not a silently truncated trace.
fn capture(
    agent: &Agent,
    seen_total: &mut u64,
    trace: &mut Vec<Trace>,
    ordinals: &mut BTreeMap<CapId, u32>,
    body: &mut usize,
) -> Result<()> {
    let Some(events) = agent.events_since(*seen_total) else {
        return Err(Error::Replay(
            "the event tape wrapped; the session is too long to record".into(),
        ));
    };
    for event in &events {
        let entry = trace_of(event, ordinals);
        // The event entries are part of the encoded body, so they are charged
        // here, not only at `encode` (round 4, M-1). An entry is its flag and
        // length (`trace_len`), plus the four-byte ordinal only when it names a
        // capability: the recorder charged four phantom bytes for every
        // cap-less entry, so a large session could refuse a package that fits
        // (R-12 round 6, L1).
        let addition =
            trace_len(&entry.event)?.saturating_add(if entry.cap.is_some() { 4 } else { 0 });
        let next = body.saturating_add(addition);
        if next > MAX_PACKAGE_BYTES - 32 {
            return Err(Error::Replay("package exceeds the size ceiling".into()));
        }
        *body = next;
        trace.push(entry);
    }
    *seen_total = agent.total_events();
    Ok(())
}

fn trace_of(event: &Event, ordinals: &mut BTreeMap<CapId, u32>) -> Trace {
    let mut ordinal = |cap: CapId| {
        let next = ordinals.len() as u32;
        Some(*ordinals.entry(cap).or_insert(next))
    };
    match event {
        Event::CapMinted { cap, .. } => Trace {
            event: "cap.minted".into(),
            cap: ordinal(*cap),
        },
        Event::CapRetained(cap) => Trace {
            event: "cap.retained".into(),
            cap: ordinal(*cap),
        },
        Event::CapReleased(cap) => Trace {
            event: "cap.released".into(),
            cap: ordinal(*cap),
        },
        Event::CapDropped(cap) => Trace {
            event: "cap.dropped".into(),
            cap: ordinal(*cap),
        },
        Event::CapRevoked(cap) => Trace {
            event: "cap.revoked".into(),
            cap: ordinal(*cap),
        },
        Event::CapExpired(cap) => Trace {
            event: "cap.expired".into(),
            cap: ordinal(*cap),
        },
        Event::CapExported(cap) => Trace {
            event: "cap.exported".into(),
            cap: ordinal(*cap),
        },
        Event::CapRestored(cap) => Trace {
            event: "cap.restored".into(),
            cap: ordinal(*cap),
        },
        Event::CapRecordOrphaned(cap) => Trace {
            event: "cap.record-orphaned".into(),
            cap: ordinal(*cap),
        },
        Event::CapRebound { cap, .. } => Trace {
            event: "cap.rebound".into(),
            cap: ordinal(*cap),
        },
        Event::RotationCarried {
            cap,
            jobs,
            promises,
            claims,
        } => Trace {
            // The counts are the fact: a package that moved three answers must
            // not compare equal to one that moved none.
            event: format!("cap.rotation-carried:{jobs}/{promises}/{claims}"),
            cap: ordinal(*cap),
        },
        Event::CapIntroduced { cap, fingerprint } => Trace {
            // A 128-bit prefix of the peer's public fingerprint: two
            // introductions to different peers must not compare equal, and a
            // peer that chooses its own certificate must not be able to target
            // a collision. The raw identity is never recorded.
            event: format!("cap.introduced:{}", hex_prefix(fingerprint, 16)),
            cap: ordinal(*cap),
        },
        Event::ProviderPanicked { phase, .. } => Trace {
            // The phase distinguishes an invoke panic from an on_drop panic; the
            // provider id is kernel-local and is not part of the trace.
            event: format!("provider.panicked:{phase:?}"),
            cap: None,
        },
        Event::IntroSkipped { .. } => Trace {
            // Kernel-local bookkeeping: the reason names a surface, not a
            // capability, and a replay does not depend on it.
            event: "intro.skipped".into(),
            cap: None,
        },
        Event::LaneCreated(_) => Trace {
            event: "lane.created".into(),
            cap: None,
        },
        Event::LaneDestroyed { .. } => Trace {
            event: "lane.destroyed".into(),
            cap: None,
        },
        Event::CallQueued {
            cap,
            method,
            args_bytes,
            ..
        } => Trace {
            // The method and the charged size are what a queued call asked for;
            // without them a package could be edited from one granted method to
            // another and still compare equal.
            event: format!("call.queued:{method}:{args_bytes}"),
            cap: ordinal(*cap),
        },
        Event::BatchDispatched { .. } => Trace {
            event: "batch.dispatched".into(),
            cap: None,
        },
        Event::JobCompleted { .. } => Trace {
            event: "job.completed".into(),
            cap: None,
        },
        Event::PromiseResolved(_) => Trace {
            event: "promise.resolved".into(),
            cap: None,
        },
        Event::ReceiptsDropped { .. } => Trace {
            // Receipts are an audit side channel; their eviction does not change
            // a decision, so the trace keeps the fact and not the count.
            event: "receipts.dropped".into(),
            cap: None,
        },
        Event::PromiseRejected { code, .. } => Trace {
            event: format!("promise.rejected:{code}"),
            cap: None,
        },
        Event::ChannelSend { .. } => Trace {
            event: "channel.send".into(),
            cap: None,
        },
        Event::ChannelCreated(_) => Trace {
            event: "channel.created".into(),
            cap: None,
        },
        Event::ChannelSubscribed { .. } => Trace {
            event: "channel.subscribed".into(),
            cap: None,
        },
        Event::ChannelUnsubscribed { .. } => Trace {
            event: "channel.unsubscribed".into(),
            cap: None,
        },
        Event::ChannelClosed(_) => Trace {
            event: "channel.closed".into(),
            cap: None,
        },
        Event::ChannelDestroyed { .. } => Trace {
            event: "channel.destroyed".into(),
            cap: None,
        },
        Event::ChannelRecv { .. } => Trace {
            event: "channel.recv".into(),
            cap: None,
        },
        Event::CapTransferred { cap, .. } => Trace {
            event: "cap.transferred".into(),
            cap: ordinal(*cap),
        },
        Event::CallRefused { cap, code, .. } => Trace {
            event: format!("call.refused:{code}"),
            cap: cap.and_then(&mut ordinal),
        },
        Event::BudgetExhausted { cap, dimension } => Trace {
            event: format!("budget.exhausted:{dimension}"),
            cap: cap.and_then(&mut ordinal),
        },
        Event::ToolRefused { cap, reason } => Trace {
            event: format!("tool.refused:{reason}"),
            cap: ordinal(*cap),
        },
    }
}

/// The input entry one operation contributes to the trace.
///
/// Every field the kernel's events do not name appears here, digested: the grant
/// and TTL of a mint, the parent of an attenuation, the method and size of a
/// call (admitted or refused), the target of a revoke. 128-bit digests, like
/// every discriminator in this module.
fn input_event(op: &Op) -> String {
    match op {
        Op::SetLatency(ms) => format!("op.latency:{ms}"),
        Op::Mint { methods, ttl_ms } => {
            format!("op.mint:{}:{}", digest_of(methods), ttl_label(*ttl_ms))
        }
        Op::Attenuate {
            parent,
            methods,
            ttl_ms,
        } => format!(
            "op.attenuate:{parent}:{}:{}",
            digest_of(methods),
            ttl_label(*ttl_ms)
        ),
        Op::Call {
            cap,
            method,
            arg_bytes,
        } => format!(
            "op.call:{cap}:{}:{arg_bytes}",
            digest_of_text(b"active-rpc/replay/op-call/v1\0", method)
        ),
        Op::Revoke { cap } => format!("op.revoke:{cap}"),
    }
}

/// The encoded size of one operation, in bytes.
///
/// `encode` writes the fields directly; this is its accounting, and
/// `the_size_estimate_matches_the_encoder` holds the two together.
fn op_len(op: &Op) -> Result<usize> {
    let attrs = |methods: &[String], ttl_ms: Option<u64>| -> Result<usize> {
        let mut len = 2usize;
        for method in methods {
            len = len
                .checked_add(2)
                .and_then(|len| len.checked_add(method.len()))
                .ok_or_else(|| Error::Replay("the package size overflows".into()))?;
        }
        Ok(len + 1 + if ttl_ms.is_some() { 8 } else { 0 })
    };
    let len = match op {
        Op::SetLatency(_) => 1 + 8,
        Op::Mint { methods, ttl_ms } => 1 + attrs(methods, *ttl_ms)?,
        Op::Attenuate {
            methods, ttl_ms, ..
        } => 1 + 4 + attrs(methods, *ttl_ms)?,
        Op::Call {
            method, arg_bytes, ..
        } => {
            if *arg_bytes > MAX_ARG_BYTES {
                return Err(Error::Replay("argument size exceeds the ceiling".into()));
            }
            if method.len() > MAX_STRING {
                return Err(Error::Replay("string exceeds the ceiling".into()));
            }
            1 + 4 + 4 + method.len() + 8
        }
        Op::Revoke { .. } => 1 + 4,
    };
    Ok(len)
}

/// The encoded size of one trace entry, in bytes.
fn trace_len(event: &str) -> Result<usize> {
    if event.len() > MAX_STRING {
        return Err(Error::Replay("string exceeds the ceiling".into()));
    }
    1usize
        .checked_add(4)
        .and_then(|len| len.checked_add(event.len()))
        .ok_or_else(|| Error::Replay("the package size overflows".into()))
}

/// A 128-bit digest of a method set.
///
/// Length-prefixed so `["ab", "c"]` and `["a", "bc"]` differ, and hashed rather
/// than rendered because a method name is caller-chosen and can be megabytes.
fn digest_of(methods: &[String]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"active-rpc/replay/op-methods/v1\0");
    for method in methods {
        hasher.update(&(method.len() as u64).to_le_bytes());
        hasher.update(method.as_bytes());
    }
    hex_prefix(hasher.finalize().as_bytes(), 16)
}

/// A 128-bit, domain-separated digest of one text value.
fn digest_of_text(domain: &[u8], text: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&(text.len() as u64).to_le_bytes());
    hasher.update(text.as_bytes());
    hex_prefix(hasher.finalize().as_bytes(), 16)
}

fn ttl_label(ttl_ms: Option<u64>) -> String {
    match ttl_ms {
        Some(ttl) => format!("ttl={ttl}"),
        None => "ttl=-".to_string(),
    }
}

fn hex_prefix(bytes: &[u8; 32], len: usize) -> String {
    let mut out = String::with_capacity(len * 2);
    for byte in &bytes[..len.min(32)] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The demo provider used by recording and replay: deterministic and free of
/// arguments, so the trace depends only on the recorded operations.
struct Demo;

impl Provider for Demo {
    fn name(&self) -> &'static str {
        "demo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "sum".to_string(), "slow".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Refuse a body that the decoder's whole-package ceiling would reject.
///
/// The check runs as the body grows, not at the end: a session that would build
/// 77 MiB of package (300 mints of 64 four-kilobyte methods is a legal one) must
/// fail before the allocation, and the decoder refuses anything over the same
/// ceiling.
fn check_body(out: &[u8]) -> Result<()> {
    // The checksum is 32 bytes and is appended after the body.
    if out.len() > MAX_PACKAGE_BYTES - 32 {
        return Err(Error::Replay("package exceeds the size ceiling".into()));
    }
    Ok(())
}

fn write_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.len() > MAX_STRING {
        return Err(Error::Replay("string exceeds the ceiling".into()));
    }
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len())
        .map_err(|_| Error::Replay("a string is too long for a package".into()))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_attrs(out: &mut Vec<u8>, methods: &[String], ttl_ms: Option<u64>) -> Result<()> {
    if methods.len() > MAX_METHODS {
        return Err(Error::Replay("too many methods for a package".into()));
    }
    let count = u16::try_from(methods.len())
        .map_err(|_| Error::Replay("too many methods for a package".into()))?;
    out.extend_from_slice(&count.to_le_bytes());
    for method in methods {
        let bytes = method.as_bytes();
        let length = u16::try_from(bytes.len())
            .map_err(|_| Error::Replay("a method name is too long for a package".into()))?;
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(bytes);
    }
    match ttl_ms {
        Some(ttl) => {
            out.push(1);
            out.extend_from_slice(&ttl.to_le_bytes());
        }
        None => out.push(0),
    }
    Ok(())
}

fn read_attrs(reader: &mut Reader<'_>) -> Result<(Vec<String>, Option<u64>)> {
    let count = reader.u16()? as usize;
    if count > MAX_METHODS {
        return Err(Error::Replay("too many methods".into()));
    }
    let mut methods = Vec::with_capacity(count);
    for _ in 0..count {
        methods.push(reader.short_string()?);
    }
    let ttl = match reader.u8()? {
        0 => None,
        1 => Some(reader.u64()?),
        _ => return Err(Error::Replay("unknown TTL flag".into())),
    };
    Ok((methods, ttl))
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(count)
            .ok_or_else(|| Error::Replay("length overflow".into()))?;
        if end > self.bytes.len() {
            return Err(Error::Replay("package is truncated".into()));
        }
        let slice = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    }

    fn string(&mut self) -> Result<String> {
        let length = self.u32()? as usize;
        if length > MAX_STRING {
            return Err(Error::Replay("string exceeds the ceiling".into()));
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Replay("string is not UTF-8".into()))
    }

    fn short_string(&mut self) -> Result<String> {
        let length = self.u16()? as usize;
        if length > MAX_STRING {
            return Err(Error::Replay("string exceeds the ceiling".into()));
        }
        let bytes = self.take(length)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::Replay("string is not UTF-8".into()))
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trace keeps a 128-bit prefix of an introduced peer's fingerprint. A
    /// host chooses its certificate, so a 32-bit prefix was a target, not a
    /// discriminator; two fingerprints that differ only past the old prefix must
    /// produce different entries.
    #[test]
    fn two_introductions_are_distinct_in_the_trace() {
        let first = [0x11u8; 32];
        let mut second = first;
        second[15] ^= 0x01;
        let mut ordinals = BTreeMap::new();
        let left = trace_of(
            &Event::CapIntroduced {
                cap: CapId([1u8; 16]),
                fingerprint: first,
            },
            &mut ordinals,
        );
        let right = trace_of(
            &Event::CapIntroduced {
                cap: CapId([1u8; 16]),
                fingerprint: second,
            },
            &mut ordinals,
        );
        assert_ne!(left.event, right.event, "{left:?} and {right:?}");
        assert!(left.event.starts_with("cap.introduced:"));
        // 32 hex characters, plus the prefix and the colon.
        assert_eq!(left.event.len(), "cap.introduced:".len() + 32);
    }
}

#[cfg(test)]
mod decode_ceiling_tests {
    use super::*;

    /// The decoded heap a package describes is bounded, not only its bytes:
    /// the test drives the real parser with a tiny ceiling, so a package that
    /// expands past it is refused before the objects are built
    /// (R-12 round 6, L2).
    #[test]
    fn a_package_that_expands_past_the_ceiling_is_refused() {
        let mut recorder = Recorder::new(1).expect("recorder");
        let cap = recorder.mint(&["echo"], None).expect("mint");
        recorder.call(cap, "echo", 0).expect("call");
        let bytes = recorder
            .package()
            .expect("package")
            .encode()
            .expect("encode");
        // The shipped ceiling accepts a small package.
        ReplayPackage::decode(&bytes).expect("the package decodes");
        let error = ReplayPackage::decode_with_ceiling(&bytes, 1)
            .expect_err("a one-byte ceiling refuses it");
        assert_eq!(error.code(), "rpc/replay", "{error}");
        assert!(
            error.to_string().contains("decode ceiling"),
            "the refusal names the ceiling: {error}"
        );
    }
}

#[cfg(test)]
mod recorder_handle_tests {
    use super::*;

    /// A recording step that refuses before the kernel call must not clone the
    /// capability handle. The clone's retain and release events would be
    /// captured with the next operation, and no recorded op produces them, so
    /// the package would encode, decode and then fail its own replay
    /// (R-12 round 7, F1).
    #[test]
    fn a_refused_recording_step_does_not_leak_handle_events() {
        let mut recorder = Recorder::new(1).expect("recorder");
        let cap = recorder.mint(&["echo"], None).expect("mint");
        // Force the next recording step to fail at the package ceiling, which
        // is the only refusal between the handle lookup and the kernel call.
        recorder.body = MAX_PACKAGE_BYTES;
        let refused = recorder.attenuate(cap, &["echo"], None);
        assert!(refused.is_err(), "the ceiling must refuse the operation");
        // The same shape on the other two paths: a regression that cloned the
        // handle before the recording step would leak two events from either.
        assert!(
            recorder.call(cap, "echo", 0).is_err(),
            "the ceiling must refuse a call"
        );
        assert!(
            recorder.revoke(cap).is_err(),
            "the ceiling must refuse a revoke"
        );
        // The session stays usable, and its package must replay: that fails if
        // the refused step leaked two events into the next capture.
        recorder.body = 0;
        recorder
            .mint(&["echo"], None)
            .expect("the session continues after a refused step");
        let package = recorder.package().expect("package");
        let bytes = package.encode().expect("encode");
        ReplayPackage::decode(&bytes)
            .expect("decode")
            .replay()
            .expect("the recorded package replays");
    }
}

#[cfg(test)]
mod decode_ceiling_contract_tests {
    use super::*;

    impl Recorder {
        /// A recorder whose decoded-heap ceiling is small, so the ceiling
        /// contract can be driven through the real recording path.
        fn with_decode_ceiling(latency_ms: u64, decode_ceiling: usize) -> Result<Self> {
            let mut recorder = Self::new(latency_ms)?;
            recorder.decode_ceiling = decode_ceiling;
            Ok(recorder)
        }
    }

    /// The recorder refuses an operation that would take the session past the
    /// decoder's ceiling: a legal-looking session must not encode into an
    /// artifact this crate cannot read (R-12 round 9, F2).
    #[test]
    fn a_session_that_expands_past_the_decode_ceiling_is_refused() {
        let mut recorder = Recorder::with_decode_ceiling(1, 1).expect("recorder");
        let error = recorder
            .mint(&["echo"], None)
            .expect_err("the ceiling refuses");
        assert_eq!(error.code(), "rpc/replay", "{error}");
        assert!(
            error.to_string().contains("decode ceiling"),
            "the refusal names the ceiling: {error}"
        );
    }

    /// `encode` and `decode` charge the same objects: a package the decoder
    /// accepts always encodes, and an encoder ceiling refuses what the decoder
    /// would (R-12 round 9, F2).
    #[test]
    fn encode_refuses_what_decode_would_refuse() {
        let mut recorder = Recorder::new(1).expect("recorder");
        let cap = recorder.mint(&["echo"], None).expect("mint");
        recorder.call(cap, "echo", 0).expect("call");
        let package = recorder.package().expect("package");
        let bytes = package.encode().expect("encode under the shipped ceiling");
        ReplayPackage::decode(&bytes).expect("the shipped decoder accepts what encode wrote");
        let error = package
            .encode_with_ceiling(1)
            .expect_err("a one-byte ceiling refuses the package");
        assert_eq!(error.code(), "rpc/replay", "{error}");
        assert!(
            error.to_string().contains("decode ceiling"),
            "the refusal names the ceiling: {error}"
        );
    }

    /// The running body estimate is exact, not conservative: the comment on the
    /// phantom-byte fix cited a test that did not exist (R-12 round 6, F6).
    #[test]
    fn the_size_estimate_matches_the_encoder() {
        let mut recorder = Recorder::new(1).expect("recorder");
        let cap = recorder.mint(&["echo"], None).expect("mint");
        recorder.call(cap, "echo", 3).expect("call");
        recorder.attenuate(cap, &["echo"], None).expect("attenuate");
        recorder.revoke(cap).expect("revoke");
        let package = recorder.package().expect("package");
        let bytes = package.encode().expect("encode");
        assert_eq!(
            recorder.body + 32,
            bytes.len(),
            "the running estimate ({}) plus the checksum must equal the encoded length ({})",
            recorder.body,
            bytes.len()
        );
    }
}
