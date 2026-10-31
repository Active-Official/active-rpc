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

/// Largest package the decoder accepts, in bytes.
///
/// The per-field ceilings (operation count, trace count, string length) do not
/// bound the body: a package can be arbitrarily large while every field is
/// legal. The whole body is held in memory and hashed before decoding, so the
/// total needs its own ceiling.
pub const MAX_PACKAGE_BYTES: usize = 64 << 20;

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
        /// Argument wire-size bytes (values are never recorded).
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
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&self.latency_ms.to_le_bytes());
        out.extend_from_slice(&(self.ops.len() as u32).to_le_bytes());
        for op in &self.ops {
            match op {
                Op::SetLatency(ms) => {
                    out.push(1);
                    out.extend_from_slice(&ms.to_le_bytes());
                }
                Op::Mint { methods, ttl_ms } => {
                    out.push(2);
                    write_attrs(&mut out, methods, *ttl_ms);
                }
                Op::Attenuate {
                    parent,
                    methods,
                    ttl_ms,
                } => {
                    out.push(3);
                    out.extend_from_slice(&parent.to_le_bytes());
                    write_attrs(&mut out, methods, *ttl_ms);
                }
                Op::Call {
                    cap,
                    method,
                    arg_bytes,
                } => {
                    out.push(4);
                    out.extend_from_slice(&cap.to_le_bytes());
                    write_str(&mut out, method);
                    out.extend_from_slice(&arg_bytes.to_le_bytes());
                }
                Op::Revoke { cap } => {
                    out.push(5);
                    out.extend_from_slice(&cap.to_le_bytes());
                }
            }
        }
        out.extend_from_slice(&(self.trace.len() as u32).to_le_bytes());
        for trace in &self.trace {
            out.push(u8::from(trace.cap.is_some()));
            write_str(&mut out, &trace.event);
            if let Some(cap) = trace.cap {
                out.extend_from_slice(&cap.to_le_bytes());
            }
        }
        let checksum = blake3::hash(&out);
        out.extend_from_slice(checksum.as_bytes());
        out
    }

    /// Decode and verify a package.
    pub fn decode(bytes: &[u8]) -> Result<ReplayPackage> {
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
            trace.push(Trace { event, cap });
        }
        if !reader.is_empty() {
            return Err(Error::Replay("trailing bytes after the package".into()));
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
    pub fn replay(&self) -> Result<()> {
        let trace = self.replay_trace()?;
        if self.trace.len() != trace.len() {
            return Err(Error::Replay(format!(
                "trace length differs: recorded {}, replayed {}",
                self.trace.len(),
                trace.len()
            )));
        }
        for (index, (expected, actual)) in self.trace.iter().zip(trace.iter()).enumerate() {
            if expected != actual {
                return Err(Error::Replay(format!(
                    "trace mismatch at entry {index}: recorded {expected:?}, replayed {actual:?}"
                )));
            }
        }
        Ok(())
    }

    /// Execute the package and return the trace the kernel produced.
    ///
    /// This is the diagnostic half of [`ReplayPackage::replay`]: it lets a
    /// caller inspect where a package diverges instead of only learning that it
    /// did.
    pub fn replay_trace(&self) -> Result<Vec<Trace>> {
        // Replay through the same recorder code path the original session used,
        // so handle lifetimes (retain/release events) are identical by
        // construction. The rebuilt operation list is discarded.
        let mut recorder = Recorder::new(self.latency_ms)?;
        for op in &self.ops {
            match op {
                Op::SetLatency(ms) => recorder.set_latency(*ms),
                Op::Mint { methods, ttl_ms } => {
                    ignore_refusal(recorder.mint(&method_refs(methods), *ttl_ms))?;
                }
                Op::Attenuate {
                    parent,
                    methods,
                    ttl_ms,
                } => {
                    ignore_refusal(recorder.attenuate(*parent, &method_refs(methods), *ttl_ms))?;
                }
                Op::Call {
                    cap,
                    method,
                    arg_bytes,
                } => {
                    ignore_refusal(recorder.call(*cap, method, *arg_bytes as usize))?;
                }
                Op::Revoke { cap } => {
                    ignore_refusal(recorder.revoke(*cap))?;
                }
            }
        }
        Ok(recorder.trace().to_vec())
    }
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
}

impl Recorder {
    /// Start a recorded session with the given simulated latency.
    pub fn new(latency_ms: u64) -> Result<Recorder> {
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
            ops: vec![Op::SetLatency(latency_ms)],
            trace: Vec::new(),
            seen_total: 0,
            latency_ms,
        };
        recorder.capture()?;
        Ok(recorder)
    }

    /// Simulated provider latency, in milliseconds per batch.
    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Change the simulated latency and record the change.
    pub fn set_latency(&mut self, latency_ms: u64) {
        self.latency_ms = latency_ms;
        self.agent.set_latency(latency_ms);
        self.ops.push(Op::SetLatency(latency_ms));
    }

    /// The decisions recorded so far.
    pub fn trace(&self) -> &[Trace] {
        &self.trace
    }

    /// Mint a capability and return its ordinal.
    ///
    /// The attempt is recorded even when the kernel refuses it: a refusal that
    /// emits an event must be reproducible by replay, and a refused mint is a
    /// legitimate input.
    pub fn mint(&mut self, methods: &[&str], ttl_ms: Option<u64>) -> Result<u32> {
        let attrs = attrs_for(
            &methods
                .iter()
                .map(|method| method.to_string())
                .collect::<Vec<_>>(),
            ttl_ms,
        );
        self.ops.push(Op::Mint {
            methods: methods.iter().map(|method| method.to_string()).collect(),
            ttl_ms,
        });
        let cap = self.agent.mint(self.provider, 0, attrs)?;
        let ordinal = self.caps.len() as u32;
        self.caps.push(cap);
        self.capture()?;
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
        let handle =
            self.caps.get(parent as usize).cloned().ok_or_else(|| {
                Error::Replay(format!("capability ordinal {parent} does not exist"))
            })?;
        let attrs = attrs_for(
            &methods
                .iter()
                .map(|method| method.to_string())
                .collect::<Vec<_>>(),
            ttl_ms,
        );
        self.ops.push(Op::Attenuate {
            parent,
            methods: methods.iter().map(|method| method.to_string()).collect(),
            ttl_ms,
        });
        let child = self.agent.attenuate(&handle, attrs)?;
        let ordinal = self.caps.len() as u32;
        self.caps.push(child);
        self.capture()?;
        Ok(ordinal)
    }

    /// Issue a call. Refusals are recorded in the trace, not returned.
    pub fn call(&mut self, cap: u32, method: &str, arg_bytes: usize) -> Result<()> {
        let handle = self
            .caps
            .get(cap as usize)
            .cloned()
            .ok_or_else(|| Error::Replay(format!("capability ordinal {cap} does not exist")))?;
        self.ops.push(Op::Call {
            cap,
            method: method.to_string(),
            arg_bytes: arg_bytes as u64,
        });
        let args = if arg_bytes == 0 {
            Vec::new()
        } else {
            vec![Arg::text("x".repeat(arg_bytes))]
        };
        if let Ok(promise) = self.agent.call(self.lane, &handle, method, args) {
            self.agent.run();
            let _ = promise.value();
        } else {
            self.agent.run();
        }
        self.capture()?;
        Ok(())
    }

    /// Revoke a capability.
    pub fn revoke(&mut self, cap: u32) -> Result<()> {
        let handle = self
            .caps
            .get(cap as usize)
            .cloned()
            .ok_or_else(|| Error::Replay(format!("capability ordinal {cap} does not exist")))?;
        self.agent.revoke(&handle);
        self.ops.push(Op::Revoke { cap });
        self.capture()?;
        Ok(())
    }

    /// The recorded package.
    pub fn package(&self) -> ReplayPackage {
        ReplayPackage {
            latency_ms: self.latency_ms,
            ops: self.ops.clone(),
            trace: self.trace.clone(),
        }
    }

    fn capture(&mut self) -> Result<()> {
        capture(
            &self.agent,
            &mut self.seen_total,
            &mut self.trace,
            &mut self.ordinals,
        )
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
) -> Result<()> {
    let events = agent.events();
    let total = agent.total_events();
    let retained = events.len() as u64;
    let missed = total.saturating_sub(*seen_total);
    if missed > retained {
        return Err(Error::Replay(
            "the event tape wrapped; the session is too long to record".into(),
        ));
    }
    let skip = (retained - missed) as usize;
    for event in &events[skip..] {
        trace.push(trace_of(event, ordinals));
    }
    *seen_total = total;
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
        Event::CapIntroduced { cap, .. } => Trace {
            event: "cap.introduced".into(),
            cap: ordinal(*cap),
        },
        Event::LaneCreated(_) => Trace {
            event: "lane.created".into(),
            cap: None,
        },
        Event::LaneDestroyed(_) => Trace {
            event: "lane.destroyed".into(),
            cap: None,
        },
        Event::CallQueued { cap, .. } => Trace {
            event: "call.queued".into(),
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
        Event::PromiseRejected { code, .. } => Trace {
            event: format!("promise.rejected:{code}"),
            cap: None,
        },
        Event::ChannelSend { .. } => Trace {
            event: "channel.send".into(),
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
            cap: ordinal(*cap),
        },
        Event::BudgetExhausted { cap, dimension } => Trace {
            event: format!("budget.exhausted:{dimension}"),
            cap: ordinal(*cap),
        },
        Event::ToolRefused { cap, reason } => Trace {
            event: format!("tool.refused:{reason}"),
            cap: ordinal(*cap),
        },
    }
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

fn write_str(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn write_attrs(out: &mut Vec<u8>, methods: &[String], ttl_ms: Option<u64>) {
    out.extend_from_slice(&(methods.len() as u16).to_le_bytes());
    for method in methods {
        let bytes = method.as_bytes();
        out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(bytes);
    }
    match ttl_ms {
        Some(ttl) => {
            out.push(1);
            out.extend_from_slice(&ttl.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn read_attrs(reader: &mut Reader<'_>) -> Result<(Vec<String>, Option<u64>)> {
    let count = reader.u16()? as usize;
    if count > 64 {
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
