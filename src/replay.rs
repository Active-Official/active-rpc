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
    ///
    /// Fails when the package cannot be represented: the counts are `u32` and
    /// each method length is `u16`, so a session that outgrew a ceiling is
    /// refused here instead of silently truncated into a package that re-frames
    /// its own op stream.
    pub fn encode(&self) -> Result<Vec<u8>> {
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
        }
        out.extend_from_slice(&(self.trace.len() as u32).to_le_bytes());
        for trace in &self.trace {
            out.push(u8::from(trace.cap.is_some()));
            write_str(&mut out, &trace.event)?;
            if let Some(cap) = trace.cap {
                out.extend_from_slice(&cap.to_le_bytes());
            }
        }
        let checksum = blake3::hash(&out);
        out.extend_from_slice(checksum.as_bytes());
        Ok(out)
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
    /// first differing entry. The rebuilt operation list is compared too, which
    /// is what catches an edit to a call's method or argument size: those fields
    /// are recorded but no kernel event names them.
    pub fn replay(&self) -> Result<()> {
        // The header latency is the *initial* rate; the recording always emits
        // it as the first operation, and a package that does not is using the
        // field for something else.
        if self.ops.first() != Some(&Op::SetLatency(self.latency_ms)) {
            return Err(Error::Replay(
                "the package does not begin with its header latency".into(),
            ));
        }
        let (trace, rebuilt) = self.replay_trace()?;
        if rebuilt.len() != self.ops.len() || rebuilt[1..] != self.ops[1..] {
            return Err(Error::Replay(
                "the recorded operations do not match the replayed ones".into(),
            ));
        }
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
                    "trace mismatch at entry {index}: recorded {}, replayed {}",
                    summary(&expected.event),
                    summary(&actual.event)
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
    /// did.
    pub fn replay_trace(&self) -> Result<(Vec<Trace>, Vec<Op>)> {
        // Replay through the same recorder code path the original session used,
        // so handle lifetimes (retain/release events) are identical by
        // construction.
        let mut recorder = Recorder::new(self.latency_ms)?;
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
                    ignore_refusal(recorder.call(*cap, method, *arg_bytes as usize))?;
                    Ok(())
                }
                Op::Revoke { cap } => {
                    ignore_refusal(recorder.revoke(*cap))?;
                    Ok(())
                }
            }?;
        }
        let package = recorder.package()?;
        Ok((recorder.trace().to_vec(), package.ops))
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
            initial_latency_ms: latency_ms,
            poisoned: false,
        };
        recorder.capture()?;
        Ok(recorder)
    }

    /// Simulated provider latency, in milliseconds per batch.
    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Change the simulated latency and record the change.
    pub fn set_latency(&mut self, latency_ms: u64) -> Result<()> {
        self.reserve_op()?;
        self.latency_ms = latency_ms;
        self.agent.set_latency(latency_ms);
        self.ops.push(Op::SetLatency(latency_ms));
        Ok(())
    }

    /// The decisions recorded so far.
    pub fn trace(&self) -> &[Trace] {
        &self.trace
    }

    /// Refuse a session that would produce a package its own decoder rejects.
    fn reserve_op(&mut self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Replay(
                "the recorder lost events; the session cannot be packaged".into(),
            ));
        }
        if self.ops.len() >= MAX_OPS {
            self.poisoned = true;
            return Err(Error::Replay(
                "the session exceeds the operation ceiling".into(),
            ));
        }
        Ok(())
    }

    /// Refuse a method set the package format cannot encode.
    ///
    /// The wire stores a method count and each length as `u16`; recording
    /// something larger would make `encode` truncate a length and re-frame the
    /// rest of the package, so the limit is enforced here, at the only place a
    /// caller can reach it.
    fn check_methods(methods: &[&str]) -> Result<()> {
        if methods.len() > u16::MAX as usize {
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

    fn capture(&mut self) -> Result<()> {
        let result = capture(
            &self.agent,
            &mut self.seen_total,
            &mut self.trace,
            &mut self.ordinals,
        );
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
        self.reserve_op()?;
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
        let cap = match self.agent.mint(self.provider, 0, attrs) {
            Ok(cap) => cap,
            Err(error) => {
                // A refusal emits events (`cap.expired`, retention churn); they
                // belong to the recorded session even though the op failed.
                self.capture()?;
                return Err(error);
            }
        };
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
        Self::check_methods(methods)?;
        self.reserve_op()?;
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
        let child = match self.agent.attenuate(&handle, attrs) {
            Ok(child) => child,
            Err(error) => {
                // The refusal churns the parent handle (retain/release) and may
                // emit `cap.expired`; capture before returning so the trace
                // still describes what the kernel decided.
                self.capture()?;
                return Err(error);
            }
        };
        let ordinal = self.caps.len() as u32;
        self.caps.push(child);
        self.capture()?;
        Ok(ordinal)
    }

    /// Issue a call. Refusals are recorded in the trace, not returned.
    pub fn call(&mut self, cap: u32, method: &str, arg_bytes: usize) -> Result<()> {
        self.reserve_op()?;
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
        self.reserve_op()?;
        let handle = self
            .caps
            .get(cap as usize)
            .cloned()
            .ok_or_else(|| Error::Replay(format!("capability ordinal {cap} does not exist")))?;
        self.ops.push(Op::Revoke { cap });
        if let Err(error) = self.agent.revoke(&handle) {
            // A refused revoke still produced a decision.
            self.capture()?;
            return Err(error);
        }
        self.capture()?;
        Ok(())
    }

    /// The recorded package.
    ///
    /// A recorder that lost events refuses: the op list and the trace no longer
    /// line up, so the artifact could not replay.
    pub fn package(&self) -> Result<ReplayPackage> {
        if self.poisoned {
            return Err(Error::Replay(
                "the recorder lost events; the session cannot be packaged".into(),
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
) -> Result<()> {
    let Some(events) = agent.events_since(*seen_total) else {
        return Err(Error::Replay(
            "the event tape wrapped; the session is too long to record".into(),
        ));
    };
    for event in &events {
        trace.push(trace_of(event, ordinals));
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
        Event::CapIntroduced { cap, fingerprint } => Trace {
            // A short prefix of the peer's public fingerprint: two introductions
            // to different peers must not compare equal, and the raw identity is
            // never recorded.
            event: format!("cap.introduced:{}", hex_prefix(fingerprint, 4)),
            cap: ordinal(*cap),
        },
        Event::ProviderPanicked { phase, .. } => Trace {
            // The phase distinguishes an invoke panic from an on_drop panic; the
            // provider id is kernel-local and is not part of the trace.
            event: format!("provider.panicked:{phase:?}"),
            cap: None,
        },
        Event::LaneCreated(_) => Trace {
            event: "lane.created".into(),
            cap: None,
        },
        Event::LaneDestroyed(_) => Trace {
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

fn write_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len())
        .map_err(|_| Error::Replay("a string is too long for a package".into()))?;
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_attrs(out: &mut Vec<u8>, methods: &[String], ttl_ms: Option<u64>) -> Result<()> {
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
