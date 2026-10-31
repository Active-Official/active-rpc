//! The kernel: one agent's capability table, promise graph, lanes, channels and
//! dispatch loop.
//!
//! The kernel is a deterministic state machine. Nothing here does I/O, timing or
//! threading: providers are ordinary objects, the clock is a counter, and the
//! dispatch loop is driven by [`Agent::run`]. That makes capability semantics,
//! attenuation and pipelining observable and reproducible in tests — and it
//! means a transport is a thin adapter over the same machine (ADR-0002 in this
//! crate).
//!
//! # Dispatch and round-trips
//!
//! A *batch* is every queued job for one provider, ordered so that a job whose
//! promise dependencies are produced in the same batch runs after its producer.
//! One batch is one provider round-trip. A client that waits for each result and
//! then issues the next call produces one batch per call; a client that passes
//! promises as arguments produces one batch for the whole chain. That difference
//! is what the pipelining tests measure.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use crate::budget::{Budget, BudgetMeter};
use crate::cap::{CapAttrs, CapControl, CapHandle, CapId, CapRecord, ProviderId, ToolPolicy};
use crate::channel::{Channel, ChannelId, Direction, Message};
use crate::error::{Error, Result};
use crate::identity::{AdmittedIdentity, PeerIdentity, FINGERPRINT_LEN};
use crate::lane::{Lane, LaneId};
use crate::promise::{PromiseId, PromiseRecord, PromiseState};
use crate::value::{Arg, Call, Response, Value};

/// Global ceiling on lanes in one kernel.
///
/// Lane creation is a local operation, but a caller that can create lanes
/// without bound can exhaust memory. The ceiling is high enough for any real
/// agent and finite, so a hostile or buggy caller fails closed.
pub const MAX_LANES: usize = 4_096;

/// Global ceiling on channels in one kernel.
pub const MAX_CHANNELS: usize = 4_096;

/// Global ceiling on live promise and job records in one kernel.
///
/// The ceiling covers a kernel that keeps issuing calls on long-lived lanes and
/// is a backpressure valve, not a lifetime quota: after each drain the kernel
/// trims settled promise records to [`MAX_SETTLED_PROMISES`] and
/// [`MAX_SETTLED_BYTES`], and completed jobs are removed immediately.
pub const MAX_PROMISES: usize = 100_000;

/// Target number of settled promise records retained after a drain.
///
/// Retention is handle-pinned: a record with a live [`PromiseHandle`] is never
/// evicted, so a caller that holds handles for a large batch can read every
/// result. Only records with no live handle are candidates; pending records are
/// never evicted.
pub const MAX_SETTLED_PROMISES: usize = 1_024;

/// Target bytes of settled values retained per kernel after a drain.
///
/// Values can be large; this bounds the payload memory an *unreferenced*
/// completed call chain pins. Handle-pinned records are exempt because the
/// caller can still read them.
pub const MAX_SETTLED_BYTES: usize = 64 << 20;

/// Ceiling on the retained event log.
///
/// The log is diagnostic, not a durable audit trail. Keeping it finite means a
/// peer that issues calls forever cannot grow kernel memory without bound; the
/// oldest events are dropped first and [`Metrics`] keeps the totals.
pub const MAX_EVENTS: usize = 16_384;

/// A provider of capabilities: a module, a tool, a peer.
pub trait Provider {
    /// Stable adapter name.
    fn name(&self) -> &'static str;
    /// Methods this provider answers (introspection).
    fn methods(&self) -> Vec<String>;
    /// Whether this provider answers `method`.
    fn has_method(&self, method: &str) -> bool {
        self.methods().iter().any(|name| name == method)
    }
    /// Whether `method` mutates provider state (refused on read-only caps).
    fn mutating(&self, method: &str) -> bool;
    /// Invoke a method on `object`.
    fn invoke(&mut self, object: u64, call: &Call) -> Result<Response>;
    /// Called when the last capability referencing `object` is dropped.
    fn on_drop(&mut self, _object: u64, _cap: CapId) {}

    /// Drain provider-side drop notifications recorded by [`Provider::on_drop`].
    ///
    /// The kernel owns providers, so tests and operators read the notifications
    /// through [`Agent::take_drops`].
    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        Vec::new()
    }
}

/// Observable kernel events. Tests and operators assert on these.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A capability was minted.
    CapMinted {
        /// New capability.
        cap: CapId,
        /// Owning provider.
        provider: ProviderId,
    },
    /// A capability handle gained a reference.
    CapRetained(CapId),
    /// A capability handle dropped a reference.
    CapReleased(CapId),
    /// The last reference to a capability went away; the provider was notified.
    CapDropped(CapId),
    /// A capability was revoked.
    CapRevoked(CapId),
    /// A capability's lifetime elapsed; it is refused exactly like a revocation.
    CapExpired(CapId),
    /// A capability was introduced to an authenticated peer and bound to it.
    CapIntroduced {
        /// Introduced capability.
        cap: CapId,
        /// Peer fingerprint the capability is now bound to.
        fingerprint: [u8; FINGERPRINT_LEN],
    },
    /// A lane was created.
    LaneCreated(LaneId),
    /// A lane was destroyed.
    LaneDestroyed(LaneId),
    /// A call was queued.
    CallQueued {
        /// Job id.
        job: u64,
        /// Issuing lane.
        lane: LaneId,
        /// Target capability.
        cap: CapId,
    },
    /// A batch of jobs was dispatched to a provider (one round-trip).
    BatchDispatched {
        /// Provider.
        provider: ProviderId,
        /// Number of jobs in the batch.
        jobs: usize,
        /// Lanes represented in the batch.
        lanes: BTreeSet<u64>,
    },
    /// A job completed.
    JobCompleted {
        /// Job id.
        job: u64,
        /// Issuing lane.
        lane: LaneId,
    },
    /// A promise settled.
    PromiseResolved(PromiseId),
    /// A promise was rejected.
    PromiseRejected {
        /// Promise id.
        promise: PromiseId,
        /// Stable code.
        code: String,
    },
    /// A message was sent on a channel.
    ChannelSend {
        /// Channel.
        channel: ChannelId,
        /// Sequence number.
        sequence: u64,
    },
    /// A message was received from a channel.
    ChannelRecv {
        /// Channel.
        channel: ChannelId,
        /// Sequence number.
        sequence: u64,
    },
    /// A capability was transferred through a channel.
    CapTransferred {
        /// Capability.
        cap: CapId,
        /// Channel.
        channel: ChannelId,
    },
    /// A call was refused before the provider saw it.
    CallRefused {
        /// Issuing lane.
        lane: LaneId,
        /// Target capability.
        cap: CapId,
        /// Stable error code (`rpc/...`).
        code: String,
    },
    /// A budget ceiling refused work.
    BudgetExhausted {
        /// Capability whose budget (or lane ceiling) fired.
        cap: CapId,
        /// Dimension: `call`, `byte`, `lane call`, `promises`, ...
        dimension: String,
    },
    /// A tool policy refused work.
    ToolRefused {
        /// Capability whose policy fired.
        cap: CapId,
        /// Stable reason string; never contains argument values.
        reason: String,
    },
}

/// Point-in-time kernel counters for operators and metrics exporters.
///
/// Counters carry no capability ids, arguments or secret material: they are
/// safe to export by default. Per-capability detail stays in [`Event`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Metrics {
    /// Calls accepted into the queue.
    pub calls_queued: u64,
    /// Calls refused before dispatch.
    pub calls_refused: u64,
    /// Refusals caused by a budget ceiling.
    pub budget_exhaustions: u64,
    /// Refusals caused by tool policy.
    pub tool_refusals: u64,
    /// Capabilities revoked.
    pub revocations: u64,
    /// Promises resolved.
    pub promises_resolved: u64,
    /// Promises rejected.
    pub promises_rejected: u64,
    /// Provider round trips.
    pub round_trips: u64,
    /// Capability transfers through channels.
    pub transfers: u64,
    /// Settlements attempted on an already-settled promise.
    pub promises_double_settled: u64,
    /// Calls refused because the local queue ceiling was reached.
    pub backpressure_refusals: u64,
    /// Calls refused because the peer's identity did not match the capability.
    pub identity_refusals: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobState {
    Queued,
    Done,
}

#[derive(Debug, Clone)]
struct Job {
    #[allow(dead_code)]
    id: u64,
    lane: LaneId,
    cap: CapId,
    call: Call,
    deps: Vec<PromiseId>,
    promise: PromiseId,
    state: JobState,
}

/// The deterministic kernel: providers, capabilities, budgets and promises.
///
/// It performs no I/O of its own; transports hand it envelopes and take the
/// results back. Holding the kernel is the only way to reach a provider.
pub struct Kernel {
    secret: [u8; 32],
    providers: BTreeMap<ProviderId, Box<dyn Provider>>,
    caps: BTreeMap<CapId, CapRecord>,
    meters: BTreeMap<CapId, BudgetMeter>,
    promises: BTreeMap<PromiseId, PromiseRecord>,
    lanes: BTreeMap<LaneId, Lane>,
    channels: BTreeMap<ChannelId, Channel>,
    jobs: BTreeMap<u64, Job>,
    queue: VecDeque<u64>,
    events: VecDeque<Event>,
    /// Monotonic count of events ever appended, including evicted ones.
    events_total: u64,
    /// Settled promises in settlement order, with the retained value size.
    settled: VecDeque<(PromiseId, usize)>,
    settled_bytes: usize,
    metrics: Metrics,
    round_trips: u64,
    next_promise: u64,
    next_job: u64,
    next_lane: u64,
    next_channel: u64,
    next_serial: u64,
    next_provider: u64,
    queue_ceiling: usize,
    channel_ceiling: usize,
    idempotency: BTreeMap<(CapId, String, String), PromiseId>,
    allow_durable: bool,
    idempotency_order: VecDeque<(CapId, String, String)>,
    now_ms: u64,
    latency_ms: u64,
    transfers: u64,
    receipts: std::collections::VecDeque<crate::receipts::Receipt>,
    receipts_enabled: bool,
    next_receipt: u64,
}

/// Control half of a capability handle: reference counting and provider
/// notification. Keeping it separate from the kernel cell lets handles hold an
/// `Rc<dyn CapControl>` without exposing the kernel itself.
pub(crate) struct HandleControl {
    cell: KernelCell,
}

impl HandleControl {
    fn new(cell: KernelCell) -> Self {
        Self { cell }
    }
}

impl CapControl for HandleControl {
    fn retain(&self, id: CapId) {
        if let Ok(mut kernel) = self.cell.try_borrow_mut() {
            if let Some(record) = kernel.caps.get_mut(&id) {
                record.refs = record.refs.saturating_add(1);
                kernel.push_event(Event::CapRetained(id));
            }
        }
    }

    fn release(&self, id: CapId) {
        let dropped = {
            let Ok(mut kernel) = self.cell.try_borrow_mut() else {
                return;
            };
            let Some(record) = kernel.caps.get_mut(&id) else {
                return;
            };
            record.refs = record.refs.saturating_sub(1);
            let last = record.refs == 0;
            kernel.push_event(Event::CapReleased(id));
            last
        };
        if !dropped {
            return;
        }
        let mut kernel = self.cell.borrow_mut();
        let Some(record) = kernel.caps.remove(&id) else {
            return;
        };
        kernel.meters.remove(&id);
        kernel.push_event(Event::CapDropped(id));
        if let Some(provider) = kernel.providers.get_mut(&record.provider) {
            provider.on_drop(record.object, id);
        }
    }
}

/// Shared kernel cell.
pub type KernelCell = Rc<RefCell<Kernel>>;

/// One agent: an owner of lanes, channels, capabilities and promises.
#[derive(Clone)]
pub struct Agent {
    cell: KernelCell,
    control: Rc<dyn CapControl>,
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent {
    /// Create an agent kernel with an unpredictable capability secret.
    ///
    /// The secret comes from the operating system's CSPRNG. A clock-derived
    /// seed would make capability ids guessable to a peer that can estimate the
    /// start time, which defeats unforgeability.
    pub fn new() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("the operating system CSPRNG must be available");
        Self::with_secret(seed)
    }

    /// Create an agent with a fixed secret (tests, deterministic replays).
    pub fn with_secret(secret: [u8; 32]) -> Self {
        let kernel = Kernel {
            secret,
            providers: BTreeMap::new(),
            caps: BTreeMap::new(),
            meters: BTreeMap::new(),
            promises: BTreeMap::new(),
            lanes: BTreeMap::new(),
            channels: BTreeMap::new(),
            jobs: BTreeMap::new(),
            queue: VecDeque::new(),
            events: VecDeque::new(),
            events_total: 0,
            settled: VecDeque::new(),
            settled_bytes: 0,
            metrics: Metrics::default(),
            round_trips: 0,
            next_promise: 0,
            next_job: 0,
            next_lane: 0,
            next_channel: 0,
            next_serial: 0,
            next_provider: 0,
            queue_ceiling: MAX_PROMISES,
            channel_ceiling: crate::channel::MAX_QUEUED_PER_CHANNEL,
            idempotency: BTreeMap::new(),
            allow_durable: false,
            idempotency_order: VecDeque::new(),
            now_ms: 0,
            latency_ms: 1,
            transfers: 0,
            receipts: std::collections::VecDeque::new(),
            receipts_enabled: false,
            next_receipt: 0,
        };
        let cell: KernelCell = Rc::new(RefCell::new(kernel));
        let control: Rc<dyn CapControl> = Rc::new(HandleControl::new(Rc::clone(&cell)));
        Agent { cell, control }
    }

    /// Enable or disable capability receipts.
    ///
    /// When enabled, every admitted call appends a [`crate::Receipt`] to a
    /// bounded ring. Disabling also clears the ring. Receipts carry the
    /// capability's correlation id and the method, never arguments or secrets.
    pub fn enable_receipts(&self, enabled: bool) {
        let mut kernel = self.cell.borrow_mut();
        kernel.receipts_enabled = enabled;
        if !enabled {
            kernel.receipts.clear();
        }
    }

    /// The receipts recorded so far, oldest first.
    pub fn receipts(&self) -> Vec<crate::Receipt> {
        self.cell.borrow().receipts.iter().cloned().collect()
    }

    /// Verify that a receipt came from this kernel and was not edited.
    pub fn verify_receipt(&self, receipt: &crate::Receipt) -> bool {
        let secret = self.cell.borrow().secret;
        receipt.verify(&secret)
    }

    /// The shared cell, for transports and adapters that need direct access.
    pub fn cell(&self) -> &KernelCell {
        &self.cell
    }

    /// Register a provider and return its id.
    pub fn register(&self, provider: Box<dyn Provider>) -> ProviderId {
        let mut kernel = self.cell.borrow_mut();
        let id = ProviderId(kernel.next_provider);
        kernel.next_provider += 1;
        kernel.providers.insert(id, provider);
        id
    }

    /// Configure the simulated provider latency (milliseconds per batch).
    pub fn set_latency(&self, latency_ms: u64) {
        self.cell.borrow_mut().latency_ms = latency_ms;
    }

    /// Set the per-channel queued-message ceiling. Zero is refused.
    pub fn set_channel_queue_ceiling(&self, ceiling: usize) -> Result<()> {
        if ceiling == 0 {
            return Err(Error::InvalidArgument("channel ceiling must be non-zero"));
        }
        self.cell.borrow_mut().channel_ceiling =
            ceiling.min(crate::channel::MAX_QUEUED_PER_CHANNEL);
        Ok(())
    }

    /// Current per-channel queued-message ceiling.
    pub fn channel_queue_ceiling(&self) -> usize {
        self.cell.borrow().channel_ceiling
    }

    /// Allow or refuse durable capability minting. Default: refused.
    pub fn set_durable_capabilities(&self, allow: bool) {
        self.cell.borrow_mut().allow_durable = allow;
    }

    /// Whether durable capability minting is allowed.
    pub fn durable_capabilities_allowed(&self) -> bool {
        self.cell.borrow().allow_durable
    }

    /// Mint a first-generation capability.
    pub fn mint(&self, provider: ProviderId, object: u64, attrs: CapAttrs) -> Result<CapHandle> {
        if attrs.persistence == crate::cap::CapPersistence::Durable
            && !self.cell.borrow().allow_durable
        {
            return Err(Error::CapabilityTable(
                "durable capability refused by policy",
            ));
        }
        attrs.budget.check()?;
        if attrs.methods.is_empty() {
            return Err(Error::InvalidArgument("capability grants no methods"));
        }
        let mut kernel = self.cell.borrow_mut();
        if !kernel.providers.contains_key(&provider) {
            return Err(Error::InvalidArgument("unknown provider"));
        }
        let serial = kernel.next_serial;
        kernel.next_serial += 1;
        let id = CapId::derive(&kernel.secret, serial, None);
        let expires_at = attrs.ttl_ms.map(|ttl| kernel.now_ms.saturating_add(ttl));
        let mut record = CapRecord::new(id, provider, object, attrs.clone());
        record.expires_at = expires_at;
        kernel.meters.insert(id, BudgetMeter::new(attrs.budget));
        kernel.caps.insert(id, record);
        kernel.push_event(Event::CapMinted { cap: id, provider });
        Ok(CapHandle::new(Rc::clone(&self.control), id))
    }

    /// Mint a capability bound to one admitted peer.
    ///
    /// The binding is recorded on the capability and enforced at dispatch: the
    /// same id presented by another peer, or with no identity, is refused with
    /// `rpc/identity`. The parameter is an [`AdmittedIdentity`], which only
    /// [`crate::identity::IdentityPolicy::admit`] can produce, so a caller
    /// cannot bind a capability to an identity the transport never verified.
    pub fn mint_bound(
        &self,
        peer: &AdmittedIdentity,
        provider: ProviderId,
        object: u64,
        attrs: CapAttrs,
    ) -> Result<CapHandle> {
        if !peer.can_bind() {
            return Err(Error::Identity(
                "cannot bind a capability to an unauthenticated peer",
            ));
        }
        self.mint(provider, object, attrs.bound_to(peer.fingerprint()))
    }

    /// Introduce an existing capability to an admitted peer.
    ///
    /// Binds the capability to that peer's authenticated fingerprint and returns
    /// the descriptor to send over the transport. A capability already bound to
    /// a different peer is refused rather than rebound, so introduction can
    /// never move authority between principals.
    pub fn introduce_to(
        &self,
        cap: &CapHandle,
        peer: &AdmittedIdentity,
    ) -> Result<crate::wire::CapDescriptor> {
        if !peer.can_bind() {
            return Err(Error::Identity(
                "cannot introduce a capability to an unauthenticated peer",
            ));
        }
        let fingerprint = peer.fingerprint();
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .caps
            .get_mut(&cap.id())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
        if record.revoked {
            return Err(Error::Revoked(cap_token(cap.id())));
        }
        match record.attrs.bound_to {
            Some(bound) if bound != fingerprint => {
                return Err(Error::Identity(
                    "capability is already bound to another peer",
                ))
            }
            _ => {}
        }
        record.attrs.bound_to = Some(fingerprint);
        let descriptor = crate::wire::CapDescriptor::from_attrs(record.id, &record.attrs);
        let introduced = record.id;
        kernel.push_event(Event::CapIntroduced {
            cap: introduced,
            fingerprint,
        });
        Ok(descriptor)
    }

    /// Attenuate a capability. Refuses any widening.
    pub fn attenuate(&self, parent: &CapHandle, attrs: CapAttrs) -> Result<CapHandle> {
        let parent_id = parent.id();
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .caps
            .get(&parent_id)
            .ok_or(Error::UnknownCapability(cap_token(parent_id)))?
            .clone();
        if record.revoked {
            return Err(Error::Revoked(cap_token(parent_id)));
        }
        attrs.budget.check()?;
        let attrs = record.attrs.attenuate(attrs)?;
        let serial = kernel.next_serial;
        kernel.next_serial += 1;
        let id = CapId::derive(&kernel.secret, serial, Some(&parent_id));
        let mut child = CapRecord::new(id, record.provider, record.object, attrs.clone());
        child.parent = Some(parent_id);
        // A derived capability never outlives its parent: keep the parent's
        // absolute expiry when the child asked for a longer (or no) lifetime.
        child.expires_at = match (record.expires_at, attrs.ttl_ms) {
            (Some(parent_expiry), Some(ttl)) => {
                Some(parent_expiry.min(kernel.now_ms.saturating_add(ttl)))
            }
            (Some(parent_expiry), None) => Some(parent_expiry),
            (None, Some(ttl)) => Some(kernel.now_ms.saturating_add(ttl)),
            (None, None) => None,
        };
        kernel.meters.insert(id, BudgetMeter::new(attrs.budget));
        kernel.caps.insert(id, child);
        kernel.push_event(Event::CapMinted {
            cap: id,
            provider: record.provider,
        });
        Ok(CapHandle::new(Rc::clone(&self.control), id))
    }

    /// Import a capability id without owning a reference.
    ///
    /// This is how a peer handle is reconstructed from the wire: the id must
    /// already exist in this kernel, otherwise the first call fails with
    /// `rpc/unknown-capability`. Importing never proves authority; the registry
    /// does.
    pub fn import(&self, id: CapId) -> CapHandle {
        CapHandle::borrowed(Rc::clone(&self.control), id)
    }

    /// Revoke a capability and every capability derived from it.
    pub fn revoke(&self, cap: &CapHandle) {
        let mut kernel = self.cell.borrow_mut();
        let mut doomed = BTreeSet::new();
        let mut stack = vec![cap.id()];
        while let Some(id) = stack.pop() {
            if !doomed.insert(id) {
                continue;
            }
            for (child, record) in &kernel.caps {
                if record.parent == Some(id) {
                    stack.push(*child);
                }
            }
        }
        for id in doomed {
            if let Some(record) = kernel.caps.get_mut(&id) {
                record.revoked = true;
            }
            kernel.push_event(Event::CapRevoked(id));
            kernel.metrics.revocations = kernel.metrics.revocations.saturating_add(1);
        }
    }

    /// Create a lane.
    pub fn create_lane(&self, name: impl Into<String>, budget: Budget) -> Result<LaneId> {
        budget.check()?;
        let mut kernel = self.cell.borrow_mut();
        let open = kernel.lanes.values().filter(|lane| !lane.closed).count();
        if open >= MAX_LANES {
            return Err(Error::BudgetExceeded("lanes"));
        }
        let id = LaneId(kernel.next_lane);
        kernel.next_lane += 1;
        kernel.lanes.insert(id, Lane::new(id, name, budget));
        kernel.push_event(Event::LaneCreated(id));
        Ok(id)
    }

    /// Attenuate a lane's budget.
    pub fn attenuate_lane(&self, lane: LaneId, budget: Budget) -> Result<()> {
        budget.check()?;
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .lanes
            .get_mut(&lane)
            .ok_or(Error::UnknownLane(lane.0))?;
        record.attenuate(budget)
    }

    /// Destroy a lane and drop its queued work.
    ///
    /// Queued jobs are removed from the dispatch queue and their promises are
    /// rejected, so a destroyed lane cannot keep spending budget or produce side
    /// effects after the fact.
    pub fn destroy_lane(&self, lane: LaneId) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        {
            let record = kernel
                .lanes
                .get_mut(&lane)
                .ok_or(Error::UnknownLane(lane.0))?;
            record.destroy();
        }
        let doomed: Vec<u64> = kernel
            .jobs
            .iter()
            .filter(|(_, job)| job.lane == lane && job.state == JobState::Queued)
            .map(|(id, _)| *id)
            .collect();
        kernel.queue.retain(|id| !doomed.contains(id));
        for job_id in doomed {
            kernel.fail_job(job_id, Error::UnknownLane(lane.0));
        }
        // Reclaim the dispatch records this lane owns. Promise records stay:
        // a caller that holds a handle must still see the settled value (or a
        // rejected one) rather than an unrelated `unknown-promise`. The promise
        // ceiling bounds them; the kernel itself is the lifetime.
        kernel.jobs.retain(|_, job| job.lane != lane);
        for channel in kernel.channels.values_mut() {
            channel.subscribers.remove(&lane.0);
        }
        kernel.lanes.remove(&lane);
        kernel.push_event(Event::LaneDestroyed(lane));
        Ok(())
    }

    /// Destroy a channel and remove it from every lane's subscription set.
    pub fn destroy_channel(&self, channel: ChannelId) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        kernel
            .channels
            .remove(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        for lane in kernel.lanes.values_mut() {
            lane.channels.remove(&channel.0);
        }
        Ok(())
    }

    /// Create a channel.
    pub fn create_channel(
        &self,
        name: impl Into<String>,
        direction: Direction,
    ) -> Result<ChannelId> {
        let mut kernel = self.cell.borrow_mut();
        if kernel.channels.len() >= MAX_CHANNELS {
            return Err(Error::BudgetExceeded("channels"));
        }
        let id = ChannelId(kernel.next_channel);
        kernel.next_channel += 1;
        kernel
            .channels
            .insert(id, Channel::new(id, name, direction));
        Ok(id)
    }

    /// Subscribe a lane to a channel.
    pub fn subscribe(&self, lane: LaneId, channel: ChannelId) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
        if lane_record.closed {
            return Err(Error::UnknownLane(lane.0));
        }
        let channel_record = kernel
            .channels
            .get(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        if channel_record.queued() >= kernel.channel_ceiling {
            kernel.metrics.backpressure_refusals =
                kernel.metrics.backpressure_refusals.saturating_add(1);
            return Err(Error::Backpressure("channel queue ceiling reached"));
        }
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        record.subscribers.insert(lane.0);
        if let Some(lane) = kernel.lanes.get_mut(&lane) {
            lane.channels.insert(channel.0);
        }
        Ok(())
    }

    /// Send a message, transferring capabilities with it.
    pub fn send(
        &self,
        lane: LaneId,
        channel: ChannelId,
        payload: Value,
        caps: &[CapHandle],
    ) -> Result<u64> {
        self.send_as(None, lane, channel, payload, caps)
    }

    /// Send a message on behalf of the peer the transport authenticated.
    ///
    /// A capability bound to a peer may only be sent by that peer, and a bound
    /// capability cannot be transferred at all: a channel cannot prove who will
    /// read the message, so delegation across an identity boundary must use
    /// [`Agent::introduce_to`] explicitly.
    pub fn send_as(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        channel: ChannelId,
        payload: Value,
        caps: &[CapHandle],
    ) -> Result<u64> {
        let mut kernel = self.cell.borrow_mut();
        let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
        if lane_record.closed {
            return Err(Error::UnknownLane(lane.0));
        }
        let channel_record = kernel
            .channels
            .get(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        if channel_record.queued() >= kernel.channel_ceiling {
            kernel.metrics.backpressure_refusals =
                kernel.metrics.backpressure_refusals.saturating_add(1);
            return Err(Error::Backpressure("channel queue ceiling reached"));
        }
        let mut cap_ids = Vec::with_capacity(caps.len());
        for cap in caps {
            let record = kernel
                .caps
                .get(&cap.id())
                .ok_or(Error::InvalidArgument("unknown capability"))?;
            if record.revoked {
                return Err(Error::Revoked(cap_token(cap.id())));
            }
            if let Some(bound) = record.attrs.bound_to {
                let presented = peer.map(|identity| identity.fingerprint());
                if presented != Some(bound) {
                    return Err(Error::Identity(
                        "capability is bound to a different peer identity",
                    ));
                }
                return Err(Error::Identity(
                    "a bound capability cannot be transferred over a channel",
                ));
            }
            // A channel shares (borrows) the capability: the id travels with
            // the message and the sender keeps its handle. No reference is
            // created, so a channel cannot keep a capability alive after its
            // holder drops it (see `channel.rs`).
            cap_ids.push(cap.id());
        }
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let message = record.send(lane, payload, cap_ids.clone())?;
        kernel.push_event(Event::ChannelSend {
            channel,
            sequence: message.sequence,
        });
        for id in cap_ids {
            kernel.transfers += 1;
            kernel.push_event(Event::CapTransferred { cap: id, channel });
        }
        Ok(message.sequence)
    }

    /// Receive the next message on a channel.
    pub fn recv(&self, channel: ChannelId) -> Result<Option<Message>> {
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let message = record.recv()?;
        if let Some(message) = &message {
            kernel.push_event(Event::ChannelRecv {
                channel,
                sequence: message.sequence,
            });
        }
        Ok(message)
    }

    /// Issue a call. The returned promise is pending until the kernel runs.
    ///
    /// Refusals are recorded as [`Event::CallRefused`] plus a specific
    /// budget/tool event, and in [`Metrics`]. Argument values never enter the
    /// event log.
    pub fn call(
        &self,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
    ) -> Result<PromiseHandle> {
        self.call_as(None, lane, cap, method, args)
    }

    /// Issue a call that carries an envelope payload of `payload_bytes`.
    ///
    /// Transport dispatchers use this so the payload bytes an envelope carries
    /// are charged against the same `max_bytes` ceiling as the arguments. A
    /// peer cannot move a large Infinity image for free.
    pub fn call_with_payload(
        &self,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
    ) -> Result<PromiseHandle> {
        self.call_as_with_payload(None, lane, cap, method, args, payload_bytes)
    }

    /// Issue a call on behalf of the peer the transport authenticated.
    ///
    /// `None` means no identity was presented. A capability bound with
    /// [`Agent::introduce_to`] is refused unless the presented fingerprint
    /// matches, which is how a capability handed to one peer stays useless to
    /// every other one.
    pub fn call_as(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
    ) -> Result<PromiseHandle> {
        self.call_as_with_payload(peer, lane, cap, method, args, 0)
    }

    /// [`Agent::call_as`] with an envelope payload charged against the budget.
    pub fn call_as_with_payload(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
    ) -> Result<PromiseHandle> {
        let cap_id = cap.id();
        let result = self.call_inner(peer, lane, cap, method, args, payload_bytes);
        if let Err(error) = &result {
            let mut kernel = self.cell.borrow_mut();
            kernel.metrics.calls_refused = kernel.metrics.calls_refused.saturating_add(1);
            kernel.push_event(Event::CallRefused {
                lane,
                cap: cap_id,
                code: error.code().to_string(),
            });
            match error {
                Error::BudgetExceeded(dimension) => {
                    kernel.metrics.budget_exhaustions =
                        kernel.metrics.budget_exhaustions.saturating_add(1);
                    kernel.push_event(Event::BudgetExhausted {
                        cap: cap_id,
                        dimension: (*dimension).to_string(),
                    });
                }
                Error::Backpressure(_) => {
                    kernel.metrics.backpressure_refusals =
                        kernel.metrics.backpressure_refusals.saturating_add(1);
                }
                Error::Identity(_) => {
                    kernel.metrics.identity_refusals =
                        kernel.metrics.identity_refusals.saturating_add(1);
                }
                Error::ToolPolicy(reason) => {
                    kernel.metrics.tool_refusals = kernel.metrics.tool_refusals.saturating_add(1);
                    kernel.push_event(Event::ToolRefused {
                        cap: cap_id,
                        reason: (*reason).to_string(),
                    });
                }
                _ => {}
            }
        }
        result
    }

    fn call_inner(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
    ) -> Result<PromiseHandle> {
        let mut kernel = self.cell.borrow_mut();
        let cap_id = cap.id();
        let record = kernel
            .caps
            .get(&cap_id)
            .ok_or(Error::UnknownCapability(cap_token(cap_id)))?
            .clone();
        if record.revoked {
            return Err(Error::Revoked(cap_token(cap_id)));
        }
        if record
            .expires_at
            .is_some_and(|expires_at| kernel.now_ms >= expires_at)
        {
            // An expired capability is refused exactly like a revoked one. The
            // event lets an operator see the difference.
            kernel.push_event(Event::CapExpired(cap_id));
            return Err(Error::Revoked(cap_token(cap_id)));
        }
        // Identity binding is checked before any authority is exercised: a
        // capability introduced to one peer must be useless to another, even
        // with the exact same id.
        if let Some(bound) = record.attrs.bound_to {
            let presented = peer.map(|identity| identity.fingerprint());
            if presented != Some(bound) {
                return Err(Error::Identity(
                    "capability is bound to a different peer identity",
                ));
            }
        }
        let (lane_closed, lane_capacity, lane_budget) = {
            let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
            (
                lane_record.closed,
                lane_record.has_capacity(),
                lane_record.budget,
            )
        };
        if lane_closed {
            return Err(Error::UnknownLane(lane.0));
        }
        if !lane_capacity {
            return Err(Error::BudgetExceeded("lane call"));
        }
        if !record.attrs.grants(method) {
            return Err(Error::MethodNotGranted {
                method: method.to_string(),
            });
        }
        let provider = kernel
            .providers
            .get(&record.provider)
            .ok_or(Error::InvalidArgument("provider disappeared"))?;
        if !provider.has_method(method) {
            return Err(Error::MethodNotGranted {
                method: method.to_string(),
            });
        }
        if record.attrs.read_only && provider.mutating(method) {
            return Err(Error::ReadOnly);
        }
        // Path scope is enforced here, before the provider sees the call.
        if let Some(scope) = &record.attrs.path_scope {
            for arg in &args {
                if let Arg::Value(Value::Path(path)) = arg {
                    if !crate::cap::is_path_prefix(scope, path) {
                        return Err(Error::PathNotGranted(path.clone()));
                    }
                }
            }
        }
        // Tool policy is enforced here too.
        if let Some(policy) = &record.attrs.tool_policy {
            if !policy.allowed.contains(method) {
                return Err(Error::ToolPolicy("tool not allowed"));
            }
            // Count every argument shape, recursively: a nested list or map
            // must not slip past the tool's payload ceiling.
            let bytes: u64 = args.iter().map(Arg::wire_size).sum();
            if bytes > policy.max_arg_bytes {
                return Err(Error::ToolPolicy("argument too large"));
            }
        }
        let call_bytes: u64 = args
            .iter()
            .map(|arg| arg.wire_size())
            .sum::<u64>()
            .saturating_add(payload_bytes);
        let effective = record.attrs.budget.intersect(&lane_budget);
        if call_bytes > effective.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        // Registry ceilings are checked before charging: a refused call must
        // not consume budget, and the job/promise maps must stay finite even
        // when the caller never destroys its lane.
        if kernel.promises.len() >= MAX_PROMISES {
            return Err(Error::BudgetExceeded("promises"));
        }
        if kernel.jobs.len() >= MAX_PROMISES {
            return Err(Error::BudgetExceeded("jobs"));
        }
        if kernel.jobs.len() >= kernel.queue_ceiling {
            return Err(Error::Backpressure("queue ceiling reached"));
        }
        let meter = kernel
            .meters
            .get_mut(&cap_id)
            .ok_or(Error::InvalidArgument("capability has no meter"))?;
        meter.charge(call_bytes)?;

        let promise_id = PromiseId(kernel.next_promise);
        kernel.next_promise += 1;
        kernel
            .promises
            .insert(promise_id, PromiseRecord::new(promise_id, lane.0));

        // The call is authorized: record the decision before it is queued.
        if kernel.receipts_enabled {
            kernel.next_receipt = kernel.next_receipt.saturating_add(1);
            let receipt = crate::receipts::Receipt::seal(
                &kernel.secret,
                kernel.next_receipt,
                cap_id,
                method,
                kernel.now_ms,
            );
            kernel.receipts.push_back(receipt);
            if kernel.receipts.len() > crate::receipts::MAX_RECEIPTS {
                kernel.receipts.pop_front();
            }
        }

        let job_id = kernel.next_job;
        kernel.next_job += 1;
        let deps: Vec<PromiseId> = args.iter().filter_map(|arg| arg.promise()).collect();
        for dep in &deps {
            if !kernel.promises.contains_key(dep) {
                return Err(Error::UnknownPromise(dep.0));
            }
            if let Some(record) = kernel.promises.get_mut(dep) {
                record.waiters += 1;
            }
        }
        let call = Call {
            method: method.to_string(),
            args,
            path_scope: record.attrs.path_scope.clone(),
            redact: record.attrs.redact,
            read_only: record.attrs.read_only,
            tool_allows_process: record
                .attrs
                .tool_policy
                .as_ref()
                .map(|policy| policy.allow_process)
                .unwrap_or(false),
            budget: effective,
        };
        let job = Job {
            id: job_id,
            lane,
            cap: cap_id,
            call,
            deps,
            promise: promise_id,
            state: JobState::Queued,
        };
        kernel.jobs.insert(job_id, job);
        kernel.queue.push_back(job_id);
        if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
            lane_record.pending += 1;
        }
        kernel.push_event(Event::CallQueued {
            job: job_id,
            lane,
            cap: cap_id,
        });
        kernel.metrics.calls_queued = kernel.metrics.calls_queued.saturating_add(1);
        // Budgets are charged here, before the call is queued. Dispatch
        // re-checks existence and revocation; providers receive the effective
        // budget in `Call` and tool adapters must enforce their wall ceiling.
        //
        // The handle below is the only owner of this promise now; set the
        // reference immediately before constructing it, so an earlier error
        // leaves an unreferenced (and therefore trimmable) record.
        if let Some(record) = kernel.promises.get_mut(&promise_id) {
            record.handles = 1;
        }
        Ok(PromiseHandle {
            agent: self.clone(),
            id: promise_id,
        })
    }

    /// Run until no job is queued. Returns the number of provider round-trips.
    pub fn run(&self) -> u64 {
        loop {
            let batch = {
                let mut kernel = self.cell.borrow_mut();
                if kernel.queue.is_empty() {
                    kernel.trim_settled();
                    return kernel.round_trips;
                }
                match kernel.next_batch() {
                    Ok(batch) => batch,
                    Err(stuck) => {
                        // Only the jobs that cannot be ordered are failed; work
                        // for other providers stays queued.
                        for job_id in stuck {
                            let error = kernel
                                .jobs
                                .get(&job_id)
                                .map(|job| Error::UnknownCapability(cap_token(job.cap)))
                                .unwrap_or(Error::PipelinedCycle);
                            kernel.fail_job(job_id, error);
                        }
                        continue;
                    }
                }
            };
            self.dispatch(batch);
        }
    }

    /// Round-trips observed so far.
    pub fn round_trips(&self) -> u64 {
        self.cell.borrow().round_trips
    }

    /// Await a promise, running the kernel until it settles.
    pub fn await_promise(&self, promise: &PromiseHandle) -> Result<Value> {
        loop {
            {
                let kernel = self.cell.borrow();
                let record = kernel
                    .promises
                    .get(&promise.id)
                    .ok_or(Error::UnknownPromise(promise.id.0))?;
                if record.state.is_settled() {
                    return record.value();
                }
            }
            if self.cell.borrow().queue.is_empty() {
                return Err(Error::UnresolvablePromise(promise.id.0));
            }
            self.run();
        }
    }

    /// Resolve a pending promise manually (used by peers that answer out of band).
    pub fn resolve(&self, promise: &PromiseHandle, value: Value) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .promises
            .get_mut(&promise.id)
            .ok_or(Error::UnknownPromise(promise.id.0))?;
        let settled = record.resolve(value);
        if settled.is_err() {
            kernel.metrics.promises_double_settled =
                kernel.metrics.promises_double_settled.saturating_add(1);
        }
        settled?;
        kernel.push_event(Event::PromiseResolved(promise.id));
        kernel.metrics.promises_resolved = kernel.metrics.promises_resolved.saturating_add(1);
        kernel.record_settled(promise.id);
        Ok(())
    }

    /// Set the local queue ceiling. A value of zero is refused.
    pub fn set_queue_ceiling(&self, ceiling: usize) -> Result<()> {
        if ceiling == 0 {
            return Err(Error::InvalidArgument("queue ceiling must be non-zero"));
        }
        self.cell.borrow_mut().queue_ceiling = ceiling.min(MAX_PROMISES);
        Ok(())
    }

    /// Current local queue ceiling.
    pub fn queue_ceiling(&self) -> usize {
        self.cell.borrow().queue_ceiling
    }

    /// Issue a call with an idempotency key.
    ///
    /// A repeated key returns the existing promise when it is pending or
    /// resolved. A rejected/cancelled promise is forgotten so a mutating call
    /// can be retried. The key is scoped to the capability id and method.
    /// Mutating-domain semantics remain the provider's responsibility; this
    /// cache prevents a second invocation, it does not make a provider atomic.
    pub fn call_idempotent(
        &self,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        key: &str,
    ) -> Result<PromiseHandle> {
        if key.is_empty() {
            return Err(Error::InvalidArgument("idempotency key is empty"));
        }
        let map_key = (cap.id(), method.to_string(), key.to_string());
        {
            let mut kernel = self.cell.borrow_mut();
            if let Some(id) = kernel.idempotency.get(&map_key).copied() {
                let reusable = kernel
                    .promises
                    .get(&id)
                    .map(|record| {
                        matches!(
                            record.state,
                            PromiseState::Pending | PromiseState::Resolved(_)
                        )
                    })
                    .unwrap_or(false);
                if reusable {
                    if let Some(record) = kernel.promises.get_mut(&id) {
                        record.handles = record.handles.saturating_add(1);
                    }
                    return Ok(PromiseHandle {
                        agent: self.clone(),
                        id,
                    });
                }
                kernel.idempotency.remove(&map_key);
            }
        }
        let promise = self.call(lane, cap, method, args)?;
        let id = promise.id();
        let mut kernel = self.cell.borrow_mut();
        kernel.idempotency.insert(map_key.clone(), id);
        kernel.idempotency_order.push_back(map_key);
        const MAX_IDEMPOTENCY: usize = 1024;
        while kernel.idempotency.len() > MAX_IDEMPOTENCY {
            if let Some(oldest) = kernel.idempotency_order.pop_front() {
                kernel.idempotency.remove(&oldest);
            } else {
                break;
            }
        }
        Ok(promise)
    }

    /// Cancel a promise.
    ///
    /// A job that has not been dispatched yet is removed from the queue, so a
    /// cancellation really prevents the provider call (and its side effects). A
    /// job already in flight cannot be stopped; its result is discarded.
    pub fn cancel(&self, promise: &PromiseHandle) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        {
            let record = kernel
                .promises
                .get_mut(&promise.id)
                .ok_or(Error::UnknownPromise(promise.id.0))?;
            record.cancel()?;
        }
        let queued: Option<u64> = kernel
            .jobs
            .iter()
            .find(|(_, job)| job.promise == promise.id && job.state == JobState::Queued)
            .map(|(id, _)| *id);
        if let Some(job_id) = queued {
            kernel.queue.retain(|id| *id != job_id);
            let lane = kernel.jobs.get(&job_id).map(|job| job.lane);
            kernel.jobs.remove(&job_id);
            kernel.record_settled(promise.id);
            if let Some(lane) = lane {
                if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
                    lane_record.complete();
                }
            }
        }
        Ok(())
    }

    /// Cancel a promise and every promise that depends on it.
    ///
    /// The tree walk follows queued job dependencies. A dependent whose job is
    /// still queued is removed before dispatch, so a cancellation prevents the
    /// provider call and its side effects. An already-settled root is refused;
    /// dependent promises that already settled are left untouched.
    pub fn cancel_tree(&self, promise: &PromiseHandle) -> Result<Vec<PromiseId>> {
        let mut kernel = self.cell.borrow_mut();
        let root_pending = kernel
            .promises
            .get(&promise.id)
            .ok_or(Error::UnknownPromise(promise.id.0))?
            .state
            == PromiseState::Pending;
        if !root_pending {
            return Err(Error::PromiseAlreadyResolved(promise.id.0));
        }

        let mut targets = vec![promise.id];
        let mut index = 0;
        while index < targets.len() {
            let id = targets[index];
            if let Some(record) = kernel.promises.get_mut(&id) {
                if record.state == PromiseState::Pending {
                    record.cancel()?;
                }
            }
            let dependents: Vec<PromiseId> = kernel
                .jobs
                .values()
                .filter(|job| job.deps.contains(&id))
                .map(|job| job.promise)
                .collect();
            for dependent in dependents {
                if !targets.contains(&dependent) {
                    targets.push(dependent);
                }
            }
            index += 1;
        }

        let queued: Vec<(u64, PromiseId, u64)> = kernel
            .jobs
            .iter()
            .filter(|(_, job)| job.state == JobState::Queued && targets.contains(&job.promise))
            .map(|(id, job)| (*id, job.promise, job.lane.0))
            .collect();
        for (job_id, promise_id, lane) in queued {
            kernel.queue.retain(|queued_id| *queued_id != job_id);
            kernel.jobs.remove(&job_id);
            kernel.record_settled(promise_id);
            if let Some(lane_record) = kernel.lanes.get_mut(&LaneId(lane)) {
                lane_record.complete();
            }
        }
        Ok(targets)
    }

    /// Reference a promise record from a handle.
    fn retain_promise(&self, id: PromiseId) {
        if let Ok(mut kernel) = self.cell.try_borrow_mut() {
            if let Some(record) = kernel.promises.get_mut(&id) {
                record.handles = record.handles.saturating_add(1);
            }
        }
    }

    /// Drop a handle's reference to a promise record.
    fn release_promise(&self, id: PromiseId) {
        if let Ok(mut kernel) = self.cell.try_borrow_mut() {
            if let Some(record) = kernel.promises.get_mut(&id) {
                record.handles = record.handles.saturating_sub(1);
            }
        }
    }

    /// Drain drop notifications recorded by one provider.
    pub fn take_drops(&self, provider: ProviderId) -> Vec<(u64, CapId)> {
        self.cell
            .borrow_mut()
            .providers
            .get_mut(&provider)
            .map(|provider| provider.take_drop_notifications())
            .unwrap_or_default()
    }

    /// The event log.
    pub fn events(&self) -> Vec<Event> {
        self.cell.borrow().events.iter().cloned().collect()
    }

    /// Monotonic total of events ever appended, including evicted ones.
    ///
    /// Consumers that tail [`Agent::events`] use this to turn the retained
    /// suffix into a delta once the bounded tape has wrapped.
    pub fn total_events(&self) -> u64 {
        self.cell.borrow().events_total
    }

    /// Point-in-time counters. Contains no capability ids or payloads.
    pub fn metrics(&self) -> Metrics {
        let kernel = self.cell.borrow();
        Metrics {
            round_trips: kernel.round_trips,
            transfers: kernel.transfers,
            ..kernel.metrics
        }
    }

    /// Number of live promise records (pending plus retained settled).
    pub fn promise_count(&self) -> usize {
        self.cell.borrow().promises.len()
    }

    /// Number of live job records (queued or in flight).
    pub fn job_count(&self) -> usize {
        self.cell.borrow().jobs.len()
    }

    /// Project the retained event window into the observability schema.
    ///
    /// Sequences are monotonic across evictions: a reader can page with
    /// `last_sequence + 1` without missing or repeating a record.
    pub fn trace(&self) -> Vec<crate::observability::TraceEvent> {
        let kernel = self.cell.borrow();
        let total = kernel.events_total;
        let len = kernel.events.len() as u64;
        let first = total.saturating_sub(len);
        kernel
            .events
            .iter()
            .enumerate()
            .map(|(index, event)| crate::observability::project(event, first + index as u64))
            .collect()
    }

    /// The retained events as one JSON array in the observability schema.
    pub fn trace_json(&self) -> String {
        crate::observability::to_json_array(&self.trace())
    }

    /// Counters and gauges as JSON (`active-rpc/metrics/1`).
    pub fn metrics_json(&self) -> String {
        let metrics = self.metrics();
        crate::observability::metrics_json(
            &metrics,
            self.promise_count(),
            self.job_count(),
            self.lane_count(),
            self.channel_count(),
        )
    }

    /// Number of live lanes.
    pub fn lane_count(&self) -> usize {
        self.cell.borrow().lanes.len()
    }

    /// Number of live channels.
    pub fn channel_count(&self) -> usize {
        self.cell.borrow().channels.len()
    }

    /// Lane statistics.
    pub fn lane(&self, lane: LaneId) -> Result<Lane> {
        self.cell
            .borrow()
            .lanes
            .get(&lane)
            .cloned()
            .ok_or(Error::UnknownLane(lane.0))
    }

    /// Channel statistics.
    pub fn channel(&self, channel: ChannelId) -> Result<Channel> {
        self.cell
            .borrow()
            .channels
            .get(&channel)
            .cloned()
            .ok_or(Error::UnknownChannel(channel.0))
    }

    /// Capability attributes, for tests and policy tooling.
    pub fn cap_attrs(&self, cap: &CapHandle) -> Result<CapAttrs> {
        self.cell
            .borrow()
            .caps
            .get(&cap.id())
            .map(|record| record.attrs.clone())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))
    }

    fn dispatch(&self, batch: Vec<u64>) {
        // No kernel borrow is held while a provider runs: a provider may hold an
        // `Agent` and call back into the kernel, and a re-entrant borrow would
        // panic (or, with `try_borrow_mut`, silently drop a refcount update).
        // Each phase takes a short borrow and returns owned data.
        let (provider_id, provider) = {
            let mut kernel = self.cell.borrow_mut();
            kernel.round_trips += 1;
            kernel.now_ms = kernel.now_ms.saturating_add(kernel.latency_ms);
            let Some(first) = batch.first().and_then(|id| kernel.jobs.get(id)) else {
                return;
            };
            let provider_id = kernel
                .caps
                .get(&first.cap)
                .map(|record| record.provider)
                .unwrap_or(ProviderId(u64::MAX));
            let lanes: BTreeSet<u64> = batch
                .iter()
                .filter_map(|id| kernel.jobs.get(id).map(|job| job.lane.0))
                .collect();
            kernel.push_event(Event::BatchDispatched {
                provider: provider_id,
                jobs: batch.len(),
                lanes,
            });
            let provider = kernel.providers.remove(&provider_id);
            (provider_id, provider)
        };
        let Some(mut provider) = provider else {
            let mut kernel = self.cell.borrow_mut();
            for job_id in batch {
                kernel.fail_job(
                    job_id,
                    Error::Provider {
                        code: "rpc/provider".to_string(),
                    },
                );
            }
            return;
        };

        for job_id in &batch {
            // Phase 1: decide, under a read borrow.
            let prepared = {
                let kernel = self.cell.borrow();
                let Some(job) = kernel.jobs.get(job_id).cloned() else {
                    continue;
                };
                if job.state == JobState::Done {
                    continue;
                }
                let mut args = Vec::with_capacity(job.call.args.len());
                let mut failure = None;
                for arg in &job.call.args {
                    match arg {
                        Arg::Promise(id) => match kernel.promises.get(id) {
                            Some(record) if record.state.is_settled() => match record.value() {
                                Ok(value) => args.push(Arg::Value(value)),
                                Err(error) => {
                                    failure = Some(error);
                                    break;
                                }
                            },
                            Some(_) => {
                                failure = Some(Error::UnresolvablePromise(id.0));
                                break;
                            }
                            None => {
                                failure = Some(Error::UnknownPromise(id.0));
                                break;
                            }
                        },
                        other => args.push(other.clone()),
                    }
                }
                // Authority is re-checked at dispatch: a capability revoked
                // after the call was queued must not reach the provider.
                let record = kernel.caps.get(&job.cap).cloned();
                let failure = match &record {
                    None => Some(Error::UnknownCapability(cap_token(job.cap))),
                    Some(record) if record.revoked => Some(Error::Revoked(cap_token(record.id))),
                    Some(_) => failure,
                };
                Some((
                    job,
                    args,
                    failure,
                    record.map(|record| record.object).unwrap_or(0),
                ))
            };
            let Some((job, args, failure, object)) = prepared else {
                continue;
            };

            // Phase 2: run provider code with no borrow held.
            let outcome = match failure {
                Some(error) => Err(error),
                None => {
                    let call = Call {
                        args,
                        ..job.call.clone()
                    };
                    provider.invoke(object, &call).map(Response::into_value)
                }
            };

            // Phase 3: settle under a write borrow.
            let mut kernel = self.cell.borrow_mut();
            let mut settled_now = false;
            match &outcome {
                Ok(value) => {
                    if let Some(record) = kernel.promises.get_mut(&job.promise) {
                        if record.resolve(value.clone()).is_ok() {
                            settled_now = true;
                        } else {
                            kernel.metrics.promises_double_settled =
                                kernel.metrics.promises_double_settled.saturating_add(1);
                        }
                    }
                    kernel.push_event(Event::PromiseResolved(job.promise));
                    kernel.metrics.promises_resolved =
                        kernel.metrics.promises_resolved.saturating_add(1);
                }
                Err(error) => {
                    if let Some(record) = kernel.promises.get_mut(&job.promise) {
                        if record.reject(error.clone()).is_ok() {
                            settled_now = true;
                        } else {
                            kernel.metrics.promises_double_settled =
                                kernel.metrics.promises_double_settled.saturating_add(1);
                        }
                    }
                    kernel.push_event(Event::PromiseRejected {
                        promise: job.promise,
                        code: error.code().to_string(),
                    });
                    kernel.metrics.promises_rejected =
                        kernel.metrics.promises_rejected.saturating_add(1);
                }
            }
            if settled_now {
                kernel.record_settled(job.promise);
            }
            // A completed job no longer needs its Call or arguments. Removing it
            // here is what makes the jobs ceiling a transient bound rather than
            // a lifetime quota.
            kernel.jobs.remove(job_id);
            if let Some(lane_record) = kernel.lanes.get_mut(&job.lane) {
                lane_record.complete();
            }
            kernel.push_event(Event::JobCompleted {
                job: *job_id,
                lane: job.lane,
            });
        }

        self.cell
            .borrow_mut()
            .providers
            .insert(provider_id, provider);
    }
}

impl Kernel {
    /// Append an event, dropping the oldest when the log is full.
    fn push_event(&mut self, event: Event) {
        if self.events.len() >= MAX_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
        self.events_total = self.events_total.saturating_add(1);
    }

    /// Remember a settled promise for bounded retention.
    fn record_settled(&mut self, id: PromiseId) {
        let size = self
            .promises
            .get(&id)
            .and_then(|record| record.value().ok())
            .map(|value| value.wire_size() as usize)
            .unwrap_or(0);
        self.settled.push_back((id, size));
        self.settled_bytes = self.settled_bytes.saturating_add(size);
    }

    /// Trim settled promises after the queue drains.
    ///
    /// Only called with no queued job, so no dependency can still need an
    /// evicted record. A record with a live handle is pinned and never evicted;
    /// if every record is pinned the limits are a target, not a reason to drop
    /// a result the caller can still read.
    fn trim_settled(&mut self) {
        while (self.settled.len() > MAX_SETTLED_PROMISES || self.settled_bytes > MAX_SETTLED_BYTES)
            && self.settled.len() > 1
        {
            let mut victim = None;
            for (index, (id, _)) in self.settled.iter().enumerate() {
                let pinned = self
                    .promises
                    .get(id)
                    .map(|record| record.handles > 0)
                    .unwrap_or(false);
                if !pinned {
                    victim = Some(index);
                    break;
                }
            }
            let Some(index) = victim else {
                break;
            };
            let Some((id, size)) = self.settled.remove(index) else {
                break;
            };
            self.settled_bytes = self.settled_bytes.saturating_sub(size);
            self.promises.remove(&id);
        }
    }

    /// Build the next dispatch batch: all queued jobs for the head job's
    /// provider, ordered so promise producers precede consumers.
    fn next_batch(&mut self) -> std::result::Result<Vec<u64>, Vec<u64>> {
        let Some(head) = self.queue.front().copied() else {
            return Ok(Vec::new());
        };
        let Some(head_job) = self.jobs.get(&head) else {
            self.queue.pop_front();
            return Ok(Vec::new());
        };
        let Some(provider) = self.caps.get(&head_job.cap).map(|record| record.provider) else {
            // The capability vanished; fail this job and let the caller retry.
            self.queue.pop_front();
            return Err(vec![head]);
        };
        let mut candidates: Vec<u64> = self
            .queue
            .iter()
            .copied()
            .filter(|id| {
                self.jobs
                    .get(id)
                    .and_then(|job| self.caps.get(&job.cap))
                    .map(|record| record.provider == provider)
                    .unwrap_or(false)
            })
            .collect();
        // Producers first: order by promise dependencies inside the batch.
        let mut ordered: Vec<u64> = Vec::new();
        let mut pending = candidates.clone();
        let mut progress = true;
        while progress && !pending.is_empty() {
            progress = false;
            let mut index = 0;
            while index < pending.len() {
                let id = pending[index];
                let job = self.jobs.get(&id).cloned();
                let ready = match &job {
                    Some(job) => job.deps.iter().all(|dep| {
                        // Resolved already, or produced by an ordered job.
                        match self.promises.get(dep) {
                            Some(record) if record.state.is_settled() => true,
                            _ => ordered
                                .iter()
                                .any(|other| self.jobs.get(other).map(|j| j.promise) == Some(*dep)),
                        }
                    }),
                    None => true,
                };
                if ready {
                    ordered.push(id);
                    pending.remove(index);
                    progress = true;
                } else {
                    index += 1;
                }
            }
        }
        if !pending.is_empty() {
            // Unorderable: the remaining jobs form (or depend on) a cycle.
            for id in &pending {
                self.queue.retain(|queued| queued != id);
            }
            return Err(pending);
        }
        candidates.clear();
        self.queue.retain(|id| !ordered.contains(id));
        Ok(ordered)
    }

    fn fail_job(&mut self, job_id: u64, error: Error) {
        if let Some(job) = self.jobs.get_mut(&job_id) {
            job.state = JobState::Done;
            let promise = job.promise;
            let lane = job.lane;
            let code = error.code().to_string();
            let mut settled_now = false;
            if let Some(record) = self.promises.get_mut(&promise) {
                if record.reject(error).is_ok() {
                    settled_now = true;
                } else {
                    self.metrics.promises_double_settled =
                        self.metrics.promises_double_settled.saturating_add(1);
                }
            }
            if let Some(lane_record) = self.lanes.get_mut(&lane) {
                lane_record.complete();
            }
            self.push_event(Event::PromiseRejected { promise, code });
            self.metrics.promises_rejected = self.metrics.promises_rejected.saturating_add(1);
            if settled_now {
                self.record_settled(promise);
            }
            self.jobs.remove(&job_id);
            self.push_event(Event::JobCompleted { job: job_id, lane });
        }
    }
}

fn pad128(id: CapId) -> [u8; 16] {
    id.0
}

fn cap_token(id: CapId) -> crate::cap::CapToken {
    crate::cap::CapToken(u128::from_be_bytes(pad128(id)))
}

/// A handle to a pending or settled result.
pub struct PromiseHandle {
    agent: Agent,
    id: PromiseId,
}

impl Clone for PromiseHandle {
    fn clone(&self) -> Self {
        self.agent.retain_promise(self.id);
        Self {
            agent: self.agent.clone(),
            id: self.id,
        }
    }
}

impl Drop for PromiseHandle {
    fn drop(&mut self) {
        self.agent.release_promise(self.id);
    }
}

impl PromiseHandle {
    /// Promise id.
    pub fn id(&self) -> PromiseId {
        self.id
    }

    /// The owning agent.
    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// Await the value, running the kernel as needed.
    pub fn value(&self) -> Result<Value> {
        self.agent.await_promise(self)
    }

    /// The settled value without running the kernel.
    pub fn peek(&self) -> Result<Value> {
        self.agent
            .cell
            .borrow()
            .promises
            .get(&self.id)
            .ok_or(Error::UnknownPromise(self.id.0))?
            .value()
    }

    /// Whether the promise has settled.
    pub fn is_settled(&self) -> bool {
        self.agent
            .cell
            .borrow()
            .promises
            .get(&self.id)
            .map(|record| record.state.is_settled())
            .unwrap_or(false)
    }
}

impl std::fmt::Debug for PromiseHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromiseHandle")
            .field("id", &self.id)
            .field("settled", &self.is_settled())
            .finish()
    }
}

/// Tool policy helper re-exported for callers building attenuated tools.
pub fn tool_policy_for(methods: &[&str]) -> ToolPolicy {
    ToolPolicy::allow(methods)
}

/// Promise state accessor for tests and diagnostics.
pub fn promise_state(agent: &Agent, id: PromiseId) -> Option<PromiseState> {
    agent
        .cell
        .borrow()
        .promises
        .get(&id)
        .map(|record| record.state.clone())
}
