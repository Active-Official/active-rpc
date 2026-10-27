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
use crate::lane::{Lane, LaneId};
use crate::promise::{PromiseId, PromiseRecord, PromiseState};
use crate::value::{Arg, Call, Response, Value};

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
    events: Vec<Event>,
    round_trips: u64,
    next_promise: u64,
    next_job: u64,
    next_lane: u64,
    next_channel: u64,
    next_serial: u64,
    next_provider: u64,
    now_ms: u64,
    latency_ms: u64,
    transfers: u64,
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
                kernel.events.push(Event::CapRetained(id));
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
            kernel.events.push(Event::CapReleased(id));
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
        kernel.events.push(Event::CapDropped(id));
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
            events: Vec::new(),
            round_trips: 0,
            next_promise: 0,
            next_job: 0,
            next_lane: 0,
            next_channel: 0,
            next_serial: 0,
            next_provider: 0,
            now_ms: 0,
            latency_ms: 1,
            transfers: 0,
        };
        let cell: KernelCell = Rc::new(RefCell::new(kernel));
        let control: Rc<dyn CapControl> = Rc::new(HandleControl::new(Rc::clone(&cell)));
        Agent { cell, control }
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

    /// Mint a first-generation capability.
    pub fn mint(&self, provider: ProviderId, object: u64, attrs: CapAttrs) -> Result<CapHandle> {
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
        let record = CapRecord::new(id, provider, object, attrs.clone());
        kernel.meters.insert(id, BudgetMeter::new(attrs.budget));
        kernel.caps.insert(id, record);
        kernel.events.push(Event::CapMinted { cap: id, provider });
        Ok(CapHandle::new(Rc::clone(&self.control), id))
    }

    /// Attenuate a capability. Refuses any widening.
    pub fn attenuate(&self, parent: &CapHandle, attrs: CapAttrs) -> Result<CapHandle> {
        let parent_id = parent.id();
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .caps
            .get(&parent_id)
            .ok_or(Error::UnknownCapability(u128::from_be_bytes(pad128(
                parent_id,
            ))))?
            .clone();
        if record.revoked {
            return Err(Error::Revoked(u128::from_be_bytes(pad128(parent_id))));
        }
        let attrs = record.attrs.attenuate(attrs)?;
        let serial = kernel.next_serial;
        kernel.next_serial += 1;
        let id = CapId::derive(&kernel.secret, serial, Some(&parent_id));
        let mut child = CapRecord::new(id, record.provider, record.object, attrs.clone());
        child.parent = Some(parent_id);
        kernel.meters.insert(id, BudgetMeter::new(attrs.budget));
        kernel.caps.insert(id, child);
        kernel.events.push(Event::CapMinted {
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
            kernel.events.push(Event::CapRevoked(id));
        }
    }

    /// Create a lane.
    pub fn create_lane(&self, name: impl Into<String>, budget: Budget) -> Result<LaneId> {
        budget.check()?;
        let mut kernel = self.cell.borrow_mut();
        let id = LaneId(kernel.next_lane);
        kernel.next_lane += 1;
        kernel.lanes.insert(id, Lane::new(id, name, budget));
        kernel.events.push(Event::LaneCreated(id));
        Ok(id)
    }

    /// Attenuate a lane's budget.
    pub fn attenuate_lane(&self, lane: LaneId, budget: Budget) -> Result<()> {
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
        kernel.events.push(Event::LaneDestroyed(lane));
        Ok(())
    }

    /// Create a channel.
    pub fn create_channel(
        &self,
        name: impl Into<String>,
        direction: Direction,
    ) -> Result<ChannelId> {
        let mut kernel = self.cell.borrow_mut();
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
        if !kernel.lanes.contains_key(&lane) {
            return Err(Error::UnknownLane(lane.0));
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
        let mut kernel = self.cell.borrow_mut();
        if !kernel.lanes.contains_key(&lane) {
            return Err(Error::UnknownLane(lane.0));
        }
        let mut cap_ids = Vec::with_capacity(caps.len());
        for cap in caps {
            let record = kernel
                .caps
                .get(&cap.id())
                .ok_or(Error::InvalidArgument("unknown capability"))?;
            if record.revoked {
                return Err(Error::Revoked(u128::from_be_bytes(pad128(cap.id()))));
            }
            // A transfer moves the capability: the sender's reference is
            // consumed by the message, which keeps the capability alive for
            // the receiver.
            cap_ids.push(cap.id());
        }
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let message = record.send(lane, payload, cap_ids.clone())?;
        kernel.events.push(Event::ChannelSend {
            channel,
            sequence: message.sequence,
        });
        for id in cap_ids {
            if let Some(record) = kernel.caps.get_mut(&id) {
                record.refs = record.refs.saturating_add(1);
            }
            kernel.transfers += 1;
            kernel
                .events
                .push(Event::CapTransferred { cap: id, channel });
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
            kernel.events.push(Event::ChannelRecv {
                channel,
                sequence: message.sequence,
            });
        }
        Ok(message)
    }

    /// Issue a call. The returned promise is pending until the kernel runs.
    pub fn call(
        &self,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
    ) -> Result<PromiseHandle> {
        let mut kernel = self.cell.borrow_mut();
        let cap_id = cap.id();
        let record = kernel
            .caps
            .get(&cap_id)
            .ok_or(Error::UnknownCapability(u128::from_be_bytes(pad128(
                cap_id,
            ))))?
            .clone();
        if record.revoked {
            return Err(Error::Revoked(u128::from_be_bytes(pad128(cap_id))));
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
        let call_bytes: u64 = args.iter().map(|arg| arg.wire_size()).sum();
        let effective = record.attrs.budget.intersect(&lane_budget);
        if call_bytes > effective.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
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
        kernel.events.push(Event::CallQueued {
            job: job_id,
            lane,
            cap: cap_id,
        });
        // Budgets are enforced again at dispatch with the effective grant.
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
                    return kernel.round_trips;
                }
                match kernel.next_batch() {
                    Ok(batch) => batch,
                    Err(stuck) => {
                        // Only the jobs that cannot be ordered are failed; work
                        // for other providers stays queued.
                        for job_id in stuck {
                            kernel.fail_job(job_id, Error::PipelinedCycle);
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
        record.resolve(value)?;
        kernel.events.push(Event::PromiseResolved(promise.id));
        Ok(())
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
            if let Some(job) = kernel.jobs.get_mut(&job_id) {
                job.state = JobState::Done;
            }
            if let Some(lane) = lane {
                if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
                    lane_record.complete();
                }
            }
        }
        Ok(())
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
        self.cell.borrow().events.clone()
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
            .ok_or(Error::UnknownCapability(u128::from_be_bytes(pad128(
                cap.id(),
            ))))
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
            kernel.events.push(Event::BatchDispatched {
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
                    None => Some(Error::UnknownCapability(0)),
                    Some(record) if record.revoked => {
                        Some(Error::Revoked(u128::from_be_bytes(pad128(record.id))))
                    }
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
            match &outcome {
                Ok(value) => {
                    if let Some(record) = kernel.promises.get_mut(&job.promise) {
                        let _ = record.resolve(value.clone());
                    }
                    kernel.events.push(Event::PromiseResolved(job.promise));
                }
                Err(error) => {
                    if let Some(record) = kernel.promises.get_mut(&job.promise) {
                        let _ = record.reject(error.clone());
                    }
                    kernel.events.push(Event::PromiseRejected {
                        promise: job.promise,
                        code: error.code().to_string(),
                    });
                }
            }
            if let Some(record) = kernel.jobs.get_mut(job_id) {
                record.state = JobState::Done;
            }
            if let Some(lane_record) = kernel.lanes.get_mut(&job.lane) {
                lane_record.complete();
            }
            kernel.events.push(Event::JobCompleted {
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
            if let Some(record) = self.promises.get_mut(&promise) {
                let _ = record.reject(error);
            }
            if let Some(lane_record) = self.lanes.get_mut(&lane) {
                lane_record.complete();
            }
            self.events.push(Event::PromiseRejected { promise, code });
            self.events.push(Event::JobCompleted { job: job_id, lane });
        }
    }
}

fn pad128(id: CapId) -> [u8; 16] {
    id.0
}

/// A handle to a pending or settled result.
#[derive(Clone)]
pub struct PromiseHandle {
    agent: Agent,
    id: PromiseId,
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
