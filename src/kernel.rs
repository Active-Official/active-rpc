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
use crate::cap::{
    CapAttrs, CapControl, CapHandle, CapId, CapPersistence, CapRecord, ProviderId, ToolPolicy,
};
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

/// Global ceiling on live capabilities in one kernel.
///
/// A capability is a registry entry, so an unbounded registry is an
/// unbounded allocation a peer could drive by asking for attenuations.
pub const MAX_CAPS: usize = 65_536;

/// Ceiling on tombstoned durable record ids.
///
/// A tombstone is authority metadata that must never be evicted (eviction is
/// fail-open), so the set is bounded instead: past this point a new durable
/// capability is refused rather than letting an operator lose a kill switch.
pub const MAX_TOMBSTONES: usize = 65_536;

/// Deepest capability chain attenuation may build.
///
/// Each link copies its ancestors, so the memory of a chain grows with the
/// square of its length; a chain is also the unit revocation walks.
pub const MAX_LINEAGE_DEPTH: usize = 64;

/// Largest idempotency key a caller may present.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;

/// Aggregate payload bytes every channel in one kernel may hold.
///
/// The per-channel ceiling alone is not a memory bound: 4 096 channels of 64 MiB
/// is 256 GiB. This counter is what a sender actually pays for.
pub const MAX_QUEUED_CHANNEL_BYTES: u64 = 256 << 20;

/// Largest lane or channel name accepted, in bytes.
pub const MAX_OBJECT_NAME_BYTES: usize = 256;

/// Channels one lane may subscribe to.
pub const MAX_CHANNELS_PER_LANE: usize = 1_024;

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
    /// Provider code panicked; the kernel recovered and the panic continues.
    ProviderPanicked {
        /// Provider whose callback unwound.
        provider: ProviderId,
        /// Which callback: `invoke` or `on_drop`.
        phase: String,
    },
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
    /// Argument bytes measured when the call was queued, with promises counted
    /// at their placeholder size. Dispatch charges the difference once the
    /// promises resolve.
    args_bytes: u64,
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
    /// Drops whose provider was checked out for a call.
    deferred_drops: Vec<(ProviderId, u64, CapId)>,
    /// Reverse index: for each capability, the capabilities derived from it.
    ///
    /// Maintained on attenuation and on drop so revocation walks the subtree
    /// instead of rescanning every capability per doomed id.
    children: BTreeMap<CapId, BTreeSet<CapId>>,
    /// Reference operations that arrived while the kernel was borrowed.
    ///
    /// Shared with the handle control, which cannot borrow the kernel from a
    /// `Drop` that runs inside a dispatch phase.
    deferred_refops: Rc<std::cell::RefCell<VecDeque<(CapId, bool)>>>,
    /// True while a dispatch batch has its provider checked out.
    dispatching: bool,
    /// Providers whose `on_drop` is running right now.
    delivering: BTreeSet<ProviderId>,
    /// Payload bytes queued across every channel.
    queued_channel_bytes: u64,
    idempotency: BTreeMap<(CapId, LaneId, String, String), PromiseId>,
    allow_durable: bool,
    idempotency_order: VecDeque<(CapId, LaneId, String, String)>,
    now_ms: u64,
    latency_ms: u64,
    /// When true, dispatch advances the clock to wall time instead of by one
    /// simulated round trip. The clock never decreases in either mode.
    wall_clock: bool,
    transfers: u64,
    receipts: std::collections::VecDeque<crate::receipts::Receipt>,
    receipts_enabled: bool,
    next_receipt: u64,
    /// Deployment key that seals durable records. Without it a record cannot
    /// be exported or restored: an unverifiable credential is not accepted.
    record_key: Option<[u8; 32]>,
    /// Record ids tombstoned by a revocation.
    revoked_records: BTreeSet<[u8; 32]>,
}

/// Control half of a capability handle: reference counting and provider
/// notification. Keeping it separate from the kernel cell lets handles hold an
/// `Rc<dyn CapControl>` without exposing the kernel itself.
pub(crate) struct HandleControl {
    cell: KernelCell,
    /// Reference operations that could not take the kernel borrow.
    deferred_refops: Rc<std::cell::RefCell<VecDeque<(CapId, bool)>>>,
}

impl HandleControl {
    /// Apply one reference operation to the kernel.
    fn apply(kernel: &mut Kernel, id: CapId, retain: bool) {
        if retain {
            if let Some(record) = kernel.caps.get_mut(&id) {
                record.refs = record.refs.saturating_add(1);
                kernel.push_event(Event::CapRetained(id));
            }
            return;
        }
        let Some(record) = kernel.caps.get_mut(&id) else {
            return;
        };
        record.refs = record.refs.saturating_sub(1);
        let last = record.refs == 0;
        kernel.push_event(Event::CapReleased(id));
        if last {
            Kernel::drop_record(kernel, id);
        }
    }
}

impl HandleControl {
    /// Apply now, or queue behind earlier operations.
    ///
    /// The kernel is borrowed by the dispatch phase that is running a provider;
    /// losing an operation would leave a handle that is never matched by a
    /// release (or a release that never balances a retain). Queueing behind a
    /// non-empty queue also keeps FIFO order across the two paths: a retain
    /// queued from `on_drop` must not be overtaken by a release that can take
    /// the borrow immediately.
    fn enqueue_or_apply(&self, id: CapId, retain: bool) {
        if !self.deferred_refops.borrow().is_empty() {
            self.deferred_refops.borrow_mut().push_back((id, retain));
            return;
        }
        match self.cell.try_borrow_mut() {
            Ok(mut kernel) => {
                Self::apply(&mut kernel, id, retain);
                drop(kernel);
                // A release may have queued a provider notification; deliver it
                // now, with the borrow released.
                deliver_pending_drops(&self.cell);
            }
            Err(_) => self.deferred_refops.borrow_mut().push_back((id, retain)),
        }
    }
}

impl CapControl for HandleControl {
    fn retain(&self, id: CapId) {
        self.enqueue_or_apply(id, true);
    }

    fn release(&self, id: CapId) {
        self.enqueue_or_apply(id, false);
    }
}

/// Shared kernel cell.
pub type KernelCell = Rc<RefCell<Kernel>>;

/// Restores the kernel after one dispatch batch, on the normal path and on
/// unwind.
///
/// A provider runs with no borrow held and may panic; without this guard a
/// caught panic would leave `dispatching` set and the provider removed, so
/// every later `run()` would be a no-op and queued work would never settle.
fn deliver_pending_drops(cell: &KernelCell) {
    for _ in 0..65_536 {
        let pending: Vec<(ProviderId, u64, CapId)> = {
            let Ok(mut kernel) = cell.try_borrow_mut() else {
                return;
            };
            if kernel.dispatching {
                // An outer dispatch owns the checked-out provider; its tail
                // flushes when it is done.
                return;
            }
            std::mem::take(&mut kernel.deferred_drops)
        };
        if pending.is_empty() {
            return;
        }
        let mut requeued = 0usize;
        for (provider_id, object, cap) in pending {
            let already_delivering = match cell.try_borrow_mut() {
                Ok(mut kernel) => {
                    if kernel.delivering.contains(&provider_id) {
                        true
                    } else {
                        kernel.delivering.insert(provider_id);
                        false
                    }
                }
                Err(_) => {
                    if let Ok(mut kernel) = cell.try_borrow_mut() {
                        kernel.deferred_drops.push((provider_id, object, cap));
                    }
                    return;
                }
            };
            if already_delivering {
                // A drop raised from inside this provider's own `on_drop`. The
                // provider is not in the registry while its callback runs, so
                // the entry waits for the outer delivery to finish.
                if let Ok(mut kernel) = cell.try_borrow_mut() {
                    kernel.deferred_drops.push((provider_id, object, cap));
                }
                requeued += 1;
                continue;
            }
            let provider = match cell.try_borrow_mut() {
                Ok(mut kernel) => kernel.providers.remove(&provider_id),
                Err(_) => {
                    // Put the entry back: it was already taken out of the
                    // queue, and losing it would strand the notification.
                    if let Ok(mut kernel) = cell.try_borrow_mut() {
                        kernel.deferred_drops.push((provider_id, object, cap));
                    }
                    return;
                }
            };
            let Some(mut provider) = provider else {
                // The provider is gone: there is nobody to notify.
                if let Ok(mut kernel) = cell.try_borrow_mut() {
                    kernel.delivering.remove(&provider_id);
                }
                continue;
            };
            let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                provider.on_drop(object, cap);
            }))
            .is_err();
            if let Ok(mut kernel) = cell.try_borrow_mut() {
                kernel.providers.insert(provider_id, provider);
                kernel.delivering.remove(&provider_id);
                if unwound {
                    // `on_drop` often runs from a `Drop`; letting this panic
                    // escape would abort the process on the second one, and the
                    // provider would stay out of the registry.
                    kernel.push_event(Event::ProviderPanicked {
                        provider: provider_id,
                        phase: "on_drop".to_string(),
                    });
                }
                // The callback may have dropped handles, which queue more work.
                kernel.apply_deferred_refops();
            } else {
                return;
            }
        }
        if requeued > 0 {
            // The outer delivery owns the rest; it runs again as soon as its
            // own callback returns.
            return;
        }
    }
}

struct DispatchGuard<'a> {
    agent: &'a Agent,
    provider_id: ProviderId,
    provider: Option<Box<dyn Provider>>,
}

impl DispatchGuard<'_> {
    fn provider_mut(&mut self) -> &mut Box<dyn Provider> {
        self.provider
            .as_mut()
            .expect("the guard holds the provider")
    }
}

impl Drop for DispatchGuard<'_> {
    fn drop(&mut self) {
        let Ok(mut kernel) = self.agent.cell.try_borrow_mut() else {
            return;
        };
        kernel.dispatching = false;
        if let Some(provider) = self.provider.take() {
            kernel.providers.insert(self.provider_id, provider);
        }
    }
}

/// One agent: an owner of lanes, channels, capabilities and promises.
#[derive(Clone)]
pub struct Agent {
    cell: KernelCell,
    control: Rc<dyn CapControl>,
    /// Promise reference operations that could not take the kernel borrow.
    promise_ops: Rc<std::cell::RefCell<VecDeque<(PromiseId, bool)>>>,
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
        let deferred_refops = Rc::new(std::cell::RefCell::new(VecDeque::new()));
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
            deferred_drops: Vec::new(),
            dispatching: false,
            delivering: BTreeSet::new(),
            queued_channel_bytes: 0,
            idempotency: BTreeMap::new(),
            allow_durable: false,
            idempotency_order: VecDeque::new(),
            now_ms: 0,
            latency_ms: 1,
            wall_clock: false,
            transfers: 0,
            receipts: std::collections::VecDeque::new(),
            receipts_enabled: false,
            next_receipt: 0,
            record_key: None,
            revoked_records: BTreeSet::new(),
            children: BTreeMap::new(),
            deferred_refops: Rc::clone(&deferred_refops),
        };
        let cell: KernelCell = Rc::new(RefCell::new(kernel));
        let control: Rc<dyn CapControl> = Rc::new(HandleControl {
            cell: Rc::clone(&cell),
            deferred_refops,
        });
        Agent {
            cell,
            control,
            promise_ops: Rc::new(std::cell::RefCell::new(VecDeque::new())),
        }
    }

    /// Describe this agent's surface as a canonical Active Infinity module.
    ///
    /// The module lists provider names, granted methods and the default budget
    /// ceilings. It carries no capability ids, arguments or secrets, and its
    /// bytes are deterministic for a given provider table.
    pub fn intro(&self) -> Result<Vec<u8>> {
        let (providers, budget) = {
            let kernel = self.cell.borrow();
            let providers: Vec<(String, Vec<String>)> = kernel
                .providers
                .values()
                .map(|provider| (provider.name().to_string(), provider.methods()))
                .collect();
            (providers, Budget::default())
        };
        crate::intro::build(
            &format!("active-rpc/{}", crate::VERSION),
            &providers,
            &budget,
        )
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

    /// Set the key that seals capability records.
    ///
    /// A record is a credential: whoever can write one can mint the authority
    /// it describes. The key binds every field to the deployment, so a record
    /// that was edited, fabricated or copied from another deployment is refused
    /// before any capability is minted. Without a key the kernel exports and
    /// restores nothing, which is the fail-closed default.
    pub fn set_record_seal_key(&self, key: [u8; 32]) {
        self.cell.borrow_mut().record_key = Some(key);
    }

    /// The record seal key, if one is configured.
    fn record_key(&self) -> Option<[u8; 32]> {
        self.cell.borrow().record_key
    }

    /// Export a durable capability's authority as a record.
    ///
    /// Only a `Durable` capability can be exported, only while it is live, and
    /// only through the handle that owns it: an imported (id-only) handle has no
    /// authority of its own to persist. The record carries no capability id and
    /// no secret; it carries the capability's record id, which a revocation
    /// tombstones.
    pub fn export_capability(
        &self,
        cap: &CapHandle,
    ) -> Result<crate::persistence::CapabilityRecord> {
        if !cap.is_owning() {
            return Err(Error::persistence(
                "an imported handle cannot export authority",
            ));
        }
        let kernel = self.cell.borrow();
        let record = kernel
            .caps
            .get(&cap.id())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
        if record.attrs.persistence != CapPersistence::Durable {
            return Err(Error::persistence(
                "only a durable capability can be exported",
            ));
        }
        if !kernel.allow_durable {
            return Err(Error::persistence(
                "durable capabilities are not enabled for this agent",
            ));
        }
        if record.revoked {
            return Err(Error::Revoked(cap_token(cap.id())));
        }
        if let Some(expires_at) = record.expires_at {
            if kernel.now_ms >= expires_at {
                return Err(Error::Revoked(cap_token(cap.id())));
            }
        }
        let provider = kernel
            .providers
            .get(&record.provider)
            .ok_or_else(|| Error::persistence("the provider is no longer registered"))?;
        let key = kernel
            .record_key
            .ok_or_else(|| Error::persistence("no record seal key is configured"))?;
        if record.attrs.bound_to.is_none() {
            // A credential that names no peer would restore for anybody. The
            // record's binding is a snapshot, so an earlier unbound export
            // would also escape a later `introduce_to`.
            return Err(Error::Identity(
                "a durable record must name the peer it was bound to",
            ));
        }
        // A record describes what is left, not what was granted: a durable
        // credential must not be a way to refill a spent grant.
        let meter = kernel
            .meters
            .get(&record.id)
            .ok_or_else(|| Error::persistence("the capability has no meter"))?;
        let remaining_calls = meter.remaining_calls();
        let remaining_bytes = record.attrs.budget.max_bytes.saturating_sub(meter.bytes());
        if remaining_calls == 0 || remaining_bytes == 0 {
            return Err(Error::persistence("the capability's grant is spent"));
        }
        if record
            .attrs
            .path_scope
            .as_deref()
            .is_some_and(str::is_empty)
        {
            // `from_json` refuses an empty scope, so such a record could never
            // be restored: refuse it at the source instead of writing it.
            return Err(Error::persistence("an empty path scope is not a scope"));
        }
        let mut record = crate::persistence::CapabilityRecord {
            provider: provider.name().to_string(),
            object: record.object,
            methods: record.attrs.methods.clone(),
            budget: crate::budget::Budget {
                max_calls: remaining_calls,
                max_bytes: remaining_bytes,
                ..record.attrs.budget
            },
            read_only: record.attrs.read_only,
            redact: record.attrs.redact,
            path_scope: record.attrs.path_scope.clone(),
            topics: record.attrs.topics.clone(),
            tool_policy: record.attrs.tool_policy.clone(),
            bound_to: record.attrs.bound_to,
            expires_at: record.expires_at,
            wall_clock: record.wall_clock,
            lease_ms: record
                .expires_at
                .map(|expires_at| expires_at.saturating_sub(kernel.now_ms)),
            record_id: record.record_id,
            seal: None,
        };
        record.seal_with(&key);
        Ok(record)
    }

    /// Restore a durable capability as a fresh, peer-bound capability.
    ///
    /// The restored capability has a new id (ids are kernel-specific), the
    /// recorded authority, the original absolute deadline and a binding to
    /// `peer`. Restoring is refused unless durable capabilities are enabled, a
    /// record seal key is configured, the record's seal verifies, its record id
    /// was never tombstoned by a revocation, the provider is registered, the
    /// deadline has not passed and the record is not bound to a different peer.
    /// A record alone is therefore not authority: it must have been sealed by
    /// this deployment, and the peer must be admitted too.
    pub fn restore_capability(
        &self,
        record: &crate::persistence::CapabilityRecord,
        peer: &crate::identity::AdmittedIdentity,
    ) -> Result<CapHandle> {
        if !self.durable_capabilities_allowed() {
            return Err(Error::persistence(
                "durable capabilities are not enabled for this agent",
            ));
        }
        let key = self
            .record_key()
            .ok_or_else(|| Error::persistence("no record seal key is configured"))?;
        // The seal comes before every other field: a forged record must not be
        // able to steer which check reports the refusal.
        if !record.seal_is_valid(&key) {
            return Err(Error::persistence(
                "the record is not sealed by this deployment",
            ));
        }
        {
            let kernel = self.cell.borrow();
            if kernel.revoked_records.contains(&record.record_id) {
                return Err(Error::Revoked(record_token(&record.record_id)));
            }
        }
        // The binding is about the caller, so it is reported before any state
        // of this kernel. A record that names no peer would restore for anyone.
        let Some(bound) = record.bound_to else {
            return Err(Error::Identity("the record names no peer"));
        };
        if bound != peer.fingerprint() {
            return Err(Error::Identity("the record is bound to a different peer"));
        }
        // Restoring is a re-mint, so N restores of one credential would be N
        // independent grants that a single revocation cannot reach.
        if self
            .cell
            .borrow()
            .caps
            .values()
            .any(|live| live.record_id == record.record_id && !live.revoked)
        {
            return Err(Error::persistence("the record is already live"));
        }
        let provider = {
            let kernel = self.cell.borrow();
            let mut matches = kernel
                .providers
                .iter()
                .filter(|(_, provider)| provider.name() == record.provider)
                .map(|(id, _)| *id);
            let first = matches
                .next()
                .ok_or_else(|| Error::persistence("the record names an unknown provider"))?;
            if matches.next().is_some() {
                return Err(Error::persistence(
                    "the record's provider name is ambiguous",
                ));
            }
            first
        };
        // A bounded deadline is expressed in the exporting kernel's clock
        // domain; interpreting it in the other mode turns a short lease into
        // an effectively unbounded one.
        if record.expires_at.is_some() && record.wall_clock != self.uses_wall_clock() {
            return Err(Error::persistence(
                "the record's clock mode differs from this kernel's",
            ));
        }
        let now = self.cell.borrow().now_ms;
        let ttl_ms = match record.expires_at {
            Some(expires_at) if expires_at <= now => {
                return Err(Error::persistence("the record's deadline has passed"))
            }
            Some(expires_at) => {
                // Two virtual clocks have unrelated epochs: the absolute
                // deadline alone would stretch the lease across a restart, so
                // the sealed remaining lifetime is the ceiling.
                let Some(lease) = record.lease_ms else {
                    return Err(Error::persistence("a bounded record carries no lease"));
                };
                Some((expires_at - now).min(lease))
            }
            None => None,
        };
        let attrs = record.attrs(ttl_ms);
        let restored = self.mint_restored(peer, provider, record.object, attrs)?;
        // Keep the record identity: a revocation that reaches this capability
        // must tombstone the same record id the credential carries.
        if let Some(live) = self.cell.borrow_mut().caps.get_mut(&restored.id()) {
            live.record_id = record.record_id;
        }
        Ok(restored)
    }

    /// The kernel's current logical time, in milliseconds.
    ///
    /// Always monotonic. In the default (virtual) mode it advances by one
    /// simulated round trip per dispatch; in wall-clock mode it tracks
    /// `SystemTime` and never moves backwards.
    pub fn now_ms(&self) -> u64 {
        self.cell.borrow().now_ms
    }

    /// Select the clock the kernel uses for deadlines.
    ///
    /// The default is virtual: deterministic and replayable. Wall-clock mode is
    /// for a long-running agent that mints capabilities whose lifetime must
    /// follow real time. Enabling it jumps `now_ms` forward to the wall clock
    /// (never backwards), so a pending deadline can only expire earlier, never
    /// later. Disabling it keeps the current time and returns to simulated
    /// advancement.
    pub fn use_wall_clock(&self, enabled: bool) {
        let mut kernel = self.cell.borrow_mut();
        kernel.wall_clock = enabled;
        if enabled {
            kernel.now_ms = kernel.now_ms.max(wall_now_ms());
        }
    }

    /// Whether the kernel follows the wall clock.
    pub fn uses_wall_clock(&self) -> bool {
        self.cell.borrow().wall_clock
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
            return Err(Error::persistence(
                "durable capabilities are not enabled for this agent",
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
        if kernel.caps.len() >= MAX_CAPS {
            return Err(Error::BudgetExceeded("caps"));
        }
        if attrs.persistence == crate::cap::CapPersistence::Durable
            && durable_ceiling_reached(&kernel)
        {
            return Err(Error::BudgetExceeded("tombstones"));
        }
        let serial = kernel.next_serial;
        kernel.next_serial += 1;
        let id = CapId::derive(&kernel.secret, serial, None);
        let expires_at = attrs.ttl_ms.map(|ttl| kernel.now_ms.saturating_add(ttl));
        let mut record = CapRecord::new(id, provider, object, attrs.clone());
        record.expires_at = expires_at;
        record.wall_clock = kernel.wall_clock;
        record.record_id = CapId::derive_record(&kernel.secret, serial, None);
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
        if attrs
            .bound_to
            .is_some_and(|bound| bound != peer.fingerprint())
        {
            return Err(Error::Identity(
                "the capability is already bound to a different peer",
            ));
        }
        self.mint(provider, object, attrs.bound_to(peer.fingerprint()))
    }

    /// Mint a restored capability, bypassing the tombstone ceiling.
    ///
    /// A restore adds no tombstone and consumes no new record id, so a full
    /// kill list must not turn a valid credential into a budget error.
    fn mint_restored(
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
        let attrs = attrs.bound_to(peer.fingerprint());
        attrs.budget.check()?;
        if attrs.methods.is_empty() {
            return Err(Error::InvalidArgument("capability grants no methods"));
        }
        let mut kernel = self.cell.borrow_mut();
        if !kernel.providers.contains_key(&provider) {
            return Err(Error::InvalidArgument("unknown provider"));
        }
        if kernel.caps.len() >= MAX_CAPS {
            return Err(Error::BudgetExceeded("caps"));
        }
        let serial = kernel.next_serial;
        kernel.next_serial += 1;
        let id = CapId::derive(&kernel.secret, serial, None);
        let expires_at = attrs.ttl_ms.map(|ttl| kernel.now_ms.saturating_add(ttl));
        let mut record = CapRecord::new(id, provider, object, attrs.clone());
        record.expires_at = expires_at;
        record.wall_clock = kernel.wall_clock;
        record.record_id = CapId::derive_record(&kernel.secret, serial, None);
        kernel.meters.insert(id, BudgetMeter::new(attrs.budget));
        kernel.caps.insert(id, record);
        kernel.push_event(Event::CapMinted { cap: id, provider });
        Ok(CapHandle::new(Rc::clone(&self.control), id))
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
        let (revoked, expired, already_bound) = {
            let record = kernel
                .caps
                .get(&cap.id())
                .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
            (
                record.revoked,
                record
                    .expires_at
                    .is_some_and(|expires_at| kernel.now_ms >= expires_at),
                record.attrs.bound_to,
            )
        };
        if revoked {
            return Err(Error::Revoked(cap_token(cap.id())));
        }
        if expired {
            kernel.push_event(Event::CapExpired(cap.id()));
            return Err(Error::Revoked(cap_token(cap.id())));
        }
        match already_bound {
            Some(bound) if bound != fingerprint => {
                return Err(Error::Identity(
                    "capability is already bound to another peer",
                ))
            }
            _ => {}
        }
        let record = kernel
            .caps
            .get_mut(&cap.id())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
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
        if record
            .expires_at
            .is_some_and(|expires_at| kernel.now_ms >= expires_at)
        {
            kernel.push_event(Event::CapExpired(parent_id));
            return Err(Error::Revoked(cap_token(parent_id)));
        }
        attrs.budget.check()?;
        if !kernel.allow_durable
            && (record.attrs.persistence == CapPersistence::Durable
                || attrs.persistence == CapPersistence::Durable)
        {
            return Err(Error::persistence(
                "durable capabilities are not enabled for this agent",
            ));
        }
        if attrs.persistence == CapPersistence::Durable && durable_ceiling_reached(&kernel) {
            return Err(Error::BudgetExceeded("tombstones"));
        }
        if kernel.caps.len() >= MAX_CAPS {
            return Err(Error::BudgetExceeded("caps"));
        }
        if record.lineage.len() >= MAX_LINEAGE_DEPTH {
            return Err(Error::Escalation("capability chain is too deep"));
        }
        if record.expires_at.is_some() && record.wall_clock != kernel.wall_clock {
            // The parent's absolute deadline lives in another clock domain; the
            // clamp below would mix the two.
            return Err(Error::InvalidArgument(
                "the parent's deadline is in another clock domain",
            ));
        }
        let attrs = record.attrs.attenuate(attrs)?;
        let serial = kernel.next_serial;
        kernel.next_serial += 1;
        let id = CapId::derive(&kernel.secret, serial, Some(&parent_id));
        let mut child = CapRecord::new(id, record.provider, record.object, attrs.clone());
        child.parent = Some(parent_id);
        child.record_id = CapId::derive_record(&kernel.secret, serial, Some(&parent_id));
        child.lineage = record.lineage.clone();
        child.lineage.push(parent_id);
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
        child.wall_clock = kernel.wall_clock;
        // Every ancestor now has a live descendant: its record and meter must
        // survive the parent handle, or the subtree's budget is freed and each
        // child spends the grant again.
        for ancestor in &child.lineage {
            if let Some(parent_record) = kernel.caps.get_mut(ancestor) {
                parent_record.descendants = parent_record.descendants.saturating_add(1);
            }
            kernel.children.entry(*ancestor).or_default().insert(id);
        }
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
    ///
    /// The subtree is found once, through a parent/lineage index, instead of
    /// rescanning every capability per doomed id: revoking a wide tree is a
    /// linear walk. Each doomed record also tombstones its durable record id,
    /// so a record exported before the revocation cannot restore the authority.
    pub fn revoke(&self, cap: &CapHandle) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        let id = cap.id();
        if !kernel.caps.contains_key(&id) {
            return Err(Error::UnknownCapability(cap_token(id)));
        }
        let mut doomed = BTreeSet::new();
        let mut stack = vec![id];
        while let Some(id) = stack.pop() {
            if !doomed.insert(id) {
                continue;
            }
            if let Some(descendants) = kernel.children.get(&id) {
                stack.extend(descendants.iter().copied());
            }
        }
        // Every capability restored from the same record is revoked with it: a
        // peer that restored twice before the kill switch must not keep a copy.
        let record_ids: BTreeSet<[u8; 32]> = doomed
            .iter()
            .filter_map(|id| kernel.caps.get(id).map(|record| record.record_id))
            .collect();
        for (id, record) in &kernel.caps {
            if record_ids.contains(&record.record_id) {
                doomed.insert(*id);
            }
        }
        for id in doomed {
            let record_id = match kernel.caps.get_mut(&id) {
                Some(record) => {
                    record.revoked = true;
                    // Only a durable record can ever be restored, so only its
                    // id needs a tombstone; an ephemeral one would leak an
                    // entry per mint/revoke cycle forever.
                    if record.attrs.persistence == CapPersistence::Durable {
                        Some(record.record_id)
                    } else {
                        None
                    }
                }
                None => None,
            };
            if let Some(record_id) = record_id {
                kernel.revoked_records.insert(record_id);
            }
            kernel.push_event(Event::CapRevoked(id));
            kernel.metrics.revocations = kernel.metrics.revocations.saturating_add(1);
        }
        Ok(())
    }

    /// Record a revocation tombstone from a deployment's persistent store.
    ///
    /// Tombstones live in memory, so process restarts would otherwise resurrect
    /// every exported record. A deployment replays its kill list here at
    /// startup; the ceiling is checked so the set can never grow without bound.
    pub fn tombstone_record(&self, record_id: [u8; 32]) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        if kernel.revoked_records.len() >= MAX_TOMBSTONES
            && !kernel.revoked_records.contains(&record_id)
        {
            return Err(Error::BudgetExceeded("tombstones"));
        }
        kernel.revoked_records.insert(record_id);
        Ok(())
    }

    /// Number of tombstoned durable record ids, for operators and tests.
    pub fn record_tombstone_count(&self) -> usize {
        self.cell.borrow().revoked_records.len()
    }

    /// True when a record id was tombstoned by a revocation.
    pub fn record_is_tombstoned(&self, record_id: &[u8; 32]) -> bool {
        self.cell.borrow().revoked_records.contains(record_id)
    }

    /// Create a lane.
    pub fn create_lane(&self, name: impl Into<String>, budget: Budget) -> Result<LaneId> {
        budget.check()?;
        let name = name.into();
        if name.len() > MAX_OBJECT_NAME_BYTES {
            return Err(Error::InvalidArgument("lane name is too long"));
        }
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
        // A set: `doomed.contains` inside `retain` is quadratic, and a full
        // lane (100 000 queued jobs) is exactly the case that matters.
        let doomed: BTreeSet<u64> = kernel
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
        let orphaned: Vec<PromiseId> = kernel
            .jobs
            .values()
            .filter(|job| job.lane == lane)
            .flat_map(|job| job.deps.clone())
            .collect();
        Kernel::release_waiters(&mut kernel, &orphaned);
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
        let removed = kernel
            .channels
            .remove(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        kernel.queued_channel_bytes = kernel
            .queued_channel_bytes
            .saturating_sub(removed.queued_bytes());
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
        let name = name.into();
        if name.len() > MAX_OBJECT_NAME_BYTES {
            return Err(Error::InvalidArgument("channel name is too long"));
        }
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

    /// Close a channel: further sends are refused, queued messages stay
    /// receivable.
    ///
    /// [`Agent::channel`] returns a snapshot, so closing the snapshot would
    /// leave the kernel's channel live.
    pub fn close_channel(&self, channel: ChannelId) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        record.close();
        Ok(())
    }

    /// Subscribe a lane to a channel.
    pub fn subscribe(&self, lane: LaneId, channel: ChannelId) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
        if lane_record.closed {
            return Err(Error::UnknownLane(lane.0));
        }
        kernel
            .channels
            .get(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        if let Some(lane) = kernel.lanes.get_mut(&lane) {
            if lane.channels.len() >= MAX_CHANNELS_PER_LANE && !lane.channels.contains(&channel.0) {
                return Err(Error::BudgetExceeded("subscriptions"));
            }
            lane.channels.insert(channel.0);
        }
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        record.subscribers.insert(lane.0);
        Ok(())
    }

    /// Count and log a refused send or publish, exactly as a refused call is.
    fn note_refusal(&self, lane: LaneId, cap: Option<CapId>, result: Result<u64>) -> Result<u64> {
        if let Err(error) = &result {
            let mut kernel = self.cell.borrow_mut();
            kernel.metrics.calls_refused = kernel.metrics.calls_refused.saturating_add(1);
            if matches!(error, Error::BudgetExceeded(_)) {
                kernel.metrics.budget_exhaustions =
                    kernel.metrics.budget_exhaustions.saturating_add(1);
            }
            kernel.push_event(Event::CallRefused {
                lane,
                cap: cap.unwrap_or(CapId([0u8; 16])),
                code: error.code().to_string(),
            });
        }
        result
    }

    /// Send a message, transferring capabilities with it.
    pub fn send(
        &self,
        lane: LaneId,
        channel: ChannelId,
        payload: Value,
        caps: &[CapHandle],
    ) -> Result<u64> {
        let result = self.send_as(None, lane, channel, payload, caps);
        self.note_refusal(lane, caps.first().map(CapHandle::id), result)
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
        let (lane_closed, lane_budget, lane_bytes, lane_capacity) = {
            let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
            (
                lane_record.closed,
                lane_record.budget,
                lane_record.bytes,
                lane_record.has_capacity(),
            )
        };
        if lane_closed {
            return Err(Error::UnknownLane(lane.0));
        }
        if !lane_capacity {
            return Err(Error::BudgetExceeded("lane call"));
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
            if cap_ids.contains(&cap.id()) {
                return Err(Error::InvalidArgument(
                    "a message cannot transfer the same capability twice",
                ));
            }
            let record = kernel
                .caps
                .get(&cap.id())
                .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
            if record.revoked {
                return Err(Error::Revoked(cap_token(cap.id())));
            }
            if record
                .expires_at
                .is_some_and(|expires_at| kernel.now_ms >= expires_at)
            {
                kernel.push_event(Event::CapExpired(cap.id()));
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
        // A message is lane traffic like a call: the lane's byte and call
        // ceilings bound it, and every transferred id costs its wire size. A
        // lane that spends nothing while filling a channel would let 4 096
        // messages of 64 MiB sit in kernel memory it never paid for.
        let bytes = payload
            .wire_size()
            .saturating_add((cap_ids.len() as u64).saturating_mul(16));
        if bytes > lane_budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        if lane_bytes.saturating_add(bytes) > lane_budget.max_bytes {
            return Err(Error::BudgetExceeded("lane byte"));
        }
        // Channel capacity is checked before the lane and the meters are
        // charged: a refused send must not spend the sender's grant.
        if !channel_record.has_room_for(bytes) {
            kernel.metrics.backpressure_refusals =
                kernel.metrics.backpressure_refusals.saturating_add(1);
            return Err(Error::Backpressure("channel byte ceiling reached"));
        }
        if kernel.queued_channel_bytes.saturating_add(bytes) > MAX_QUEUED_CHANNEL_BYTES {
            kernel.metrics.backpressure_refusals =
                kernel.metrics.backpressure_refusals.saturating_add(1);
            return Err(Error::Backpressure("the kernel's channel byte ceiling"));
        }
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let sequence = record.send_sequence(lane, payload, cap_ids.clone())?;
        kernel.queued_channel_bytes = kernel.queued_channel_bytes.saturating_add(bytes);
        if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
            lane_record.bytes = lane_record.bytes.saturating_add(bytes);
            lane_record.completed = lane_record.completed.saturating_add(1);
        }
        kernel.push_event(Event::ChannelSend { channel, sequence });
        for id in cap_ids {
            kernel.transfers += 1;
            kernel.push_event(Event::CapTransferred { cap: id, channel });
        }
        Ok(sequence)
    }

    /// Publish a message on a topic under a capability.
    ///
    /// The capability is the authority: it must be live (not revoked and not
    /// expired), and when it carries a topic set the topic must be in it. A
    /// capability bound to a peer publishes only through
    /// [`Agent::publish_as`]: a channel cannot prove who published, so an
    /// unauthenticated publish cannot exercise a bound capability. The payload
    /// is charged against the capability's byte budget intersected with the
    /// lane's. The message transfers no capabilities; use [`Agent::send`] for
    /// that.
    pub fn publish(
        &self,
        lane: LaneId,
        channel: ChannelId,
        cap: &CapHandle,
        topic: &str,
        payload: Value,
    ) -> Result<u64> {
        let result = self.publish_as(None, lane, channel, cap, topic, payload);
        self.note_refusal(lane, Some(cap.id()), result)
    }

    /// [`Agent::publish`] on behalf of the peer the transport authenticated.
    pub fn publish_as(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        channel: ChannelId,
        cap: &CapHandle,
        topic: &str,
        payload: Value,
    ) -> Result<u64> {
        let mut kernel = self.cell.borrow_mut();
        let (lane_closed, lane_budget, lane_bytes, lane_capacity) = {
            let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
            (
                lane_record.closed,
                lane_record.budget,
                lane_record.bytes,
                lane_record.has_capacity(),
            )
        };
        if lane_closed {
            return Err(Error::UnknownLane(lane.0));
        }
        if !lane_capacity {
            return Err(Error::BudgetExceeded("lane call"));
        }
        let record = kernel
            .caps
            .get(&cap.id())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))?
            .clone();
        if record.revoked {
            return Err(Error::Revoked(cap_token(cap.id())));
        }
        if record
            .expires_at
            .is_some_and(|expires_at| kernel.now_ms >= expires_at)
        {
            kernel.push_event(Event::CapExpired(cap.id()));
            return Err(Error::Revoked(cap_token(cap.id())));
        }
        if record.attrs.bound_to.is_some() {
            let presented = peer.map(|identity| identity.fingerprint());
            if presented != record.attrs.bound_to {
                return Err(Error::Identity(
                    "capability is bound to a different peer identity",
                ));
            }
        }
        if record.attrs.read_only {
            // Publishing writes to a channel; a read-only grant cannot mutate.
            return Err(Error::ReadOnly);
        }
        if let Some(topics) = &record.attrs.topics {
            if !topics.contains(topic) {
                return Err(Error::TopicNotGranted(topic.to_string()));
            }
        }
        // Channel state is checked before the budget is charged: a refused
        // publish must not consume the capability's bytes.
        let (can_send, queued) = {
            let channel_record = kernel
                .channels
                .get(&channel)
                .ok_or(Error::UnknownChannel(channel.0))?;
            (channel_record.can_send(), channel_record.queued())
        };
        if !can_send {
            return Err(Error::InvalidArgument("channel is closed or receive-only"));
        }
        let ceiling = kernel.channel_ceiling;
        if queued >= ceiling {
            kernel.metrics.backpressure_refusals =
                kernel.metrics.backpressure_refusals.saturating_add(1);
            return Err(Error::Backpressure("channel queue ceiling reached"));
        }
        // The topic name is metadata the channel stores and forwards, so it is
        // payload as far as the grant is concerned: charging only the value let
        // a 1 KiB topic ride through a 32-byte budget.
        let bytes = payload.wire_size().saturating_add(topic.len() as u64);
        // Channel capacity comes before the charge: a publish the channel would
        // refuse must not spend the grant or queue nothing silently.
        {
            let channel_record = kernel
                .channels
                .get(&channel)
                .ok_or(Error::UnknownChannel(channel.0))?;
            if !channel_record.has_room_for(bytes) {
                kernel.metrics.backpressure_refusals =
                    kernel.metrics.backpressure_refusals.saturating_add(1);
                return Err(Error::Backpressure("channel byte ceiling reached"));
            }
        }
        if kernel.queued_channel_bytes.saturating_add(bytes) > MAX_QUEUED_CHANNEL_BYTES {
            kernel.metrics.backpressure_refusals =
                kernel.metrics.backpressure_refusals.saturating_add(1);
            return Err(Error::Backpressure("the kernel's channel byte ceiling"));
        }
        let effective = record.attrs.budget.intersect(&lane_budget);
        if bytes > effective.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        if lane_bytes.saturating_add(bytes) > lane_budget.max_bytes {
            return Err(Error::BudgetExceeded("lane byte"));
        }
        // A publish is a call through the capability and through every
        // ancestor, exactly like `call_inner`.
        let mut chain: Vec<CapId> = record.lineage.clone();
        chain.push(cap.id());
        for id in &chain {
            if let Some(meter) = kernel.meters.get(id) {
                meter.check(bytes)?;
            }
        }
        for id in &chain {
            if let Some(meter) = kernel.meters.get_mut(id) {
                meter.charge(bytes)?;
            }
        }
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let message = record.send_topic(lane, Some(topic), payload, Vec::new())?;
        kernel.queued_channel_bytes = kernel.queued_channel_bytes.saturating_add(bytes);
        if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
            lane_record.bytes = lane_record.bytes.saturating_add(bytes);
            lane_record.completed = lane_record.completed.saturating_add(1);
        }
        kernel.push_event(Event::ChannelSend {
            channel,
            sequence: message.sequence,
        });
        Ok(message.sequence)
    }

    /// Receive the next message published on `topic`.
    pub fn recv_topic(&self, channel: ChannelId, topic: &str) -> Result<Option<Message>> {
        let mut kernel = self.cell.borrow_mut();
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let message = record.recv_topic(topic)?;
        if let Some(message) = &message {
            let bytes =
                Channel::message_bytes(&message.payload, &message.caps, message.topic.as_deref());
            kernel.queued_channel_bytes = kernel.queued_channel_bytes.saturating_sub(bytes);
            kernel.push_event(Event::ChannelRecv {
                channel,
                sequence: message.sequence,
            });
        }
        Ok(message)
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
            let bytes =
                Channel::message_bytes(&message.payload, &message.caps, message.topic.as_deref());
            kernel.queued_channel_bytes = kernel.queued_channel_bytes.saturating_sub(bytes);
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
        let (lane_closed, lane_capacity, lane_budget, lane_bytes) = {
            let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
            (
                lane_record.closed,
                lane_record.has_capacity(),
                lane_record.budget,
                lane_record.bytes,
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
            .ok_or(Error::Provider {
                code: "rpc/provider".to_string(),
            })?;
        if !provider.has_method(method) {
            return Err(Error::MethodNotGranted {
                method: method.to_string(),
            });
        }
        if record.attrs.read_only && provider.mutating(method) {
            return Err(Error::ReadOnly);
        }
        // Path scope is enforced here, before the provider sees the call. The
        // walk is recursive: a `Path` nested in a list or map is the same
        // argument to a provider that flattens it.
        if let Some(scope) = &record.attrs.path_scope {
            for arg in &args {
                if let Arg::Value(value) = arg {
                    if let Some(path) = path_outside_scope(value, scope) {
                        return Err(Error::PathNotGranted(path));
                    }
                }
            }
        }
        // Tool policy is enforced here too.
        let args_bytes: u64 = args.iter().map(Arg::wire_size).sum();
        if let Some(policy) = &record.attrs.tool_policy {
            if !policy.allowed.contains(method) {
                return Err(Error::ToolPolicy("tool not allowed"));
            }
            // Count every argument shape, recursively: a nested list or map
            // must not slip past the tool's payload ceiling.
            if args_bytes > policy.max_arg_bytes {
                return Err(Error::ToolPolicy("argument too large"));
            }
        }
        let call_bytes: u64 = args_bytes.saturating_add(payload_bytes);
        let effective = record.attrs.budget.intersect(&lane_budget);
        if call_bytes > effective.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        // A lane's byte ceiling is cumulative, not a per-call limit: otherwise
        // any number of calls each just under it would pass.
        if lane_bytes.saturating_add(call_bytes) > lane_budget.max_bytes {
            return Err(Error::BudgetExceeded("lane byte"));
        }
        // Every dependency must exist before anything is charged, recorded or
        // receipted: a refused call must leave no trace and cost nothing.
        let deps: Vec<PromiseId> = args.iter().filter_map(|arg| arg.promise()).collect();
        for dep in &deps {
            // A promise is the private result of one lane. Accepting an id from
            // another lane would deliver that lane's value to this caller and
            // turn the id space into a membership oracle.
            match kernel.promises.get(dep) {
                Some(record) if record.lane == lane.0 => {}
                _ => return Err(Error::UnknownPromise(dep.0)),
            }
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
        // The budget of a capability bounds its whole subtree: a call through a
        // child is also a call through every ancestor, so the grant of a parent
        // is not multiplied by the branching factor of its delegations. Every
        // meter in the chain is checked before any is charged.
        let mut chain: Vec<CapId> = record.lineage.clone();
        chain.push(cap_id);
        for id in &chain {
            if let Some(meter) = kernel.meters.get(id) {
                meter.check(call_bytes)?;
            }
        }
        for id in &chain {
            if let Some(meter) = kernel.meters.get_mut(id) {
                meter.charge(call_bytes)?;
            }
        }
        if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
            lane_record.bytes = lane_record.bytes.saturating_add(call_bytes);
        }

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
        for dep in &deps {
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
            args_bytes,
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
        self.flush_promise_refops();
        self.flush_drops();
        loop {
            let batch = {
                let mut kernel = self.cell.borrow_mut();
                if kernel.dispatching {
                    // A provider called back into `run`. Its own provider is
                    // checked out, so a nested batch could not run and must not
                    // fail the queued work; the outer dispatch continues.
                    return kernel.round_trips;
                }
                if kernel.queue.is_empty() {
                    kernel.apply_deferred_refops();
                    kernel.trim_settled();
                    return kernel.round_trips;
                }
                // Reference operations that arrived during a provider call are
                // applied before the next batch is chosen.
                kernel.apply_deferred_refops();
                match kernel.next_batch() {
                    Ok(batch) if batch.is_empty() => {
                        kernel.apply_deferred_refops();
                        kernel.trim_settled();
                        return kernel.round_trips;
                    }
                    Ok(batch) => batch,
                    Err(stuck) => {
                        // Only the jobs that cannot be ordered are failed; work
                        // for other providers stays queued.
                        for job_id in stuck {
                            let error = match kernel.jobs.get(&job_id) {
                                Some(job) if kernel.caps.contains_key(&job.cap) => {
                                    Error::PipelinedCycle
                                }
                                Some(job) => Error::UnknownCapability(cap_token(job.cap)),
                                None => Error::PipelinedCycle,
                            };
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
        if self.cell.borrow().dispatching {
            // A provider is running and the kernel cannot make progress for it:
            // the outer dispatch owns the queue. Spinning here would burn CPU
            // with no error and no settlement, and `rpc/provider` would invite
            // a retry of work that never ran.
            return Err(Error::UnresolvablePromise(promise.id.0));
        }
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
        let settled = {
            let record = kernel
                .promises
                .get_mut(&promise.id)
                .ok_or(Error::UnknownPromise(promise.id.0))?;
            record.resolve(value)
        };
        if settled.is_err() {
            kernel.metrics.promises_double_settled =
                kernel.metrics.promises_double_settled.saturating_add(1);
        }
        settled?;
        // A promise answered out of band must not still run its provider: the
        // side effect would happen after the caller already has the answer.
        if let Some(job_id) = kernel
            .jobs
            .iter()
            .find(|(id, job)| job.promise == promise.id && kernel.queue.contains(id))
            .map(|(id, _)| *id)
        {
            kernel.queue.retain(|queued| *queued != job_id);
            let lane = kernel.jobs.get(&job_id).map(|job| job.lane);
            let deps = kernel
                .jobs
                .get(&job_id)
                .map(|job| job.deps.clone())
                .unwrap_or_default();
            Kernel::release_waiters(&mut kernel, &deps);
            kernel.jobs.remove(&job_id);
            if let Some(lane) = lane {
                if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
                    lane_record.complete();
                }
            }
        }
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

    /// Issue the call an envelope describes, from a transport.
    ///
    /// An envelope is peer input, so its arguments cannot carry authority: a
    /// promise id would name a result this kernel computed for someone else,
    /// and a capability id in an argument is opaque data, not a grant. Both are
    /// refused as `rpc/wire`, and the envelope payload is charged like any
    /// other call.
    pub fn call_from_envelope(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        envelope: &crate::wire::Envelope,
    ) -> Result<PromiseHandle> {
        for arg in &envelope.args {
            if matches!(arg, Arg::Promise(_) | Arg::Cap(_)) {
                return Err(Error::Wire(
                    "an envelope cannot carry a promise or capability argument",
                ));
            }
        }
        self.call_as_with_payload(
            peer,
            lane,
            cap,
            &envelope.method,
            envelope.args.clone(),
            envelope.payload.len() as u64,
        )
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
        self.call_idempotent_as(None, lane, cap, method, args, key)
    }

    /// [`Agent::call_idempotent`] on behalf of the peer the transport
    /// authenticated.
    ///
    /// A replay is a fresh exercise of the same authority: it re-checks that the
    /// capability is live and, when it is bound, that the caller is the bound
    /// peer. Caching the promise must not turn a revoked or rebound capability
    /// back on.
    pub fn call_idempotent_as(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        key: &str,
    ) -> Result<PromiseHandle> {
        if key.is_empty() {
            return Err(Error::InvalidArgument("idempotency key is empty"));
        }
        if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            return Err(Error::InvalidArgument("idempotency key is too long"));
        }
        // A replay is an exercise of authority in one lane: the key is scoped
        // to it, and the lane must still exist and have capacity, exactly as a
        // fresh call requires.
        {
            let kernel = self.cell.borrow();
            let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
            if lane_record.closed {
                return Err(Error::UnknownLane(lane.0));
            }
            if !lane_record.has_capacity() {
                return Err(Error::BudgetExceeded("lane call"));
            }
        }
        let map_key = (cap.id(), lane, method.to_string(), key.to_string());
        {
            let mut kernel = self.cell.borrow_mut();
            if let Some(id) = kernel.idempotency.get(&map_key).copied() {
                {
                    let record = kernel
                        .caps
                        .get(&cap.id())
                        .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
                    if record.revoked {
                        return Err(Error::Revoked(cap_token(cap.id())));
                    }
                    if record
                        .expires_at
                        .is_some_and(|expires_at| kernel.now_ms >= expires_at)
                    {
                        kernel.push_event(Event::CapExpired(cap.id()));
                        return Err(Error::Revoked(cap_token(cap.id())));
                    }
                    if let Some(bound) = record.attrs.bound_to {
                        let presented = peer.map(|identity| identity.fingerprint());
                        if presented != Some(bound) {
                            return Err(Error::Identity(
                                "capability is bound to a different peer identity",
                            ));
                        }
                    }
                }
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
            // A stale entry leaves its key in the order deque; without this the
            // deque grows with caller-controlled keys.
            kernel.idempotency_order.retain(|queued| *queued != map_key);
        }
        let promise = self.call_as(peer, lane, cap, method, args)?;
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
        // A job in the current dispatch batch is no longer in the queue, so it
        // cannot be stopped and must not be completed here: its settlement path
        // owns the lane accounting.
        let queued: Option<u64> = kernel
            .jobs
            .iter()
            .find(|(id, job)| job.promise == promise.id && kernel.queue.contains(id))
            .map(|(id, _)| *id);
        if let Some(job_id) = queued {
            kernel.queue.retain(|id| *id != job_id);
            let lane = kernel.jobs.get(&job_id).map(|job| job.lane);
            let deps = kernel
                .jobs
                .get(&job_id)
                .map(|job| job.deps.clone())
                .unwrap_or_default();
            Kernel::release_waiters(&mut kernel, &deps);
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

        // One reverse index instead of a scan per target: a deep chain is the
        // normal shape of a pipeline, and a scan per link is quadratic.
        let mut dependents_of: BTreeMap<PromiseId, Vec<PromiseId>> = BTreeMap::new();
        for job in kernel.jobs.values() {
            for dep in &job.deps {
                dependents_of.entry(*dep).or_default().push(job.promise);
            }
        }
        let mut targets = vec![promise.id];
        let mut seen: BTreeSet<PromiseId> = BTreeSet::new();
        seen.insert(promise.id);
        let mut index = 0;
        while index < targets.len() {
            let id = targets[index];
            if let Some(record) = kernel.promises.get_mut(&id) {
                if record.state == PromiseState::Pending {
                    record.cancel()?;
                }
            }
            if let Some(dependents) = dependents_of.get(&id) {
                for dependent in dependents {
                    if seen.insert(*dependent) {
                        targets.push(*dependent);
                    }
                }
            }
            index += 1;
        }

        let targets_set: BTreeSet<PromiseId> = seen;
        let queued: Vec<(u64, PromiseId, u64)> = kernel
            .jobs
            .iter()
            .filter(|(id, job)| kernel.queue.contains(id) && targets_set.contains(&job.promise))
            .map(|(id, job)| (*id, job.promise, job.lane.0))
            .collect();
        for (job_id, promise_id, lane) in queued {
            kernel.queue.retain(|queued_id| *queued_id != job_id);
            let deps = kernel
                .jobs
                .get(&job_id)
                .map(|job| job.deps.clone())
                .unwrap_or_default();
            Kernel::release_waiters(&mut kernel, &deps);
            kernel.jobs.remove(&job_id);
            kernel.record_settled(promise_id);
            if let Some(lane_record) = kernel.lanes.get_mut(&LaneId(lane)) {
                lane_record.complete();
            }
        }
        Ok(targets)
    }

    /// Reference a promise record from a handle.
    ///
    /// A handle cloned while the kernel is borrowed must not lose the
    /// operation: the count would fall to zero with a live handle and the record
    /// would be evicted underneath it (`rpc/unknown-promise` for a promise that
    /// settled). The operation is queued and applied at the next borrow point,
    /// exactly like a capability reference.
    fn retain_promise(&self, id: PromiseId) {
        self.promise_refop(id, true);
    }

    /// Drop a handle's reference to a promise record.
    fn release_promise(&self, id: PromiseId) {
        self.promise_refop(id, false);
    }

    fn promise_refop(&self, id: PromiseId, retain: bool) {
        if !self.promise_ops.borrow().is_empty() {
            self.promise_ops.borrow_mut().push_back((id, retain));
            return;
        }
        match self.cell.try_borrow_mut() {
            Ok(mut kernel) => Self::apply_promise_refop(&mut kernel, id, retain),
            Err(_) => self.promise_ops.borrow_mut().push_back((id, retain)),
        }
    }

    fn apply_promise_refop(kernel: &mut Kernel, id: PromiseId, retain: bool) {
        if let Some(record) = kernel.promises.get_mut(&id) {
            record.handles = if retain {
                record.handles.saturating_add(1)
            } else {
                record.handles.saturating_sub(1)
            };
        }
    }

    /// Apply promise reference operations queued behind a borrow.
    fn flush_promise_refops(&self) {
        for _ in 0..4096 {
            let Some((id, retain)) = self.promise_ops.borrow_mut().pop_front() else {
                return;
            };
            let Ok(mut kernel) = self.cell.try_borrow_mut() else {
                self.promise_ops.borrow_mut().push_front((id, retain));
                return;
            };
            Self::apply_promise_refop(&mut kernel, id, retain);
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

    /// Live dependents of a promise, for operators and tests.
    pub fn promise_waiters(&self, promise: &PromiseHandle) -> u32 {
        self.cell
            .borrow()
            .promises
            .get(&promise.id)
            .map(|record| record.waiters)
            .unwrap_or(0)
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

    /// Charge the bytes a resolved promise added to a queued call.
    ///
    /// The call was charged at queue time with each promise counted at its
    /// placeholder size. A promise that resolves to a larger value must not
    /// deliver it for free: the difference is charged to the capability, to
    /// every ancestor and to the lane before the provider runs.
    fn charge_dispatch_delta(&self, job: &Job, extra: u64) -> Result<()> {
        if extra == 0 {
            return Ok(());
        }
        let mut kernel = self.cell.borrow_mut();
        if let Some(lane_record) = kernel.lanes.get(&job.lane) {
            if lane_record.bytes.saturating_add(extra) > lane_record.budget.max_bytes {
                return Err(Error::BudgetExceeded("lane byte"));
            }
        }
        let mut chain: Vec<CapId> = kernel
            .caps
            .get(&job.cap)
            .map(|record| record.lineage.clone())
            .unwrap_or_default();
        chain.push(job.cap);
        for id in &chain {
            if let Some(meter) = kernel.meters.get(id) {
                meter.check_bytes(extra)?;
            }
        }
        for id in &chain {
            if let Some(meter) = kernel.meters.get_mut(id) {
                meter.charge_bytes(extra)?;
            }
        }
        if let Some(lane_record) = kernel.lanes.get_mut(&job.lane) {
            lane_record.bytes = lane_record.bytes.saturating_add(extra);
        }
        Ok(())
    }

    fn dispatch(&self, batch: Vec<u64>) {
        // No kernel borrow is held while a provider runs: a provider may hold an
        // `Agent` and call back into the kernel, and a re-entrant borrow would
        // panic (or, with `try_borrow_mut`, silently drop a refcount update).
        // Each phase takes a short borrow and returns owned data.
        let (provider_id, provider) = {
            let mut kernel = self.cell.borrow_mut();
            kernel.round_trips += 1;
            kernel.now_ms = if kernel.wall_clock {
                kernel.now_ms.max(wall_now_ms())
            } else {
                kernel.now_ms.saturating_add(kernel.latency_ms)
            };
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
            kernel.dispatching = true;
            let provider = kernel.providers.remove(&provider_id);
            (provider_id, provider)
        };
        let Some(provider) = provider else {
            let mut kernel = self.cell.borrow_mut();
            kernel.dispatching = false;
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
        // The guard restores `dispatching` and re-inserts the provider even if
        // provider code unwinds: a panic must not leave the kernel wedged with
        // no provider and a queue that never drains.
        let mut guard = DispatchGuard {
            agent: self,
            provider_id,
            provider: Some(provider),
        };
        let mut first_panic: Option<Box<dyn std::any::Any + Send>> = None;

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
                // Authority is re-checked at dispatch: a capability revoked or
                // expired after the call was queued must not reach the
                // provider. Dispatch advances the virtual clock by one round
                // trip, so a call that was live when queued can expire before
                // it runs; that is the same refusal as a revocation.
                let record = kernel.caps.get(&job.cap).cloned();
                let mut expired = false;
                let mut failure = match &record {
                    None => Some(Error::UnknownCapability(cap_token(job.cap))),
                    Some(record) if record.revoked => Some(Error::Revoked(cap_token(record.id))),
                    Some(record) => {
                        if record
                            .expires_at
                            .is_some_and(|expires_at| kernel.now_ms >= expires_at)
                        {
                            expired = true;
                            Some(Error::Revoked(cap_token(record.id)))
                        } else {
                            failure
                        }
                    }
                };
                // A promise argument was a placeholder when the call was
                // queued. Its value is authority-bearing too, so the path
                // scope, the tool ceiling and the byte budget are re-checked
                // against what the provider is about to receive.
                let resolved_bytes: u64 = args.iter().map(Arg::wire_size).sum();
                if failure.is_none() {
                    if let Some(record) = &record {
                        if let Some(scope) = &record.attrs.path_scope {
                            for arg in &args {
                                if let Arg::Value(value) = arg {
                                    if let Some(path) = path_outside_scope(value, scope) {
                                        failure = Some(Error::PathNotGranted(path));
                                        break;
                                    }
                                }
                            }
                        }
                        if failure.is_none() {
                            if let Some(policy) = &record.attrs.tool_policy {
                                if resolved_bytes > policy.max_arg_bytes {
                                    failure = Some(Error::ToolPolicy("argument too large"));
                                }
                            }
                        }
                        if failure.is_none() && resolved_bytes > job.call.budget.max_bytes {
                            failure = Some(Error::BudgetExceeded("byte"));
                        }
                    }
                }
                let extra = if failure.is_none() {
                    resolved_bytes.saturating_sub(job.args_bytes)
                } else {
                    0
                };
                Some((
                    job,
                    args,
                    failure,
                    record.map(|record| record.object).unwrap_or(0),
                    expired,
                    extra,
                ))
            };
            let Some((job, args, failure, object, expired, extra)) = prepared else {
                continue;
            };
            if expired {
                self.cell
                    .borrow_mut()
                    .push_event(Event::CapExpired(job.cap));
            }
            // The bytes a promise resolved into are paid for before the
            // provider runs, by the capability and by every ancestor.
            let failure = match failure {
                Some(error) => Some(error),
                None => self.charge_dispatch_delta(&job, extra).err(),
            };
            // Phase 2: run provider code with no borrow held.
            let outcome = match failure {
                Some(error) => Err(error),
                None => {
                    let call = Call {
                        args,
                        ..job.call.clone()
                    };
                    // A provider panic settles this job as a provider fault and
                    // is resumed after the batch: a leaked job would leave its
                    // promise pending forever, and the host still sees the
                    // panic.
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        guard.provider_mut().invoke(object, &call)
                    })) {
                        Ok(result) => result.map(Response::into_value),
                        Err(payload) => {
                            self.cell.borrow_mut().push_event(Event::ProviderPanicked {
                                provider: provider_id,
                                phase: "invoke".to_string(),
                            });
                            if first_panic.is_none() {
                                first_panic = Some(payload);
                            }
                            Err(Error::Provider {
                                code: "rpc/provider".to_string(),
                            })
                        }
                    }
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
            Kernel::release_waiters(&mut kernel, &job.deps);
            kernel.jobs.remove(job_id);
            if let Some(lane_record) = kernel.lanes.get_mut(&job.lane) {
                lane_record.complete();
            }
            kernel.push_event(Event::JobCompleted {
                job: *job_id,
                lane: job.lane,
            });
        }

        // Restore the kernel, then deliver the drops that happened during the
        // batch with no borrow held: `on_drop` is provider code and may call
        // back into the agent.
        drop(guard);
        self.flush_drops();
        if let Some(payload) = first_panic {
            // Every job in the batch is settled before the caller sees the
            // panic again.
            std::panic::resume_unwind(payload);
        }
    }

    /// Deliver queued provider notifications with no kernel borrow held.
    ///
    /// A drop can happen anywhere (a handle falling out of scope, a provider
    /// dropping its own object), including inside a callback that already holds
    /// a borrow. Delivery therefore always goes through the queue: take the
    /// list under a short borrow, release it, then run provider code.
    fn flush_drops(&self) {
        deliver_pending_drops(&self.cell);
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

    /// Release the waiter count of every promise a removed job depended on.
    fn release_waiters(kernel: &mut Kernel, deps: &[PromiseId]) {
        for dep in deps {
            if let Some(record) = kernel.promises.get_mut(dep) {
                record.waiters = record.waiters.saturating_sub(1);
            }
        }
    }

    /// Remember a settled promise for bounded retention.
    fn record_settled(&mut self, id: PromiseId) {
        let size = match self.promises.get(&id).map(|record| &record.state) {
            Some(PromiseState::Resolved(value)) => value.wire_size() as usize,
            // Provider-controlled error text is bounded only by the record
            // count otherwise; charge it like a value.
            Some(PromiseState::Rejected(error)) => error.to_string().len(),
            _ => 0,
        };
        self.settled.push_back((id, size));
        self.settled_bytes = self.settled_bytes.saturating_add(size);
    }

    /// Remove a capability whose last reference died and notify its provider.
    ///
    /// The provider may be checked out for a call it is running; the drop is
    /// then queued and delivered when the batch finishes.
    fn drop_record(kernel: &mut Kernel, id: CapId) {
        let mut doomed = vec![id];
        while let Some(id) = doomed.pop() {
            let Some(record) = kernel.caps.get(&id) else {
                continue;
            };
            // A descendant can still call through this capability, so the
            // record, its meter and the provider's object stay alive.
            if record.refs > 0 || record.descendants > 0 {
                continue;
            }
            let Some(record) = kernel.caps.remove(&id) else {
                continue;
            };
            kernel.meters.remove(&id);
            kernel.push_event(Event::CapDropped(id));
            kernel.queue_provider_drop(record.provider, record.object, id);
            for ancestor in &record.lineage {
                if let Some(parent) = kernel.caps.get_mut(ancestor) {
                    parent.descendants = parent.descendants.saturating_sub(1);
                    if parent.refs == 0 && parent.descendants == 0 {
                        doomed.push(*ancestor);
                    }
                }
                if let Some(children) = kernel.children.get_mut(ancestor) {
                    children.remove(&id);
                    if children.is_empty() {
                        kernel.children.remove(ancestor);
                    }
                }
            }
        }
    }

    /// Queue a provider notification. Delivery happens with no kernel borrow
    /// held (see [`Agent::flush_drops`]), because `on_drop` is provider code.
    fn queue_provider_drop(&mut self, provider: ProviderId, object: u64, cap: CapId) {
        self.deferred_drops.push((provider, object, cap));
    }

    /// Apply reference operations that arrived while the kernel was borrowed.
    ///
    /// Drained in a loop because applying one operation can queue another (an
    /// `on_drop` that clones a handle); the bound stops a pathological callback
    /// from pinning the drain.
    fn apply_deferred_refops(&mut self) {
        for _ in 0..4096 {
            let Some((id, retain)) = self.deferred_refops.borrow_mut().pop_front() else {
                return;
            };
            HandleControl::apply(self, id, retain);
        }
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
                    .unwrap_or(false)
                    // An idempotency key that still names this promise must keep
                    // it: replaying the key has to return the original result.
                    || self.idempotency.values().any(|mapped| mapped == id);
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

    /// Build the next dispatch batch.
    ///
    /// A batch holds the runnable jobs of one provider, ordered so promise
    /// producers precede consumers. The provider is the first one in queue
    /// order with a runnable job: in a cross-provider pipeline the head job's
    /// provider can be blocked while the producer's provider has work, and
    /// pinning the batch to the head would livelock the kernel.
    fn next_batch(&mut self) -> std::result::Result<Vec<u64>, Vec<u64>> {
        // A job whose record or capability vanished can never run.
        let orphans: Vec<u64> = self
            .queue
            .iter()
            .copied()
            .filter(|id| {
                !self
                    .jobs
                    .get(id)
                    .map(|job| self.caps.contains_key(&job.cap))
                    .unwrap_or(false)
            })
            .collect();
        if !orphans.is_empty() {
            let doomed: std::collections::HashSet<u64> = orphans.iter().copied().collect();
            self.queue.retain(|id| !doomed.contains(id));
            return Err(orphans);
        }

        // Providers in queue order, then the first that can run a job now.
        let mut providers: Vec<ProviderId> = Vec::new();
        for id in self.queue.iter() {
            if let Some(provider) = self
                .jobs
                .get(id)
                .and_then(|job| self.caps.get(&job.cap))
                .map(|record| record.provider)
            {
                if !providers.contains(&provider) {
                    providers.push(provider);
                }
            }
        }
        let mut skipped_for_delivery = false;
        for provider in providers {
            if self.delivering.contains(&provider) {
                // The provider is running its own `on_drop`; its jobs wait for
                // the next run rather than being failed as a missing provider.
                skipped_for_delivery = true;
                continue;
            }
            let candidates: Vec<u64> = self
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
            let ordered = self.order_candidates(&candidates);
            if !ordered.is_empty() {
                let taken: std::collections::HashSet<u64> = ordered.iter().copied().collect();
                self.queue.retain(|id| !taken.contains(id));
                return Ok(ordered);
            }
        }

        if skipped_for_delivery {
            // Every queued job belongs to a provider that is being notified.
            // This is not a cycle: the outer pass resumes the queue.
            return Ok(Vec::new());
        }
        // Nothing can run: every queued job waits on a promise that no queued
        // job will settle.
        Err(self.queue.drain(..).collect())
    }

    /// Order one provider's queued jobs so producers precede consumers.
    ///
    /// Only jobs whose dependencies are settled or produced earlier in the
    /// same batch are returned; the rest stay queued for a later batch (their
    /// producer may be queued on another provider).
    fn order_candidates(&self, candidates: &[u64]) -> Vec<u64> {
        let mut ordered: Vec<u64> = Vec::new();
        let mut pending: Vec<u64> = candidates.to_vec();
        let mut progress = true;
        while progress && !pending.is_empty() {
            progress = false;
            let mut index = 0;
            while index < pending.len() {
                let id = pending[index];
                let ready = match self.jobs.get(&id) {
                    Some(job) => job.deps.iter().all(|dep| {
                        // Resolved already, or produced by an ordered job.
                        match self.promises.get(dep) {
                            Some(record) if record.state.is_settled() => true,
                            _ => ordered.iter().any(|other| {
                                self.jobs.get(other).map(|job| job.promise) == Some(*dep)
                            }),
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
        ordered
    }

    fn fail_job(&mut self, job_id: u64, error: Error) {
        let deps = self
            .jobs
            .get(&job_id)
            .map(|job| job.deps.clone())
            .unwrap_or_default();
        Kernel::release_waiters(self, &deps);
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

/// Milliseconds since the Unix epoch, or 0 if the clock is before it.
fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

fn pad128(id: CapId) -> [u8; 16] {
    id.0
}

/// True when the durable grant budget is used up: every tombstone plus every
/// live durable capability would exceed the set the kernel can tombstone.
fn durable_ceiling_reached(kernel: &Kernel) -> bool {
    let live = kernel
        .caps
        .values()
        .filter(|record| record.attrs.persistence == CapPersistence::Durable)
        .count();
    kernel.revoked_records.len().saturating_add(live) >= MAX_TOMBSTONES
}

fn cap_token(id: CapId) -> crate::cap::CapToken {
    crate::cap::CapToken(u128::from_be_bytes(pad128(id)))
}

/// Correlation token for a durable record id.
///
/// A revoked record is reported with the same `rpc/revoked` code as a revoked
/// capability; the token correlates to the record, never to a live capability.
fn record_token(record_id: &[u8; 32]) -> crate::cap::CapToken {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&record_id[..16]);
    crate::cap::CapToken(u128::from_be_bytes(bytes))
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
    ///
    /// A promise that is still pending is `rpc/invalid-argument`: it may still
    /// settle, so it is not `rpc/unresolvable-promise` (which means "can never
    /// settle").
    pub fn peek(&self) -> Result<Value> {
        let kernel = self.agent.cell.borrow();
        let record = kernel
            .promises
            .get(&self.id)
            .ok_or(Error::UnknownPromise(self.id.0))?;
        if record.state == PromiseState::Pending {
            return Err(Error::InvalidArgument("the promise is still pending"));
        }
        record.value()
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

/// The first path in `value` (at any depth) that is outside `scope`.
fn path_outside_scope(value: &Value, scope: &str) -> Option<String> {
    match value {
        Value::Path(path) => {
            if crate::cap::is_path_prefix(scope, path) {
                None
            } else {
                Some(path.clone())
            }
        }
        Value::List(items) => items
            .iter()
            .find_map(|item| path_outside_scope(item, scope)),
        Value::Map(map) => map
            .values()
            .find_map(|item| path_outside_scope(item, scope)),
        _ => None,
    }
}
