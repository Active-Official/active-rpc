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

/// Ceiling on the record ids one kernel remembers as exported or restored.
///
/// The two sets exist so one credential cannot be exported or restored twice;
/// without a ceiling a kernel that keeps exporting would remember a 32-byte id
/// per export forever, because the capability itself can be dropped. Past the
/// ceiling a new export or restore is refused (fail-closed) rather than growing
/// the set without bound.
pub const MAX_RECORD_IDS: usize = 65_536;

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
pub const MAX_OBJECT_NAME_BYTES: usize = 128;

/// Channels one lane may subscribe to.
pub const MAX_CHANNELS_PER_LANE: usize = 1_024;

/// Global ceiling on channels in one kernel.
pub const MAX_CHANNELS: usize = 4_096;

/// Most capabilities one channel message may carry.
///
/// A message is a bounded transfer, not a sweep of the registry: the duplicate
/// check was a linear scan per capability, so 65 536 handles meant ~2×10⁹
/// comparisons on the dispatch thread before any budget was charged.
pub const MAX_CAPS_PER_MESSAGE: usize = 1_024;

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
    ///
    /// Once per object, not once per capability: this is the signal a provider
    /// uses to reclaim per-object state, so it must not fire while a sibling
    /// capability on the same object can still call. Delivery happens with no
    /// kernel borrow held (see `Agent::flush_drops`).
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
///
/// `#[non_exhaustive]`: the enum grows as the kernel gains observable work (this
/// is how `ReceiptsDropped` arrived), and a downstream crate should match with a
/// wildcard arm rather than break on a minor release.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
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
    /// A capability was exported as a sealed, durable record.
    CapExported(CapId),
    /// A sealed durable record was restored as a live capability.
    CapRestored(CapId),
    /// A capability bound to one peer was rebound to its rotated successor.
    CapRebound {
        /// Capability whose binding moved.
        cap: CapId,
        /// Fingerprint it was bound to before the rotation.
        from: [u8; FINGERPRINT_LEN],
        /// Fingerprint it is bound to now.
        to: [u8; FINGERPRINT_LEN],
    },
    /// The last live handle of an *exported* durable capability was dropped.
    ///
    /// The sealed record can still be restored; a deployment that treats a
    /// dropped handle as a dead credential must tombstone it (STATUS.md,
    /// residual). The event exists so the window is observable
    /// (audit AR-03).
    CapRecordOrphaned(CapId),
    /// A capability was introduced to an authenticated peer and bound to it.
    CapIntroduced {
        /// Introduced capability.
        cap: CapId,
        /// Peer fingerprint the capability is now bound to.
        fingerprint: [u8; FINGERPRINT_LEN],
    },
    /// A lane was created.
    LaneCreated(LaneId),
    /// A lane was destroyed, with the number of queued jobs it dropped.
    LaneDestroyed {
        /// Lane that was removed.
        lane: LaneId,
        /// Queued jobs failed with it.
        jobs: u64,
    },
    /// A channel was created.
    ChannelCreated(ChannelId),
    /// A lane subscribed to a channel.
    ChannelSubscribed {
        /// Subscribing lane.
        lane: LaneId,
        /// Channel it may now receive from.
        channel: ChannelId,
    },
    /// A lane released its subscription to a channel.
    ChannelUnsubscribed {
        /// Lane that withdrew.
        lane: LaneId,
        /// Channel it no longer receives from.
        channel: ChannelId,
    },
    /// A channel was closed to further sends.
    ChannelClosed(ChannelId),
    /// A channel was destroyed, with the number of messages it still held.
    ChannelDestroyed {
        /// Channel that was removed.
        channel: ChannelId,
        /// Messages dropped with it.
        dropped: u64,
    },
    /// A call was queued.
    CallQueued {
        /// Job id.
        job: u64,
        /// Issuing lane.
        lane: LaneId,
        /// Target capability.
        cap: CapId,
        /// Method name, truncated to `MAX_METHOD_EVENT_BYTES`.
        ///
        /// The decision trace needs the method: no other record names what a
        /// queued call asked for, so a replay package that carried only the
        /// capability could be edited from one granted method to another and
        /// still compare equal.
        method: String,
        /// Argument bytes the call was charged for.
        args_bytes: u64,
    },
    /// A batch of jobs was dispatched to a provider (one round-trip).
    BatchDispatched {
        /// Provider.
        provider: ProviderId,
        /// Number of jobs in the batch.
        jobs: usize,
        /// Number of distinct lanes represented in the batch.
        ///
        /// A count, not the set: the tape is bounded in records, and one batch
        /// can span every lane (`MAX_LANES`), so a retained `BTreeSet` per
        /// record could hold orders of magnitude more memory than the events.
        lane_count: usize,
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
    /// A receipt left the bounded ring (evicted, or cleared by disabling).
    ReceiptsDropped {
        /// Total receipts dropped so far.
        count: u64,
    },
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
        /// Target capability, when the refusal names one.
        ///
        /// `None` is a refusal that happened before a capability was selected
        /// (a send with no capability, an unknown lane). It used to be reported
        /// as the all-zero id, whose correlation hash is the same in every
        /// deployment and indistinguishable from a real capability.
        cap: Option<CapId>,
        /// Stable error code (`rpc/...`).
        code: String,
    },
    /// A budget ceiling refused work.
    BudgetExhausted {
        /// Capability whose budget (or lane ceiling) fired, when there is one.
        cap: Option<CapId>,
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
    /// Calls, sends and publishes refused before dispatch.
    ///
    /// Named for calls because that is the common case, but a refused send or
    /// publish is the same kind of event and lands here; a dashboard that
    /// divides it by `calls_queued` must not read it as a call-only rate.
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
    /// Events this kernel has ever recorded (a total, not the tape length).
    ///
    /// A decrease means a *different* kernel: the tape is bounded, so
    /// `events_retained` can shrink legitimately while `events_total` cannot.
    pub events_total: u64,
    /// Events currently on the bounded tape.
    pub events_retained: u64,
    /// Events the bounded tape discarded to stay bounded.
    pub events_evicted: u64,
    /// Receipts the ring evicted, or that disabling cleared.
    pub receipts_dropped: u64,
    /// Promise records that are still pending.
    pub promises_pending: u64,
    /// Promise records retained (pending plus settled-but-readable).
    pub promises_retained: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JobState {
    Queued,
    /// The job is in the current batch and its provider may be running right
    /// now. A lane destroyed at this point must not settle its promise: this
    /// dispatch owns the settlement, and a rejection here would disagree with
    /// the receipt the same dispatch seals.
    Running,
}

#[derive(Debug, Clone)]
struct Job {
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
    /// True once a receipt records this job's decision, so a later failure path
    /// does not record a second one.
    receipted: bool,
    /// Fingerprint the caller presented when the call was queued.
    ///
    /// Dispatch re-checks the binding against this value, not against whatever
    /// peer the batch is dispatched for: a capability introduced while the call
    /// waits must not hand the queued caller authority the operator withdrew
    /// after it was authorized.
    identity: Option<[u8; crate::identity::FINGERPRINT_LEN]>,
}

/// The deterministic kernel: providers, capabilities, budgets and promises.
///
/// It performs no I/O of its own; transports hand it envelopes and take the
/// results back. Holding the kernel is the only way to reach a provider.
pub struct Kernel {
    secret: [u8; 32],
    /// Key that seals receipts, derived from `secret` so a verifier can be given
    /// the receipt key without being handed the authority that mints ids.
    receipt_key: [u8; 32],
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
    /// Events the bounded tape discarded.
    events_evicted: u64,
    /// Settled promises in settlement order, with the retained value size.
    settled: VecDeque<(PromiseId, usize)>,
    settled_bytes: usize,
    metrics: Metrics,
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
    /// Live capability records per `(provider, object)`.
    ///
    /// `on_drop` fires once per object, when its last record goes. Scanning
    /// every capability to answer that was quadratic: dropping 20k capabilities
    /// took 1.33 s in a release build.
    object_records: BTreeMap<(ProviderId, u64), usize>,
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
    /// Cached idempotency claims: the promise, the request fingerprint, and the
    /// fingerprint of the peer that claimed the key.
    idempotency: BTreeMap<IdempotencyKey, IdempotencyEntry>,
    allow_durable: bool,
    idempotency_order: VecDeque<IdempotencyKey>,
    now_ms: u64,
    latency_ms: u64,
    /// When true, dispatch advances the clock to wall time instead of by one
    /// simulated round trip. The clock never decreases in either mode.
    wall_clock: bool,
    receipts: std::collections::VecDeque<crate::receipts::Receipt>,
    receipts_enabled: bool,
    next_receipt: u64,
    /// Receipts evicted from the ring (or cleared when receipts were disabled).
    receipts_dropped: u64,
    /// Deployment key that seals durable records. Without it a record cannot
    /// be exported or restored: an unverifiable credential is not accepted.
    record_key: Option<[u8; 32]>,
    /// Record ids tombstoned by a revocation.
    revoked_records: BTreeSet<[u8; 32]>,
    /// Record ids already exported (consumed) by this kernel.
    consumed_records: BTreeSet<[u8; 32]>,
    /// Record ids already restored by this kernel.
    restored_records: BTreeSet<[u8; 32]>,
    /// Ceiling on either record-id set.
    record_id_ceiling: usize,
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

/// Puts the provider table back when it is dropped, on the normal path and on
/// unwind.
///
/// `Agent::intro` takes the table out so provider code runs with no kernel
/// borrow held; a panic inside that code must not leave the kernel with no
/// providers.
struct ProviderTableGuard {
    cell: KernelCell,
    table: Option<BTreeMap<ProviderId, Box<dyn Provider>>>,
}

impl Drop for ProviderTableGuard {
    fn drop(&mut self) {
        if let Some(table) = self.table.take() {
            if let Ok(mut kernel) = self.cell.try_borrow_mut() {
                kernel.providers = table;
            }
        }
    }
}

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

/// Fails the jobs of a batch that a panic prevented from running.
///
/// Provider code is contained by `catch_unwind`, but a panic in phase 1 (a
/// substitution) or phase 3 (a settlement) would unwind past the batch and
/// leave the remaining jobs dequeued and never scheduled: pending forever. The
/// guard fails them on the way out.
struct BatchGuard<'a> {
    agent: &'a Agent,
    pending: BTreeSet<u64>,
}

impl Drop for BatchGuard<'_> {
    fn drop(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let ids = std::mem::take(&mut self.pending);
        let Ok(mut kernel) = self.agent.cell.try_borrow_mut() else {
            return;
        };
        for id in ids {
            if kernel.jobs.contains_key(&id) {
                kernel.fail_job(
                    id,
                    Error::Provider {
                        code: "rpc/provider".to_string(),
                    },
                    true,
                );
            }
        }
    }
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
            receipt_key: crate::receipts::derive_receipt_key(&secret),
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
            events_evicted: 0,
            settled: VecDeque::new(),
            settled_bytes: 0,
            metrics: Metrics::default(),
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

            receipts: std::collections::VecDeque::new(),
            receipts_enabled: false,
            next_receipt: 0,
            receipts_dropped: 0,
            record_key: None,
            revoked_records: BTreeSet::new(),
            consumed_records: BTreeSet::new(),
            restored_records: BTreeSet::new(),
            record_id_ceiling: MAX_RECORD_IDS,
            children: BTreeMap::new(),
            object_records: BTreeMap::new(),
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
        // Provider code runs with no kernel borrow held, exactly as dispatch
        // arranges it: a provider that holds an `Agent` clone and calls back into
        // the kernel would otherwise panic on a re-borrow, and one that calls
        // `intro()` again would recurse to a stack overflow.
        let table = std::mem::take(&mut self.cell.borrow_mut().providers);
        let guard = ProviderTableGuard {
            cell: Rc::clone(&self.cell),
            table: Some(table),
        };
        let surface: Vec<(String, Vec<String>)> = guard
            .table
            .as_ref()
            .map(|table| {
                table
                    .values()
                    .map(|provider| (provider.name().to_string(), provider.methods()))
                    .collect()
            })
            .unwrap_or_default();
        // The guard puts the table back before the module is built, so an error
        // from `intro::build` never leaves the kernel without providers.
        drop(guard);
        crate::intro::build(
            &format!("active-rpc/{}", crate::VERSION),
            &surface,
            &Budget::default(),
        )
    }

    /// Enable or disable capability receipts.
    ///
    /// When enabled, every call that reaches dispatch appends a
    /// [`crate::Receipt`] to a bounded ring, recording the decision taken there
    /// (admitted, or refused with the code). A call that never reaches dispatch
    /// because the kernel refused it first (an unorderable pipeline, a provider
    /// that vanished, a destroyed lane) is recorded when it is failed, so a
    /// refusal never leaves the ring silent. Disabling also clears the ring;
    /// [`Agent::receipts_dropped`] counts what was cleared or evicted, so an
    /// exported window never pretends to be the whole history.
    pub fn enable_receipts(&self, enabled: bool) {
        let mut kernel = self.cell.borrow_mut();
        kernel.receipts_enabled = enabled;
        if !enabled {
            let cleared = kernel.receipts.len() as u64;
            kernel.receipts.clear();
            if cleared > 0 {
                kernel.receipts_dropped = kernel.receipts_dropped.saturating_add(cleared);
                let total = kernel.receipts_dropped;
                kernel.push_event(Event::ReceiptsDropped { count: total });
            }
        }
    }

    /// The receipts recorded so far, oldest first.
    pub fn receipts(&self) -> Vec<crate::Receipt> {
        self.cell.borrow().receipts.iter().cloned().collect()
    }

    /// The key that seals receipts, derived from the kernel secret.
    ///
    /// Hand this to a verifier ([`crate::ReceiptLog::verify_macs`]) instead of
    /// the kernel secret: the secret mints capability ids, and a verifier that
    /// only needs to check an audit log must not be able to create authority.
    pub fn receipt_key(&self) -> [u8; 32] {
        self.cell.borrow().receipt_key
    }

    /// Set the sequence the next receipt will carry.
    ///
    /// A kernel that continues an existing log across a restart adopts the log's
    /// next sequence here. Sequences are otherwise monotonic from 1, and a log
    /// refuses a receipt that does not follow its own order. Zero is not a
    /// sequence, and `u64::MAX` would be issued twice, so both are refused.
    pub fn set_receipt_sequence(&self, next: u64) -> crate::Result<()> {
        // The last sequence a log can hold: a window starting above this would
        // seal receipts no `create_starting_at` accepts, so the session's
        // evidence could never be exported.
        let ceiling = u64::MAX - crate::receipts::MAX_LOG_RECORDS;
        if next == 0 || next > ceiling {
            return Err(Error::InvalidArgument(
                "a receipt sequence must be 1..=u64::MAX - MAX_LOG_RECORDS",
            ));
        }
        let mut kernel = self.cell.borrow_mut();
        if kernel.next_receipt > 0 && next <= kernel.next_receipt {
            // A rewind reuses a sequence the ring already holds: both copies
            // verify, and the batch can no longer be exported.
            return Err(Error::InvalidArgument(
                "a receipt sequence cannot move backwards",
            ));
        }
        // A gap is a hole in the evidence, so it is counted like an eviction:
        // an auditor could not otherwise tell a continued log from a truncated
        // one.
        if kernel.next_receipt > 0 {
            kernel.receipts_dropped = kernel
                .receipts_dropped
                .saturating_add(next - kernel.next_receipt - 1);
        }
        // `next_receipt` holds the last sequence issued, so the seal increments
        // before using it: storing `next - 1` makes the next receipt `next`.
        kernel.next_receipt = next - 1;
        Ok(())
    }

    /// Receipts the ring evicted, or that disabling cleared.
    ///
    /// An exported window starts at a sequence above 1 exactly when this is
    /// non-zero; without the counter an auditor could not tell a short session
    /// from a truncated record.
    pub fn receipts_dropped(&self) -> u64 {
        self.cell.borrow().receipts_dropped
    }

    /// Verify that a receipt came from this kernel and was not edited.
    pub fn verify_receipt(&self, receipt: &crate::Receipt) -> bool {
        let key = self.cell.borrow().receipt_key;
        receipt.verify(&key)
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
        let mut kernel = self.cell.borrow_mut();
        refresh_clock(&mut kernel);
        // A clone: the export reserves the budget on the meters, which needs a
        // mutable borrow.
        let record = kernel
            .caps
            .get(&cap.id())
            .cloned()
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
                kernel.push_event(Event::CapExpired(cap.id()));
                return Err(Error::Revoked(cap_token(cap.id())));
            }
        }
        let provider_name = kernel
            .providers
            .get(&record.provider)
            .map(|provider| provider.name().to_string())
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
        if !record.attrs.bound_to.is_some_and(crate::identity::bindable) {
            return Err(Error::Identity(
                "a durable record cannot name an anonymous or loopback identity",
            ));
        }
        // Every refusal that means "this record cannot be built" comes before
        // the reserve: a grant must not be burned by a record that is never
        // handed out. `from_json` refuses an empty scope, so such a record
        // could never be restored either.
        if record
            .attrs
            .path_scope
            .as_deref()
            .is_some_and(str::is_empty)
        {
            return Err(Error::persistence("an empty path scope is not a scope"));
        }
        // A record describes what is left, not what was granted, and the
        // transfer is real: what the record carries is reserved on this
        // capability *and* on every ancestor, so restoring it cannot create a
        // second copy of a grant the subtree already spent.
        if kernel.consumed_records.contains(&record.record_id) {
            return Err(Error::persistence(
                "the record was already exported and consumed",
            ));
        }
        // The mark set is bounded: past the ceiling a new export is refused
        // rather than letting a long-lived kernel remember ids forever.
        if kernel.consumed_records.len() >= kernel.record_id_ceiling {
            return Err(Error::BudgetExceeded("records"));
        }
        let meter = kernel
            .meters
            .get(&record.id)
            .ok_or_else(|| Error::persistence("the capability has no meter"))?;
        let own_calls = meter.remaining_calls();
        let own_bytes = meter.remaining_bytes();
        let mut remaining_calls = own_calls;
        let mut remaining_bytes = own_bytes;
        for ancestor in &record.lineage {
            // An export hands out the grant the whole chain still has. A
            // skipped ancestor would let the record carry more than that
            // ancestor allows, so a missing meter fails the export (round 4).
            let parent_meter = meter_for(&kernel, *ancestor)?
                .ok_or(Error::Persistence("the capability has no meter"))?;
            remaining_calls = remaining_calls.min(parent_meter.remaining_calls());
            remaining_bytes = remaining_bytes.min(parent_meter.remaining_bytes());
        }
        if remaining_calls == 0 || remaining_bytes == 0 {
            return Err(Error::persistence("the capability's grant is spent"));
        }
        let mut chain: Vec<CapId> = record.lineage.clone();
        chain.push(record.id);
        for id in &chain {
            let meter = meter_for(&kernel, *id)?
                .ok_or(Error::Persistence("the capability has no meter"))?;
            meter
                .check_reserve(remaining_calls, remaining_bytes)
                .map_err(|_| Error::persistence("the grant is already committed"))?;
        }
        let mut record = crate::persistence::CapabilityRecord {
            provider: provider_name,
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
            publish: record.attrs.publish,
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
        // The record must be one this crate can read back, and that is checked
        // *before* anything is reserved or consumed: exporting an artifact the
        // parser refuses used to burn the grant and the record id, so the caller
        // got `rpc/persistence` and a dead capability. An unexportable
        // capability now fails with its authority intact.
        crate::persistence::CapabilityRecord::from_json(&record.to_json())?;
        for id in &chain {
            let meter = meter_mut_for(&mut kernel, *id)?
                .ok_or(Error::Persistence("the capability has no meter"))?;
            meter
                .reserve(remaining_calls, remaining_bytes)
                .map_err(|_| Error::persistence("the grant is already committed"))?;
        }
        kernel.consumed_records.insert(record.record_id);
        kernel.push_event(Event::CapExported(cap.id()));
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
        self.restore_capability_with(record, peer, None)
    }

    /// Restore a durable capability, checking a durable "already restored" set.
    ///
    /// [`Agent::restore_capability`] remembers restored record ids *in this
    /// process*: a restart, or a second kernel in the same deployment, would
    /// restore the same sealed record again and mint a fresh grant for the full
    /// recorded budget. A deployment that stores records passes a
    /// [`crate::persistence::RecordStore`] here, so the record is single-use
    /// across kernels and restarts.
    ///
    /// The store is marked only after the mint succeeds; if marking fails the
    /// minted capability is revoked and the refusal returned, so a store that
    /// cannot remember never leaves a usable grant behind.
    pub fn restore_capability_with(
        &self,
        record: &crate::persistence::CapabilityRecord,
        peer: &crate::identity::AdmittedIdentity,
        store: Option<&mut dyn crate::persistence::RecordStore>,
    ) -> Result<CapHandle> {
        // The store is consulted *after* the seal and the binding, not before:
        // an unsealed record must not be able to probe the deployment's restore
        // set.
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
        // The binding is about the caller, so it is reported before any state
        // of this kernel: a wrong peer learns nothing about whether a record id
        // was tombstoned (round 4, #3). A record that names no peer would
        // restore for anyone.
        let Some(bound) = record.bound_to else {
            return Err(Error::Identity("the record names no peer"));
        };
        if !crate::identity::matches(
            crate::identity::presented_fingerprint(Some(peer.identity())),
            bound,
        ) {
            return Err(Error::Identity("the record is bound to a different peer"));
        }
        {
            let kernel = self.cell.borrow();
            if kernel.revoked_records.contains(&record.record_id) {
                return Err(Error::Revoked(record_token(&record.record_id)));
            }
        }
        {
            let kernel = self.cell.borrow();
            // Restoring is a re-mint, so N restores of one credential would be N
            // independent grants that a single revocation cannot reach.
            if kernel
                .caps
                .values()
                .any(|live| live.record_id == record.record_id && !live.revoked)
            {
                return Err(Error::persistence("the record is already live"));
            }
            // A credential is restored once: the budgets inside it were
            // reserved at export, and restoring them again would mint a second
            // grant from the same record.
            if kernel.restored_records.contains(&record.record_id) {
                return Err(Error::persistence("the record was already restored"));
            }
            if kernel.restored_records.len() >= kernel.record_id_ceiling {
                return Err(Error::BudgetExceeded("records"));
            }
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
        let now = {
            let mut kernel = self.cell.borrow_mut();
            refresh_clock(&mut kernel);
            kernel.now_ms
        };
        // The absolute deadline is compared in its own domain only, and a
        // virtual clock has a different epoch in every kernel. Refusing a record
        // whose deadline already passed therefore denies a live credential when
        // the restorer's virtual clock is ahead; restoring it on the lease alone
        // would instead hand a *fresh* lease to a record that expired in its own
        // domain. Refusing is the safe side, and `persistence.md` records it.
        let ttl_ms = match record.expires_at {
            Some(expires_at) if expires_at <= now => {
                return Err(Error::persistence("the record's deadline has passed"))
            }
            Some(expires_at) => {
                // Two wall clocks share an epoch, but the absolute deadline
                // alone would still stretch the lease across a restart, so the
                // sealed remaining lifetime is the ceiling.
                let Some(lease) = record.lease_ms else {
                    return Err(Error::persistence("a bounded record carries no lease"));
                };
                Some((expires_at - now).min(lease))
            }
            None => None,
        };
        // A record whose budget disables a ceiling is not restorable; it is a
        // durable refusal, not a bad argument from the caller.
        record
            .budget
            .check()
            .map_err(|_| Error::persistence("the record's budget disables a ceiling"))?;
        // Claim the record *before* minting. `claim` is atomic where the store
        // can make it so: a check-then-mark pair let two processes restore one
        // record into two grants, and the second grant's budget was a second
        // copy that no revocation reached. A claim left behind by a failed mint
        // is fail-closed: the record is spent, not duplicated.
        if let Some(store) = store {
            store.claim(&record.record_id)?;
        }
        let attrs = record.attrs(ttl_ms);
        let restored = self.mint_restored(peer, provider, record.object, attrs)?;
        self.cell
            .borrow_mut()
            .restored_records
            .insert(record.record_id);
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
        check_binding(&attrs)?;
        if attrs.methods.is_empty() {
            return Err(Error::InvalidArgument("capability grants no methods"));
        }
        check_method_names(&attrs)?;
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
        kernel.insert_cap_record(record);
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
            .is_some_and(|bound| !crate::identity::matches(Some(peer.fingerprint()), bound))
        {
            return Err(Error::Identity(
                "the capability is already bound to a different peer",
            ));
        }
        if !peer.can_bind() {
            return Err(Error::Identity(
                "only a certificate peer can hold a binding",
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
        check_binding(&attrs)?;
        if attrs.methods.is_empty() {
            return Err(Error::InvalidArgument("capability grants no methods"));
        }
        check_method_names(&attrs)?;
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
        kernel.insert_cap_record(record);
        kernel.push_event(Event::CapMinted { cap: id, provider });
        // A restore is a mint of a sealed record: the trace names both, so an
        // operator reading only this tape sees where the authority came from.
        kernel.push_event(Event::CapRestored(id));
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
        // Introducing authority requires holding it: an imported handle is a
        // borrowed id, not ownership. A channel message shows ids, so without
        // this a receiver could bind the sender's capability to a peer of its
        // choosing and lock the owner out.
        if !cap.is_owning() {
            return Err(Error::Identity(
                "an imported handle cannot introduce authority",
            ));
        }
        let fingerprint = peer.fingerprint();
        let mut kernel = self.cell.borrow_mut();
        refresh_clock(&mut kernel);
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
        // Bind the live subtree, not only this capability. A child minted before
        // the introduction would otherwise stay usable by another peer and
        // transferable over a channel while its parent is locked to this one.
        let subtree = descendants_of(&kernel.children, cap.id());
        for id in &subtree {
            if let Some(child) = kernel.caps.get(id) {
                // A revoked or expired record is dead authority: its binding is
                // history, and letting it block the introduction would make a
                // dead child permanent denial of service on a live capability.
                if child.revoked
                    || child
                        .expires_at
                        .is_some_and(|expires_at| kernel.now_ms >= expires_at)
                {
                    continue;
                }
                if let Some(bound) = child.attrs.bound_to {
                    if bound != fingerprint {
                        return Err(Error::Identity(
                            "a descendant is already bound to another peer",
                        ));
                    }
                }
            }
        }
        for id in std::iter::once(cap.id()).chain(subtree) {
            if let Some(child) = kernel.caps.get_mut(&id) {
                child.attrs.bound_to = Some(fingerprint);
            }
        }
        let record = kernel
            .caps
            .get(&cap.id())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
        let descriptor = crate::wire::CapDescriptor::from_attrs(record.id, &record.attrs);
        let introduced = record.id;
        kernel.push_event(Event::CapIntroduced {
            cap: introduced,
            fingerprint,
        });
        Ok(descriptor)
    }

    /// Move a peer-bound capability (and its live subtree) to the peer's
    /// rotated successor certificate.
    ///
    /// A fingerprint is the whole DER, so a leaf renewal invalidated every
    /// binding at once (audit AR-04). The caller proves it holds the old peer
    /// — it presents the `PeerIdentity` whose fingerprint matches the current
    /// binding — and names the new admitted peer. Authority does not change:
    /// the same records, budgets, expiry and policy move to the new binding.
    pub fn reintroduce_to(
        &self,
        cap: &CapHandle,
        from: &crate::identity::PeerIdentity,
        to: &AdmittedIdentity,
    ) -> Result<crate::wire::CapDescriptor> {
        if !cap.is_owning() {
            return Err(Error::Identity(
                "an imported handle cannot rebind authority",
            ));
        }
        if !to.can_bind() {
            return Err(Error::Identity(
                "cannot rebind a capability to an unauthenticated peer",
            ));
        }
        let from_fingerprint = from.fingerprint();
        let to_fingerprint = to.fingerprint();
        let mut kernel = self.cell.borrow_mut();
        refresh_clock(&mut kernel);
        let (revoked, expired, bound) = {
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
        if bound != Some(from_fingerprint) {
            return Err(Error::Identity(
                "the capability is not bound to the peer being rotated",
            ));
        }
        let subtree = descendants_of(&kernel.children, cap.id());
        for id in &subtree {
            if let Some(child) = kernel.caps.get(id) {
                if child.revoked
                    || child
                        .expires_at
                        .is_some_and(|expires_at| kernel.now_ms >= expires_at)
                {
                    continue;
                }
                // A descendant bound to a different peer is somebody else's
                // authority; moving it would hand them a rotated identity.
                if child
                    .attrs
                    .bound_to
                    .is_some_and(|other| other != from_fingerprint)
                {
                    return Err(Error::Identity("a descendant is bound to another peer"));
                }
            }
        }
        for id in std::iter::once(cap.id()).chain(subtree) {
            if let Some(child) = kernel.caps.get_mut(&id) {
                if child.attrs.bound_to == Some(from_fingerprint) {
                    child.attrs.bound_to = Some(to_fingerprint);
                }
            }
        }
        let record = kernel
            .caps
            .get(&cap.id())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
        let descriptor = crate::wire::CapDescriptor::from_attrs(record.id, &record.attrs);
        let rebound = record.id;
        kernel.push_event(Event::CapRebound {
            cap: rebound,
            from: from_fingerprint,
            to: to_fingerprint,
        });
        Ok(descriptor)
    }

    /// Attenuate a capability. Refuses any widening.
    pub fn attenuate(&self, parent: &CapHandle, attrs: CapAttrs) -> Result<CapHandle> {
        // A borrowed (imported) handle names a capability this kernel minted for
        // someone else: attenuating it would launder a grant out of a borrow and
        // pin the owner's record alive through `descendants` (round 4, #1).
        if !parent.is_owning() {
            return Err(Error::Identity(
                "an imported handle cannot attenuate authority",
            ));
        }
        let parent_id = parent.id();
        let mut kernel = self.cell.borrow_mut();
        refresh_clock(&mut kernel);
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
        check_binding(&attrs)?;
        check_method_names(&attrs)?;
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
        kernel.insert_cap_record(child);
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
        // Revocation is an owner action: a borrowed handle travels on a channel,
        // and any receiver holding one could otherwise kill the sender's grant
        // (round 4, #2).
        if !cap.is_owning() {
            return Err(Error::Identity(
                "an imported handle cannot revoke authority",
            ));
        }
        let mut kernel = self.cell.borrow_mut();
        let id = cap.id();
        if !kernel.caps.contains_key(&id) {
            return Err(Error::UnknownCapability(cap_token(id)));
        }
        revoke_subtree(&mut kernel, [id]);
        Ok(())
    }

    /// Record a revocation tombstone from a deployment's persistent store.
    ///
    /// Tombstones live in memory, so process restarts would otherwise resurrect
    /// every exported record. A deployment replays its kill list here at
    /// startup; the ceiling is checked so the set can never grow without bound.
    ///
    /// A tombstone is a kill switch, so it also revokes every live capability
    /// carrying the id: a restore path that ran before the replay would
    /// otherwise keep a copy of a revoked credential alive for its whole lease,
    /// because dispatch never consults the tombstone set.
    pub fn tombstone_record(&self, record_id: [u8; 32]) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        if kernel.revoked_records.len() >= MAX_TOMBSTONES
            && !kernel.revoked_records.contains(&record_id)
        {
            return Err(Error::BudgetExceeded("tombstones"));
        }
        kernel.revoked_records.insert(record_id);
        let live: Vec<CapId> = kernel
            .caps
            .iter()
            .filter(|(_, record)| record.record_id == record_id)
            .map(|(id, _)| *id)
            .collect();
        if !live.is_empty() {
            revoke_subtree(&mut kernel, live);
        }
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

    /// Set the ceiling on the record ids a kernel remembers. Zero is refused.
    pub fn set_record_id_ceiling(&self, ceiling: usize) -> Result<()> {
        if ceiling == 0 {
            return Err(Error::InvalidArgument("record id ceiling must be non-zero"));
        }
        self.cell.borrow_mut().record_id_ceiling = ceiling.min(MAX_RECORD_IDS);
        Ok(())
    }

    /// Current record-id ceiling.
    pub fn record_id_ceiling(&self) -> usize {
        self.cell.borrow().record_id_ceiling
    }

    /// Record ids this kernel has exported and consumed.
    pub fn consumed_record_count(&self) -> usize {
        self.cell.borrow().consumed_records.len()
    }

    /// Record ids this kernel has restored.
    pub fn restored_record_count(&self) -> usize {
        self.cell.borrow().restored_records.len()
    }

    /// Create a lane.
    pub fn create_lane(&self, name: impl Into<String>, budget: Budget) -> Result<LaneId> {
        budget.check()?;
        let name = name.into();
        // A lane name is a label an operator reads, so it follows the same rule
        // as a channel name and a topic: non-empty, bounded, no control or
        // reordering characters (round 2, #3).
        if !crate::security::valid_text(&name, MAX_OBJECT_NAME_BYTES) {
            return Err(Error::InvalidArgument(
                "a lane name must be 1..=128 bytes without control or reordering characters",
            ));
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
        let failed = doomed.len() as u64;
        for job_id in doomed {
            // Quiet: a destroyed lane can hold thousands of jobs, and one
            // rejection + completion event each would evict the whole bounded
            // tape (16 384 records) on a single legitimate operation. The
            // receipts still record every refusal, and `LaneDestroyed` carries
            // the count (round 4, #3).
            kernel.fail_job(job_id, Error::UnknownLane(lane.0), false);
        }
        // `doomed` never holds a running job (its state is `Running`), so the
        // retain below keeps that one record until its dispatch settles it.
        // Reclaim the dispatch records this lane owns. Promise records stay:
        // a caller that holds a handle must still see the settled value (or a
        // rejected one) rather than an unrelated `unknown-promise`. The promise
        // ceiling bounds them; the kernel itself is the lifetime.
        // No waiter sweep: `fail_job` already released the dependencies of
        // every doomed job, and a running job (kept below) releases its own when
        // its dispatch settles. A sweep released them a second time, which
        // `saturating_sub` hid while the waiter count drifted (round 2, #2).
        kernel
            .jobs
            .retain(|_, job| job.lane != lane || job.state == JobState::Running);
        for channel in kernel.channels.values_mut() {
            channel.subscribers.remove(&lane.0);
        }
        kernel.lanes.remove(&lane);
        kernel.push_event(Event::LaneDestroyed { lane, jobs: failed });
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
        // A destroy can drop a backlog. Without an event an operator cannot tell
        // "destroyed empty" from "destroyed with 4 000 messages".
        kernel.push_event(Event::ChannelDestroyed {
            channel,
            dropped: removed.queued() as u64,
        });
        Ok(())
    }

    /// Create a channel.
    pub fn create_channel(
        &self,
        name: impl Into<String>,
        direction: Direction,
    ) -> Result<ChannelId> {
        let name = name.into();
        // A channel name reaches a log line and an event, so it is bounded text
        // like a topic: control and reordering characters would let it render
        // as two records or as a different name.
        if !crate::security::valid_text(&name, MAX_OBJECT_NAME_BYTES) {
            return Err(Error::InvalidArgument(
                "a channel name must be 1..=128 bytes without control or reordering characters",
            ));
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
        kernel.push_event(Event::ChannelCreated(id));
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
        // `closed` is the state the event reports, so a receive-only channel
        // that is open still changes: `can_send` was false from the start and
        // the event would be lost.
        let was_open = !record.is_closed();
        record.close();
        if was_open {
            kernel.push_event(Event::ChannelClosed(channel));
        }
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
        let inserted = match kernel.lanes.get_mut(&lane) {
            Some(lane) => {
                if lane.channels.len() >= MAX_CHANNELS_PER_LANE
                    && !lane.channels.contains(&channel.0)
                {
                    return Err(Error::BudgetExceeded("subscriptions"));
                }
                lane.channels.insert(channel.0)
            }
            None => false,
        };
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let subscribed = record.subscribers.insert(lane.0);
        // A repeat subscription changes nothing, and an event per call would let
        // a loop evict the tape (round 4, #2).
        if inserted || subscribed {
            kernel.push_event(Event::ChannelSubscribed { lane, channel });
        }
        Ok(())
    }

    /// Remove a lane's subscription to a channel.
    ///
    /// Subscriptions only grow otherwise (a destroy clears them), and a lane at
    /// its subscription ceiling could never subscribe again even after it no
    /// longer needed a channel. `Ok` when the lane was not subscribed.
    pub fn unsubscribe(&self, lane: LaneId, channel: ChannelId) -> Result<()> {
        let mut kernel = self.cell.borrow_mut();
        let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
        if lane_record.closed {
            return Err(Error::UnknownLane(lane.0));
        }
        // The channel must exist: silently accepting a destroyed id would hide
        // a use-after-destroy, and every other channel operation answers
        // `rpc/unknown-channel` for one.
        kernel
            .channels
            .get(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        let removed = match kernel.lanes.get_mut(&lane) {
            Some(lane) => lane.channels.remove(&channel.0),
            None => false,
        };
        let unsubscribed = match kernel.channels.get_mut(&channel) {
            Some(record) => record.subscribers.remove(&lane.0),
            None => false,
        };
        if removed || unsubscribed {
            kernel.push_event(Event::ChannelUnsubscribed { lane, channel });
        }
        Ok(())
    }

    /// Count and log a refused send or publish, exactly as a refused call is.
    /// Record a refusal once, with the metrics and the event that describe it.
    ///
    /// One function so every refusing entry point (`call`, `send`, `send_as`,
    /// `publish`, `publish_as`) reports the same counters and the same event:
    /// the transport-facing `*_as` variants used to bypass this entirely, so a
    /// peer-initiated refusal produced no metric and no event.
    fn note_refusal(&self, lane: LaneId, cap: Option<CapId>, result: Result<u64>) -> Result<u64> {
        if let Err(error) = &result {
            self.record_refusal(lane, cap, error);
        }
        result
    }

    /// Record one refusal: the counter, the dimension when it is a budget, and
    /// the trace event.
    ///
    /// Every refusing entry point goes through here. The idempotent path used to
    /// return early without it, so the highest-value replay denials (`rpc/revoked`
    /// on a cache hit, a key reused with different arguments) were invisible.
    fn record_refusal(&self, lane: LaneId, cap: Option<CapId>, error: &Error) {
        let mut kernel = self.cell.borrow_mut();
        Self::record_refusal_in(&mut kernel, lane, cap, error);
    }

    /// [`Agent::record_refusal`] for a caller that already holds the kernel.
    fn record_refusal_in(kernel: &mut Kernel, lane: LaneId, cap: Option<CapId>, error: &Error) {
        kernel.metrics.calls_refused = kernel.metrics.calls_refused.saturating_add(1);
        if matches!(error, Error::BudgetExceeded(_)) {
            kernel.metrics.budget_exhaustions = kernel.metrics.budget_exhaustions.saturating_add(1);
            kernel.push_event(Event::BudgetExhausted {
                cap,
                dimension: budget_dimension(error).to_string(),
            });
        }
        if matches!(error, Error::Identity(_)) {
            kernel.metrics.identity_refusals = kernel.metrics.identity_refusals.saturating_add(1);
        }
        kernel.push_event(Event::CallRefused {
            lane,
            cap,
            code: error.code().to_string(),
        });
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
    ///
    /// A refusal is recorded here, not only in [`Agent::send`]: a transport
    /// calls this variant directly, and its refusals used to produce no metric
    /// and no event.
    pub fn send_as(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        channel: ChannelId,
        payload: Value,
        caps: &[CapHandle],
    ) -> Result<u64> {
        let result = self.send_inner(peer, lane, channel, payload, caps);
        self.note_refusal(lane, caps.first().map(CapHandle::id), result)
    }

    fn send_inner(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        channel: ChannelId,
        payload: Value,
        caps: &[CapHandle],
    ) -> Result<u64> {
        let mut kernel = self.cell.borrow_mut();
        refresh_clock(&mut kernel);
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
        // A closed or receive-only channel is not "busy": reporting
        // backpressure for it would tell the sender to retry a send that can
        // never succeed.
        if !channel_record.can_send() {
            return Err(Error::InvalidArgument("channel is closed or receive-only"));
        }
        if channel_record.queued() >= kernel.channel_ceiling {
            kernel.metrics.backpressure_refusals =
                kernel.metrics.backpressure_refusals.saturating_add(1);
            return Err(Error::Backpressure("channel queue ceiling reached"));
        }
        if caps.len() > MAX_CAPS_PER_MESSAGE {
            return Err(Error::BudgetExceeded("caps per message"));
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut cap_ids = Vec::with_capacity(caps.len());
        for cap in caps {
            if !seen.insert(cap.id()) {
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
                if !crate::identity::matches(crate::identity::presented_fingerprint(peer), bound) {
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
        if let Some(error) = shape_refusal(&payload, &lane_budget) {
            return Err(error);
        }
        if value_too_deep(&payload, crate::wire::MAX_VALUE_DEPTH) {
            return Err(Error::BudgetExceeded("depth"));
        }
        let bytes = payload
            .wire_size()
            .checked_add((cap_ids.len() as u64).saturating_mul(16))
            .ok_or(Error::BudgetExceeded("byte"))?;
        if bytes > lane_budget.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        if lane_bytes
            .checked_add(bytes)
            .ok_or(Error::BudgetExceeded("lane byte"))?
            > lane_budget.max_bytes
        {
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
            lane_record.bytes = lane_record
                .bytes
                .checked_add(bytes)
                .ok_or(Error::BudgetExceeded("lane byte"))?;
            lane_record.completed = lane_record.completed.saturating_add(1);
        }
        kernel.push_event(Event::ChannelSend { channel, sequence });
        for id in cap_ids {
            kernel.metrics.transfers += 1;
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
        self.publish_as(None, lane, channel, cap, topic, payload)
    }

    /// [`Agent::publish`] on behalf of the peer the transport authenticated.
    ///
    /// A refusal is recorded here, not only in [`Agent::publish`].
    pub fn publish_as(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        channel: ChannelId,
        cap: &CapHandle,
        topic: &str,
        payload: Value,
    ) -> Result<u64> {
        let result = self.publish_inner(peer, lane, channel, cap, topic, payload);
        self.note_refusal(lane, Some(cap.id()), result)
    }

    fn publish_inner(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        channel: ChannelId,
        cap: &CapHandle,
        topic: &str,
        payload: Value,
    ) -> Result<u64> {
        let mut kernel = self.cell.borrow_mut();
        refresh_clock(&mut kernel);
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
        if let Some(bound) = record.attrs.bound_to {
            if !crate::identity::matches(crate::identity::presented_fingerprint(peer), bound) {
                return Err(Error::Identity(
                    "capability is bound to a different peer identity",
                ));
            }
        }
        if record.attrs.read_only {
            // Publishing writes to a channel; a read-only grant cannot mutate.
            return Err(Error::ReadOnly);
        }
        // Publishing is a grant of its own: holding a capability for some other
        // provider must not let a lane speak on a channel under a topic a
        // subscriber trusts.
        if !record.attrs.publish {
            return Err(Error::MethodNotGranted {
                method: "publish".to_string(),
            });
        }
        // The topic is attacker-controlled text that reaches an event and an
        // error message, so it is validated here like a method name, before it
        // can be copied anywhere.
        check_topic(topic)?;
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
        let effective = record.attrs.budget.intersect(&lane_budget);
        // The shape gate runs before the measurement, exactly as on the call
        // path: `wire_size` walks the whole value, and a publish that the ceiling
        // refuses must not pay that walk first (round 6, #1).
        if let Some(error) = shape_refusal(&payload, &effective) {
            return Err(error);
        }
        if value_too_deep(&payload, crate::wire::MAX_VALUE_DEPTH) {
            return Err(Error::BudgetExceeded("depth"));
        }
        // The topic name is metadata the channel stores and forwards, so it is
        // payload as far as the grant is concerned: charging only the value let
        // a 1 KiB topic ride through a 32-byte budget.
        let bytes = payload
            .wire_size()
            .checked_add(topic.len() as u64)
            .ok_or(Error::BudgetExceeded("byte"))?;
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
        if bytes > effective.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        if lane_bytes
            .checked_add(bytes)
            .ok_or(Error::BudgetExceeded("lane byte"))?
            > lane_budget.max_bytes
        {
            return Err(Error::BudgetExceeded("lane byte"));
        }
        // A publish is a call through the capability and through every
        // ancestor, exactly like `call_inner`.
        let mut chain: Vec<CapId> = record.lineage.clone();
        chain.push(cap.id());
        for id in &chain {
            if let Some(meter) = meter_for(&kernel, *id)? {
                meter.check(bytes)?;
            }
        }
        for id in &chain {
            if let Some(meter) = meter_mut_for(&mut kernel, *id)? {
                meter.charge(bytes)?;
            }
        }
        let record = kernel
            .channels
            .get_mut(&channel)
            .ok_or(Error::UnknownChannel(channel.0))?;
        // A publish needs the sequence, not the message: `send_topic` would
        // copy the whole payload for a value this path discards (round 2, #1).
        let sequence = record.send_topic_sequence(lane, topic, payload, Vec::new())?;
        kernel.queued_channel_bytes = kernel.queued_channel_bytes.saturating_add(bytes);
        if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
            lane_record.bytes = lane_record
                .bytes
                .checked_add(bytes)
                .ok_or(Error::BudgetExceeded("lane byte"))?;
            lane_record.completed = lane_record.completed.saturating_add(1);
        }
        kernel.push_event(Event::ChannelSend { channel, sequence });
        Ok(sequence)
    }

    /// Receive the next message published on `topic`, as `lane`.
    ///
    /// `lane` must be subscribed to the channel. Receiving used to need nothing
    /// but a channel id, and ids were a sequential counter, so any lane in the
    /// kernel could drain any other lane's messages. A lane that may not read a
    /// channel gets the same answer as one that names a channel which does not
    /// exist, so the refusal is not an oracle.
    pub fn recv_topic(
        &self,
        lane: LaneId,
        channel: ChannelId,
        topic: &str,
    ) -> Result<Option<Message>> {
        let mut kernel = self.cell.borrow_mut();
        check_subscriber(&kernel, lane, channel)?;
        // A topic the channel could never hold is invalid text, not "no
        // message". The subscriber check comes first so an unsubscribed lane
        // still cannot tell an invalid topic from a valid one.
        check_topic(topic)?;
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

    /// Receive the next message on a channel, as `lane`.
    ///
    /// `lane` must be subscribed to the channel; see [`Agent::recv_topic`].
    pub fn recv(&self, lane: LaneId, channel: ChannelId) -> Result<Option<Message>> {
        let mut kernel = self.cell.borrow_mut();
        check_subscriber(&kernel, lane, channel)?;
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
        self.call_with_origin(peer, lane, cap, method, args, payload_bytes, false)
    }

    /// One call with an explicit origin.
    ///
    /// `from_peer` marks arguments that a transport decoded: those can never
    /// carry authority, because a promise id names a result this kernel computed
    /// for someone else and a capability id in an argument is opaque data.
    #[allow(clippy::too_many_arguments)]
    fn call_with_origin(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
        from_peer: bool,
    ) -> Result<PromiseHandle> {
        self.call_with_origin_payload(
            peer,
            lane,
            cap,
            method,
            args,
            payload_bytes,
            Vec::new(),
            from_peer,
        )
    }

    /// One call with an explicit origin and the payload bytes it carried.
    ///
    /// The payload is what a bulk or blob provider reads; it was already charged
    /// as `payload_bytes`, so it travels to the provider instead of being
    /// discarded after the charge.
    #[allow(clippy::too_many_arguments)]
    fn call_with_origin_payload(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
        payload: Vec<u8>,
        from_peer: bool,
    ) -> Result<PromiseHandle> {
        if from_peer
            && args
                .iter()
                .any(|arg| matches!(arg, Arg::Promise(_) | Arg::Cap(_)))
        {
            return Err(Error::Wire(
                "an envelope cannot carry a promise or capability argument",
            ));
        }
        let cap_id = cap.id();
        let result = self.call_inner_payload(peer, lane, cap, method, args, payload_bytes, payload);
        if let Err(error) = &result {
            let mut kernel = self.cell.borrow_mut();
            kernel.metrics.calls_refused = kernel.metrics.calls_refused.saturating_add(1);
            kernel.push_event(Event::CallRefused {
                lane,
                cap: Some(cap_id),
                code: error.code().to_string(),
            });
            match error {
                Error::BudgetExceeded(dimension) => {
                    kernel.metrics.budget_exhaustions =
                        kernel.metrics.budget_exhaustions.saturating_add(1);
                    kernel.push_event(Event::BudgetExhausted {
                        cap: Some(cap_id),
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

    #[allow(clippy::too_many_arguments)]
    fn call_inner_payload(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
        payload: Vec<u8>,
    ) -> Result<PromiseHandle> {
        // A method name is caller-controlled text that reaches a refusal
        // message, an event and a receipt. A granted name is bounded at mint
        // (1..=1024 bytes), so a longer one cannot be granted and is refused
        // before anything clones or walks it (round 6, #6).
        if method.len() > MAX_GRANTED_METHOD_BYTES {
            return Err(Error::InvalidArgument(
                "a method name must be at most 1024 bytes",
            ));
        }
        // The wire bounds a message's argument list; an in-process caller is
        // bounded here, before any per-argument walk (round 7, F4).
        if args.len() > MAX_ARGS_PER_CALL {
            return Err(Error::BudgetExceeded("args"));
        }
        let mut kernel = self.cell.borrow_mut();
        // The expiry check below compares against `now_ms`. In wall-clock mode
        // that value only moves when someone refreshes it, so a capability whose
        // TTL elapsed since the last call used to be queued (and charged) and
        // refused only at dispatch.
        refresh_clock(&mut kernel);
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
            if !crate::identity::matches(crate::identity::presented_fingerprint(peer), bound) {
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
        let effective = record.attrs.budget.intersect(&lane_budget);
        // The shape ceilings bound the work every later check does: the path
        // walk, the tool ceiling and the byte measurement all traverse the
        // value, so an oversized value is refused first, by the bounded walk.
        // Measuring with `wire_size` before this point walked a hostile value in
        // full (round 5, N2).
        for arg in &args {
            let Arg::Value(value) = arg else { continue };
            if let Some(error) = shape_refusal(value, &effective) {
                return Err(error);
            }
            // The wire's absolute ceiling binds an in-process caller too: a
            // value deeper than that cannot be dropped or cloned safely
            // (round 10, #2). It runs after the budget gate, which refuses a
            // wide value in constant time.
            if value_too_deep(value, crate::wire::MAX_VALUE_DEPTH) {
                return Err(Error::BudgetExceeded("depth"));
            }
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
        let mut args_bytes = 0u64;
        for arg in &args {
            args_bytes = args_bytes
                .checked_add(Arg::wire_size(arg))
                .ok_or(Error::BudgetExceeded("byte"))?;
        }
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
        let call_bytes: u64 = args_bytes
            .checked_add(payload_bytes)
            .ok_or(Error::BudgetExceeded("byte"))?;
        if call_bytes > effective.max_bytes {
            return Err(Error::BudgetExceeded("byte"));
        }
        // A lane's byte ceiling is cumulative, not a per-call limit: otherwise
        // any number of calls each just under it would pass.
        if lane_bytes
            .checked_add(call_bytes)
            .ok_or(Error::BudgetExceeded("lane byte"))?
            > lane_budget.max_bytes
        {
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
            if let Some(meter) = meter_for(&kernel, *id)? {
                meter.check(call_bytes)?;
            }
        }
        for id in &chain {
            if let Some(meter) = meter_mut_for(&mut kernel, *id)? {
                meter.charge(call_bytes)?;
            }
        }
        if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
            lane_record.bytes = lane_record
                .bytes
                .checked_add(call_bytes)
                .ok_or(Error::BudgetExceeded("lane byte"))?;
        }

        let promise_id = PromiseId(kernel.next_promise);
        kernel.next_promise += 1;
        kernel
            .promises
            .insert(promise_id, PromiseRecord::new(promise_id, lane.0));

        // The call is authorized at queue time, but the receipt is written at
        // dispatch: that is where revocation, expiry and identity are re-checked,
        // and a receipt must record the decision the kernel actually took.

        let job_id = kernel.next_job;
        kernel.next_job += 1;
        for dep in &deps {
            if let Some(record) = kernel.promises.get_mut(dep) {
                record.waiters = record.waiters.saturating_add(1);
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
            payload,
            // The queue time is only a placeholder; dispatch stamps the clock it
            // actually decided at (see `dispatch`).
            now_ms: kernel.now_ms,
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
            receipted: false,
            identity: crate::identity::presented_fingerprint(peer),
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
            method: method_event_label(method),
            args_bytes,
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
                    return kernel.metrics.round_trips;
                }
                if kernel.queue.is_empty() {
                    kernel.apply_deferred_refops();
                    kernel.trim_settled();
                    return kernel.metrics.round_trips;
                }
                // Reference operations that arrived during a provider call are
                // applied before the next batch is chosen.
                kernel.apply_deferred_refops();
                match kernel.next_batch() {
                    Ok(batch) if batch.is_empty() => {
                        // Work is queued (for a provider being notified), so
                        // nothing may be trimmed: a queued consumer may still
                        // need its producer's record.
                        kernel.apply_deferred_refops();
                        return kernel.metrics.round_trips;
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
                            kernel.fail_job(job_id, error, true);
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
        self.cell.borrow().metrics.round_trips
    }

    /// Whether this kernel issued `promise`.
    ///
    /// Promise ids are a per-kernel counter, so two agents in one process issue
    /// colliding ids. A handle index into the wrong kernel would read, cancel or
    /// answer another tenant's call (round 3, F1).
    fn owns_promise(&self, promise: &PromiseHandle) -> bool {
        std::rc::Rc::ptr_eq(&self.cell, &promise.agent.cell)
    }

    /// Await a promise, running the kernel until it settles.
    pub fn await_promise(&self, promise: &PromiseHandle) -> Result<Value> {
        if !self.owns_promise(promise) {
            return Err(Error::UnknownPromise(promise.id.0));
        }
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
            let before = self.round_trips();
            self.run();
            if self.round_trips() == before && !self.cell.borrow().queue.is_empty() {
                // No batch ran: the only queued work belongs to a provider that
                // is being notified (a drop handler awaiting its own call).
                // Spinning here would burn CPU with no settlement.
                return Err(Error::UnresolvablePromise(promise.id.0));
            }
        }
    }

    /// Resolve a pending promise manually (used by peers that answer out of band).
    ///
    /// A capability bound to a peer can only be answered by that peer; use
    /// [`Agent::resolve_as`] from a transport, which presents the verified
    /// identity. This entry point presents none, so it refuses a bound call.
    pub fn resolve(&self, promise: &PromiseHandle, value: Value) -> Result<()> {
        self.resolve_as(None, promise, value)
    }

    /// [`Agent::resolve`] on behalf of the peer the transport authenticated.
    ///
    /// An out-of-band answer settles the same call dispatch would have run, so
    /// it is held to the same authority: the capability must be live and
    /// unexpired, the lane must exist, the peer binding must match, and the
    /// value is charged and shape-checked against the call's grant (round 7 F1,
    /// round 8 #2, round 9 F2/F3).
    pub fn resolve_as(
        &self,
        peer: Option<&PeerIdentity>,
        promise: &PromiseHandle,
        value: Value,
    ) -> Result<()> {
        if !self.owns_promise(promise) {
            return Err(Error::UnknownPromise(promise.id.0));
        }
        let mut kernel = self.cell.borrow_mut();
        // The expiry comparison below is against `now_ms`, which only moves when
        // it is refreshed in wall-clock mode (round 9, F3).
        refresh_clock(&mut kernel);
        let job = kernel
            .jobs
            .values()
            .find(|job| job.promise == promise.id)
            .cloned();
        if job.is_none() {
            // A pending promise always has a job. One without a job is already
            // settled (the settle below reports that); a pending one is a broken
            // invariant, and an answer with no job has no grant to be checked
            // against, so it fails closed.
            let pending = kernel
                .promises
                .get(&promise.id)
                .is_some_and(|record| record.state == crate::promise::PromiseState::Pending);
            if pending {
                return Err(Error::UnresolvablePromise(promise.id.0));
            }
        }
        if let Some(job) = &job {
            let lane_budget = match kernel.caps.get(&job.cap) {
                Some(record) if record.revoked => return Err(Error::Revoked(cap_token(job.cap))),
                Some(record)
                    if record
                        .expires_at
                        .is_some_and(|expires_at| kernel.now_ms >= expires_at) =>
                {
                    return Err(Error::Revoked(cap_token(job.cap)))
                }
                Some(record) => {
                    if let Some(bound) = record.attrs.bound_to {
                        if !crate::identity::matches(
                            crate::identity::presented_fingerprint(peer),
                            bound,
                        ) {
                            return Err(Error::Identity(
                                "a bound capability's promise can only be answered by its peer",
                            ));
                        }
                    }
                    match kernel.lanes.get(&job.lane) {
                        Some(lane_record) if !lane_record.closed => lane_record.budget,
                        _ => return Err(Error::UnknownLane(job.lane.0)),
                    }
                }
                None => return Err(Error::UnknownCapability(cap_token(job.cap))),
            };
            let budget = job.call.budget.intersect(&lane_budget);
            if let Some(error) = shape_refusal(&value, &budget) {
                return Err(error);
            }
            // The absolute wire ceiling too: a redaction or a later clone walks
            // the value recursively (round 10, #1).
            if value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) {
                return Err(Error::BudgetExceeded("depth"));
            }
        }
        drop(kernel);
        // The same egress policy dispatch applies: a redacting call receives a
        // redacted value, and a call that did not ask for redaction must not
        // receive a module that still carries structural secrets.
        let value = match &job {
            Some(job) => {
                let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if job.call.redact {
                        Ok(crate::security::redact_value(value))
                    } else {
                        crate::security::assert_no_structural_secrets(&value).map(|()| value)
                    }
                }))
                .unwrap_or_else(|_| {
                    Err(Error::Provider {
                        code: "wasm/trap".to_string(),
                    })
                });
                checked?
            }
            None => value,
        };
        // Eligibility first: a cancelled or already-settled promise must not
        // debit the chain for a value the caller will never receive
        // (audit AR-02).
        {
            let state = {
                let kernel = self.cell.borrow();
                match kernel.promises.get(&promise.id) {
                    Some(record) => record.state.clone(),
                    None => return Err(Error::UnknownPromise(promise.id.0)),
                }
            };
            match state {
                crate::promise::PromiseState::Cancelled => {
                    return Err(Error::PromiseCancelled(promise.id.0));
                }
                crate::promise::PromiseState::Resolved(_)
                | crate::promise::PromiseState::Rejected(_) => {
                    // The refusal is counted, as the settle path counted it:
                    // an operator must see the attempt even though nothing was
                    // charged for it.
                    {
                        let mut kernel = self.cell.borrow_mut();
                        kernel.metrics.promises_double_settled =
                            kernel.metrics.promises_double_settled.saturating_add(1);
                    }
                    return Err(Error::PromiseAlreadyResolved(promise.id.0));
                }
                _ => {}
            }
        }
        if let Some(job) = &job {
            // Charged before the settlement: a value the grant cannot afford
            // must not become the promise's answer. When the job is still in the
            // queue it is removed below, so the dispatch egress charge cannot
            // double-charge; a job already executing may be charged a second
            // time, which errs on the refusing side.
            self.charge_egress(job, value.wire_size())?;
        }
        let mut kernel = self.cell.borrow_mut();
        let settled = {
            let record = kernel
                .promises
                .get_mut(&promise.id)
                .ok_or(Error::UnknownPromise(promise.id.0))?;
            let cancelled = record.state == crate::promise::PromiseState::Cancelled;
            (record.resolve(value), cancelled)
        };
        if settled.0.is_err() && !settled.1 {
            // A cancelled promise is a caller decision (round 6, #5).
            kernel.metrics.promises_double_settled =
                kernel.metrics.promises_double_settled.saturating_add(1);
        }
        settled.0?;
        // The answer is the decision: mark the job receipted before the
        // queued-job cleanup, which would otherwise seal a refusal for a call
        // that was answered (R-02 round 4 #1).
        if let Some(job) = &job {
            if let Some(stored) = kernel.jobs.get_mut(&job.id) {
                stored.receipted = true;
            }
        }
        // A promise answered out of band must not still run its provider: the
        // side effect would happen after the caller already has the answer.
        if let Some(job_id) = kernel
            .jobs
            .iter()
            .find(|(id, job)| job.promise == promise.id && kernel.queue.contains(id))
            .map(|(id, _)| *id)
        {
            // The caller answered before the kernel ran the call; the queued
            // work is dropped, which is a refusal an audit must show.
            kernel.record_queued_refusal(job_id, &Error::PromiseAlreadyResolved(promise.id.0));
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
                // The answered job never ran, but a tape that ends at
                // `call.queued` cannot tell that from a stranded job
                // (round 7, #3).
                kernel.push_event(Event::JobCompleted { job: job_id, lane });
            }
        }
        kernel.push_event(Event::PromiseResolved(promise.id));
        kernel.metrics.promises_resolved = kernel.metrics.promises_resolved.saturating_add(1);
        kernel.record_settled(promise.id);
        drop(kernel);
        if let Some(job) = &job {
            // The caller holds this value: seal the decision here, so a later
            // dispatch cannot seal a `Refused` receipt for a call that was
            // answered (round 4, #1).
            self.record_receipt(job, None);
        }
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
        // The authority-argument guard is `call_with_origin_payload`'s, with
        // `from_peer` set: one choke point instead of a copy that a new entry
        // point can forget (round 4, #7).
        self.call_with_origin_payload(
            peer,
            lane,
            cap,
            &envelope.method,
            envelope.args.clone(),
            envelope.payload.len() as u64,
            envelope.payload.clone(),
            true,
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
        self.call_idempotent_as_with_payload(peer, lane, cap, method, args, 0, key)
    }

    /// Issue a call on behalf of a peer the policy admitted.
    ///
    /// [`Agent::call_as`] takes a bare [`PeerIdentity`], which a caller can only
    /// produce through the transport's report; this takes the type
    /// [`crate::identity::IdentityPolicy::admit`] returned, so a dispatcher that
    /// has one has already run the policy and cannot silently drop the trust
    /// level.
    pub fn call_peer(
        &self,
        lane: LaneId,
        cap: &CapHandle,
        peer: &crate::identity::AdmittedIdentity,
        method: &str,
        args: Vec<Arg>,
    ) -> Result<PromiseHandle> {
        self.call_as(Some(peer.identity()), lane, cap, method, args)
    }

    /// Admit a transport peer under `policy`, then dispatch an envelope.
    ///
    /// This is the one call a transport-side dispatcher needs: the policy decides
    /// whether the peer may proceed at all, and the admitted identity is what the
    /// kernel checks a binding against. Calling [`Agent::call_from_envelope`]
    /// directly with a raw `PeerIdentity` skips [`crate::identity::IdentityPolicy::admit`]
    /// entirely.
    ///
    /// `loopback` must come from the connection's own addresses (see
    /// [`crate::identity::IdentityPolicy::admit`]); it is never a header or a caller flag.
    pub fn dispatch_envelope(
        &self,
        policy: &crate::identity::IdentityPolicy,
        peer: Option<&PeerIdentity>,
        loopback: bool,
        lane: LaneId,
        cap: &CapHandle,
        envelope: &crate::wire::Envelope,
    ) -> Result<PromiseHandle> {
        let admitted = policy.admit(peer, loopback)?;
        self.call_from_envelope(Some(admitted.identity()), lane, cap, envelope)
    }

    /// [`Agent::call_idempotent_as`] for a call that carries `payload_bytes`.
    ///
    /// Only the payload **size** is part of the fingerprint, because this entry
    /// point never sees the body: two payloads of the same length under one key
    /// are the same call to it. A caller that holds the body uses
    /// [`Agent::call_idempotent_as_with_body`], which fingerprints its content.
    /// The bytes are charged exactly as a non-idempotent call would charge them.
    #[allow(clippy::too_many_arguments)]
    pub fn call_idempotent_as_with_payload(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
        key: &str,
    ) -> Result<PromiseHandle> {
        self.call_idempotent_inner(peer, lane, cap, method, args, payload_bytes, None, key)
    }

    /// [`Agent::call_idempotent_as`] for a call that carries a `body`.
    ///
    /// The body's content is part of the fingerprint, so two same-length
    /// payloads are different calls and a replay with an edited body is
    /// refused.
    #[allow(clippy::too_many_arguments)]
    pub fn call_idempotent_as_with_body(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        body: &[u8],
        key: &str,
    ) -> Result<PromiseHandle> {
        self.call_idempotent_inner(
            peer,
            lane,
            cap,
            method,
            args,
            body.len() as u64,
            Some(body),
            key,
        )
    }

    /// The shared body of the keyed entries.
    #[allow(clippy::too_many_arguments)]
    fn call_idempotent_inner(
        &self,
        peer: Option<&PeerIdentity>,
        lane: LaneId,
        cap: &CapHandle,
        method: &str,
        args: Vec<Arg>,
        payload_bytes: u64,
        body: Option<&[u8]>,
        key: &str,
    ) -> Result<PromiseHandle> {
        // The method goes into the key map and the fingerprint, so its bound
        // is checked before anything copies it (round 7, F3).
        if method.len() > MAX_GRANTED_METHOD_BYTES {
            let error = Error::InvalidArgument("a method name must be at most 1024 bytes");
            self.record_refusal(lane, Some(cap.id()), &error);
            return Err(error);
        }
        if args.len() > MAX_ARGS_PER_CALL {
            let error = Error::BudgetExceeded("args");
            self.record_refusal(lane, Some(cap.id()), &error);
            return Err(error);
        }
        if key.is_empty() {
            let error = Error::InvalidArgument("idempotency key is empty");
            self.record_refusal(lane, Some(cap.id()), &error);
            return Err(error);
        }
        if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
            let error = Error::InvalidArgument("idempotency key is too long");
            self.record_refusal(lane, Some(cap.id()), &error);
            return Err(error);
        }
        // The fingerprint hashes every byte of the arguments, so the shape
        // ceilings gate the work before anything traverses the value. The
        // capability's budget is the widest grant this call can run under; the
        // lane intersection is re-checked on the queue path (round 5, N3).
        if !self.cell.borrow().caps.contains_key(&cap.id()) {
            let error = Error::UnknownCapability(cap_token(cap.id()));
            self.record_refusal(lane, Some(cap.id()), &error);
            return Err(error);
        }
        let shape_error = {
            let kernel = self.cell.borrow();
            let cap_budget = kernel
                .caps
                .get(&cap.id())
                .ok_or(Error::UnknownCapability(cap_token(cap.id())))?
                .attrs
                .budget;
            // The lane may be narrower than the capability: gating on the cap
            // alone would let a wide capability hash a value that the lane will
            // refuse (round 6, #4).
            let budget = match kernel.lanes.get(&lane) {
                Some(lane_record) => cap_budget.intersect(&lane_record.budget),
                None => cap_budget,
            };
            let mut error = None;
            for arg in &args {
                let Arg::Value(value) = arg else { continue };
                if let Some(refusal) = shape_refusal(value, &budget) {
                    error = Some(refusal);
                    break;
                }
                if value_too_deep(value, crate::wire::MAX_VALUE_DEPTH) {
                    error = Some(Error::BudgetExceeded("depth"));
                    break;
                }
            }
            error
        };
        if let Some(error) = shape_error {
            self.record_refusal(lane, Some(cap.id()), &error);
            return Err(error);
        }
        let fingerprint = fingerprint_with_payload(&args, payload_bytes, body);
        // A replay is an exercise of authority in one lane: the key is scoped
        // to it, and the lane must still exist and have capacity, exactly as a
        // fresh call requires.
        {
            let kernel = self.cell.borrow();
            let unknown = !kernel.lanes.contains_key(&lane)
                || kernel.lanes.get(&lane).is_some_and(|record| record.closed);
            drop(kernel);
            if unknown {
                let error = Error::UnknownLane(lane.0);
                self.record_refusal(lane, Some(cap.id()), &error);
                return Err(error);
            }
            // Capacity is checked on the miss path only: a cached replay makes
            // no call, and refusing it at the ceiling would defeat the retry
            // idempotency exists for.
        }
        let map_key = (cap.id(), lane, method.to_string(), key.to_string());
        {
            let mut kernel = self.cell.borrow_mut();
            // A replay re-uses a cached promise; the capability it names must
            // still be live now, not as of the last refresh.
            refresh_clock(&mut kernel);
            if let Some((id, stored_args, stored_peer)) = kernel.idempotency.get(&map_key).copied()
            {
                if stored_args != fingerprint {
                    let error = Error::InvalidArgument(
                        "the idempotency key was used with different arguments",
                    );
                    Self::record_refusal_in(&mut kernel, lane, Some(cap.id()), &error);
                    return Err(error);
                }
                // A key names the principal that claimed it. A replay from
                // another peer would hand it a promise whose job was stamped for
                // the first caller, and dispatch would then refuse it — a
                // confusing failure for a request that is simply not the same
                // one.
                if stored_peer != crate::identity::presented_fingerprint(peer) {
                    let error = Error::Identity("the idempotency key belongs to another peer");
                    Self::record_refusal_in(&mut kernel, lane, Some(cap.id()), &error);
                    return Err(error);
                }
                {
                    let record = kernel
                        .caps
                        .get(&cap.id())
                        .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
                    if record.revoked {
                        let error = Error::Revoked(cap_token(cap.id()));
                        Self::record_refusal_in(&mut kernel, lane, Some(cap.id()), &error);
                        return Err(error);
                    }
                    if record
                        .expires_at
                        .is_some_and(|expires_at| kernel.now_ms >= expires_at)
                    {
                        kernel.push_event(Event::CapExpired(cap.id()));
                        let error = Error::Revoked(cap_token(cap.id()));
                        Self::record_refusal_in(&mut kernel, lane, Some(cap.id()), &error);
                        return Err(error);
                    }
                    if let Some(bound) = record.attrs.bound_to {
                        if !crate::identity::matches(
                            crate::identity::presented_fingerprint(peer),
                            bound,
                        ) {
                            let error =
                                Error::Identity("capability is bound to a different peer identity");
                            Self::record_refusal_in(&mut kernel, lane, Some(cap.id()), &error);
                            return Err(error);
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
                    // The value was admitted under the grant at the time. A lane
                    // narrowed since then must not serve it again, or a replay
                    // becomes a way past the current ceiling (round 10, #3).
                    let current = match (kernel.caps.get(&cap.id()), kernel.lanes.get(&lane)) {
                        (Some(record), Some(lane_record)) => {
                            record.attrs.budget.intersect(&lane_record.budget)
                        }
                        (Some(record), None) => record.attrs.budget,
                        _ => return Err(Error::UnknownCapability(cap_token(cap.id()))),
                    };
                    let over = match kernel.promises.get(&id) {
                        Some(record) => match &record.state {
                            PromiseState::Resolved(value) => shape_refusal(value, &current),
                            _ => None,
                        },
                        None => None,
                    };
                    if let Some(error) = over {
                        Self::record_refusal_in(&mut kernel, lane, Some(cap.id()), &error);
                        return Err(error);
                    }
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
        if !self
            .cell
            .borrow()
            .lanes
            .get(&lane)
            .is_some_and(|record| record.has_capacity())
        {
            let error = Error::BudgetExceeded("lane call");
            self.record_refusal(lane, Some(cap.id()), &error);
            return Err(error);
        }
        let promise = match body {
            Some(bytes) => self.call_with_origin_payload(
                peer,
                lane,
                cap,
                method,
                args,
                payload_bytes,
                bytes.to_vec(),
                false,
            )?,
            // A size-only caller has no body to deliver: the charge is the only
            // thing it can account for, and its doc says so.
            None => self.call_as_with_payload(peer, lane, cap, method, args, payload_bytes)?,
        };
        let id = promise.id();
        let mut kernel = self.cell.borrow_mut();
        kernel.idempotency.insert(
            map_key.clone(),
            (
                id,
                fingerprint,
                crate::identity::presented_fingerprint(peer),
            ),
        );
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
        if !self.owns_promise(promise) {
            return Err(Error::UnknownPromise(promise.id.0));
        }
        let mut kernel = self.cell.borrow_mut();
        {
            let record = kernel
                .promises
                .get_mut(&promise.id)
                .ok_or(Error::UnknownPromise(promise.id.0))?;
            record.cancel()?;
        }
        // A job whose provider is running cannot be stopped; a job that is in
        // the batch but has not started yet still can, and removing it is the
        // point of `cancel` (its provider would otherwise run after the caller
        // was told the call was cancelled).
        let queued: Option<u64> = kernel
            .jobs
            .iter()
            .find(|(_, job)| job.promise == promise.id && job.state == JobState::Queued)
            .map(|(id, _)| *id);
        if let Some(job_id) = queued {
            kernel.record_queued_refusal(job_id, &Error::PromiseCancelled(promise.id.0));
            kernel.queue.retain(|id| *id != job_id);
            let lane = kernel.jobs.get(&job_id).map(|job| job.lane);
            let cap = kernel.jobs.get(&job_id).map(|job| job.cap);
            // A cancelled job never ran: count and trace the refusal exactly as
            // `fail_job` does, so the tape does not end at `call.queued`
            // (round 6, #2).
            kernel.metrics.calls_refused = kernel.metrics.calls_refused.saturating_add(1);
            if let Some(lane) = lane {
                kernel.push_event(Event::CallRefused {
                    lane,
                    cap,
                    code: "rpc/promise-cancelled".to_string(),
                });
            }
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
                kernel.push_event(Event::JobCompleted { job: job_id, lane });
            }
        } else if let Some(job) = kernel
            .jobs
            .values()
            .find(|job| job.promise == promise.id)
            .cloned()
        {
            // The job is in the current batch and its provider is running (or
            // about to). Its phase 3 cannot settle a cancelled record, so record
            // the terminal state here, and seal the decision: the provider may
            // have run, and a receipt that says nothing hides that
            // (round 5, #2).
            kernel.record_settled(promise.id);
            if kernel.receipts_enabled {
                kernel.seal_receipt(&job, Some(&Error::PromiseCancelled(promise.id.0)));
            }
            if let Some(stored) = kernel.jobs.get_mut(&job.id) {
                stored.receipted = true;
            }
        }
        Ok(())
    }

    /// Cancel a promise and every promise that depends on it.
    ///
    /// The tree walk follows queued job dependencies. A dependent whose job is
    /// still queued is removed before dispatch, so a cancellation prevents the
    /// provider call and its side effects. An already-settled root is refused;
    /// dependent promises that already settled are left untouched. The returned
    /// list holds the promises this call cancelled.
    pub fn cancel_tree(&self, promise: &PromiseHandle) -> Result<Vec<PromiseId>> {
        if !self.owns_promise(promise) {
            return Err(Error::UnknownPromise(promise.id.0));
        }
        let mut kernel = self.cell.borrow_mut();
        let root_state = kernel
            .promises
            .get(&promise.id)
            .ok_or(Error::UnknownPromise(promise.id.0))?
            .state
            .clone();
        if root_state != PromiseState::Pending {
            return Err(match root_state {
                PromiseState::Cancelled => Error::PromiseCancelled(promise.id.0),
                _ => Error::PromiseAlreadyResolved(promise.id.0),
            });
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
        let mut cancelled: Vec<PromiseId> = Vec::new();
        let mut seen: BTreeSet<PromiseId> = BTreeSet::new();
        seen.insert(promise.id);
        let mut index = 0;
        while index < targets.len() {
            let id = targets[index];
            if let Some(record) = kernel.promises.get_mut(&id) {
                if record.state == PromiseState::Pending {
                    record.cancel()?;
                    cancelled.push(id);
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
        // A job the current batch has dequeued but not started still has state
        // `Queued`: it can be cancelled for real, exactly as `cancel` does, so it
        // is counted and traced rather than treated as a provider that already
        // ran (round 8, #1).
        let queued: Vec<(u64, PromiseId, u64, CapId)> = kernel
            .jobs
            .iter()
            .filter(|(_, job)| job.state == JobState::Queued && targets_set.contains(&job.promise))
            .map(|(id, job)| (*id, job.promise, job.lane.0, job.cap))
            .collect();
        let mut queued_promises: BTreeSet<PromiseId> = BTreeSet::new();
        for (job_id, promise_id, lane, cap) in queued {
            kernel.record_queued_refusal(job_id, &Error::PromiseCancelled(promise_id.0));
            kernel.queue.retain(|queued_id| *queued_id != job_id);
            let deps = kernel
                .jobs
                .get(&job_id)
                .map(|job| job.deps.clone())
                .unwrap_or_default();
            Kernel::release_waiters(&mut kernel, &deps);
            kernel.jobs.remove(&job_id);
            kernel.record_settled(promise_id);
            queued_promises.insert(promise_id);
            kernel.metrics.calls_refused = kernel.metrics.calls_refused.saturating_add(1);
            kernel.push_event(Event::CallRefused {
                lane: LaneId(lane),
                cap: Some(cap),
                code: "rpc/promise-cancelled".to_string(),
            });
            if let Some(lane_record) = kernel.lanes.get_mut(&LaneId(lane)) {
                lane_record.complete();
            }
            kernel.push_event(Event::JobCompleted {
                job: job_id,
                lane: LaneId(lane),
            });
        }
        // A promise cancelled while its job is in the current batch is removed
        // by that dispatch, which cannot settle a cancelled record: without this
        // the record is never evictable and repeated cancellations wedge the
        // promise ceiling (round 3, F3). Only a promise this call cancelled is
        // recorded, and only once: `record_settled` pushes to its deque on every
        // call, so a second record would inflate the settled size and evict live
        // records early (round 4, #2).
        for id in &cancelled {
            if !queued_promises.contains(id) {
                kernel.record_settled(*id);
                // The target's job is in the current batch and its provider is
                // running. Its dispatch will discard the outcome, so without a
                // receipt here the executed work leaves no decision on the tape
                // (round 7, #1).
                if let Some(job) = kernel.jobs.values().find(|job| job.promise == *id).cloned() {
                    if !job.receipted && kernel.receipts_enabled {
                        kernel.seal_receipt(&job, Some(&Error::PromiseCancelled(id.0)));
                    }
                    if let Some(stored) = kernel.jobs.get_mut(&job.id) {
                        stored.receipted = true;
                    }
                }
            }
        }
        // The caller gets the promises this call cancelled, not every dependent
        // it walked: an already-settled dependent was left untouched.
        Ok(cancelled)
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
        if !self.owns_promise(promise) {
            return 0;
        }
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

    /// The events the bounded tape gained since `seen_total`.
    ///
    /// `None` means the tape wrapped: some of the delta was evicted before it
    /// could be read, and a caller that needs every event (a recorder) must fail
    /// rather than pretend it saw a shorter history. Only the delta is cloned,
    /// so a consumer that captures per operation stays linear instead of
    /// copying the whole tape each time.
    pub fn events_since(&self, seen_total: u64) -> Option<Vec<Event>> {
        let kernel = self.cell.borrow();
        let total = kernel.events_total;
        let retained = kernel.events.len() as u64;
        // A `seen_total` above this kernel's total is a *different* kernel (a
        // restart reuses the number space from zero). Returning an empty delta
        // would tell a recorder it saw a silent stretch when in fact it must
        // fail: `saturating_sub` would make the miss look like zero.
        if seen_total > total {
            return None;
        }
        let missed = total - seen_total;
        if missed > retained {
            return None;
        }
        let skip = (retained - missed) as usize;
        Some(kernel.events.iter().skip(skip).cloned().collect())
    }

    /// Bytes this capability's own meter has left.
    ///
    /// The meter's ceiling, not an ancestor's: a caller that needs the
    /// intersected figure can compare with its lane. Exposed so an operator
    /// (and the audit regression) can prove a refused out-of-band resolve
    /// charged nothing (audit AR-02).
    pub fn remaining_bytes(&self, cap: &CapHandle) -> Result<u64> {
        let kernel = self.cell.borrow();
        let record = kernel
            .caps
            .get(&cap.id())
            .ok_or(Error::UnknownCapability(cap_token(cap.id())))?;
        Ok(kernel
            .meters
            .get(&record.id)
            .map(|meter| meter.remaining_bytes())
            .unwrap_or(record.attrs.budget.max_bytes))
    }

    /// Point-in-time counters. Contains no capability ids or payloads.
    pub fn metrics(&self) -> Metrics {
        let kernel = self.cell.borrow();
        let mut metrics = kernel.metrics;
        // Gauges that live on the kernel rather than in the counter struct are
        // copied here, so `metrics_json` can report them without a second
        // source that could drift.
        metrics.events_total = kernel.events_total;
        metrics.events_retained = kernel.events.len() as u64;
        metrics.events_evicted = kernel.events_evicted;
        metrics.receipts_dropped = kernel.receipts_dropped;
        metrics.promises_retained = kernel.promises.len() as u64;
        metrics.promises_pending = kernel
            .promises
            .values()
            .filter(|record| record.state == PromiseState::Pending)
            .count() as u64;
        metrics
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

    /// Calls issued by `lane` that are still waiting to be dispatched.
    ///
    /// This is the part of [`Lane::pending`] the kernel has not handed to a
    /// provider yet. Linear in the number of queued calls; a caller that needs
    /// every lane wants [`Agent::lane_queue_depths`] instead.
    pub fn lane_queue_depth(&self, lane: LaneId) -> Result<usize> {
        let kernel = self.cell.borrow();
        if !kernel.lanes.contains_key(&lane) {
            return Err(Error::UnknownLane(lane.0));
        }
        Ok(kernel
            .queue
            .iter()
            .filter(|id| kernel.jobs.get(id).is_some_and(|job| job.lane == lane))
            .count())
    }

    /// Queued-call depth for every live lane, in one pass over the queue.
    ///
    /// A dashboard that asked per lane would walk the queue once per lane on
    /// every snapshot, on the same thread that dispatches.
    pub fn lane_queue_depths(&self) -> std::collections::BTreeMap<LaneId, usize> {
        let kernel = self.cell.borrow();
        let mut depths: std::collections::BTreeMap<LaneId, usize> =
            kernel.lanes.keys().map(|lane| (*lane, 0)).collect();
        for id in &kernel.queue {
            if let Some(job) = kernel.jobs.get(id) {
                if let Some(depth) = depths.get_mut(&job.lane) {
                    *depth += 1;
                }
            }
        }
        depths
    }

    /// Channel statistics.
    /// Statistics for one channel, with no queue and no messages.
    ///
    /// This used to return a clone of the channel, which owns its queue and can
    /// `recv`: a lane that was refused a read could take the mailbox, payload and
    /// transferred capability ids included.
    pub fn channel(&self, channel: ChannelId) -> Result<crate::channel::ChannelStats> {
        self.cell
            .borrow()
            .channels
            .get(&channel)
            .map(crate::channel::Channel::stats)
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
            if lane_record
                .bytes
                .checked_add(extra)
                .ok_or(Error::BudgetExceeded("lane byte"))?
                > lane_record.budget.max_bytes
            {
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
            if let Some(meter) = meter_for(&kernel, *id)? {
                meter.check_bytes(extra)?;
            }
        }
        for id in &chain {
            if let Some(meter) = meter_mut_for(&mut kernel, *id)? {
                meter.charge_bytes(extra)?;
            }
        }
        if let Some(lane_record) = kernel.lanes.get_mut(&job.lane) {
            lane_record.bytes = lane_record
                .bytes
                .checked_add(extra)
                .ok_or(Error::BudgetExceeded("lane byte"))?;
        }
        Ok(())
    }

    /// Charge a provider's response against the grant, before it is delivered.
    ///
    /// `max_bytes` is documented as the payload bytes moved *through* a
    /// capability, and a response moves through it. Charging here keeps the
    /// "charged before work" rule for the request and still makes the ceiling an
    /// egress bound: a response that does not fit settles as
    /// `rpc/budget-exceeded` instead of leaving the kernel for free.
    fn charge_egress(&self, job: &Job, bytes: u64) -> Result<()> {
        self.charge_egress_for(job.lane, job.cap, bytes)
    }

    /// Charge `bytes` of egress on behalf of a capability and lane.
    ///
    /// [`Agent::call_from_envelope`] charges the *inbound* payload; a dispatcher
    /// that attaches a payload to the response envelope must charge that too,
    /// otherwise `max_bytes` ("both directions") only bounds one of them. The
    /// chain is checked in full before anything is charged.
    pub fn charge_egress_bytes(&self, lane: LaneId, cap: &CapHandle, bytes: u64) -> Result<()> {
        self.charge_egress_for(lane, cap.id(), bytes)
    }

    fn charge_egress_for(&self, lane: LaneId, cap: CapId, bytes: u64) -> Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        let mut kernel = self.cell.borrow_mut();
        // A lane that no longer exists cannot bound the response: fail closed
        // rather than deliver it against the capability alone (round 4, #2).
        let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
        // `checked_add`: a saturated counter would pass every later check.
        let total = lane_record
            .bytes
            .checked_add(bytes)
            .ok_or(Error::BudgetExceeded("lane byte"))?;
        if total > lane_record.budget.max_bytes {
            return Err(Error::BudgetExceeded("lane byte"));
        }
        let mut chain: Vec<CapId> = kernel
            .caps
            .get(&cap)
            .map(|record| record.lineage.clone())
            .unwrap_or_default();
        chain.push(cap);
        for id in &chain {
            if let Some(meter) = meter_for(&kernel, *id)? {
                meter.check_bytes(bytes)?;
            }
        }
        for id in &chain {
            if let Some(meter) = meter_mut_for(&mut kernel, *id)? {
                meter.charge_bytes(bytes)?;
            }
        }
        if let Some(lane_record) = kernel.lanes.get_mut(&lane) {
            lane_record.bytes = lane_record
                .bytes
                .checked_add(bytes)
                .ok_or(Error::BudgetExceeded("lane byte"))?;
        }
        Ok(())
    }

    /// Record the dispatch decision for a job, when receipts are enabled.
    ///
    /// `refusal` is the error the kernel settled the job with, if any. Marks the
    /// job as receipted so a later `fail_job` does not record the same decision
    /// twice.
    fn record_receipt(&self, job: &Job, refusal: Option<&Error>) {
        let mut kernel = self.cell.borrow_mut();
        if !kernel.receipts_enabled {
            return;
        }
        kernel.seal_receipt(job, refusal);
        if let Some(stored) = kernel.jobs.get_mut(&job.id) {
            stored.receipted = true;
        }
    }

    fn dispatch(&self, batch: Vec<u64>) {
        // No kernel borrow is held while a provider runs: a provider may hold an
        // `Agent` and call back into the kernel, and a re-entrant borrow would
        // panic (or, with `try_borrow_mut`, silently drop a refcount update).
        // Each phase takes a short borrow and returns owned data.
        let (provider_id, provider, now_ms) = {
            let mut kernel = self.cell.borrow_mut();
            let Some(first) = batch.first().and_then(|id| kernel.jobs.get(id)) else {
                return;
            };
            let provider_id = kernel
                .caps
                .get(&first.cap)
                .map(|record| record.provider)
                .unwrap_or(ProviderId(u64::MAX));
            // A batch whose provider has vanished is not a round trip: it used
            // to advance the counter and emit `BatchDispatched` before failing
            // every job (round 4, #6).
            if kernel.providers.contains_key(&provider_id) {
                kernel.metrics.round_trips += 1;
                kernel.now_ms = if kernel.wall_clock {
                    kernel.now_ms.max(wall_now_ms())
                } else {
                    kernel.now_ms.saturating_add(kernel.latency_ms)
                };
                let lane_count: usize = batch
                    .iter()
                    .filter_map(|id| kernel.jobs.get(id).map(|job| job.lane.0))
                    .collect::<BTreeSet<u64>>()
                    .len();
                kernel.push_event(Event::BatchDispatched {
                    provider: provider_id,
                    jobs: batch.len(),
                    lane_count,
                });
            }
            kernel.dispatching = true;
            let provider = kernel.providers.remove(&provider_id);
            // Captured with the provider so phase 2 (which holds no borrow) can
            // stamp the call time without borrowing the cell again.
            let now_ms = kernel.now_ms;
            (provider_id, provider, now_ms)
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
                    true,
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
        // Dropped after `guard`, so a panic in any phase fails the jobs that
        // have not run yet instead of stranding them.
        let mut batch_guard = BatchGuard {
            agent: self,
            pending: batch.iter().copied().collect(),
        };

        for job_id in &batch {
            // Phase 1: decide, under a read borrow.
            let prepared = {
                let kernel = self.cell.borrow();
                let Some(job) = kernel.jobs.get(job_id).cloned() else {
                    continue;
                };
                let mut args = Vec::with_capacity(job.call.args.len());
                // The arguments were authorized when they were queued, possibly
                // under a wider lane. Gate them before this loop copies
                // anything: a `Value` clone recurses, and the substituted copy
                // below is the one that must not happen for a value the current
                // grant refuses (round 8, #1).
                // The grant as it is now: the capability's current budget
                // intersected with the lane's. The copy on the job is the one
                // taken at queue time, and an attenuation between queue and
                // dispatch would otherwise let a value the current grant refuses
                // be cloned before the refusal (round 8, #2).
                let gate_budget = match (kernel.caps.get(&job.cap), kernel.lanes.get(&job.lane)) {
                    (Some(record), Some(lane)) => record.attrs.budget.intersect(&lane.budget),
                    (Some(record), None) => record.attrs.budget,
                    (None, _) => job.call.budget,
                };
                // The caller may have cancelled or answered this job after the
                // batch was chosen. It must not run: the provider side effect
                // would land after the caller was told the call would not run
                // (round 5, #1).
                let mut failure = match kernel.promises.get(&job.promise) {
                    Some(record) if record.state.is_settled() => Some(match &record.state {
                        crate::promise::PromiseState::Cancelled => {
                            Error::PromiseCancelled(job.promise.0)
                        }
                        _ => Error::PromiseAlreadyResolved(job.promise.0),
                    }),
                    None => Some(Error::UnknownPromise(job.promise.0)),
                    Some(_) => None,
                };
                for arg in &job.call.args {
                    let Arg::Value(value) = arg else { continue };
                    if let Some(error) = shape_refusal(value, &gate_budget) {
                        failure = Some(error);
                        break;
                    }
                    // Budget-relative ceilings are not enough here: a lane may
                    // allow a depth the derived `Clone` cannot survive, and the
                    // substitution loop below copies every value (round 9, F1).
                    if value_too_deep(value, crate::wire::MAX_VALUE_DEPTH) {
                        failure = Some(Error::BudgetExceeded("depth"));
                        break;
                    }
                }
                if failure.is_none() {
                    for arg in &job.call.args {
                        match arg {
                            Arg::Promise(id) => match kernel.promises.get(id) {
                                Some(record) if record.state.is_settled() => match &record.state {
                                    crate::promise::PromiseState::Resolved(value) => {
                                        // `Value::clone` recurses, so a deep value
                                        // must be refused before the copy is made
                                        // (round 7, F2). The shape ceiling is
                                        // checked here too: copying a value the
                                        // grant refuses doubles its memory before
                                        // the refusal.
                                        if value_too_deep(value, crate::wire::MAX_VALUE_DEPTH) {
                                            failure = Some(Error::BudgetExceeded("depth"));
                                            break;
                                        }
                                        if let Some(error) = shape_refusal(value, &gate_budget) {
                                            failure = Some(error);
                                            break;
                                        }
                                        args.push(Arg::Value(value.clone()));
                                    }
                                    crate::promise::PromiseState::Rejected(error) => {
                                        failure = Some(error.clone());
                                        break;
                                    }
                                    crate::promise::PromiseState::Cancelled => {
                                        failure = Some(Error::PromiseCancelled(id.0));
                                        break;
                                    }
                                    crate::promise::PromiseState::Pending => {
                                        failure = Some(Error::UnresolvablePromise(id.0));
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
                // The identity binding is re-checked here, not only at queue
                // time: a capability introduced to another peer after this call
                // was authorized must not hand the queued caller authority the
                // operator has since withdrawn.
                if failure.is_none() {
                    if let Some(record) = &record {
                        if let Some(bound) = record.attrs.bound_to {
                            if !crate::identity::matches(job.identity, bound) {
                                failure = Some(Error::Identity(
                                    "capability is bound to a different peer identity",
                                ));
                            }
                        }
                    }
                }
                // A lane's grant can be narrowed after a call was queued
                // (`Agent::attenuate_lane`). The budget a queued call is
                // re-checked against, and the one the provider receives, is the
                // capability's grant intersected with the lane's *current*
                // grant; the copy taken at queue time would let a call queued
                // under a wide lane run after the lane narrowed.
                // A missing lane is a refusal, not a wider grant: using the
                // capability's budget alone would dispatch work whose lane no
                // longer exists under a ceiling that no longer exists either
                // (round 3, F3). `destroy_lane` also fails queued jobs, so this
                // is the belt to that brace.
                let (effective_budget, lane_live) = match kernel.lanes.get(&job.lane) {
                    Some(lane_record) => (
                        record.as_ref().map_or(job.call.budget, |record| {
                            record.attrs.budget.intersect(&lane_record.budget)
                        }),
                        !lane_record.closed,
                    ),
                    None => (
                        record
                            .as_ref()
                            .map_or(job.call.budget, |record| record.attrs.budget),
                        false,
                    ),
                };
                if !lane_live && failure.is_none() {
                    failure = Some(Error::UnknownLane(job.lane.0));
                }
                // A promise argument was a placeholder when the call was
                // queued. Its value is authority-bearing too, so the shape
                // ceilings gate the work first: the byte measurement and the
                // path walk both traverse the value, and the gate is the
                // bounded walk (round 6, #2).
                if failure.is_none() {
                    for arg in &args {
                        let Arg::Value(value) = arg else { continue };
                        if let Some(error) = shape_refusal(value, &effective_budget) {
                            failure = Some(error);
                            break;
                        }
                    }
                }
                let resolved_bytes: u64 = if failure.is_none() {
                    let mut total = 0u64;
                    for arg in &args {
                        match total.checked_add(Arg::wire_size(arg)) {
                            Some(next) => total = next,
                            None => {
                                failure = Some(Error::BudgetExceeded("byte"));
                                break;
                            }
                        }
                    }
                    total
                } else {
                    0
                };
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
                        if failure.is_none() {
                            // The *complete* delivered request: a payload queued
                            // under a wide grant must not ride in when the lane
                            // or capability was narrowed afterwards
                            // (audit ARPC-001).
                            let payload = job.call.payload.len() as u64;
                            match resolved_bytes.checked_add(payload) {
                                Some(delivered) if delivered <= effective_budget.max_bytes => {}
                                Some(_) => {
                                    failure = Some(Error::BudgetExceeded("byte"));
                                }
                                None => {
                                    failure = Some(Error::BudgetExceeded("byte"));
                                }
                            }
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
                    effective_budget,
                ))
            };
            let Some((job, args, failure, object, expired, extra, effective_budget)) = prepared
            else {
                continue;
            };
            // The job is executing from here: a provider may destroy the lane it
            // is running on, and the promise then belongs to this dispatch until
            // the outcome is recorded.
            if let Some(entry) = self.cell.borrow_mut().jobs.get_mut(&job.id) {
                entry.state = JobState::Running;
            }
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
            // Phase 2: run provider code with no borrow held. Whether the
            // method mutates decides how a post-provider refusal is reported:
            // a provider that ran may already have changed its state
            // (round 31, F1).
            let mutating = guard.provider_mut().mutating(&job.call.method);
            let mut provider_succeeded = false;
            let outcome = match failure {
                Some(error) => Err(error),
                None => {
                    let mut call = Call {
                        args,
                        budget: effective_budget,
                        ..job.call.clone()
                    };
                    // The decision time, from the kernel's clock, so a provider
                    // that reads a clock follows the kernel's policy.
                    call.now_ms = now_ms;
                    // A provider panic settles this job as a provider fault and
                    // is resumed after the batch: a leaked job would leave its
                    // promise pending forever, and the host still sees the
                    // panic.
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        guard.provider_mut().invoke(object, &call)
                    })) {
                        Ok(Ok(response)) => {
                            provider_succeeded = true;
                            let value = response.into_value();
                            // Settlement hashes and walks the value; an
                            // unbounded one would abort the process where no
                            // catch_unwind can reach.
                            if value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) {
                                Err(Error::BudgetExceeded("depth"))
                            } else {
                                Ok(value)
                            }
                        }
                        Ok(Err(error)) => Err(error),
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

            // Set when an out-of-band answer or a cancellation settled the
            // promise while the provider was running: phase 3 then discards this
            // outcome, which is not a kernel double settlement, and the decision
            // already sealed (by the resolve or the cancel) stands. It is the
            // promise's state that decides, not which branch of the outcome
            // produced it (round 6, #1).
            let resolved_out_of_band = self
                .cell
                .borrow()
                .promises
                .get(&job.promise)
                .is_some_and(|record| record.state.is_settled());
            // Egress is charged before settlement: a response larger than the
            // remaining grant never leaves the kernel.
            let outcome = match outcome {
                Ok(value) => match shape_refusal(&value, &effective_budget) {
                    Some(error) => Err(error),
                    // The ceilings come before the policy walk: `redact_value`
                    // and `assert_no_structural_secrets` recurse, and a value
                    // deeper than the stack aborts the process where
                    // `catch_unwind` cannot help (round 30, L-8).
                    None if value_too_deep(&value, crate::wire::MAX_VALUE_DEPTH) => {
                        Err(Error::BudgetExceeded("depth"))
                    }
                    None => {
                        // The redaction policy is enforced here, not left to the
                        // provider: a redacting call gets a redacted value, and a
                        // call that did not ask for redaction must not receive a
                        // module that still carries structural secrets.
                        // The policy decodes `Value::Module` bytes, and those may be
                        // chosen by remote code (a WASM guest's output). The codec is
                        // fail-closed by contract, but a panic here would unwind
                        // outside the provider's `catch_unwind`, so it is contained
                        // and reported as a provider fault.
                        let checked =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                if job.call.redact {
                                    Ok(crate::security::redact_value(value))
                                } else {
                                    crate::security::assert_no_structural_secrets(&value)
                                        .map(|()| value)
                                }
                            }))
                            .unwrap_or_else(|_| {
                                Err(Error::Provider {
                                    code: "wasm/trap".to_string(),
                                })
                            });
                        match checked {
                            Err(error) => Err(error),
                            Ok(value) => {
                                // A resolve that won the race already delivered its
                                // value; charging this one would bill twice for a
                                // value the caller never sees (round 3, F4).
                                if resolved_out_of_band {
                                    Ok(value)
                                } else {
                                    match self.charge_egress(&job, value.wire_size()) {
                                        Ok(()) => Ok(value),
                                        Err(error) => Err(error),
                                    }
                                }
                            }
                        }
                    }
                },
                Err(error) => Err(error),
            };

            // A mutating provider that ran already applied its effect. A
            // post-provider budget or lane refusal is then a withheld reply,
            // not a call that did not happen: a retryable budget class would
            // invite a second, non-idempotent write, and a `Refused` receipt
            // would deny an effect that landed (round 31, F1).
            let mut effect_withheld = false;
            let outcome = match outcome {
                Err(Error::BudgetExceeded(_)) | Err(Error::UnknownLane(_))
                    if provider_succeeded && mutating =>
                {
                    effect_withheld = true;
                    Err(Error::Provider {
                        code: "provider/reply-withheld".to_string(),
                    })
                }
                other => other,
            };

            // The decision is final here: dispatch's re-checks, provider code
            // and the egress policy (redaction, shape ceilings, the byte charge)
            // have all run. Seal exactly one receipt with the outcome the caller
            // will see: a refusal after that point (an egress budget, a module
            // carrying secret material) used to be sealed as `Admitted`, so the
            // audit artifact disagreed with the metric and the caller. When the
            // provider ran and only the reply was withheld, the effect stands
            // and the receipt records the admission.
            if !resolved_out_of_band {
                if effect_withheld {
                    self.record_receipt(&job, None);
                } else {
                    self.record_receipt(&job, outcome.as_ref().err());
                }
            }

            // Phase 3: settle under a write borrow.
            let mut kernel = self.cell.borrow_mut();
            let mut settled_now = false;
            match &outcome {
                Ok(value) => {
                    if let Some(record) = kernel.promises.get_mut(&job.promise) {
                        if record.resolve(value.clone()).is_ok() {
                            settled_now = true;
                        } else if record.state != crate::promise::PromiseState::Cancelled
                            && !resolved_out_of_band
                        {
                            // A cancelled promise is a caller decision, not a
                            // kernel double settlement: the outcome is
                            // discarded on purpose (round 5, N4).
                            kernel.metrics.promises_double_settled =
                                kernel.metrics.promises_double_settled.saturating_add(1);
                        }
                    }
                    if settled_now {
                        kernel.push_event(Event::PromiseResolved(job.promise));
                        kernel.metrics.promises_resolved =
                            kernel.metrics.promises_resolved.saturating_add(1);
                    }
                }
                Err(error) => {
                    if let Some(record) = kernel.promises.get_mut(&job.promise) {
                        if record.reject(error.clone()).is_ok() {
                            settled_now = true;
                        } else if record.state != crate::promise::PromiseState::Cancelled
                            && !resolved_out_of_band
                        {
                            kernel.metrics.promises_double_settled =
                                kernel.metrics.promises_double_settled.saturating_add(1);
                        }
                    }
                    if settled_now {
                        kernel.push_event(Event::PromiseRejected {
                            promise: job.promise,
                            code: error.code().to_string(),
                        });
                        kernel.metrics.promises_rejected =
                            kernel.metrics.promises_rejected.saturating_add(1);
                        // The dispatch re-checks (a promise's resolved bytes, a
                        // shape ceiling, a tool ceiling, the egress charge) are
                        // budget and tool refusals too. They used to settle as a
                        // bare rejection, so a dashboard read "no budget
                        // exhaustions" while calls were being refused for a
                        // budget, and the dimension was lost.
                        match error {
                            Error::BudgetExceeded(_) => {
                                kernel.metrics.calls_refused =
                                    kernel.metrics.calls_refused.saturating_add(1);
                                kernel.push_event(Event::CallRefused {
                                    lane: job.lane,
                                    cap: Some(job.cap),
                                    code: error.code().to_string(),
                                });
                                kernel.metrics.budget_exhaustions =
                                    kernel.metrics.budget_exhaustions.saturating_add(1);
                                kernel.push_event(Event::BudgetExhausted {
                                    cap: Some(job.cap),
                                    dimension: budget_dimension(error).to_string(),
                                });
                            }
                            Error::ToolPolicy(_) => {
                                kernel.metrics.calls_refused =
                                    kernel.metrics.calls_refused.saturating_add(1);
                                kernel.push_event(Event::CallRefused {
                                    lane: job.lane,
                                    cap: Some(job.cap),
                                    code: error.code().to_string(),
                                });
                                kernel.metrics.tool_refusals =
                                    kernel.metrics.tool_refusals.saturating_add(1);
                                kernel.push_event(Event::ToolRefused {
                                    cap: job.cap,
                                    reason: error.to_string(),
                                });
                            }
                            // An authority refusal that only surfaced at
                            // dispatch (a revoke, an expiry, a binding, a gone
                            // lane) was invisible to the counters and the tape
                            // (round 3, F7).
                            Error::Identity(_) => {
                                kernel.metrics.identity_refusals =
                                    kernel.metrics.identity_refusals.saturating_add(1);
                                kernel.metrics.calls_refused =
                                    kernel.metrics.calls_refused.saturating_add(1);
                                kernel.push_event(Event::CallRefused {
                                    lane: job.lane,
                                    cap: Some(job.cap),
                                    code: error.code().to_string(),
                                });
                            }
                            Error::Revoked(_)
                            | Error::UnknownCapability(_)
                            | Error::UnknownLane(_)
                            | Error::PathNotGranted(_)
                            | Error::MethodNotGranted { .. }
                            | Error::ReadOnly
                            | Error::TopicNotGranted(_)
                            | Error::UnknownPromise(_)
                            | Error::UnresolvablePromise(_)
                            | Error::PromiseCancelled(_)
                            | Error::PromiseAlreadyResolved(_) => {
                                kernel.metrics.calls_refused =
                                    kernel.metrics.calls_refused.saturating_add(1);
                                kernel.push_event(Event::CallRefused {
                                    lane: job.lane,
                                    cap: Some(job.cap),
                                    code: error.code().to_string(),
                                });
                            }
                            _ => {}
                        }
                    }
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
            batch_guard.pending.remove(job_id);
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
            // A bounded tape must say what it dropped: without this an operator
            // cannot tell a quiet kernel from one whose history was overwritten.
            self.events_evicted = self.events_evicted.saturating_add(1);
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

    /// Record a new capability and count it against its object.
    ///
    /// Every capability enters the registry through here, so the per-object
    /// count that drives `on_drop` cannot drift from the registry.
    fn insert_cap_record(&mut self, record: CapRecord) {
        *self
            .object_records
            .entry((record.provider, record.object))
            .or_insert(0) += 1;
        self.caps.insert(record.id, record);
    }

    /// Remove a capability and decrement its object's count.
    fn remove_cap_record(&mut self, id: CapId) -> Option<CapRecord> {
        let record = self.caps.remove(&id)?;
        let key = (record.provider, record.object);
        if let Some(count) = self.object_records.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.object_records.remove(&key);
            }
        }
        Some(record)
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
            let Some(record) = kernel.remove_cap_record(id) else {
                continue;
            };
            kernel.meters.remove(&id);
            kernel.push_event(Event::CapDropped(id));
            if kernel.consumed_records.contains(&record.record_id) {
                // Exported and now unreferenced: the record is still
                // restorable, which an operator must be able to see
                // (audit AR-03).
                kernel.push_event(Event::CapRecordOrphaned(id));
            }
            // `on_drop` means "the last capability that referenced this object
            // is gone": a provider may use it to reclaim per-object state. It
            // used to fire for every capability, so a provider that freed the
            // object when its first capability was dropped would free it while
            // a sibling could still call it.
            if !kernel
                .object_records
                .contains_key(&(record.provider, record.object))
            {
                kernel.queue_provider_drop(record.provider, record.object, id);
            }
            // The counter is an index over the registry, and every insertion
            // and removal goes through `insert_cap_record`/`remove_cap_record`.
            // A path that bypassed either would make `on_drop` fire early (the
            // provider frees an object a sibling still calls) or never. A full
            // drain must empty both, which is cheap to assert on every drop; a
            // per-object cross-check would restore the quadratic scan this
            // counter removed.
            debug_assert_eq!(
                kernel.caps.is_empty(),
                kernel.object_records.is_empty(),
                "the per-object record count disagrees with the registry"
            );
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
                    || self
                        .idempotency
                        .values()
                        .any(|(mapped, _, _)| mapped == id);
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
        // Kahn's algorithm in waves: each wave emits, in candidate order, every
        // job whose remaining dependencies were produced by earlier waves. That
        // is the same output order as the old scan-and-remove loop, but linear
        // in the batch (audit AR-01; the old `pending.remove(index)` was
        // quadratic and stalled dispatch on a large queue).
        let count = candidates.len();
        let mut position: std::collections::HashMap<u64, usize> =
            std::collections::HashMap::with_capacity(count);
        for (index, id) in candidates.iter().enumerate() {
            position.insert(*id, index);
        }
        let mut producers: std::collections::HashMap<PromiseId, usize> =
            std::collections::HashMap::with_capacity(count);
        for (index, id) in candidates.iter().enumerate() {
            if let Some(job) = self.jobs.get(id) {
                producers.insert(job.promise, index);
            }
        }
        let mut indegree = vec![0usize; count];
        let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); count];
        // A dependency produced outside this batch that is not settled yet can
        // never be satisfied here: such a job is left out, as before.
        let mut blocked = vec![false; count];
        for (index, id) in candidates.iter().enumerate() {
            let Some(job) = self.jobs.get(id) else {
                continue;
            };
            for dep in &job.deps {
                let settled = match self.promises.get(dep) {
                    Some(record) => record.state.is_settled(),
                    None => false,
                };
                if settled {
                    continue;
                }
                match producers.get(dep) {
                    Some(producer) => {
                        indegree[index] += 1;
                        dependents[*producer].push(index);
                    }
                    None => blocked[index] = true,
                }
            }
        }
        let mut ready: BTreeSet<usize> = (0..count)
            .filter(|index| indegree[*index] == 0 && !blocked[*index])
            .collect();
        let mut ordered = Vec::with_capacity(count);
        while !ready.is_empty() {
            // The wave is the ready set at its start: a job that becomes ready
            // while this wave emits belongs to the next one, which is what the
            // old per-pass scan did.
            let wave: Vec<usize> = ready.iter().copied().collect();
            ready.clear();
            for index in wave {
                ordered.push(candidates[index]);
                for dependent in &dependents[index] {
                    indegree[*dependent] = indegree[*dependent].saturating_sub(1);
                    if indegree[*dependent] == 0 && !blocked[*dependent] {
                        ready.insert(*dependent);
                    }
                }
            }
        }
        ordered
    }

    /// Record a refusal for a queued job that is about to be dropped.
    ///
    /// A caller that cancels, resolves out of band or destroys a lane removes
    /// work the kernel never dispatched. That is a decision the audit must show,
    /// for the same reason `fail_job` records one.
    fn record_queued_refusal(&mut self, job_id: u64, error: &Error) {
        if !self.receipts_enabled {
            return;
        }
        let Some(job) = self.jobs.get(&job_id).filter(|job| !job.receipted).cloned() else {
            return;
        };
        self.seal_receipt(&job, Some(error));
        if let Some(stored) = self.jobs.get_mut(&job_id) {
            stored.receipted = true;
        }
    }

    /// Seal one receipt into the ring and update the ring's bookkeeping.
    ///
    /// Lives on `Kernel` so both the dispatch path (which borrows the cell) and
    /// `fail_job` (which is `&mut self`) record through the same code.
    fn seal_receipt(&mut self, job: &Job, refusal: Option<&Error>) {
        // A receipt records when the decision was taken. Only dispatch used to
        // advance the virtual clock, so a kernel that continued a log across a
        // restart and then refused a call before any dispatch sealed `at_ms = 0`
        // and poisoned the whole export. Refresh from the wall clock here when
        // the kernel follows it, and never move backwards.
        if self.wall_clock {
            self.now_ms = self.now_ms.max(wall_now_ms());
        }
        let Some(next) = self.next_receipt.checked_add(1) else {
            // The sequence space is exhausted; a repeated sequence would make
            // every later export fail, so the ring stops recording instead.
            self.receipts_dropped = self.receipts_dropped.saturating_add(1);
            return;
        };
        self.next_receipt = next;
        let decision = match refusal {
            Some(error) => crate::receipts::Decision::Refused(error.code().to_string()),
            None => crate::receipts::Decision::Admitted,
        };
        let receipt = crate::receipts::Receipt::seal(
            &self.receipt_key,
            self.next_receipt,
            job.cap,
            &receipt_method(&job.call.method),
            self.now_ms,
            decision,
        );
        self.receipts.push_back(receipt);
        if self.receipts.len() > crate::receipts::MAX_RECEIPTS {
            self.receipts.pop_front();
            self.receipts_dropped = self.receipts_dropped.saturating_add(1);
            // Report at 1, 2, 4, 8 … evictions, always with the running total.
            // One event per eviction would flush the useful history out of the
            // bounded tape; one event ever would leave a reader with "1" after a
            // thousand drops. The power-of-two ladder bounds both.
            let total = self.receipts_dropped;
            if total.is_power_of_two() {
                self.push_event(Event::ReceiptsDropped { count: total });
            }
        }
    }

    fn fail_job(&mut self, job_id: u64, error: Error, events: bool) {
        // A job failed before dispatch (an unorderable pipeline, a provider that
        // vanished, a destroyed lane) still took a decision: record it, so an
        // auditor can tell "no call" from "refused and undocumented". A job that
        // already has a receipt (admitted or refused at dispatch) is not
        // recorded twice.
        self.record_queued_refusal(job_id, &error);
        // A job that never ran is still a refused call: the counters say so, and
        // the tape too unless the caller coalesced a mass destroy
        // (round 4, #3).
        self.metrics.calls_refused = self.metrics.calls_refused.saturating_add(1);
        if let Error::Identity(_) = &error {
            self.metrics.identity_refusals = self.metrics.identity_refusals.saturating_add(1);
        }
        if events {
            if let Some(job) = self.jobs.get(&job_id) {
                let lane = job.lane;
                let cap = job.cap;
                let code = error.code().to_string();
                self.push_event(Event::CallRefused {
                    lane,
                    cap: Some(cap),
                    code,
                });
            }
        }
        let deps = self
            .jobs
            .get(&job_id)
            .map(|job| job.deps.clone())
            .unwrap_or_default();
        Kernel::release_waiters(self, &deps);
        if let Some(job) = self.jobs.get_mut(&job_id) {
            let promise = job.promise;
            let lane = job.lane;
            let code = error.code().to_string();
            let mut settled_now = false;
            if let Some(record) = self.promises.get_mut(&promise) {
                if record.reject(error).is_ok() {
                    settled_now = true;
                }
                // A failed reject means the promise was already settled (a
                // cancel, an out-of-band answer, a duplicate failure). That is a
                // caller decision or a repeated failure, not a kernel double
                // settlement (round 8, #3).
            }
            if let Some(lane_record) = self.lanes.get_mut(&lane) {
                lane_record.complete();
            }
            if settled_now {
                // Only a settlement that happened is a rejection: a record that
                // was already settled (cancelled, resolved out of band) must not
                // appear as both settled and rejected.
                if events {
                    self.push_event(Event::PromiseRejected { promise, code });
                }
                self.metrics.promises_rejected = self.metrics.promises_rejected.saturating_add(1);
                self.record_settled(promise);
            }
            self.jobs.remove(&job_id);
            if events {
                self.push_event(Event::JobCompleted { job: job_id, lane });
            }
        }
    }
}

/// Longest topic a channel accepts, in bytes.
pub const MAX_TOPIC_BYTES: usize = 128;

/// Whether a topic can travel through a channel, an event and an error message.
///
/// A topic is caller-supplied text that a subscriber treats as provenance, so an
/// empty string, an unbounded string or a control character cannot be accepted:
/// the first is indistinguishable from "no topic", the second is a memory and
/// log problem, and the third forges a line in a terminal or a log file.
pub fn valid_topic(topic: &str) -> bool {
    crate::security::valid_text(topic, MAX_TOPIC_BYTES)
}

/// Refuse a topic the channel surfaces cannot represent.
fn check_topic(topic: &str) -> Result<()> {
    if !valid_topic(topic) {
        return Err(Error::InvalidArgument(
            "a topic must be 1..=128 bytes without control or reordering characters",
        ));
    }
    Ok(())
}

/// Refuse a receive from a lane that did not subscribe.
///
/// The same error as an unknown channel: a lane that may not read a channel must
/// not be able to tell it apart from one that does not exist, or the ids become
/// a membership oracle.
fn check_subscriber(kernel: &Kernel, lane: LaneId, channel: ChannelId) -> Result<()> {
    // The lane's liveness comes first: every other operation answers
    // `rpc/unknown-lane` for a lane that is gone, and a receive would otherwise
    // report the channel class for a lane that no longer exists (round 4, #1).
    let lane_record = kernel.lanes.get(&lane).ok_or(Error::UnknownLane(lane.0))?;
    if lane_record.closed {
        return Err(Error::UnknownLane(lane.0));
    }
    match kernel.channels.get(&channel) {
        Some(record) if record.subscribers.contains(&lane.0) => Ok(()),
        _ => Err(Error::UnknownChannel(channel.0)),
    }
}

/// Milliseconds since the Unix epoch, or 0 if the clock is before it.
fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// The budget dimension a refusal names, for the event that records it.
fn budget_dimension(error: &Error) -> &'static str {
    match error {
        Error::BudgetExceeded(dimension) => match &dimension[..] {
            "call" => "call",
            "byte" => "byte",
            "lane call" => "lane call",
            "lane byte" => "lane byte",
            "promises" => "promises",
            "jobs" => "jobs",
            "caps" => "caps",
            "lanes" => "lanes",
            "channels" => "channels",
            "subscriptions" => "subscriptions",
            "records" => "records",
            "tombstones" => "tombstones",
            "nodes" => "nodes",
            "keys" => "keys",
            "value" => "value",
            "wall" => "wall",
            "depth" => "depth",
            "array_len" => "array_len",
            "value_size" => "value_size",
            "caps per message" => "caps per message",
            "args" => "args",
            "channel queue" => "channel queue",
            _ => "other",
        },
        _ => "other",
    }
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

/// Longest method label a queued-call event carries.
///
/// The trace needs the method to pin what a queued call asked for; a method
/// longer than this is represented by an escaped prefix plus a digest tail, so
/// two long names that share a prefix still differ.
pub const MAX_METHOD_EVENT_BYTES: usize = 64;

/// Largest method name a capability may grant, and therefore the largest one a
/// call may name. `receipts::valid_method` enforces the same bound at mint.
pub const MAX_GRANTED_METHOD_BYTES: usize = 1_024;

/// Most arguments one call may carry.
///
/// The wire caps an envelope at 4 096 arguments, and the kernel holds an
/// in-process caller to the same bound: every check on the call path walks the
/// argument list, so an unbounded one makes a refusal cost its own length.
pub const MAX_ARGS_PER_CALL: usize = 4_096;

/// A log-safe, bounded label for a method name.
fn method_event_label(method: &str) -> String {
    // The fast path applies the receipt rule, not just "no control character":
    // `valid_text` also refuses line separators, bidi controls and zero-width
    // characters, and a method carrying one would be sealed into a receipt the
    // log then refuses to encode.
    if method.len() <= MAX_METHOD_EVENT_BYTES && crate::security::valid_text(method, method.len()) {
        return method.to_string();
    }
    let mut label: String = method
        .chars()
        .take(MAX_METHOD_EVENT_BYTES)
        .flat_map(char::escape_debug)
        .collect();
    let digest = blake3::hash(method.as_bytes());
    label.push('#');
    // 128 bits: a caller chooses the name, so a short tail would let two names
    // that share a prefix be confused for one another in a receipt or a trace.
    for byte in &digest.as_bytes()[..16] {
        label.push_str(&format!("{byte:02x}"));
    }
    label
}

/// The method name a receipt records.
///
/// A granted method is already representable (`check_method_names`), so it is
/// recorded exactly. A refused call can carry any caller-chosen name, including
/// one the receipt format cannot hold: that name is escaped and bounded like an
/// event label, so the refusal is still exportable and still distinguishes
/// names that share a prefix.
fn receipt_method(method: &str) -> String {
    if crate::receipts::valid_method(method) {
        return method.to_string();
    }
    let label = method_event_label(method);
    // The fallback must be total: an escaped label that still fails the receipt
    // rule would make the whole ring unexportable.
    if !crate::receipts::valid_method(&label) {
        return "<unrepresentable>".to_string();
    }
    if label.is_empty() {
        "<empty>".to_string()
    } else {
        label
    }
}

/// Refuse a granted method name the audit surfaces cannot represent.
///
/// A receipt stores the method in a `u16`-length field and must not carry a
/// control character, and the event label has the same rule. A name that breaks
/// either would be minted but never exportable, which turns one bad grant into
/// an audit log that cannot be written at all.
fn check_method_names(attrs: &CapAttrs) -> Result<()> {
    if attrs
        .methods
        .iter()
        .any(|method| !crate::receipts::valid_method(method))
    {
        return Err(Error::InvalidArgument(
            "a method name must be 1..=1024 bytes without control characters",
        ));
    }
    // A granted topic the channel cannot carry would mint a capability that can
    // never publish, and the name reaches an event: both are checked at the
    // grant, like a method name.
    if let Some(topics) = &attrs.topics {
        if topics.iter().any(|topic| !valid_topic(topic)) {
            return Err(Error::InvalidArgument(
                "a topic must be 1..=128 bytes without control or reordering characters",
            ));
        }
    }
    // A path scope reaches the same surfaces (an event, an error message, the
    // sealed record), and an empty scope is the one `from_json` refuses: a
    // capability that cannot be exported or restored is a mint that should have
    // failed (round 4, #6).
    if let Some(scope) = &attrs.path_scope {
        if !crate::security::valid_text(scope, MAX_PATH_SCOPE_BYTES) {
            return Err(Error::InvalidArgument(
                "a path scope must be 1..=1024 bytes without control or reordering characters",
            ));
        }
    }
    // A tool name is a method name on the other side of the policy.
    if let Some(policy) = &attrs.tool_policy {
        if policy
            .allowed
            .iter()
            .any(|name| !crate::receipts::valid_method(name))
        {
            return Err(Error::InvalidArgument(
                "a tool name must be 1..=1024 bytes without control characters",
            ));
        }
    }
    Ok(())
}

/// Longest path scope a capability may carry.
pub const MAX_PATH_SCOPE_BYTES: usize = 1_024;

/// Refuse a binding that names no real peer.
///
/// The all-zero fingerprint is the anonymous constant and the loopback
/// fingerprint is shared by every local process; a capability bound to either
/// would be usable by a peer that never proved anything.
fn check_binding(attrs: &CapAttrs) -> Result<()> {
    if let Some(bound) = attrs.bound_to {
        if !crate::identity::bindable(bound) {
            return Err(Error::Identity(
                "a capability cannot be bound to an anonymous or loopback identity",
            ));
        }
    }
    Ok(())
}

/// Every live descendant of `root` in the children index.
fn descendants_of(children: &BTreeMap<CapId, BTreeSet<CapId>>, root: CapId) -> Vec<CapId> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        if let Some(descendants) = children.get(&id) {
            for child in descendants {
                if seen.insert(*child) {
                    stack.push(*child);
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Revoke `seeds`, every capability derived from them and every capability that
/// carries one of their record ids; tombstone each durable record.
///
/// One walk, shared by `revoke` and `tombstone_record`, so a kill switch cannot
/// reach a capability that a revocation would have reached.
fn revoke_subtree(kernel: &mut Kernel, seeds: impl IntoIterator<Item = CapId>) {
    let mut doomed = BTreeSet::new();
    let mut stack: Vec<CapId> = seeds.into_iter().collect();
    while let Some(id) = stack.pop() {
        if !doomed.insert(id) {
            continue;
        }
        if let Some(descendants) = kernel.children.get(&id) {
            stack.extend(descendants.iter().copied());
        }
    }
    // Every capability restored from the same record is revoked with it: a peer
    // that restored twice before the kill switch must not keep a copy.
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
        let mut was_revoked = false;
        let record_id = match kernel.caps.get_mut(&id) {
            Some(record) => {
                was_revoked = record.revoked;
                record.revoked = true;
                // Only a durable record can ever be restored, so only its id
                // needs a tombstone; an ephemeral one would leak an entry per
                // mint/revoke cycle forever.
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
        // A second revoke of the same capability is authority-correct but is
        // not a second revocation: counting it let a retry loop over-report the
        // kill switch and flush the tape the incident review needs.
        if !was_revoked {
            kernel.push_event(Event::CapRevoked(id));
            kernel.metrics.revocations = kernel.metrics.revocations.saturating_add(1);
        }
    }
}

/// Fingerprint of an argument list: shape and content, no secret bytes.
///
/// An idempotency key must not answer a *different* request, so the cache
/// compares this before returning the stored promise. A secret contributes its
/// marker and size only: hashing its content would be an oracle.
fn fingerprint_with_payload(args: &[Arg], payload_bytes: u64, body: Option<&[u8]>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"active-rpc/idempotency-payload/v1\0");
    hasher.update(&args_fingerprint(args));
    hasher.update(&payload_bytes.to_le_bytes());
    // A body is fingerprinted by content. The size is all a caller that passes
    // only a length can offer, and the two forms are domain-separated so a
    // size-only key can never match a content key for the same length.
    match body {
        Some(bytes) => {
            hasher.update(b"body");
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        None => {
            hasher.update(b"size");
        }
    }
    *hasher.finalize().as_bytes()
}

fn args_fingerprint(args: &[Arg]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(args.len() as u64).to_le_bytes());
    let mut stack: Vec<&Value> = Vec::new();
    for arg in args {
        match arg {
            Arg::Value(value) => {
                hasher.update(b"v");
                stack.push(value);
                while let Some(value) = stack.pop() {
                    match value {
                        Value::Null => {
                            hasher.update(b"\0");
                        }
                        Value::Bool(flag) => {
                            hasher.update(b"b");
                            hasher.update(&[u8::from(*flag)]);
                        }
                        Value::Int(number) => {
                            hasher.update(b"i");
                            hasher.update(&number.to_le_bytes());
                        }
                        Value::Float(number) => {
                            hasher.update(b"f");
                            hasher.update(&number.to_bits().to_le_bytes());
                        }
                        Value::Text(text) => {
                            hasher.update(b"t");
                            hasher.update(&(text.len() as u64).to_le_bytes());
                            hasher.update(text.as_bytes());
                        }
                        Value::Path(path) => {
                            hasher.update(b"p");
                            hasher.update(&(path.len() as u64).to_le_bytes());
                            hasher.update(path.as_bytes());
                        }
                        Value::Module(bytes) => {
                            hasher.update(b"m");
                            hasher.update(&(bytes.len() as u64).to_le_bytes());
                            hasher.update(bytes);
                        }
                        Value::Secret => {
                            hasher.update(b"s");
                        }
                        Value::List(items) => {
                            hasher.update(b"l");
                            hasher.update(&(items.len() as u64).to_le_bytes());
                            stack.extend(items.iter().rev());
                        }
                        Value::Map(entries) => {
                            hasher.update(b"o");
                            hasher.update(&(entries.len() as u64).to_le_bytes());
                            for (key, _) in entries.iter().rev() {
                                hasher.update(&(key.len() as u64).to_le_bytes());
                                hasher.update(key.as_bytes());
                            }
                            stack.extend(entries.values().rev());
                        }
                    }
                }
            }
            Arg::Promise(id) => {
                hasher.update(b"q");
                hasher.update(&id.0.to_le_bytes());
            }
            Arg::Cap(id) => {
                hasher.update(b"c");
                hasher.update(&id.0);
            }
        }
    }
    *hasher.finalize().as_bytes()
}

/// Key of the idempotency cache: capability, lane, method and caller key.
type IdempotencyKey = (CapId, LaneId, String, String);

/// One cached idempotency claim: the promise, the request fingerprint, and the
/// fingerprint of the peer that claimed the key (so a replay from another peer
/// is refused at the hit rather than at dispatch).
type IdempotencyEntry = (PromiseId, [u8; 32], Option<[u8; 32]>);

/// True when a provider's value nests deeper than the wire accepts.
///
/// The decoder caps nesting at 64; a provider can build anything. Settlement
/// hashes and walks the value, so an unbounded one overflows the stack and
/// aborts the process (a panic cannot be caught).
/// Refuse a value whose shape exceeds the grant it is moved under.
///
/// The same three ceilings apply wherever a value crosses the boundary: before
/// a provider runs (`call`), after a promise resolves (dispatch), on the
/// response a provider produced (egress), and on lane traffic (`send`,
/// `publish`). One helper keeps the four sites from drifting.
/// The meter that bounds a capability in a call chain, when it still has one.
///
/// Every live capability has a meter: mint, attenuation and restore insert it,
/// and `drop_record` removes the record and the meter together. A capability
/// with no record was dropped, which a provider may do during its own call (the
/// handle it holds is the last reference); its grant is gone with it and the
/// rest of the chain still bounds the call, so `None` means "charge the rest".
/// A capability that still has a record but no meter is a broken invariant, and
/// skipping its charge would hand it an unbounded grant, so that fails closed.
fn meter_for(kernel: &Kernel, id: CapId) -> Result<Option<&BudgetMeter>> {
    match kernel.meters.get(&id) {
        Some(meter) => Ok(Some(meter)),
        None if kernel.caps.contains_key(&id) => {
            Err(Error::Persistence("the capability has no meter"))
        }
        None => Ok(None),
    }
}

fn meter_mut_for(kernel: &mut Kernel, id: CapId) -> Result<Option<&mut BudgetMeter>> {
    if !kernel.meters.contains_key(&id) {
        return if kernel.caps.contains_key(&id) {
            Err(Error::Persistence("the capability has no meter"))
        } else {
            Ok(None)
        };
    }
    Ok(kernel.meters.get_mut(&id))
}

fn shape_refusal(value: &Value, budget: &Budget) -> Option<Error> {
    // The bounded walk stops at the first violation, so a hostile in-process
    // value is refused without materialising its whole shape.
    if let Some(dimension) = value.shape_exceeded(budget) {
        return Some(Error::BudgetExceeded(dimension));
    }
    let shape = value.shape();
    if shape.depth > budget.max_depth {
        return Some(Error::BudgetExceeded("depth"));
    }
    if shape.widest > budget.max_array_len {
        return Some(Error::BudgetExceeded("array_len"));
    }
    if shape.size > budget.max_value_size {
        return Some(Error::BudgetExceeded("value_size"));
    }
    None
}

fn value_too_deep(value: &Value, limit: usize) -> bool {
    // A bounded depth probe: `shape_exceeded` stops at the first violation
    // instead of pushing every child of a wide value first (round 8, #3). The
    // other ceilings are disabled by construction: this asks about depth alone.
    let budget = crate::budget::Budget {
        max_depth: limit as u64,
        max_array_len: u64::MAX,
        max_value_size: u64::MAX,
        ..crate::budget::Budget::default()
    };
    value.shape_exceeded(&budget).is_some()
}

/// Advance the wall clock before an authority check.
///
/// The stored clock moves on a dispatch. A kernel that only publishes, sends,
/// attenuates or introduces would otherwise compare a deadline against a stale
/// `now_ms`, so a time-bounded capability would never expire on those paths. The
/// virtual clock is left alone: it advances by a round trip per dispatch, which
/// is what makes replays deterministic.
fn refresh_clock(kernel: &mut Kernel) {
    if kernel.wall_clock {
        kernel.now_ms = kernel.now_ms.max(wall_now_ms());
    }
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
    // Iterative, for the same reason `shape` and `is_tainted` are: a value can
    // be nested deeper than the Rust stack, and this walk runs on the way in to
    // every scoped call, so a recursion here is an abort a caller can choose
    // (round 6, #3).
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Path(path) => {
                if !crate::cap::is_path_prefix(scope, path) {
                    return Some(path.clone());
                }
            }
            Value::List(items) => stack.extend(items.iter().rev()),
            Value::Map(map) => stack.extend(map.values().rev()),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod fail_closed_tests {
    use super::*;

    struct Ping;

    impl Provider for Ping {
        fn name(&self) -> &'static str {
            "ping"
        }

        fn methods(&self) -> Vec<String> {
            vec!["ping".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> Result<Response> {
            Ok(Response::Value(Value::Int(1)))
        }
    }

    /// A capability in a chain without a meter has failed a kernel invariant.
    /// Charging nothing for it would hand it an unbounded grant, so the call is
    /// refused instead.
    #[test]
    fn a_capability_without_a_meter_fails_closed() {
        let agent = Agent::with_secret([0x5a; 32]);
        let provider = agent.register(Box::new(Ping));
        let cap = agent
            .mint(provider, 0, CapAttrs::new(&["ping"]))
            .expect("mint");
        let lane = agent
            .create_lane("no-meter", Budget::default())
            .expect("lane");
        agent.cell.borrow_mut().meters.remove(&cap.id());
        let error = agent
            .call(lane, &cap, "ping", Vec::new())
            .expect_err("a capability with no meter must not call unmetered");
        assert_eq!(error.code(), "rpc/persistence");
        assert_eq!(
            error.to_string(),
            "durable capability refused: the capability has no meter"
        );
    }

    /// The publish path charges the same chain; a meter-less capability in it
    /// must refuse the publish rather than send it unmetered.
    #[test]
    fn a_publish_from_a_capability_without_a_meter_fails_closed() {
        let agent = Agent::with_secret([0x5b; 32]);
        let provider = agent.register(Box::new(Ping));
        let attrs = CapAttrs::new(&["ping", "publish"]).restrict_topics(&["t"]);
        let cap = agent.mint(provider, 0, attrs).expect("mint");
        let lane = agent
            .create_lane("no-meter-publish", Budget::default())
            .expect("lane");
        let channel = agent
            .create_channel("c", crate::channel::Direction::Both)
            .expect("channel");
        agent.cell.borrow_mut().meters.remove(&cap.id());
        let error = agent
            .publish(lane, channel, &cap, "t", Value::Int(1))
            .expect_err("a publish through a capability with no meter must fail");
        assert!(
            error.to_string().ends_with("has no meter"),
            "unexpected refusal: {error}"
        );
    }

    /// An export hands out what the whole chain still has. An ancestor whose
    /// meter is gone must fail the export rather than be skipped, or the record
    /// would carry more authority than that ancestor allows (round 4, F3).
    #[test]
    fn an_export_with_a_meterless_ancestor_is_refused() {
        let agent = Agent::with_secret([0x5c; 32]);
        agent.set_durable_capabilities(true);
        agent.set_record_seal_key([0x92; 32]);
        let provider = agent.register(Box::new(Ping));
        let owner = crate::identity::IdentityPolicy::default()
            .admit(
                Some(&crate::identity::PeerIdentity::from_certificate(
                    b"meter-owner",
                )),
                true,
            )
            .expect("admit");
        let parent = agent
            .mint_bound(&owner, provider, 0, CapAttrs::new(&["ping"]).durable())
            .expect("parent");
        let child = agent
            .attenuate(&parent, CapAttrs::new(&["ping"]).durable())
            .expect("child");
        agent.cell.borrow_mut().meters.remove(&parent.id());
        let error = agent
            .export_capability(&child)
            .expect_err("an export must not skip a meterless ancestor");
        assert!(
            error.to_string().ends_with("has no meter"),
            "unexpected refusal: {error}"
        );
    }
}
