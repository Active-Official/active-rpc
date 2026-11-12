//! R2-R02-01: `trim_settled` runs only at a full drain, so a run that never
//! drains fills `MAX_PROMISES` and then refuses every new call (High).
//!
//! The defect: `trim_settled` had exactly one call site, in `Agent::run`, on
//! the branch where the queue is empty. While the queue never empties — a
//! provider that enqueues follow-up work during dispatch, or a host that
//! queues a large batch and calls `run()` once — settled promise records
//! accumulated without bound inside the run, past the 1,024 target and all
//! the way to the 100,000 hard ceiling, at which point `call_inner_payload`
//! refused *every* new call with `rpc/budget-exceeded` ("promises") even
//! though jobs kept completing successfully.
//!
//! The fix (two halves, both named in the audit):
//! 1. `run()` reclaims settled records after each dispatched batch, so a
//!    never-draining run keeps a bounded settled backlog. The trim only
//!    evicts unpinned records: no live handle, no idempotency key, and —
//!    the pin the audit's literal "trim after each batch" would have
//!    missed — no queued waiter (`PromiseRecord::waiters > 0`). A queued
//!    consumer reads its producer's record twice (once in
//!    `order_candidates` to decide the dependency is settled, once in
//!    dispatch phase 1 to substitute the pipelined argument); an evicted
//!    record reads as unsettled, so the consumer would block and then be
//!    failed as a pipelined cycle. `test_queued_consumer_survives_mid_run_trim`
//!    pins that pin: it passes before the fix and after it, and fails on
//!    the naive unconditional trim.
//! 2. The `MAX_PROMISES` check in `call_inner_payload` counts only live
//!    (pending + running) records — `promises.len() - settled.len()` —
//!    instead of every record including settled ones awaiting trim. The
//!    constant's own doc already says "Global ceiling on live promise and
//!    job records"; the check now matches it. This closes the same cliff
//!    inside a single giant batch, where no between-batch trim can run:
//!    `test_live_ceiling_ignores_settled_records_mid_batch`.
//!
//! Every test here fails against the tree before the fix, except the
//! pipeline guard (see its doc): it fails only on the naive fix. The
//! verification probe `r02_kernel_dispatch_probes.rs` asserts the buggy
//! behaviour (it passes on the broken tree); these tests assert the fixed
//! behaviour. The probe needed one mechanical adaptation to run at this
//! HEAD at all: `Agent::register` returns `Result<ProviderId>` since
//! R2-PERSIST-04 (1eac72a), so its call sites take `.expect("register")`.

use std::cell::RefCell;
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::{Provider, MAX_PROMISES, MAX_SETTLED_PROMISES};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, LaneId};

/// Shared mutable state for the probe providers. Providers are `!Send`
/// single-threaded objects, so `Rc<RefCell<..>>` is the right sharing shape.
#[derive(Default)]
struct Shared {
    agent: Option<Agent>,
    lane: Option<LaneId>,
    cap: Option<active_rpc::CapHandle>,
    /// Chain links still to enqueue.
    limit: usize,
    invocations: usize,
    max_promise_count: usize,
    first_call_error: Option<String>,
    stop: bool,
    /// `live_ceiling` test: which invocation attempts the one requeue.
    requeue_at: usize,
    requeued: bool,
    requeue_handle: Option<active_rpc::PromiseHandle>,
    requeue_error: Option<String>,
}

type SharedCell = Rc<RefCell<Shared>>;

struct ChainProvider {
    shared: SharedCell,
}

impl Provider for ChainProvider {
    fn name(&self) -> &'static str {
        "probe"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let mut s = self.shared.borrow_mut();
        s.invocations += 1;
        // Self-requeueing chain. Each invoke enqueues the next call, so the
        // queue never drains while the chain runs.
        if s.invocations <= s.limit && !s.stop {
            let agent = s.agent.clone().expect("agent");
            let lane = s.lane.expect("lane");
            let cap = s.cap.clone().expect("cap");
            s.max_promise_count = s.max_promise_count.max(agent.promise_count());
            match agent.call(lane, &cap, "echo", vec![]) {
                Ok(handle) => {
                    // Drop the handle at once: the record is unpinned and
                    // trimmable in principle; only the missing trim matters.
                    drop(handle);
                }
                Err(e) => {
                    s.first_call_error = Some(format!("{} | {e}", e.code()));
                    s.stop = true;
                }
            }
        }
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

fn wide_budget(max_calls: u64) -> Budget {
    Budget {
        max_calls,
        max_bytes: 1 << 30,
        max_value_size: 1 << 20,
        ..Budget::default()
    }
}

fn setup_chain(limit: usize) -> (Agent, SharedCell, LaneId, active_rpc::CapHandle) {
    let shared: SharedCell = Rc::new(RefCell::new(Shared {
        limit,
        ..Default::default()
    }));
    let agent = Agent::with_secret([7u8; 32]);
    let provider = agent
        .register(Box::new(ChainProvider {
            shared: shared.clone(),
        }))
        .expect("register");
    let wide = wide_budget(2_000_000);
    let lane = agent.create_lane("chain", wide).expect("lane");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget = wide;
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    {
        let mut s = shared.borrow_mut();
        s.agent = Some(agent.clone());
        s.lane = Some(lane);
        s.cap = Some(cap.clone());
    }
    (agent, shared, lane, cap)
}

/// The settled backlog stays near the 1,024 target while a 3,000-link
/// self-requeueing chain runs entirely inside ONE `run()` call. Before the
/// fix the backlog grew straight past the target (3,000 observed mid-run)
/// because no trim ran while the queue never drained.
///
/// The bound is the target plus a small margin for the records a batch
/// legitimately holds: the seed call's handle is held across `run()` (so its
/// record is handle-pinned), the in-flight job's record is pending, and a
/// batch may settle one job past the target before the post-batch trim runs.
/// Before the fix the observed max was 3,000 — three times the target — so
/// the margin cannot hide the defect.
///
/// `run()` still executes all 3,001 rounds in a single call: that is
/// R2-R02-05 (no per-call round bound), a separate finding, not this one.
#[test]
fn settled_backlog_stays_bounded_mid_run() {
    let (agent, shared, lane, cap) = setup_chain(3_000);
    let before = agent.round_trips();
    let first = agent.call(lane, &cap, "echo", vec![]).expect("first call");
    let trips = agent.run();
    first.value().expect("first value");
    let s = shared.borrow();
    eprintln!(
        "R2-R02-01(mid-run, fixed): invocations={} max_promise_count_during_run={} \
         MAX_SETTLED_PROMISES={} round_trips_delta={} run_return={trips} (before={before}) \
         first_call_error={:?} promise_count_after_run={}",
        s.invocations,
        s.max_promise_count,
        MAX_SETTLED_PROMISES,
        trips - before,
        s.first_call_error,
        agent.promise_count(),
    );
    assert_eq!(
        s.invocations, 3_001,
        "chain ran to its limit (seed call + 3,000 requeues)"
    );
    assert!(s.first_call_error.is_none(), "no call failed mid-chain");
    assert!(
        s.max_promise_count <= MAX_SETTLED_PROMISES + 64,
        "settled backlog observed mid-run ({}) stayed near MAX_SETTLED_PROMISES ({}) \
         while the queue never drained",
        s.max_promise_count,
        MAX_SETTLED_PROMISES,
    );
    assert_eq!(
        trips - before,
        3_001,
        "a single run() call executed the whole chain (R2-R02-05 behaviour preserved)"
    );
    assert!(
        agent.promise_count() <= MAX_SETTLED_PROMISES + 1,
        "post-drain promise_count={} (one record stays handle-pinned)",
        agent.promise_count()
    );
}

/// The production symptom, gone: a 110,000-link chain — 10,000 links past
/// the 100,000 ceiling — runs to completion inside ONE `run()` call with no
/// `rpc/budget-exceeded` ("promises") refusal. Before the fix the chain
/// stopped at exactly 100,000 invocations with that refusal, and only a
/// full drain (and its trim) let a fresh call succeed again.
#[test]
fn sustained_load_runs_past_max_promises() {
    let (agent, shared, lane, cap) = setup_chain(110_000);
    let first = agent.call(lane, &cap, "echo", vec![]).expect("first call");
    let trips = agent.run();
    first.value().expect("first value");
    let s = shared.borrow();
    eprintln!(
        "R2-R02-01(sustained, fixed): invocations={} max_promise_count_during_run={} \
         MAX_PROMISES={MAX_PROMISES} round_trips={trips} \
         first_call_error={:?} promise_count_after_run={} MAX_SETTLED_PROMISES={MAX_SETTLED_PROMISES}",
        s.invocations, s.max_promise_count, s.first_call_error, agent.promise_count(),
    );
    assert!(
        s.first_call_error.is_none(),
        "no call was refused mid-chain: {:?}",
        s.first_call_error,
    );
    assert_eq!(
        s.invocations, 110_001,
        "chain ran past MAX_PROMISES (seed call + 110,000 requeues)"
    );
    assert!(
        s.max_promise_count <= MAX_SETTLED_PROMISES + 64,
        "settled backlog observed mid-run ({}) stayed near MAX_SETTLED_PROMISES ({})",
        s.max_promise_count,
        MAX_SETTLED_PROMISES,
    );
    assert!(
        agent.promise_count() <= MAX_SETTLED_PROMISES + 1,
        "post-drain promise_count={} (one record stays handle-pinned)",
        agent.promise_count()
    );
}

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::text("ok")),
        ))
    }
}

/// Guard for the pin the audit's literal "trim after each batch" would have
/// missed. A pipelined consumer queued on a second provider reads its
/// producer's settled record at dispatch (ordering, then argument
/// substitution); 3,000 filler jobs settle in the producer's batch and force
/// the post-batch trim to run while the consumer is still queued. The
/// producer's record is the oldest settled entry — the first eviction
/// candidate — and survives only because the queued consumer pins it
/// (`waiters > 0`). Without that pin the consumer would read its dependency
/// as unsettled, block, and be failed as a pipelined cycle.
///
/// This test passes before the fix (no mid-run trim ran at all) and after
/// it; it fails on the naive unconditional trim. That is the point: it pins
/// the invariant the correct fix depends on.
#[test]
fn queued_consumer_survives_mid_run_trim() {
    let agent = Agent::with_secret([8u8; 32]);
    let wide = wide_budget(100_000);
    let lane = agent.create_lane("pipeline", wide).expect("lane");
    let producer = agent.register(Box::new(Echo)).expect("register producer");
    let consumer = agent.register(Box::new(Echo)).expect("register consumer");
    let mut attrs_producer = CapAttrs::new(&["echo"]);
    attrs_producer.budget = wide;
    let mut attrs_consumer = CapAttrs::new(&["echo"]);
    attrs_consumer.budget = wide;
    let cap_producer = agent
        .mint(producer, 0, attrs_producer)
        .expect("cap producer");
    let cap_consumer = agent
        .mint(consumer, 0, attrs_consumer)
        .expect("cap consumer");

    // Producer first, so its settled entry is the oldest — the first
    // eviction candidate once the backlog passes the target.
    let made = agent
        .call(
            lane,
            &cap_producer,
            "echo",
            vec![Arg::Value(Value::text("pipelined-value"))],
        )
        .expect("producer call");
    // Consumer waits on the producer's promise; queued before run(), so its
    // waiter pin exists when the post-batch trim runs.
    let used = agent
        .call(lane, &cap_consumer, "echo", vec![Arg::Promise(made.id())])
        .expect("consumer call");
    assert_eq!(agent.promise_waiters(&made), 1);
    // Filler settles 3,000 records in the producer's batch: the post-batch
    // trim must evict down to the 1,024 target while the consumer waits.
    for _ in 0..3_000 {
        let filler = agent
            .call(lane, &cap_producer, "echo", vec![])
            .expect("filler call");
        drop(filler);
    }
    agent.run();
    assert_eq!(
        used.value().expect("consumer value"),
        Value::text("pipelined-value"),
        "the consumer read its producer's settled value, not an eviction refusal"
    );
    assert_eq!(
        made.value().expect("producer value"),
        Value::text("pipelined-value")
    );
    assert_eq!(agent.promise_waiters(&made), 0);
}

struct FloodProvider {
    shared: SharedCell,
}

impl Provider for FloodProvider {
    fn name(&self) -> &'static str {
        "flood"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        let mut s = self.shared.borrow_mut();
        s.invocations += 1;
        // Exactly one requeue, attempted once the batch has settled enough
        // that the live count is genuinely below the ceiling while the total
        // record count still sits on it. Before the fix the check counted
        // settled records too, so this call was refused even though jobs kept
        // completing; after the fix the ceiling counts live work only.
        if !s.requeued && s.invocations >= s.requeue_at {
            s.requeued = true;
            let agent = s.agent.clone().expect("agent");
            let lane = s.lane.expect("lane");
            let cap = s.cap.clone().expect("cap");
            match agent.call(lane, &cap, "echo", vec![]) {
                Ok(handle) => s.requeue_handle = Some(handle),
                Err(e) => {
                    s.requeue_error = Some(format!("{} | {e}", e.code()));
                }
            }
        }
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

/// The ceiling counts live work, not dead records, inside a single giant
/// batch — where no between-batch trim can run. 100,000 filler jobs are
/// pre-queued in one batch (the most the ceiling admits); when the 100th
/// job runs, 99 have settled, so the live count is 99,901 while the total
/// record count still sits on 100,000. Before the fix the requeue was
/// refused with `rpc/budget-exceeded` ("promises"); after the fix it is
/// admitted and runs in the next batch.
#[test]
fn live_ceiling_ignores_settled_records_mid_batch() {
    let shared: SharedCell = Rc::new(RefCell::new(Shared {
        requeue_at: 100,
        ..Default::default()
    }));
    let agent = Agent::with_secret([9u8; 32]);
    let provider = agent
        .register(Box::new(FloodProvider {
            shared: shared.clone(),
        }))
        .expect("register");
    let wide = wide_budget(2_000_000);
    let lane = agent.create_lane("flood", wide).expect("lane");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget = wide;
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    {
        let mut s = shared.borrow_mut();
        s.agent = Some(agent.clone());
        s.lane = Some(lane);
        s.cap = Some(cap.clone());
    }
    for _ in 0..MAX_PROMISES {
        let filler = agent.call(lane, &cap, "echo", vec![]).expect("filler call");
        drop(filler);
    }
    assert_eq!(agent.promise_count(), MAX_PROMISES);
    agent.run();
    let s = shared.borrow();
    eprintln!(
        "R2-R02-01(live-ceiling, fixed): invocations={} requeued={} \
         requeue_error={:?} promise_count_after_run={}",
        s.invocations,
        s.requeued,
        s.requeue_error,
        agent.promise_count(),
    );
    assert!(s.requeued, "the provider attempted the requeue");
    assert!(
        s.requeue_error.is_none(),
        "the mid-batch requeue was admitted: {:?}",
        s.requeue_error,
    );
    assert_eq!(
        s.invocations,
        MAX_PROMISES + 1,
        "all 100,000 fillers plus the requeued call ran"
    );
    drop(s);
    let handle = shared
        .borrow_mut()
        .requeue_handle
        .take()
        .expect("requeued handle kept");
    handle.value().expect("requeued call settled");
}
