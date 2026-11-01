//! R-04 promises and pipelining: lane isolation, idempotency retention, the
//! settlement paths and handle accounting.
//!
//! Every test here fails against the tree before its fix. This is the file the
//! section map names; the findings were previously covered nowhere.

use std::cell::Cell;
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::Envelope;
use active_rpc::{Agent, Budget, CapHandle, CapPersistence, CapabilityRecord};

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

fn admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    let peer = PeerIdentity::from_certificate(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

fn agent() -> (Agent, active_rpc::ProviderId, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x51; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent
        .create_lane("promises", Budget::default())
        .expect("lane");
    (agent, provider, lane)
}

fn durable_agent() -> (Agent, active_rpc::ProviderId) {
    let agent = Agent::with_secret([0x52; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x86; 32]);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

fn bound_durable(agent: &Agent, provider: active_rpc::ProviderId, ttl: Option<u64>) -> CapHandle {
    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    attrs.ttl_ms = ttl;
    agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap")
}

/// A promise is the private result of one lane: an id from another lane is not
/// a valid argument, and the refusal does not reveal whether it exists.
#[test]
fn promise_from_another_lane_is_refused() {
    let (agent, provider, lane) = agent();
    let other = agent.create_lane("other", Budget::default()).expect("lane");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let secret = agent
        .call(
            other,
            &cap,
            "echo",
            vec![Arg::Value(Value::text("tenant-A-secret"))],
        )
        .expect("call on the other lane");
    agent.run();
    secret.value().expect("value");

    let error = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(secret.id())])
        .expect_err("a promise from another lane is not an argument here");
    assert_eq!(error.code(), "rpc/unknown-promise", "{error}");
}

/// An envelope is peer input: it cannot name a promise or a capability.
#[test]
fn an_envelope_cannot_carry_authority_arguments() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let settled = agent
        .call(lane, &cap, "echo", vec![Arg::Value(Value::text("x"))])
        .expect("call");
    agent.run();
    settled.value().expect("value");

    let envelope = Envelope::request(1, "echo", vec![Arg::Promise(settled.id())]);
    let error = agent
        .call_from_envelope(None, lane, &cap, &envelope)
        .expect_err("a promise argument cannot arrive in an envelope");
    assert_eq!(error.code(), "rpc/wire", "{error}");

    let envelope = Envelope::request(2, "echo", vec![Arg::Cap(cap.id())]);
    let error = agent
        .call_from_envelope(None, lane, &cap, &envelope)
        .expect_err("a capability argument carries no authority");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// An idempotency key must keep returning its original promise even after the
/// retention window has trimmed thousands of later settlements.
#[test]
fn an_idempotent_replay_survives_the_retention_window() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let first = agent
        .call_idempotent(
            lane,
            &cap,
            "echo",
            vec![Arg::Value(Value::text("one"))],
            "order-1",
        )
        .expect("first call");
    agent.run();
    first.value().expect("value");
    let original = first.id();
    // Nothing holds the handle: only the key keeps the record alive.
    drop(first);

    // More settlements than the retention target (1 024): the record would be
    // trimmed if the key did not pin it.
    for _ in 0..1_200 {
        let promise = agent
            .call(lane, &cap, "echo", vec![Arg::Value(Value::text("filler"))])
            .expect("filler");
        agent.run();
        let _ = promise.value();
    }
    let replay = agent
        .call_idempotent(
            lane,
            &cap,
            "echo",
            vec![Arg::Value(Value::text("one"))],
            "order-1",
        )
        .expect("replay");
    assert_eq!(replay.id(), original, "the key re-executed the call");
    assert_eq!(
        replay
            .value()
            .expect("the original result is still readable"),
        Value::text("one")
    );
}

/// A replay is an exercise of authority in a lane that must still exist.
#[test]
fn an_idempotent_replay_needs_a_live_lane() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let first = agent
        .call_idempotent(lane, &cap, "echo", vec![], "k")
        .expect("first");
    agent.run();
    first.value().expect("value");
    agent.destroy_lane(lane).expect("destroy");
    let error = agent
        .call_idempotent(lane, &cap, "echo", vec![], "k")
        .expect_err("a destroyed lane cannot replay");
    assert_eq!(error.code(), "rpc/unknown-lane", "{error}");
}

/// The key is scoped to the lane: a second lane cannot obtain the first lane's
/// promise by replaying its key.
#[test]
fn an_idempotent_key_is_lane_scoped() {
    let (agent, provider, lane) = agent();
    let other = agent.create_lane("other", Budget::default()).expect("lane");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let first = agent
        .call_idempotent(lane, &cap, "echo", vec![], "shared")
        .expect("first");
    agent.run();
    first.value().expect("value");
    let second = agent
        .call_idempotent(other, &cap, "echo", vec![], "shared")
        .expect("second lane call");
    assert_ne!(second.id(), first.id(), "the key crossed a lane boundary");
}

/// A provider that cancels a promise while its own batch is running must not
/// complete the lane twice or log a settlement that never happened.
#[test]
fn cancelling_inside_dispatch_counts_once() {
    struct SelfCancel {
        slot: std::rc::Rc<std::cell::RefCell<Option<(Agent, CapHandle)>>>,
    }

    impl Provider for SelfCancel {
        fn name(&self) -> &'static str {
            "self-cancel"
        }

        fn methods(&self) -> Vec<String> {
            vec!["go".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            if let Some((agent, cap)) = self.slot.borrow().clone() {
                let lane = agent.create_lane("inner", Budget::default()).expect("lane");
                if let Ok(promise) = agent.call(lane, &cap, "go", Vec::new()) {
                    let _ = agent.cancel(&promise);
                }
            }
            Ok(Response::Value(Value::text("ok")))
        }
    }

    let agent = Agent::with_secret([0x53; 32]);
    let slot: Rc<std::cell::RefCell<Option<(Agent, CapHandle)>>> =
        Rc::new(std::cell::RefCell::new(None));
    let provider = agent.register(Box::new(SelfCancel {
        slot: Rc::clone(&slot),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("cap");
    *slot.borrow_mut() = Some((agent.clone(), cap.clone()));
    let lane = agent.create_lane("outer", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "go", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("the outer call settles");
    let lane_state = agent.lane(lane).expect("lane");
    assert_eq!(
        lane_state.completed, 1,
        "one call must complete the lane exactly once"
    );
    assert_eq!(lane_state.pending, 0);
}

/// An out-of-band answer prevents the provider call and settles once.
#[test]
fn resolving_a_queued_promise_prevents_the_provider_call() {
    let runs = Rc::new(Cell::new(0));
    struct Counter {
        runs: Rc<Cell<usize>>,
    }

    impl Provider for Counter {
        fn name(&self) -> &'static str {
            "counter"
        }

        fn methods(&self) -> Vec<String> {
            vec!["count".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            true
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            self.runs.set(self.runs.get() + 1);
            Ok(Response::Value(Value::text("ran")))
        }
    }

    let agent = Agent::with_secret([0x54; 32]);
    let provider = agent.register(Box::new(Counter {
        runs: Rc::clone(&runs),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["count"]))
        .expect("cap");
    let lane = agent
        .create_lane("out-of-band", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "count", Vec::new()).expect("call");
    agent
        .resolve(&promise, Value::text("answered"))
        .expect("out-of-band resolution");
    agent.run();
    assert_eq!(runs.get(), 0, "the provider ran after the answer arrived");
    assert_eq!(
        promise.value().expect("value"),
        Value::text("answered"),
        "the answer was not the resolved value"
    );
    assert_eq!(agent.metrics().promises_double_settled, 0);
}

/// A promise handle cloned while the kernel is borrowed must keep its record.
#[test]
fn a_clone_under_a_borrow_keeps_the_handle() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let promise = agent
        .call(lane, &cap, "echo", vec![Arg::Value(Value::text("kept"))])
        .expect("call");
    // Hold the kernel borrow while the handle is cloned: the retain cannot be
    // applied now and must be queued, not dropped.
    let borrow = agent.cell().borrow();
    let clone = promise.clone();
    drop(borrow);
    drop(promise);
    // Force the retention window to trim: a record whose count fell to zero with
    // a live handle would be evicted here.
    for _ in 0..1_200 {
        let filler = agent
            .call(lane, &cap, "echo", vec![Arg::Value(Value::text("f"))])
            .expect("filler");
        agent.run();
        let _ = filler.value();
    }
    assert_eq!(
        clone.value().expect("the surviving handle can still read"),
        Value::text("kept")
    );
}

/// `run` from inside `on_drop` must not fail the withdrawing provider's queued
/// work: those jobs wait for the next batch.
#[test]
fn run_from_on_drop_does_not_kill_queued_jobs() {
    struct Withdrawer {
        slot: Rc<std::cell::RefCell<Option<(Agent, CapHandle, active_rpc::LaneId)>>>,
    }

    impl Provider for Withdrawer {
        fn name(&self) -> &'static str {
            "withdrawer"
        }

        fn methods(&self) -> Vec<String> {
            vec!["go".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("ok")))
        }

        fn on_drop(&mut self, _object: u64, _cap: active_rpc::CapId) {
            if let Some((agent, _cap, _lane)) = self.slot.borrow().clone() {
                // A drop handler that drives the kernel: the queued work of this
                // very provider must survive.
                agent.run();
            }
        }
    }

    let agent = Agent::with_secret([0x55; 32]);
    let slot: Rc<std::cell::RefCell<Option<(Agent, CapHandle, active_rpc::LaneId)>>> =
        Rc::new(std::cell::RefCell::new(None));
    let provider = agent.register(Box::new(Withdrawer {
        slot: Rc::clone(&slot),
    }));
    let doomed = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("doomed");
    let survivor = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("survivor");
    let lane = agent
        .create_lane("drop-run", Budget::default())
        .expect("lane");
    *slot.borrow_mut() = Some((agent.clone(), survivor.clone(), lane));
    // Queue work for the survivor, then drop the doomed capability: the drop
    // handler runs the kernel while a job is queued for the same provider.
    let promise = agent.call(lane, &survivor, "go", Vec::new()).expect("call");
    drop(doomed);
    agent.run();
    promise
        .value()
        .expect("the queued call survived the drop handler");
}

/// A promise record reports its live dependents, and the count returns to zero.
#[test]
fn waiters_return_to_zero() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let producer = agent
        .call(lane, &cap, "echo", vec![Arg::Value(Value::text("p"))])
        .expect("producer");
    let consumer = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(producer.id())])
        .expect("consumer");
    assert_eq!(agent.promise_waiters(&producer), 1);
    agent.run();
    consumer.value().expect("consumer value");
    assert_eq!(agent.promise_waiters(&producer), 0);
}

/// `peek` on a pending promise is not the terminal "can never settle" answer.
#[test]
fn peek_on_a_pending_promise_is_not_unresolvable() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let promise = agent.call(lane, &cap, "echo", vec![]).expect("call");
    let error = promise.peek().expect_err("pending");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A child minted after a clock switch carries the kernel's clock mode, so its
/// deadline is read in the domain that produced it.
#[test]
fn a_child_after_a_clock_switch_is_stamped_with_the_new_domain() {
    let (agent, provider) = durable_agent();
    let parent = bound_durable(&agent, provider, None);
    agent.use_wall_clock(true);
    let child = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).durable().with_ttl_ms(60_000),
        )
        .expect("child in the wall-clock domain");
    let record = agent.export_capability(&child).expect("export");
    assert!(
        record.wall_clock,
        "the child's deadline was stamped with the parent's domain"
    );
}

/// A virtual deadline does not inflate when a restarted kernel reads it: the
/// sealed remaining lease is the ceiling.
#[test]
fn a_virtual_deadline_does_not_inflate_across_a_restart() {
    let (source, provider) = durable_agent();
    source.set_latency(1_000);
    let owner = PeerIdentity::from_certificate(b"owner");
    // Advance the clock to 5 000 virtual ms.
    let warmup = bound_durable(&source, provider, None);
    let lane = source.create_lane("warm", Budget::default()).expect("lane");
    for _ in 0..5 {
        let promise = source
            .call_as(Some(&owner), lane, &warmup, "echo", Vec::new())
            .expect("call");
        source.run();
        promise.value().expect("value");
    }
    let cap = bound_durable(&source, provider, Some(1_000));
    let record = source.export_capability(&cap).expect("export");
    assert_eq!(
        record.lease_ms,
        Some(1_000),
        "the lease is the remaining time"
    );

    let restarted = Agent::with_secret([0x52; 32]);
    restarted.set_durable_capabilities(true);
    restarted.set_record_seal_key([0x86; 32]);
    restarted.set_latency(100);
    restarted.register(Box::new(Echo));
    let owner = admitted(b"owner");
    let restored = restarted
        .restore_capability(&record, &owner)
        .expect("restore");
    let lane = restarted
        .create_lane("after", Budget::default())
        .expect("lane");
    // One second of virtual time is the whole lease: nine 100 ms calls fit and
    // the tenth dispatches at exactly the deadline.
    let owner_peer = PeerIdentity::from_certificate(b"owner");
    for _ in 0..9 {
        let promise = restarted
            .call_as(Some(&owner_peer), lane, &restored, "echo", Vec::new())
            .expect("within the lease");
        restarted.run();
        promise.value().expect("value");
    }
    let promise = restarted
        .call_as(Some(&owner_peer), lane, &restored, "echo", Vec::new())
        .expect("queued before the deadline");
    restarted.run();
    let error = promise
        .value()
        .expect_err("the lease does not inflate across a restart");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// A restored credential cannot refill a spent grant.
#[test]
fn a_restored_copy_cannot_refill_a_spent_grant() {
    let (agent, provider) = durable_agent();
    let cap = bound_durable(&agent, provider, None);
    let narrow = agent
        .attenuate(
            &cap,
            CapAttrs::new(&["echo"])
                .durable()
                .with_budget(Budget::calls(2)),
        )
        .expect("narrow");
    let lane = agent.create_lane("spend", Budget::default()).expect("lane");
    let owner = PeerIdentity::from_certificate(b"owner");
    // One of two calls spent: the record carries the remaining one.
    let promise = agent
        .call_as(Some(&owner), lane, &narrow, "echo", Vec::new())
        .expect("call");
    agent.run();
    promise.value().expect("value");
    let record = agent.export_capability(&narrow).expect("export");
    assert_eq!(
        record.budget.max_calls, 1,
        "the record copied the grant instead of the remainder"
    );
    drop(record);

    // The second call spends it; nothing is left to persist.
    let promise = agent
        .call_as(Some(&owner), lane, &narrow, "echo", Vec::new())
        .expect("call");
    agent.run();
    promise.value().expect("value");
    let error = agent
        .export_capability(&narrow)
        .expect_err("a spent grant cannot be exported");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A record that names no peer is refused by restore, not silently bound.
#[test]
fn an_unbound_record_is_refused_by_restore() {
    let (agent, provider) = durable_agent();
    let cap = bound_durable(&agent, provider, None);
    let mut record: CapabilityRecord = agent.export_capability(&cap).expect("export");
    record.bound_to = None;
    record.seal_with(&[0x86; 32]);
    let error = agent
        .restore_capability(&record, &admitted(b"owner"))
        .expect_err("a record must name its peer");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}
