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
        .restore_capability_in_process_only(&record, &owner)
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

    // The export transferred the remaining call: the local capability cannot
    // spend what the record now holds.
    let error = agent
        .call_as(Some(&owner), lane, &narrow, "echo", Vec::new())
        .expect_err("the grant moved into the record");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    // Nothing is left to export a second time.
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
        .restore_capability_in_process_only(&record, &admitted(b"owner"))
        .expect_err("a record must name its peer");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

/// A drop handler that awaits a call queued on its own provider cannot make
/// progress: the provider is checked out, so the answer is "unresolvable", not a
/// spin. (Regressing this hangs the suite, which is how the round-2 livelock was
/// found.)
#[test]
fn awaiting_from_on_drop_returns_instead_of_spinning() {
    type Slot = (Agent, active_rpc::PromiseHandle);

    struct AwaitsInDrop {
        slot: Rc<std::cell::RefCell<Option<Slot>>>,
        seen: Rc<std::cell::Cell<usize>>,
    }

    impl Provider for AwaitsInDrop {
        fn name(&self) -> &'static str {
            "awaits-in-drop"
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
            let (agent, promise) = self.slot.borrow().clone().expect("slot");
            let outcome = agent.await_promise(&promise);
            assert!(outcome.is_err(), "await in on_drop must not report success");
            self.seen.set(self.seen.get() + 1);
        }
    }

    let seen = Rc::new(std::cell::Cell::new(0));
    let slot: Rc<std::cell::RefCell<Option<Slot>>> = Rc::new(std::cell::RefCell::new(None));
    let agent = Agent::with_secret([0x56; 32]);
    let provider = agent.register(Box::new(AwaitsInDrop {
        slot: Rc::clone(&slot),
        seen: Rc::clone(&seen),
    }));
    // One capability is released (its drop runs the handler); the other carries
    // a queued call the handler awaits while the provider is being notified.
    let doomed = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("doomed");
    let survivor = agent
        .mint(provider, 1, CapAttrs::new(&["go"]))
        .expect("survivor");
    let lane = agent
        .create_lane("queued", Budget::default())
        .expect("lane");
    let promise = agent
        .call(lane, &survivor, "go", Vec::new())
        .expect("queued call");
    *slot.borrow_mut() = Some((agent.clone(), promise.clone()));
    drop(doomed);
    assert_eq!(seen.get(), 1);
    // The queued call still runs once the notification is over.
    agent.run();
    promise.value().expect("the queued call still settles");
}

/// A key answers exactly the request it was issued for.
#[test]
fn an_idempotency_key_refuses_different_arguments() {
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
            "same",
        )
        .expect("first");
    agent.run();
    first.value().expect("value");
    let error = agent
        .call_idempotent(
            lane,
            &cap,
            "echo",
            vec![Arg::Value(Value::text("two"))],
            "same",
        )
        .expect_err("a different request under one key is a client bug");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A cached replay is served even when the lane's call budget is spent.
#[test]
fn a_cached_replay_is_served_at_the_lane_ceiling() {
    let (agent, provider, _lane) = agent();
    let lane = agent.create_lane("capped", Budget::calls(1)).expect("lane");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let first = agent
        .call_idempotent(lane, &cap, "echo", vec![], "k")
        .expect("first");
    agent.run();
    first.value().expect("value");
    let replay = agent
        .call_idempotent(lane, &cap, "echo", vec![], "k")
        .expect("a replay makes no call");
    assert_eq!(replay.id(), first.id());
}

/// A provider value deeper than the wire limit is a provider fault, not a stack
/// overflow at settlement.
#[test]
fn a_provider_value_deeper_than_the_wire_limit_is_refused() {
    struct Deep;
    impl Provider for Deep {
        fn name(&self) -> &'static str {
            "deep"
        }
        fn methods(&self) -> Vec<String> {
            vec!["deep".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            let mut value = Value::text("leaf");
            for _ in 0..200 {
                value = Value::list(vec![value]);
            }
            Ok(Response::Value(value))
        }
    }

    let agent = Agent::with_secret([0x57; 32]);
    let provider = agent.register(Box::new(Deep));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["deep"]))
        .expect("cap");
    let lane = agent.create_lane("deep", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "deep", Vec::new()).expect("call");
    agent.run();
    let error = promise.value().expect_err("too deep is a budget refusal");
    // Round 10 (#4): the same condition on the argument side is a budget
    // refusal, so the answer carries the dimension and the event too.
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A record is restored once per kernel: the budgets inside it were reserved at
/// export, so a second restore would mint a second copy of one grant.
#[test]
fn a_record_restores_once_per_kernel() {
    let (agent, provider) = durable_agent();
    let cap = bound_durable(&agent, provider, None);
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    let owner = admitted(b"owner");
    let restored = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("restore");
    drop(restored);
    let error = agent
        .restore_capability_in_process_only(&record, &owner)
        .expect_err("the record was already restored");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// An exported record is consumed: the same capability cannot export twice.
#[test]
fn an_exported_record_is_consumed() {
    let (agent, provider) = durable_agent();
    let cap = bound_durable(&agent, provider, None);
    agent.export_capability(&cap).expect("export");
    let error = agent
        .export_capability(&cap)
        .expect_err("the grant moved out with the first record");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A restored child cannot outspend the ancestor it was derived from: the
/// export reserves the lineage, not only the capability.
#[test]
fn a_restored_child_cannot_outspend_its_parent() {
    let (agent, provider) = durable_agent();
    let parent = bound_durable(&agent, provider, None);
    let narrow_parent = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"])
                .with_budget(Budget::calls(1))
                .durable(),
        )
        .expect("narrow parent");
    let child = agent
        .attenuate(
            &narrow_parent,
            CapAttrs::new(&["echo"])
                .with_budget(Budget::calls(1))
                .durable(),
        )
        .expect("child");
    let owner = PeerIdentity::from_certificate(b"owner");
    let lane = agent.create_lane("spend", Budget::default()).expect("lane");
    let promise = agent
        .call_as(Some(&owner), lane, &narrow_parent, "echo", Vec::new())
        .expect("the parent's only call");
    agent.run();
    promise.value().expect("value");
    // The parent has nothing left, so the child cannot export a grant it could
    // then restore and spend.
    let error = agent
        .export_capability(&child)
        .expect_err("the ancestor's grant is spent");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// An export refused before it hands out a record must cost nothing: the grant
/// stays with the capability and the record id is not burned, or a deployment
/// that presents one malformed field loses both.
#[test]
fn an_empty_path_scope_is_refused_at_the_mint() {
    let (agent, provider) = durable_agent();
    let owner = admitted(b"owner");
    // `from_json` refuses an empty path scope, so such a record could never be
    // restored. Since R-03 round 4 the mint applies the same rule, so the
    // capability is never created and no authority is left unusable.
    let mut attrs = CapAttrs::new(&["echo"])
        .with_budget(Budget::calls(2))
        .with_path("");
    attrs.persistence = CapPersistence::Durable;
    let error = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect_err("an empty scope is refused at the mint");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    // A valid durable capability still mints, exports once, and is consumed.
    let cap = agent
        .mint_bound(
            &owner,
            provider,
            0,
            CapAttrs::new(&["echo"])
                .with_budget(Budget::calls(2))
                .durable(),
        )
        .expect("cap");
    let record = agent.export_capability(&cap).expect("export");
    let again = agent
        .export_capability(&cap)
        .expect_err("a record is exported once");
    assert_eq!(again.code(), "rpc/persistence", "{again}");
    assert_eq!(record.methods.len(), 1);
}

/// A tombstone is a kill switch: a capability restored from the record before
/// the kill list was replayed must be revoked, not left alive for its lease.
#[test]
fn a_tombstone_revokes_the_live_capability_it_names() {
    let (source, provider) = durable_agent();
    let cap = bound_durable(&source, provider, None);
    let record = source.export_capability(&cap).expect("export");

    let restarted = Agent::with_secret([0x52; 32]);
    restarted.set_durable_capabilities(true);
    restarted.set_record_seal_key([0x86; 32]);
    restarted.register(Box::new(Echo));
    let restored = restarted
        .restore_capability_in_process_only(&record, &admitted(b"owner"))
        .expect("restore");
    // The deployment replays its persistent kill list after the restore path
    // already ran; the live copy is the authority that has to die.
    restarted
        .tombstone_record(record.record_id)
        .expect("replay the tombstone");
    let lane = restarted
        .create_lane("killed", Budget::default())
        .expect("lane");
    let owner = PeerIdentity::from_certificate(b"owner");
    let error = restarted
        .call_as(Some(&owner), lane, &restored, "echo", Vec::new())
        .expect_err("a tombstoned credential must not dispatch");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
    // Attenuation is a use of the authority too.
    let error = restarted
        .attenuate(&restored, CapAttrs::new(&["echo"]).durable())
        .expect_err("a tombstoned credential cannot be attenuated");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// The record-id sets are bounded: a kernel that keeps exporting refuses the
/// export that would grow the set past its ceiling.
#[test]
fn the_record_id_sets_are_bounded() {
    let (agent, provider) = durable_agent();
    agent.set_record_id_ceiling(2).expect("ceiling");
    assert_eq!(agent.record_id_ceiling(), 2);
    let mut records = Vec::new();
    for index in 0..2 {
        let cap = bound_durable(&agent, provider, None);
        records.push(agent.export_capability(&cap).expect("export"));
        drop(cap);
        assert_eq!(agent.consumed_record_count(), index + 1);
    }
    let third = bound_durable(&agent, provider, None);
    let error = agent
        .export_capability(&third)
        .expect_err("the consumed set is full");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(agent.consumed_record_count(), 2);

    // The same ceiling bounds restores, so a record replay cannot grow the set.
    let restarted = Agent::with_secret([0x52; 32]);
    restarted.set_durable_capabilities(true);
    restarted.set_record_seal_key([0x86; 32]);
    restarted.set_record_id_ceiling(1).expect("ceiling");
    restarted.register(Box::new(Echo));
    let first = restarted
        .restore_capability_in_process_only(&records[0], &admitted(b"owner"))
        .expect("first restore");
    drop(first);
    let error = restarted
        .restore_capability_in_process_only(&records[1], &admitted(b"owner"))
        .expect_err("the restored set is full");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(restarted.restored_record_count(), 1);
}

/// A sealed record whose budget disables a ceiling is a durable refusal, not a
/// caller argument error.
#[test]
fn a_record_that_disables_a_ceiling_is_a_durable_refusal() {
    let (source, provider) = durable_agent();
    let cap = bound_durable(&source, provider, None);
    let mut record = source.export_capability(&cap).expect("export");
    record.budget.max_bytes = 0;
    record.seal_with(&[0x86; 32]);
    let restarted = Agent::with_secret([0x52; 32]);
    restarted.set_durable_capabilities(true);
    restarted.set_record_seal_key([0x86; 32]);
    restarted.register(Box::new(Echo));
    let error = restarted
        .restore_capability_in_process_only(&record, &admitted(b"owner"))
        .expect_err("a zero ceiling is refused");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A cancelled promise is a caller decision, not a kernel fault: the dispatch
/// that was already running discards its outcome without counting a double
/// settlement (round 5, N4).
#[test]
fn cancelling_a_running_call_is_not_a_double_settlement() {
    use std::cell::RefCell;

    struct Canceller {
        slot: Rc<RefCell<Option<active_rpc::PromiseHandle>>>,
    }

    impl Provider for Canceller {
        fn name(&self) -> &'static str {
            "canceller"
        }

        fn methods(&self) -> Vec<String> {
            vec!["go".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            if let Some(handle) = self.slot.borrow().as_ref() {
                let agent = handle.agent();
                agent.cancel(handle).expect("cancel");
            }
            Ok(Response::Value(Value::text("discarded")))
        }
    }

    let agent = Agent::with_secret([0x7d; 32]);
    let slot: Rc<RefCell<Option<active_rpc::PromiseHandle>>> = Rc::new(RefCell::new(None));
    let provider = agent.register(Box::new(Canceller {
        slot: Rc::clone(&slot),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("cap");
    let lane = agent
        .create_lane("cancel", Budget::default())
        .expect("lane");
    let promise = agent.call(lane, &cap, "go", Vec::new()).expect("call");
    *slot.borrow_mut() = Some(promise.clone());
    agent.run();
    let error = promise.value().expect_err("the call was cancelled");
    assert_eq!(error.code(), "rpc/promise-cancelled");
    assert_eq!(
        agent.metrics().promises_double_settled,
        0,
        "a caller cancellation was counted as a kernel double settlement"
    );
}

/// The record itself refuses a second settlement, whoever reaches it: the
/// kernel's early guards are additional, not the only line (C-1).
#[test]
fn a_promise_record_refuses_a_second_settlement() {
    use active_rpc::promise::{PromiseId, PromiseRecord, PromiseState};

    let mut record = PromiseRecord::new(PromiseId(1), 0);
    record
        .resolve(Value::text("one"))
        .expect("the first settlement");
    let error = record
        .resolve(Value::text("two"))
        .expect_err("a second settlement");
    assert_eq!(error.code(), "rpc/promise-resolved", "{error}");
    assert_eq!(
        record.state,
        PromiseState::Resolved(Value::text("one")),
        "the first value stays"
    );
}
