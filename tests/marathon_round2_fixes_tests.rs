//! R-02 round 3 and R-03 round 2: the subtree bound across a dropped parent,
//! durable-record lifecycle, provider callbacks and channel accounting.
//!
//! Every test here fails against the tree before its fix.

use std::cell::{Cell, RefCell};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, CapPersistence};

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
    let agent = Agent::with_secret([0x41; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent
        .create_lane("round2", Budget::default())
        .expect("lane");
    (agent, provider, lane)
}

fn durable_agent() -> (Agent, active_rpc::ProviderId) {
    let agent = Agent::with_secret([0x42; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x84; 32]);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

/// A child capability keeps its ancestors' meters alive: dropping the parent
/// handle must not hand every child the whole grant again.
#[test]
fn dropping_the_parent_handle_keeps_the_subtree_bound() {
    let (agent, provider, lane) = agent();
    let parent = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(2)),
        )
        .expect("parent");
    let first = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(2)),
        )
        .expect("first child");
    let second = agent
        .attenuate(
            &parent,
            CapAttrs::new(&["echo"]).with_budget(Budget::calls(2)),
        )
        .expect("second child");
    for _ in 0..2 {
        let promise = agent
            .call(lane, &first, "echo", Vec::new())
            .expect("call under the grant");
        agent.run();
        promise.value().expect("value");
    }
    drop(parent);
    let error = agent
        .call(lane, &second, "echo", Vec::new())
        .expect_err("the grant is spent for the whole subtree");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A tombstone is authority metadata a deployment can replay after a restart.
#[test]
fn a_tombstone_replayed_at_startup_refuses_the_record() {
    let (source, provider) = durable_agent();
    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = source
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap");
    let record = source.export_capability(&cap).expect("export");
    source.revoke(&cap).expect("revoke");
    assert!(source.record_is_tombstoned(&record.record_id));

    // A restarted kernel shares the authority domain (secret and seal key) but
    // starts with an empty tombstone set.
    let restarted = Agent::with_secret([0x42; 32]);
    restarted.set_durable_capabilities(true);
    restarted.set_record_seal_key([0x84; 32]);
    restarted.register(Box::new(Echo));
    let accepted = restarted
        .restore_capability(&record, &owner)
        .expect("without the tombstone the record restores");
    drop(accepted);

    restarted
        .tombstone_record(record.record_id)
        .expect("replay the tombstone");
    let error = restarted
        .restore_capability(&record, &owner)
        .expect_err("a replayed tombstone refuses the record");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
}

/// One credential is one live grant: a second restore must be refused, or a
/// revocation could not reach every copy.
#[test]
fn restoring_the_same_record_twice_is_refused() {
    let (agent, provider) = durable_agent();
    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap");
    let record = agent.export_capability(&cap).expect("export");
    drop(cap);
    let first = agent
        .restore_capability(&record, &owner)
        .expect("first restore");
    let error = agent
        .restore_capability(&record, &owner)
        .expect_err("the credential is already live");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
    drop(first);
    agent
        .restore_capability(&record, &owner)
        .expect("a released copy frees the credential");
}

/// Tombstones only track durable records: an ephemeral mint/revoke cycle must
/// not grow the set forever.
#[test]
fn a_revocation_tombstones_only_durable_records() {
    let (agent, provider) = durable_agent();
    let ephemeral = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("ephemeral");
    let before = agent.record_tombstone_count();
    agent.revoke(&ephemeral).expect("revoke");
    assert_eq!(
        agent.record_tombstone_count(),
        before,
        "an ephemeral capability has no restorable record"
    );

    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let durable = agent
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable");
    agent.revoke(&durable).expect("revoke");
    assert_eq!(agent.record_tombstone_count(), before + 1);
}

/// An unbound durable capability names no peer, so its record would restore for
/// anybody: export refuses it.
#[test]
fn an_unbound_durable_capability_cannot_be_exported() {
    let (agent, provider) = durable_agent();
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent.mint(provider, 0, attrs).expect("unbound durable");
    let error = agent
        .export_capability(&cap)
        .expect_err("a record must name its peer");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

/// A deadline belongs to the clock it was minted in, not to the clock the
/// export happens to run under.
#[test]
fn a_record_keeps_the_clock_mode_its_deadline_was_taken_in() {
    let (source, provider) = durable_agent();
    source.use_wall_clock(true);
    let owner = admitted(b"owner");
    let mut attrs = CapAttrs::new(&["echo"]).with_ttl_ms(60_000);
    attrs.persistence = CapPersistence::Durable;
    let cap = source
        .mint_bound(&owner, provider, 0, attrs)
        .expect("wall-clock cap");
    source.use_wall_clock(false);
    let record = source.export_capability(&cap).expect("export");
    assert!(
        record.wall_clock,
        "the export stamped the current mode instead of the deadline's"
    );

    let virtual_kernel = Agent::with_secret([0x43; 32]);
    virtual_kernel.set_durable_capabilities(true);
    virtual_kernel.set_record_seal_key([0x84; 32]);
    virtual_kernel.register(Box::new(Echo));
    let error = virtual_kernel
        .restore_capability(&record, &owner)
        .expect_err("a wall-clock deadline cannot be read in virtual time");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// Attenuation clamps to the parent's absolute deadline, so a parent minted in
/// the other clock domain is refused instead of mixing the two.
#[test]
fn attenuation_refuses_a_clock_mode_change() {
    let (agent, provider, _lane) = agent();
    // Mint in the wall-clock domain, then attenuate in the virtual one: the
    // parent's deadline stays live but belongs to the other domain.
    agent.use_wall_clock(true);
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(60_000))
        .expect("bounded cap");
    agent.use_wall_clock(false);
    let error = agent
        .attenuate(&cap, CapAttrs::new(&["echo"]).with_ttl_ms(1_000))
        .expect_err("the parent's deadline is in another domain");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A provider that calls back into the agent from `on_drop` must not panic: the
/// notification runs with no kernel borrow held.
#[test]
fn a_provider_may_use_the_agent_inside_on_drop() {
    struct Callback {
        agent: Rc<RefCell<Option<Agent>>>,
        pins: Rc<Cell<usize>>,
    }

    impl Provider for Callback {
        fn name(&self) -> &'static str {
            "callback"
        }

        fn methods(&self) -> Vec<String> {
            vec!["hold".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("ok")))
        }

        fn on_drop(&mut self, _object: u64, _cap: active_rpc::CapId) {
            let agent = self.agent.borrow().clone().expect("agent");
            // Every one of these takes a kernel borrow.
            let _ = agent.now_ms();
            let _ = agent.create_lane("from-on-drop", Budget::default());
            let _ = agent.events();
            self.pins.set(self.pins.get() + 1);
        }
    }

    let pins = Rc::new(Cell::new(0));
    let slot: Rc<RefCell<Option<Agent>>> = Rc::new(RefCell::new(None));
    let agent = Agent::with_secret([0x44; 32]);
    *slot.borrow_mut() = Some(agent.clone());
    let provider = agent.register(Box::new(Callback {
        agent: Rc::clone(&slot),
        pins: Rc::clone(&pins),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["hold"]))
        .expect("cap");
    drop(cap);
    assert_eq!(pins.get(), 1, "the notification did not run");
}

/// A provider that awaits a promise from inside its own call is refused instead
/// of spinning forever: the outer dispatch owns the queue.
#[test]
fn a_provider_awaiting_its_own_call_is_refused() {
    struct Awaiter {
        agent: Rc<RefCell<Option<Agent>>>,
        inner: Rc<RefCell<Option<CapHandle>>>,
        lane: Rc<RefCell<Option<active_rpc::LaneId>>>,
        outcome: Rc<RefCell<Option<String>>>,
    }

    impl Provider for Awaiter {
        fn name(&self) -> &'static str {
            "awaiter"
        }

        fn methods(&self) -> Vec<String> {
            vec!["wait".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            let agent = self.agent.borrow().clone().expect("agent");
            let inner = self.inner.borrow().clone().expect("inner cap");
            let lane = self.lane.borrow().expect("inner lane");
            let promise = agent
                .call(lane, &inner, "echo", Vec::new())
                .expect("queue an inner call");
            match agent.await_promise(&promise) {
                Ok(_) => *self.outcome.borrow_mut() = Some("settled".to_string()),
                Err(error) => *self.outcome.borrow_mut() = Some(error.code().to_string()),
            }
            Ok(Response::Value(Value::text("awaited")))
        }
    }

    let agent = Agent::with_secret([0x45; 32]);
    let inner_provider = agent.register(Box::new(Echo));
    let inner = agent
        .mint(inner_provider, 0, CapAttrs::new(&["echo"]))
        .expect("inner cap");
    let inner_lane = agent.create_lane("inner", Budget::default()).expect("lane");
    let slot: Rc<RefCell<Option<Agent>>> = Rc::new(RefCell::new(None));
    *slot.borrow_mut() = Some(agent.clone());
    let outcome: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let inner_slot: Rc<RefCell<Option<CapHandle>>> = Rc::new(RefCell::new(Some(inner)));
    let lane_slot: Rc<RefCell<Option<active_rpc::LaneId>>> =
        Rc::new(RefCell::new(Some(inner_lane)));
    let provider = agent.register(Box::new(Awaiter {
        agent: Rc::clone(&slot),
        inner: Rc::clone(&inner_slot),
        lane: Rc::clone(&lane_slot),
        outcome: Rc::clone(&outcome),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["wait"]))
        .expect("cap");
    let lane = agent.create_lane("outer", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "wait", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("the provider answered");
    let recorded = outcome.borrow().clone().unwrap_or_default();
    assert_eq!(recorded, "rpc/provider", "unexpected outcome: {recorded}");
}

/// A panicking provider must not wedge the kernel: the guard restores the
/// dispatch flag and the provider.
#[test]
fn a_panicking_provider_does_not_wedge_the_kernel() {
    struct BreakOnce {
        calls: Rc<Cell<usize>>,
    }

    impl Provider for BreakOnce {
        fn name(&self) -> &'static str {
            "break-once"
        }

        fn methods(&self) -> Vec<String> {
            vec!["once".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            let count = self.calls.get();
            self.calls.set(count + 1);
            if count == 0 {
                panic!("the provider unwound");
            }
            Ok(Response::Value(Value::text("ok")))
        }
    }

    let calls = Rc::new(Cell::new(0));
    let agent = Agent::with_secret([0x46; 32]);
    let provider = agent.register(Box::new(BreakOnce {
        calls: Rc::clone(&calls),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["once"]))
        .expect("cap");
    let lane = agent.create_lane("panic", Budget::default()).expect("lane");
    let promise = agent.call(lane, &cap, "once", Vec::new()).expect("call");
    let unwound = catch_unwind(AssertUnwindSafe(|| agent.run()));
    assert!(unwound.is_err(), "the panic must reach the caller");
    // The promise is settled as a provider fault, so nothing is left pending.
    let error = promise.value().expect_err("the job settles as a fault");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    let next = agent
        .call(lane, &cap, "once", Vec::new())
        .expect("second call");
    agent.run();
    next.value().expect("the kernel recovered");
    assert_eq!(calls.get(), 2);
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, active_rpc::Event::ProviderPanicked { .. })));
}

/// A panic inside `on_drop` must not remove the provider from the registry or
/// leave its id in the delivery set: the notification is best-effort and the
/// kernel recovers.
#[test]
fn a_panicking_on_drop_keeps_the_provider() {
    struct PanicOnce {
        armed: Rc<Cell<u64>>,
    }

    impl Provider for PanicOnce {
        fn name(&self) -> &'static str {
            "panic-on-drop"
        }

        fn methods(&self) -> Vec<String> {
            vec!["hold".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("ok")))
        }

        fn on_drop(&mut self, object: u64, _cap: active_rpc::CapId) {
            if object == self.armed.get() {
                self.armed.set(u64::MAX);
                panic!("on_drop unwound");
            }
        }
    }

    let armed = Rc::new(Cell::new(1));
    let agent = Agent::with_secret([0x48; 32]);
    let provider = agent.register(Box::new(PanicOnce {
        armed: Rc::clone(&armed),
    }));
    let doomed = agent
        .mint(provider, 1, CapAttrs::new(&["hold"]))
        .expect("doomed");
    let survivor = agent
        .mint(provider, 2, CapAttrs::new(&["hold"]))
        .expect("survivor");
    let lane = agent
        .create_lane("panic-drop", Budget::default())
        .expect("lane");
    // The notification panics, and the kernel absorbs it: a panic here usually
    // runs inside a `Drop`, where a second one aborts the process.
    drop(doomed);
    let promise = agent
        .call(lane, &survivor, "hold", Vec::new())
        .expect("the provider is still registered");
    agent.run();
    promise.value().expect("the surviving object still works");
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, active_rpc::Event::ProviderPanicked { .. })));
}

/// A channel message is lane traffic: it consumes the lane's byte and call
/// budgets, so a lane cannot fill a channel for free.
#[test]
fn a_send_consumes_the_lane_byte_budget() {
    let (agent, _provider, _lane) = agent();
    let lane = agent
        .create_lane(
            "send",
            Budget {
                max_bytes: 64,
                ..Budget::default()
            },
        )
        .expect("lane");
    let channel = agent
        .create_channel("pipe", Direction::Both)
        .expect("channel");
    let error = agent
        .send(lane, channel, Value::text("x".repeat(200)), &[])
        .expect_err("the lane byte ceiling bounds a send");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    agent
        .send(lane, channel, Value::text("ok"), &[])
        .expect("a small message fits");
}

/// The channel's queued-byte ceiling is real and is released on receive.
#[test]
fn a_channel_accounts_for_queued_bytes() {
    let (agent, _provider, _lane) = agent();
    let lane = agent.create_lane("ch", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("counted", Direction::Both)
        .expect("channel");
    let message = agent
        .send(lane, channel, Value::text("payload"), &[])
        .expect("send");
    let queued = agent.channel(channel).expect("channel").queued_bytes();
    assert!(queued > 0, "the message was not accounted");
    let received = agent.recv(channel).expect("recv").expect("message");
    assert_eq!(received.sequence, message);
    assert_eq!(
        agent.channel(channel).expect("channel").queued_bytes(),
        0,
        "receiving must release the accounting"
    );
}

/// A capability that a provider drops while handling its own drop is delivered
/// once, by the outer notification pass.
#[test]
fn a_drop_raised_inside_on_drop_is_delivered_once() {
    struct Nested {
        slot: Rc<RefCell<Option<CapHandle>>>,
        seen: Rc<RefCell<Vec<u64>>>,
    }

    impl Provider for Nested {
        fn name(&self) -> &'static str {
            "nested"
        }

        fn methods(&self) -> Vec<String> {
            vec!["hold".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("ok")))
        }

        fn on_drop(&mut self, object: u64, _cap: active_rpc::CapId) {
            self.seen.borrow_mut().push(object);
            let held = self.slot.borrow_mut().take();
            drop(held);
        }
    }

    let slot: Rc<RefCell<Option<CapHandle>>> = Rc::new(RefCell::new(None));
    let seen = Rc::new(RefCell::new(Vec::new()));
    let agent = Agent::with_secret([0x47; 32]);
    let provider = agent.register(Box::new(Nested {
        slot: Rc::clone(&slot),
        seen: Rc::clone(&seen),
    }));
    *slot.borrow_mut() = Some(
        agent
            .mint(provider, 7, CapAttrs::new(&["hold"]))
            .expect("held"),
    );
    let doomed = agent
        .mint(provider, 9, CapAttrs::new(&["hold"]))
        .expect("doomed");
    drop(doomed);
    assert_eq!(seen.borrow().clone(), vec![9, 7]);
}
