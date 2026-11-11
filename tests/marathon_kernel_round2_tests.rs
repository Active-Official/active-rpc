//! R-02 round 2: scheduler, clock domain, publish authority, lane budgets and
//! deferred provider notifications.

use std::cell::RefCell;
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, ProviderId};

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

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

struct Other;

impl Provider for Other {
    fn name(&self) -> &'static str {
        "other"
    }

    fn methods(&self) -> Vec<String> {
        vec!["other".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("other")))
    }
}

fn agent() -> (Agent, ProviderId, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x6a; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let lane = agent
        .create_lane("kernel", Budget::default())
        .expect("lane");
    (agent, provider, lane)
}

fn admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    let peer = PeerIdentity::from_certificate(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

/// A pipeline that crosses providers is legal: a job blocked on another
/// provider's queued producer must wait, not fail as a cycle.
#[test]
fn a_cross_provider_pipeline_settles() {
    let agent = Agent::with_secret([0x6b; 32]);
    let first = agent.register(Box::new(Echo)).expect("register provider");
    let second = agent.register(Box::new(Other)).expect("register provider");
    let lane = agent.create_lane("pipe", Budget::default()).expect("lane");
    let cap_first = agent.mint(first, 0, CapAttrs::new(&["echo"])).expect("cap");
    let cap_second = agent
        .mint(second, 0, CapAttrs::new(&["other"]))
        .expect("cap");

    let a = agent.call(lane, &cap_first, "echo", Vec::new()).expect("a");
    let b = agent
        .call(lane, &cap_second, "other", vec![Arg::Promise(a.id())])
        .expect("b");
    let c = agent
        .call(lane, &cap_first, "echo", vec![Arg::Promise(b.id())])
        .expect("c");
    agent.run();
    a.value().expect("a settles");
    b.value().expect("b settles");
    c.value()
        .expect("c settles after the other provider's batch");
}

/// A bounded record exported from a wall-clock kernel is refused by a virtual
/// kernel: its deadline is in another clock domain.
#[test]
fn a_wall_clock_record_does_not_restore_unbounded_in_virtual_mode() {
    let source = Agent::with_secret([0x6c; 32]);
    source.set_durable_capabilities(true);
    source.set_record_seal_key([0x9c; 32]);
    source.use_wall_clock(true);
    let provider = source.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]).durable();
    attrs.ttl_ms = Some(60_000);
    let owner = admitted(b"peer");
    let cap = source
        .mint_bound(&owner, provider, 0, attrs)
        .expect("durable cap");
    let record = source.export_capability(&cap).expect("export");

    let target = Agent::with_secret([0x6d; 32]);
    target.set_durable_capabilities(true);
    target.set_record_seal_key([0x9c; 32]);
    target.register(Box::new(Echo)).expect("register provider");
    let peer = admitted(b"peer");
    let error = target
        .restore_capability_in_process_only(&record, &peer)
        .expect_err("a wall-clock deadline cannot be read in virtual time");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A read-only capability cannot publish: publishing writes to a channel.
#[test]
fn a_read_only_capability_cannot_publish() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).read_only())
        .expect("cap");
    let channel = agent
        .create_channel("topic", Direction::Both)
        .expect("channel");
    let error = agent
        .publish(lane, channel, &cap, "t", Value::text("x"))
        .expect_err("a read-only grant cannot publish");
    assert_eq!(error.code(), "rpc/read-only", "{error}");
}

/// A lane's byte ceiling is cumulative across calls.
#[test]
fn a_lane_byte_budget_is_cumulative() {
    let (agent, provider, _lane) = agent();
    let lane = agent
        .create_lane(
            "bytes",
            Budget {
                max_bytes: 1_000,
                ..Budget::default()
            },
        )
        .expect("lane");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let mut refused = false;
    for _ in 0..10 {
        let result = agent.call(
            lane,
            &cap,
            "echo",
            vec![Arg::Value(Value::text("x".repeat(200)))],
        );
        if let Err(error) = result {
            assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
            refused = true;
            break;
        }
        agent.run();
    }
    assert!(refused, "the lane byte ceiling never fired");
}

/// Publishing consumes the lane's call budget as well as its bytes.
#[test]
fn publish_counts_against_the_lane_budget() {
    let (agent, provider, _lane) = agent();
    let lane = agent
        .create_lane("publish", Budget::calls(1))
        .expect("lane");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).restrict_topics(&["t"]),
        )
        .expect("cap");
    let channel = agent
        .create_channel("topic", Direction::Both)
        .expect("channel");
    agent
        .publish(lane, channel, &cap, "t", Value::text("one"))
        .expect("first publish");
    let error = agent
        .publish(lane, channel, &cap, "t", Value::text("two"))
        .expect_err("the lane call budget is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A drop inside a provider's own call is delivered once the batch finishes.
#[test]
fn on_drop_is_delivered_when_a_provider_releases_during_its_own_call() {
    struct SlotProvider {
        slot: Rc<RefCell<Option<CapHandle>>>,
        notifications: Rc<RefCell<Vec<(u64, active_rpc::CapId)>>>,
    }

    impl Provider for SlotProvider {
        fn name(&self) -> &'static str {
            "slot"
        }

        fn methods(&self) -> Vec<String> {
            vec!["go".to_string()]
        }

        fn mutating(&self, _method: &str) -> bool {
            false
        }

        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            // Drop the only handle to this provider's own object mid-call.
            let handle = self.slot.borrow_mut().take();
            drop(handle);
            Ok(Response::Value(Value::text("ok")))
        }

        fn on_drop(&mut self, object: u64, cap: active_rpc::CapId) {
            self.notifications.borrow_mut().push((object, cap));
        }
    }

    let notifications = Rc::new(RefCell::new(Vec::new()));
    let slot: Rc<RefCell<Option<CapHandle>>> = Rc::new(RefCell::new(None));
    let agent = Agent::with_secret([0x6f; 32]);
    let lane = agent.create_lane("drop", Budget::default()).expect("lane");
    let provider = agent
        .register(Box::new(SlotProvider {
            slot: Rc::clone(&slot),
            notifications: Rc::clone(&notifications),
        }))
        .expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["go"]))
        .expect("cap");
    // Give the provider the only handle to its own object; the call borrows the
    // id without creating another reference.
    let id = cap.id();
    *slot.borrow_mut() = Some(cap);
    let borrowed = agent.import(id);
    let promise = agent.call(lane, &borrowed, "go", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("the call succeeds");
    let recorded = notifications.borrow().clone();
    assert_eq!(recorded.len(), 1, "the deferred drop was not delivered");
    assert_eq!(recorded[0].0, 0);
}

/// A provider name shared by two registrations is ambiguous for a restore.
#[test]
fn restore_refuses_an_ambiguous_provider_name() {
    let source = Agent::with_secret([0x70; 32]);
    source.set_durable_capabilities(true);
    source.set_record_seal_key([0x9d; 32]);
    let provider = source.register(Box::new(Echo)).expect("register provider");
    let owner = admitted(b"peer");
    let cap = source
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["echo"]).durable())
        .expect("cap");
    let record = source.export_capability(&cap).expect("export");

    let target = Agent::with_secret([0x71; 32]);
    target.set_durable_capabilities(true);
    target.set_record_seal_key([0x9d; 32]);
    target.register(Box::new(Echo)).expect("register provider");
    target.register(Box::new(Echo)).expect("register provider"); // same name
    let peer = admitted(b"peer");
    let error = target
        .restore_capability_in_process_only(&record, &peer)
        .expect_err("two providers answer to one name");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
}

/// A durable capability record round-trips through JSON with its clock mode.
#[test]
fn a_record_carries_its_clock_mode() {
    let source = Agent::with_secret([0x72; 32]);
    source.set_durable_capabilities(true);
    source.set_record_seal_key([0x9e; 32]);
    source.use_wall_clock(true);
    let provider = source.register(Box::new(Echo)).expect("register provider");
    let owner = admitted(b"peer");
    let cap = source
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["echo"]).durable())
        .expect("cap");
    let record = source.export_capability(&cap).expect("export");
    assert!(record.wall_clock);
    let json = record.to_json();
    let parsed = active_rpc::persistence::CapabilityRecord::from_json(&json).expect("parse");
    assert!(parsed.wall_clock);
}

/// Guard against the placeholder provider in the drop test being unused.
#[test]
fn the_placeholder_agent_still_calls() {
    let (agent, provider, lane) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("ok");
}
