//! R-17 round 4: a drain is a check-out, the registry survives a dispatch, two
//! adapter instances describe one surface, and an ambiguous record is refused
//! before it is built.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use active_rpc::cap::{CapAttrs, CapId, CapPersistence};
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, ProviderId};

type AgentSlot = Rc<RefCell<Option<Agent>>>;

struct Adapter {
    name: &'static str,
    methods: Vec<String>,
}

impl Provider for Adapter {
    fn name(&self) -> &'static str {
        self.name
    }
    fn methods(&self) -> Vec<String> {
        self.methods.clone()
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

/// Calls `run()` from the drain, the shape that used to fail its own queued
/// jobs because the provider was absent from the table.
struct RunFromDrain {
    agent: AgentSlot,
    seen: Rc<RefCell<Vec<(u64, CapId)>>>,
}

impl Provider for RunFromDrain {
    fn name(&self) -> &'static str {
        "drain"
    }
    fn methods(&self) -> Vec<String> {
        vec!["noop".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
    fn on_drop(&mut self, object: u64, cap: CapId) {
        self.seen.borrow_mut().push((object, cap));
    }
    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        if let Some(agent) = self.agent.borrow().as_ref() {
            agent.run();
        }
        std::mem::take(&mut *self.seen.borrow_mut())
    }
}

/// Drops its last capability handle from the drain, raising an `on_drop` while
/// the provider is checked out.
struct DropInDrain {
    held: Rc<RefCell<Option<CapHandle>>>,
    seen: Rc<RefCell<Vec<(u64, CapId)>>>,
}

impl Provider for DropInDrain {
    fn name(&self) -> &'static str {
        "dropper"
    }
    fn methods(&self) -> Vec<String> {
        vec!["noop".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
    fn on_drop(&mut self, object: u64, cap: CapId) {
        self.seen.borrow_mut().push((object, cap));
    }
    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        // The last reference goes while the kernel has this provider checked
        // out; the notification must survive until the next delivery.
        self.held.borrow_mut().take();
        std::mem::take(&mut *self.seen.borrow_mut())
    }
}

#[test]
fn a_drain_leaves_the_providers_queued_work_alone() {
    let agent = Agent::new();
    let slot: AgentSlot = Rc::new(RefCell::new(None));
    let seen = Rc::new(RefCell::new(Vec::new()));
    let id = agent.register(Box::new(RunFromDrain {
        agent: Rc::clone(&slot),
        seen,
    }));
    *slot.borrow_mut() = Some(agent.clone());
    let lane = agent.create_lane("drain", Budget::default()).expect("lane");
    let cap = agent.mint(id, 0, CapAttrs::new(&["noop"])).expect("cap");
    let queued = agent.call(lane, &cap, "noop", Vec::new()).expect("queued");

    assert!(agent.take_drops(id).is_empty());
    agent.run();
    assert_eq!(
        queued.value().expect("the queued call still runs"),
        Value::text("ok"),
        "a re-entrant run from a drain must not fail the provider's own jobs"
    );
}

#[test]
fn a_drop_raised_during_a_drain_is_delivered_later() {
    let agent = Agent::new();
    let held: Rc<RefCell<Option<CapHandle>>> = Rc::new(RefCell::new(None));
    let seen = Rc::new(RefCell::new(Vec::new()));
    let id = agent.register(Box::new(DropInDrain {
        held: Rc::clone(&held),
        seen: Rc::clone(&seen),
    }));
    let cap = agent.mint(id, 7, CapAttrs::new(&["noop"])).expect("cap");
    let cap_id = cap.id();
    *held.borrow_mut() = Some(cap);

    // The drain drops the last handle; with the provider checked out the
    // notification waits instead of being discarded.
    assert!(agent.take_drops(id).is_empty());
    agent.run();
    assert_eq!(
        agent.take_drops(id),
        vec![(7, cap_id)],
        "the drop raised during the drain is delivered on the next pass"
    );
}

#[test]
fn two_instances_of_one_adapter_describe_one_surface() {
    let agent = Agent::new();
    agent.register(Box::new(Adapter {
        name: "bulk",
        methods: vec!["plan".to_string()],
    }));
    agent.register(Box::new(Adapter {
        name: "bulk",
        methods: vec!["put".to_string()],
    }));
    let bytes = agent
        .intro()
        .expect("two instances of one adapter are a documented configuration");
    let module = active_infinity::decode(&bytes).expect("a valid module");
    let json = active_infinity::interop::to_redacted_json(&module).expect("json");
    assert_eq!(
        json.matches("\"bulk\"").count(),
        2,
        "both instances are listed: {json}"
    );
}

#[test]
fn a_provider_may_mint_for_itself_while_it_is_dispatching() {
    struct SelfMinting {
        agent: AgentSlot,
        id: Rc<Cell<Option<ProviderId>>>,
        minted: Rc<RefCell<Option<bool>>>,
    }
    impl Provider for SelfMinting {
        fn name(&self) -> &'static str {
            "self"
        }
        fn methods(&self) -> Vec<String> {
            vec!["noop".to_string()]
        }
        fn mutating(&self, _method: &str) -> bool {
            false
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            if let (Some(agent), Some(id)) = (self.agent.borrow().as_ref(), self.id.get()) {
                let minted = agent
                    .mint(id, 0, CapAttrs::new(&["noop"]))
                    .map(|_| ())
                    .is_ok();
                *self.minted.borrow_mut() = Some(minted);
            }
            Ok(Response::Value(Value::text("ok")))
        }
    }

    let agent = Agent::new();
    let slot: AgentSlot = Rc::new(RefCell::new(Some(agent.clone())));
    let id_slot = Rc::new(Cell::new(None));
    let minted = Rc::new(RefCell::new(None));
    let id = agent.register(Box::new(SelfMinting {
        agent: Rc::clone(&slot),
        id: Rc::clone(&id_slot),
        minted: Rc::clone(&minted),
    }));
    id_slot.set(Some(id));
    let lane = agent.create_lane("self", Budget::default()).expect("lane");
    let cap = agent.mint(id, 0, CapAttrs::new(&["noop"])).expect("cap");
    let promise = agent.call(lane, &cap, "noop", Vec::new()).expect("queued");
    agent.run();
    promise.value().expect("resolved");
    assert_eq!(
        *minted.borrow(),
        Some(true),
        "the provider is registered while it is checked out for its own call"
    );
}

#[test]
fn an_ambiguous_record_is_refused_before_the_grant_is_spent() {
    let agent = Agent::with_secret([0x53; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x95; 32]);
    let first = agent.register(Box::new(Adapter {
        name: "bulk",
        methods: vec!["plan".to_string()],
    }));
    agent.register(Box::new(Adapter {
        name: "bulk",
        methods: vec!["put".to_string()],
    }));
    let owner = IdentityPolicy::default()
        .admit(
            Some(&PeerIdentity::from_certificate(b"ambiguous-owner")),
            true,
        )
        .expect("admit");
    let mut attrs = CapAttrs::new(&["plan"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent.mint_bound(&owner, first, 0, attrs).expect("cap");
    let bytes = agent.remaining_bytes(&cap).expect("meter");

    let error = agent
        .export_capability(&cap)
        .expect_err("restore resolves a provider by name, so this record is unspendable");
    assert_eq!(error.code(), "rpc/persistence", "{error}");
    assert_eq!(
        agent.remaining_bytes(&cap).expect("meter"),
        bytes,
        "the grant was not reserved"
    );
    // The capability is still usable: the refusal cost it nothing.
    let lane = agent
        .create_lane("ambiguous", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(
            Some(&PeerIdentity::from_certificate(b"ambiguous-owner")),
            lane,
            &cap,
            "plan",
            Vec::new(),
        )
        .expect("queued");
    agent.run();
    promise.value().expect("the capability still works");
}
