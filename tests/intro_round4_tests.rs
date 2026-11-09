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
fn a_drop_raised_during_a_drain_is_delivered_on_the_next_drain() {
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
    // notification waits instead of being discarded, and the drain flushes it
    // itself -- no unrelated traffic is needed (R-17 round 5, L-1).
    assert!(agent.take_drops(id).is_empty());
    assert_eq!(
        agent.take_drops(id),
        vec![(7, cap_id)],
        "the drop raised during the drain is delivered by the next drain"
    );
}

/// A provider that panics in the drain must be restored, taped, and answered
/// with an empty list (R-17 round 5, L-2).
struct PanickingDrain;

impl Provider for PanickingDrain {
    fn name(&self) -> &'static str {
        "panicking"
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
    fn take_drop_notifications(&mut self) -> Vec<(u64, CapId)> {
        panic!("the drain panics");
    }
}

#[test]
fn a_panicking_drain_restores_the_provider_and_is_on_the_tape() {
    let agent = Agent::new();
    let id = agent.register(Box::new(PanickingDrain));
    assert!(
        agent.take_drops(id).is_empty(),
        "a panicking drain answers empty"
    );
    // The provider is back in the registry and still servable.
    agent
        .mint(id, 0, CapAttrs::new(&["noop"]))
        .expect("the provider was restored");
    assert!(
        agent
            .trace()
            .iter()
            .any(|event| event.event() == "provider.panicked"),
        "the panic is on the tape"
    );
}

/// Leaks a `Ref` across `on_drop`, so the kernel cannot write its registry
/// back in place.
struct LeakyDrop {
    agent: AgentSlot,
    armed: Rc<Cell<bool>>,
    delivered: Rc<Cell<u32>>,
    dropped: Rc<Cell<u32>>,
}

impl Drop for LeakyDrop {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}

impl Provider for LeakyDrop {
    fn name(&self) -> &'static str {
        "leaky"
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
    fn on_drop(&mut self, _object: u64, _cap: CapId) {
        self.delivered.set(self.delivered.get() + 1);
        if self.armed.get() {
            if let Some(agent) = self.agent.borrow().as_ref() {
                // A provider that keeps a `Ref` past the callback: the kernel
                // cannot write the registry back and must park the provider
                // rather than drop it (R-17 round 7, F-2/F-3).
                std::mem::forget(agent.cell().borrow());
            }
        }
    }
}

#[test]
fn a_drop_that_keeps_a_borrow_parks_the_provider_instead_of_losing_it() {
    let agent = Agent::new();
    let slot: AgentSlot = Rc::new(RefCell::new(Some(agent.clone())));
    let armed = Rc::new(Cell::new(false));
    let delivered = Rc::new(Cell::new(0));
    let dropped = Rc::new(Cell::new(0));
    let id = agent.register(Box::new(LeakyDrop {
        agent: Rc::clone(&slot),
        armed: Rc::clone(&armed),
        delivered: Rc::clone(&delivered),
        dropped: Rc::clone(&dropped),
    }));
    let cap = agent.mint(id, 0, CapAttrs::new(&["noop"])).expect("cap");
    armed.set(true);
    // Releasing the last handle delivers the callback; the leak makes the
    // write-back borrow fail.
    drop(cap);
    assert_eq!(delivered.get(), 1, "the callback ran once");
    assert_eq!(
        dropped.get(),
        0,
        "the provider is parked, not dropped while the registry still names it"
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

/// The provider-name bound the introduction applies is the one the sealed-record
/// parser accepts, so a name a kernel can describe is one it can persist
/// (R-17 round 5, L-5).
#[test]
fn a_provider_name_at_the_introduction_bound_round_trips_a_record() {
    let name: &'static str = Box::leak(
        "p".repeat(active_rpc::intro::MAX_NAME_BYTES)
            .into_boxed_str(),
    );
    let agent = Agent::with_secret([0x55; 32]);
    agent.set_durable_capabilities(true);
    agent.set_record_seal_key([0x98; 32]);
    let provider = agent.register(Box::new(Adapter {
        name,
        methods: vec!["noop".to_string()],
    }));
    let owner = IdentityPolicy::default()
        .admit(
            Some(&PeerIdentity::from_certificate(b"long-name-owner")),
            true,
        )
        .expect("admit");
    let mut attrs = CapAttrs::new(&["noop"]);
    attrs.persistence = CapPersistence::Durable;
    let cap = agent.mint_bound(&owner, provider, 0, attrs).expect("cap");
    // One byte over the bound is refused by the description and, through the
    // same rule, by the record parser (R-17 round 8, #5).
    let over = "p".repeat(active_rpc::intro::MAX_NAME_BYTES + 1);
    assert!(active_rpc::intro::build(
        "peer",
        &[(over.clone(), vec!["noop".to_string()])],
        &Budget::default()
    )
    .is_err());
    let record = agent
        .export_capability(&cap)
        .expect("a name the introduction accepts is persistable");
    drop(cap);
    agent
        .restore_capability_in_process_only(&record, &owner)
        .expect("and restorable");
    assert!(!agent.intro().expect("intro").is_empty());
}

/// A refused receive is a refusal like any other (R-17 round 5, L-6).
/// One adapter whose surface the module cannot carry must not deny the
/// kernel's description to every peer (R-17 round 8, #4).
#[test]
fn a_provider_the_introduction_cannot_name_is_skipped_not_fatal() {
    let agent = Agent::new();
    agent.register(Box::new(Adapter {
        name: "bad\u{200B}name",
        methods: vec!["x".to_string()],
    }));
    agent.register(Box::new(Adapter {
        name: "good",
        methods: vec!["y".to_string()],
    }));
    let bytes = agent
        .intro()
        .expect("one bad surface does not deny the description");
    let module = active_infinity::decode(&bytes).expect("a valid module");
    let json = active_infinity::interop::to_redacted_json(&module).expect("json");
    assert!(json.contains("\"good\""), "{json}");
    assert!(!json.contains('\u{200B}'), "the bad name crossed: {json}");
    assert!(
        agent
            .trace()
            .iter()
            .any(|event| event.event() == "intro.skipped"),
        "the skip is on the tape"
    );
}

/// A provider over the introduction's method ceiling is left out, the healthy
/// surface is still described, and the omission is taped once, not per call
/// (R-17 round 9, F-3 and F-9).
#[test]
fn a_provider_with_too_many_methods_is_skipped_and_taped_once() {
    let agent = Agent::new();
    agent.register(Box::new(Adapter {
        name: "huge",
        methods: (0..=active_rpc::intro::MAX_METHODS_PER_PROVIDER)
            .map(|index| format!("m{index}"))
            .collect(),
    }));
    agent.register(Box::new(Adapter {
        name: "good",
        methods: vec!["y".to_string()],
    }));
    let bytes = agent
        .intro()
        .expect("one huge surface does not deny the rest");
    let module = active_infinity::decode(&bytes).expect("a valid module");
    let json = active_infinity::interop::to_redacted_json(&module).expect("json");
    assert!(json.contains("\"good\""), "{json}");
    assert!(!json.contains("\"huge\""), "{json}");
    agent.intro().expect("a second description");
    let skips = agent
        .trace()
        .iter()
        .filter(|event| event.event() == "intro.skipped")
        .count();
    assert_eq!(skips, 1, "one skip event per provider, not per call");
}

#[test]
fn a_refused_receive_is_recorded() {
    let agent = Agent::new();
    let channel = agent
        .create_channel("quiet", active_rpc::channel::Direction::Both)
        .expect("channel");
    let lane = agent
        .create_lane("outsider", Budget::default())
        .expect("lane");
    let before = agent.metrics().calls_refused;
    let error = agent.recv(lane, channel).expect_err("not subscribed");
    assert_eq!(error.code(), "rpc/unknown-channel");
    assert_eq!(
        agent.metrics().calls_refused,
        before + 1,
        "the refusal is in the metrics"
    );
    assert!(
        agent
            .trace()
            .iter()
            .any(|event| event.event() == "call.refused"),
        "and on the tape"
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

/// Capture stops at the introduction bound: a provider that advertises one
/// method past it must not have `mutating()` called for the whole list before
/// the refusal (R-17 round 10, R10-4).
#[test]
fn a_capture_stops_at_the_introduction_bound() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct Counting {
        asked: Arc<AtomicUsize>,
    }

    impl Provider for Counting {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn methods(&self) -> Vec<String> {
            (0..=active_rpc::intro::MAX_METHODS_PER_PROVIDER)
                .map(|index| format!("m{index}"))
                .collect()
        }
        fn mutating(&self, _method: &str) -> bool {
            self.asked.fetch_add(1, Ordering::SeqCst);
            false
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            Ok(Response::Value(Value::text("ok")))
        }
    }

    let asked = Arc::new(AtomicUsize::new(0));
    let agent = Agent::new();
    agent.register(Box::new(Counting {
        asked: Arc::clone(&asked),
    }));
    let bytes = agent.intro().expect("an undescribable provider is skipped");
    let module = active_infinity::decode(&bytes).expect("a valid module");
    let json = active_infinity::interop::to_redacted_json(&module).expect("json");
    assert!(!json.contains("counting"), "{json}");
    let asked = asked.load(Ordering::SeqCst);
    assert!(
        asked <= active_rpc::intro::MAX_METHODS_PER_PROVIDER,
        "capture asked mutating() {asked} times for {} names",
        active_rpc::intro::MAX_METHODS_PER_PROVIDER + 1
    );
}
