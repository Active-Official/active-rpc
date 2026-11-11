//! R-17 round 3: the provider surface is captured once, at registration.
//!
//! `intro()` used to take the provider table out and run `methods()` on every
//! provider, and `call()` used to run `has_method`/`mutating` under the kernel
//! borrow. Both made a provider that consults the agent while describing itself
//! a hazard. These tests pin the contract that replaced them: provider code runs
//! once, at registration, with no borrow held, and every later path reads the
//! snapshot.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget};

type AgentSlot = Rc<RefCell<Option<Agent>>>;

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

/// Counts how often the kernel describes it, and re-enters the agent from
/// `methods()` when armed -- the shape that used to fail queued work during an
/// introspection.
struct Counting {
    agent: AgentSlot,
    calls: Rc<Cell<u32>>,
    armed: Rc<Cell<bool>>,
}

impl Provider for Counting {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn methods(&self) -> Vec<String> {
        self.calls.set(self.calls.get() + 1);
        if self.armed.get() {
            if let Some(agent) = self.agent.borrow().as_ref() {
                agent.run();
            }
        }
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

/// Consults the agent from `methods()`, which `call()` must never do under a
/// borrow.
struct Reentrant {
    agent: AgentSlot,
    calls: Rc<Cell<u32>>,
}

impl Provider for Reentrant {
    fn name(&self) -> &'static str {
        "reentrant"
    }
    fn methods(&self) -> Vec<String> {
        self.calls.set(self.calls.get() + 1);
        if let Some(agent) = self.agent.borrow().as_ref() {
            // A lane it creates proves the call reached the kernel.
            agent.create_lane("from-methods", Budget::default()).ok();
        }
        vec!["ping".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

/// Changes its declared surface after registration.
struct Shifting {
    grow: Rc<Cell<bool>>,
    a_mutates: Rc<Cell<bool>>,
}

impl Provider for Shifting {
    fn name(&self) -> &'static str {
        "shifting"
    }
    fn methods(&self) -> Vec<String> {
        if self.grow.get() {
            vec!["a".to_string(), "b".to_string()]
        } else {
            vec!["a".to_string()]
        }
    }
    fn mutating(&self, method: &str) -> bool {
        method == "a" && self.a_mutates.get()
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        Ok(Response::Value(Value::text("ok")))
    }
}

/// Calls `intro()` from `invoke()`, where a dispatch has one provider checked
/// out of the table.
struct Introspecting {
    agent: AgentSlot,
    seen: Rc<RefCell<Option<Vec<u8>>>>,
}

impl Provider for Introspecting {
    fn name(&self) -> &'static str {
        "introspecting"
    }
    fn methods(&self) -> Vec<String> {
        vec!["snapshot".to_string()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        if let Some(agent) = self.agent.borrow().as_ref() {
            *self.seen.borrow_mut() = Some(agent.intro()?);
        }
        Ok(Response::Value(Value::text("ok")))
    }
}

/// Drains its notifications by consulting the agent, which the kernel must not
/// do under a borrow.
struct DropConsulting {
    agent: AgentSlot,
}

impl Provider for DropConsulting {
    fn name(&self) -> &'static str {
        "drops"
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
    fn take_drop_notifications(&mut self) -> Vec<(u64, active_rpc::cap::CapId)> {
        if let Some(agent) = self.agent.borrow().as_ref() {
            // A borrow held by the kernel here would panic.
            let _ = agent.intro();
        }
        Vec::new()
    }
}

#[test]
fn a_drop_drain_does_not_reborrow_the_kernel() {
    let agent = Agent::new();
    let slot: AgentSlot = Rc::new(RefCell::new(Some(agent.clone())));
    let id = agent
        .register(Box::new(DropConsulting {
            agent: Rc::clone(&slot),
        }))
        .expect("register provider");
    assert!(agent.take_drops(id).is_empty());
    // The provider is back in the registry.
    agent
        .mint(id, 0, CapAttrs::new(&["noop"]))
        .expect("the provider is registered");
}

#[test]
fn an_intro_runs_no_provider_code_and_keeps_queued_work() {
    let agent = Agent::new();
    let slot: AgentSlot = Rc::new(RefCell::new(None));
    let calls = Rc::new(Cell::new(0));
    let armed = Rc::new(Cell::new(false));
    let id = agent
        .register(Box::new(Counting {
            agent: Rc::clone(&slot),
            calls: Rc::clone(&calls),
            armed: Rc::clone(&armed),
        }))
        .expect("register provider");
    *slot.borrow_mut() = Some(agent.clone());
    assert_eq!(calls.get(), 1, "the surface is described once, at register");

    let lane = agent.create_lane("intro", Budget::default()).expect("lane");
    let cap = agent.mint(id, 0, CapAttrs::new(&["ping"])).expect("cap");
    let queued = agent.call(lane, &cap, "ping", Vec::new()).expect("queued");

    // If `intro()` described the provider again, this re-entry would run the
    // kernel with an empty provider table and fail the queued call.
    armed.set(true);
    agent.intro().expect("intro");
    armed.set(false);

    assert_eq!(
        calls.get(),
        1,
        "an introspection must not run provider code"
    );
    agent.run();
    assert_eq!(
        queued.value().expect("the queued call still runs"),
        Value::text("ok"),
        "an introspection must not disturb queued work"
    );
}

#[test]
fn a_call_does_not_panic_when_the_provider_methods_consults_the_agent() {
    let agent = Agent::new();
    let slot: AgentSlot = Rc::new(RefCell::new(Some(agent.clone())));
    let calls = Rc::new(Cell::new(0));
    let id = agent
        .register(Box::new(Reentrant {
            agent: Rc::clone(&slot),
            calls: Rc::clone(&calls),
        }))
        .expect("register provider");
    let lane = agent.create_lane("call", Budget::default()).expect("lane");
    let cap = agent.mint(id, 0, CapAttrs::new(&["ping"])).expect("cap");
    let promise = agent
        .call(lane, &cap, "ping", Vec::new())
        .expect("a provider that consults the agent must not panic the call path");
    agent.run();
    assert_eq!(promise.value().expect("resolved"), Value::text("ok"));
    assert_eq!(
        calls.get(),
        1,
        "the call path reads the captured surface instead of describing the provider"
    );
}

#[test]
fn the_declared_surface_is_the_one_enforced() {
    let agent = Agent::new();
    let grow = Rc::new(Cell::new(false));
    let id = agent
        .register(Box::new(Shifting {
            grow: Rc::clone(&grow),
            a_mutates: Rc::new(Cell::new(false)),
        }))
        .expect("register provider");
    let lane = agent
        .create_lane("surface", Budget::default())
        .expect("lane");
    let cap = agent
        .mint(id, 0, CapAttrs::new(&["a", "b"]))
        .expect("cap grants both");
    grow.set(true);
    assert_eq!(
        agent
            .call(lane, &cap, "b", Vec::new())
            .expect_err("a method added after registration is not admitted")
            .code(),
        "rpc/method-not-granted"
    );
    let promise = agent
        .call(lane, &cap, "a", Vec::new())
        .expect("a method in the captured surface is admitted");
    agent.run();
    promise.value().expect("resolved");
}

#[test]
fn the_mutating_facts_are_the_ones_enforced() {
    let agent = Agent::new();
    let lane = agent
        .create_lane("read-only", Budget::default())
        .expect("lane");

    // Registered as non-mutating, then flipped: a read-only capability still
    // admits the call, because the surface was captured at registration.
    let flip = Rc::new(Cell::new(false));
    let first = agent
        .register(Box::new(Shifting {
            grow: Rc::new(Cell::new(false)),
            a_mutates: Rc::clone(&flip),
        }))
        .expect("register provider");
    let mut attrs = CapAttrs::new(&["a"]);
    attrs.read_only = true;
    let read_only = agent.mint(first, 0, attrs).expect("read-only cap");
    flip.set(true);
    let promise = agent
        .call(lane, &read_only, "a", Vec::new())
        .expect("the captured facts say non-mutating");
    agent.run();
    promise.value().expect("resolved");

    // The mirror: registered as mutating, then flipped back.
    let flip = Rc::new(Cell::new(true));
    let second = agent
        .register(Box::new(Shifting {
            grow: Rc::new(Cell::new(false)),
            a_mutates: Rc::clone(&flip),
        }))
        .expect("register provider");
    let mut attrs = CapAttrs::new(&["a"]);
    attrs.read_only = true;
    let read_only = agent.mint(second, 0, attrs).expect("read-only cap");
    flip.set(false);
    assert_eq!(
        agent
            .call(lane, &read_only, "a", Vec::new())
            .expect_err("the captured facts say mutating")
            .code(),
        "rpc/read-only"
    );
}

#[test]
fn an_intro_from_a_provider_lists_the_whole_surface() {
    let agent = Agent::new();
    let slot: AgentSlot = Rc::new(RefCell::new(None));
    let seen = Rc::new(RefCell::new(None));
    let id = agent
        .register(Box::new(Introspecting {
            agent: Rc::clone(&slot),
            seen: Rc::clone(&seen),
        }))
        .expect("register provider");
    *slot.borrow_mut() = Some(agent.clone());
    agent.register(Box::new(Echo)).expect("register provider");
    let lane = agent.create_lane("facts", Budget::default()).expect("lane");
    let cap = agent
        .mint(id, 0, CapAttrs::new(&["snapshot"]))
        .expect("cap");
    let promise = agent
        .call(lane, &cap, "snapshot", Vec::new())
        .expect("queued");
    agent.run();
    promise.value().expect("resolved");
    let from_inside = seen.borrow().clone().expect("the provider took a snapshot");
    assert_eq!(
        from_inside,
        agent.intro().expect("host intro"),
        "an introspection from a dispatch must list every provider"
    );
}
