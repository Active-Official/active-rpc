//! THROWAWAY probes for the R-04 audit. Delete after use.

use std::cell::Cell;
use std::rc::Rc;

use active_rpc::budget::Budget;
use active_rpc::cap::CapAttrs;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Envelope, Provider};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }
    fn methods(&self) -> Vec<String> {
        vec!["echo".into()]
    }
    fn mutating(&self, _method: &str) -> bool {
        false
    }
    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
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

fn setup() -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x71; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("l", Budget::default()).expect("lane");
    (agent, cap, lane)
}

#[test]
fn probe_cross_lane_promise_capture() {
    let (agent, cap, lane_a) = setup();
    let lane_b = agent.create_lane("victim", Budget::default()).unwrap();

    let secretish = agent
        .call(lane_a, &cap, "echo", vec![Arg::text("tenant-A-secret")])
        .expect("call");
    let stolen = agent
        .call(lane_b, &cap, "echo", vec![Arg::Promise(secretish.id())])
        .expect("lane B references lane A promise");
    let value = stolen.value().expect("value");
    println!("PROBE cross-lane value = {value:?}");
    assert_eq!(value, Value::text("tenant-A-secret"));
}

#[test]
fn probe_wire_promise_arg_from_peer() {
    let (agent, cap, lane_a) = setup();
    let lane_b = agent.create_lane("peer", Budget::default()).unwrap();
    let p = agent
        .call(lane_a, &cap, "echo", vec![Arg::text("tenant-A-secret")])
        .expect("call");
    agent.run();

    let bytes = Envelope::request(7, "echo", vec![Arg::Promise(p.id())])
        .encode()
        .unwrap();
    let decoded = Envelope::decode(&bytes).expect("decodes");
    println!("PROBE decoded args = {:?}", decoded.args);
    let far = agent
        .call_as(None, lane_b, &cap, &decoded.method, decoded.args.clone())
        .expect("peer promise arg accepted");
    let value = far.value().expect("value");
    println!("PROBE wire value = {value:?}");
    assert_eq!(value, Value::text("tenant-A-secret"));
}

struct Counting {
    calls: Rc<Cell<usize>>,
}

impl Provider for Counting {
    fn name(&self) -> &'static str {
        "counting"
    }
    fn methods(&self) -> Vec<String> {
        vec!["mutate".into()]
    }
    fn mutating(&self, _method: &str) -> bool {
        true
    }
    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        self.calls.set(self.calls.get() + 1);
        Ok(Response::Value(Value::Bool(true)))
    }
}

#[test]
fn probe_idempotent_replay_after_trim_reexecutes() {
    let agent = Agent::with_secret([0x72; 32]);
    let calls = Rc::new(Cell::new(0));
    let provider = agent.register(Box::new(Counting {
        calls: calls.clone(),
    }));
    let wide = Budget {
        max_calls: 100_000,
        ..Budget::default()
    };
    let mut attrs = CapAttrs::new(&["mutate"]);
    attrs.budget = wide;
    let cap = agent.mint(provider, 0, attrs).unwrap();
    let lane = agent.create_lane("idem", wide).unwrap();

    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-1")
        .expect("first");
    first.value().expect("value");
    assert_eq!(calls.get(), 1);
    let first_id = first.id();
    drop(first);

    for _ in 0..1_500 {
        agent
            .call(lane, &cap, "mutate", vec![])
            .expect("filler")
            .value()
            .expect("filler value");
    }
    println!("PROBE promise_count after churn = {}", agent.promise_count());
    println!(
        "PROBE first promise still known = {}",
        active_rpc::kernel::promise_state(&agent, first_id).is_some()
    );

    let replay = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-1")
        .expect("replay accepted");
    replay.value().expect("replay value");
    println!("PROBE provider invocations = {}", calls.get());
    println!("PROBE ids {} vs {}", first_id, replay.id());
    println!("PROBE re-executed = {}", calls.get() > 1501);
}

#[test]
fn probe_idempotent_replay_on_closed_lane() {
    let agent = Agent::with_secret([0x73; 32]);
    let calls = Rc::new(Cell::new(0));
    let provider = agent.register(Box::new(Counting {
        calls: calls.clone(),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["mutate"]))
        .unwrap();
    let lane = agent.create_lane("idem", Budget::default()).unwrap();
    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "k")
        .expect("first");
    first.value().expect("value");
    agent.destroy_lane(lane).expect("destroy");

    let replay = agent.call_idempotent(lane, &cap, "mutate", vec![], "k");
    println!("PROBE closed-lane replay = {:?}", replay.as_ref().map(|p| p.id()));
    assert!(replay.is_ok(), "a destroyed lane replayed a cached result");

    let unknown = agent.call_idempotent(active_rpc::LaneId(9_999), &cap, "mutate", vec![], "k");
    println!(
        "PROBE unknown-lane replay = {:?}",
        unknown.as_ref().map(|p| p.id())
    );
    assert!(unknown.is_ok(), "an unknown lane replayed a cached result");
}

#[test]
fn probe_cancel_own_promise_during_dispatch() {
    struct SelfCancel {
        agent: Agent,
        slot: Rc<std::cell::RefCell<Option<active_rpc::PromiseHandle>>>,
        observed: Rc<std::cell::RefCell<Option<String>>>,
    }

    impl Provider for SelfCancel {
        fn name(&self) -> &'static str {
            "selfcancel"
        }
        fn methods(&self) -> Vec<String> {
            vec!["work".into()]
        }
        fn mutating(&self, _method: &str) -> bool {
            true
        }
        fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
            let handle = self.slot.borrow_mut().take();
            if let Some(handle) = handle {
                let outcome = self.agent.cancel(&handle);
                *self.observed.borrow_mut() = Some(format!("{outcome:?}"));
            }
            Ok(Response::Value(Value::text("side-effect")))
        }
    }

    let agent = Agent::with_secret([0x74; 32]);
    let slot = Rc::new(std::cell::RefCell::new(None));
    let observed = Rc::new(std::cell::RefCell::new(None));
    let provider = agent.register(Box::new(SelfCancel {
        agent: agent.clone(),
        slot: slot.clone(),
        observed: observed.clone(),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["work"]))
        .unwrap();
    let lane = agent.create_lane("s", Budget::default()).unwrap();
    let promise = agent.call(lane, &cap, "work", vec![]).expect("call");
    *slot.borrow_mut() = Some(promise.clone());
    let value = promise.value();
    let lane_state = agent.lane(lane).unwrap();
    println!("PROBE provider ran, caller sees {:?}", value.as_ref().map_err(|e| e.code()));
    println!(
        "PROBE cancel outcome = {:?}, lane pending={} completed={}",
        observed.borrow(),
        lane_state.pending,
        lane_state.completed
    );
    println!(
        "PROBE metrics resolved={} rejected={} double={} events_tail={:?}",
        agent.metrics().promises_resolved,
        agent.metrics().promises_rejected,
        agent.metrics().promises_double_settled,
        agent
            .events()
            .iter()
            .filter(|event| matches!(event, active_rpc::Event::PromiseResolved(_)))
            .count()
    );
}

#[test]
fn probe_cancel_tree_scaling() {
    use std::time::Instant;

    for depth in [1_000usize, 2_000, 4_000] {
        let (agent, _cap, _lane) = setup();
        let wide = Budget {
            max_calls: 100_000,
            ..Budget::default()
        };
        let provider = agent.register(Box::new(Echo));
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.budget = wide;
        let cap = agent.mint(provider, 0, attrs).unwrap();
        let lane = agent.create_lane("chain", wide).unwrap();
        let head = agent.call(lane, &cap, "echo", vec![Arg::text("h")]).unwrap();
        let mut prev = head.id();
        for _ in 0..depth {
            let next = agent
                .call(lane, &cap, "echo", vec![Arg::Promise(prev)])
                .unwrap();
            prev = next.id();
        }
        let started = Instant::now();
        let cancelled = agent.cancel_tree(&head).expect("cancel tree");
        println!(
            "PROBE cancel_tree depth={} cancelled={} elapsed={:?}",
            depth,
            cancelled.len(),
            started.elapsed()
        );
    }
}

#[test]
fn probe_batch_order_scaling() {
    use std::time::Instant;

    for queued in [5_000usize, 10_000, 20_000] {
        let agent = Agent::with_secret([0x75; 32]);
        let provider = agent.register(Box::new(Echo));
        let wide = Budget {
            max_calls: 100_000,
            ..Budget::default()
        };
        let mut attrs = CapAttrs::new(&["echo"]);
        attrs.budget = wide;
        let cap = agent.mint(provider, 0, attrs).unwrap();
        let lane = agent.create_lane("q", wide).unwrap();
        for _ in 0..queued {
            agent
                .call(lane, &cap, "echo", vec![Arg::text("x")])
                .expect("queue");
        }
        let started = Instant::now();
        let trips = agent.run();
        println!(
            "PROBE batch size={} round_trips={} elapsed={:?}",
            queued,
            trips,
            started.elapsed()
        );
    }
}
