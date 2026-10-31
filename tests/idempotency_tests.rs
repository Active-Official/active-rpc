//! C-5.4 idempotency keys on the shipped call path.

use std::cell::Cell;
use std::rc::Rc;

use active_rpc::budget::Budget;
use active_rpc::cap::CapAttrs;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Provider};

struct Counting {
    calls: Rc<Cell<usize>>,
    fail_next: Rc<Cell<bool>>,
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
        if self.fail_next.replace(false) {
            return Err(active_rpc::Error::Provider {
                code: "test/transient".into(),
            });
        }
        Ok(Response::Value(Value::Bool(true)))
    }
}

fn setup() -> (
    Agent,
    active_rpc::CapHandle,
    active_rpc::LaneId,
    Rc<Cell<usize>>,
    Rc<Cell<bool>>,
) {
    let agent = Agent::with_secret([0x55; 32]);
    let calls = Rc::new(Cell::new(0));
    let fail_next = Rc::new(Cell::new(false));
    let provider = agent.register(Box::new(Counting {
        calls: calls.clone(),
        fail_next: fail_next.clone(),
    }));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["mutate"]))
        .expect("cap");
    let lane = agent.create_lane("idem", Budget::default()).expect("lane");
    (agent, cap, lane, calls, fail_next)
}

#[test]
fn the_same_key_returns_the_same_promise_and_runs_once() {
    let (agent, cap, lane, calls, _) = setup();
    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-1")
        .expect("first");
    let second = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-1")
        .expect("second");
    assert_eq!(first.id(), second.id());
    agent.run();
    assert_eq!(first.value().expect("value"), Value::Bool(true));
    assert_eq!(calls.get(), 1);

    let third = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "order-2")
        .expect("third");
    agent.run();
    third.value().expect("value");
    assert_eq!(calls.get(), 2);
}

#[test]
fn a_failed_attempt_is_not_cached() {
    let (agent, cap, lane, calls, fail_next) = setup();
    fail_next.set(true);
    let first = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "retry")
        .expect("first");
    assert_eq!(first.value().unwrap_err().code(), "rpc/provider");
    let second = agent
        .call_idempotent(lane, &cap, "mutate", vec![], "retry")
        .expect("second");
    agent.run();
    second.value().expect("retry succeeds");
    assert_eq!(calls.get(), 2);
}

#[test]
fn an_empty_key_is_refused() {
    let (agent, cap, lane, _, _) = setup();
    assert_eq!(
        agent
            .call_idempotent(lane, &cap, "mutate", vec![Arg::text("x")], "")
            .unwrap_err()
            .code(),
        "rpc/invalid-argument"
    );
}
