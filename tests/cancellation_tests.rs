//! C-5.2 cancellation trees for pipelined promises.

use active_rpc::budget::Budget;
use active_rpc::cap::CapAttrs;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Provider};

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
    let agent = Agent::with_secret([0x33; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("cancel", Budget::default())
        .expect("lane");
    (agent, cap, lane)
}

#[test]
fn cancelling_the_head_cancels_every_dependent() {
    let (agent, cap, lane) = setup();
    let head = agent
        .call(lane, &cap, "echo", vec![Arg::text("head")])
        .expect("head");
    let middle = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(head.id())])
        .expect("middle");
    let tail = agent
        .call(lane, &cap, "echo", vec![Arg::Promise(middle.id())])
        .expect("tail");
    let unrelated = agent
        .call(lane, &cap, "echo", vec![Arg::text("unrelated")])
        .expect("unrelated");

    let cancelled = agent.cancel_tree(&head).expect("cancel tree");
    assert_eq!(cancelled.len(), 3);
    assert!(cancelled.contains(&head.id()));
    assert!(cancelled.contains(&middle.id()));
    assert!(cancelled.contains(&tail.id()));
    assert_eq!(head.value().unwrap_err().code(), "rpc/promise-cancelled");
    assert_eq!(middle.value().unwrap_err().code(), "rpc/promise-cancelled");
    assert_eq!(tail.value().unwrap_err().code(), "rpc/promise-cancelled");
    assert_eq!(
        unrelated.value().expect("unrelated"),
        Value::text("unrelated")
    );
}

#[test]
fn a_settled_head_is_refused() {
    let (agent, cap, lane) = setup();
    let promise = agent
        .call(lane, &cap, "echo", vec![Arg::text("done")])
        .expect("call");
    promise.value().expect("value");
    assert_eq!(
        agent.cancel_tree(&promise).unwrap_err().code(),
        "rpc/promise-resolved"
    );
}
