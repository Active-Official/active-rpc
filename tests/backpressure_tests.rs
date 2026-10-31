//! C-5.3 call-queue backpressure.

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
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::Null),
        ))
    }
}

#[test]
fn a_full_queue_refuses_the_next_call_and_counts_it() {
    let agent = Agent::with_secret([0x44; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("backpressure", Budget::default())
        .expect("lane");
    agent.set_queue_ceiling(3).expect("ceiling");
    assert_eq!(agent.queue_ceiling(), 3);

    let mut promises = Vec::new();
    for index in 0..3 {
        promises.push(
            agent
                .call(lane, &cap, "echo", vec![Arg::text(format!("{index}"))])
                .expect("queued"),
        );
    }
    let error = agent
        .call(lane, &cap, "echo", vec![Arg::text("over")])
        .expect_err("queue full");
    assert_eq!(error.code(), "rpc/backpressure");
    assert_eq!(agent.metrics().backpressure_refusals, 1);

    agent.run();
    for promise in promises {
        promise.value().expect("settled");
    }
    assert_eq!(agent.metrics().backpressure_refusals, 1);
}

#[test]
fn a_zero_ceiling_is_refused() {
    let agent = Agent::new();
    assert_eq!(
        agent.set_queue_ceiling(0).unwrap_err().code(),
        "rpc/invalid-argument"
    );
}

#[test]
fn a_full_channel_refuses_the_next_message() {
    use active_rpc::channel::Direction;
    use active_rpc::Value;

    let agent = Agent::new();
    let lane = agent
        .create_lane("channel", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("queue", Direction::Both)
        .expect("channel");
    agent.set_channel_queue_ceiling(2).expect("ceiling");
    assert_eq!(agent.channel_queue_ceiling(), 2);
    agent
        .send(lane, channel, Value::text("one"), &[])
        .expect("send");
    agent
        .send(lane, channel, Value::text("two"), &[])
        .expect("send");
    let error = agent
        .send(lane, channel, Value::text("three"), &[])
        .expect_err("full");
    assert_eq!(error.code(), "rpc/backpressure");
    assert_eq!(agent.metrics().backpressure_refusals, 1);
}
