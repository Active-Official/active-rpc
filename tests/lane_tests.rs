//! R-05 lanes and channels: lifecycle, capacity, accounting and the boundary a
//! lane does and does not draw.
//!
//! Every test here fails against the tree before its fix.

use active_rpc::cap::CapAttrs;
use active_rpc::channel::{Direction, MAX_QUEUED_BYTES};
use active_rpc::kernel::{Provider, MAX_OBJECT_NAME_BYTES};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget};

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

fn agent() -> (Agent, active_rpc::ProviderId) {
    let agent = Agent::with_secret([0x61; 32]);
    let provider = agent.register(Box::new(Echo));
    (agent, provider)
}

/// Destroying a lane with a full queue must not scan the queue per job.
#[test]
fn destroying_a_full_lane_does_not_block_the_kernel() {
    let (agent, provider) = agent();
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).with_budget(Budget {
                max_calls: 50_000,
                max_bytes: u64::MAX,
                ..Budget::default()
            }),
        )
        .expect("cap");
    let busy = agent
        .create_lane(
            "busy",
            Budget {
                max_calls: 50_000,
                max_bytes: u64::MAX,
                ..Budget::default()
            },
        )
        .expect("lane");
    let other = agent.create_lane("other", Budget::default()).expect("lane");
    for _ in 0..40_000 {
        agent.call(busy, &cap, "echo", Vec::new()).expect("queued");
    }
    let start = std::time::Instant::now();
    agent.destroy_lane(busy).expect("destroy");
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "destroying a full lane took {elapsed:?}"
    );
    // The rest of the kernel still works.
    let promise = agent.call(other, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
}

/// A publish the channel would refuse must not spend the grant.
#[test]
fn a_publish_refused_on_a_full_channel_charges_nothing() {
    let (agent, provider) = agent();
    let channel = agent
        .create_channel("full", Direction::Both)
        .expect("channel");
    let lane = agent
        .create_lane(
            "fill",
            Budget {
                max_bytes: u64::MAX,
                // The filler is one 64 MiB message, so the per-value ceiling
                // has to allow it: this test is about the channel's byte
                // ceiling, not the shape ceilings.
                max_value_size: u64::MAX,
                ..Budget::default()
            },
        )
        .expect("lane");
    // Fill the channel to its byte ceiling with one message.
    // A text value costs its tag, a length prefix and its bytes: the message
    // fills the channel exactly.
    let filler = Value::text("x".repeat(MAX_QUEUED_BYTES as usize - 5));
    agent
        .send(lane, channel, filler, &[])
        .expect("the ceiling itself fits");
    let mut attrs = CapAttrs::new(&["echo"]).allow_publish();
    attrs.budget.max_bytes = 16;
    attrs.budget.max_calls = 1;
    let cap = agent.mint(provider, 0, attrs).expect("small cap");
    let publish_lane = agent.create_lane("pub", Budget::default()).expect("lane");
    agent.subscribe(publish_lane, channel).expect("subscribe");
    let error = agent
        .publish(publish_lane, channel, &cap, "t", Value::text("0123456789"))
        .expect_err("the channel is full");
    assert_eq!(error.code(), "rpc/backpressure", "{error}");

    // Drain, then the same grant still works: the refusal charged nothing.
    agent
        .recv(publish_lane, channel)
        .expect("recv")
        .expect("message");
    agent
        .publish(publish_lane, channel, &cap, "t", Value::text("0123456789"))
        .expect("the grant survived the refusal");
}

/// Closing a channel through the agent stops sends; a snapshot cannot.
#[test]
fn closing_a_channel_stops_sends() {
    let (agent, _provider) = agent();
    let channel = agent
        .create_channel("closable", Direction::Both)
        .expect("channel");
    let lane = agent
        .create_lane("closer", Budget::default())
        .expect("lane");
    agent.close_channel(channel).expect("close");
    let error = agent
        .send(lane, channel, Value::text("x"), &[])
        .expect_err("a closed channel refuses sends");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A lane is a budget scope, not an authority boundary: authority lives on the
/// capability.
#[test]
fn a_lane_is_not_an_authority_boundary() {
    let (agent, provider) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let first = agent.create_lane("first", Budget::default()).expect("lane");
    let second = agent
        .create_lane("second", Budget::default())
        .expect("lane");
    let promise = agent.call(first, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
    // The same capability works from another lane: a lane does not own caps.
    let promise = agent.call(second, &cap, "echo", Vec::new()).expect("call");
    agent.run();
    promise.value().expect("value");
}

/// One message transfers one reference per capability.
#[test]
fn a_message_cannot_transfer_the_same_capability_twice() {
    let (agent, provider) = agent();
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("dup", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("dup", Direction::Both)
        .expect("channel");
    let error = agent
        .send(lane, channel, Value::text("x"), &[cap.clone(), cap.clone()])
        .expect_err("the same capability twice is not a transfer");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    agent
        .send(lane, channel, Value::text("x"), &[cap])
        .expect("one transfer");
    assert_eq!(agent.metrics().transfers, 1);
}

/// Names and subscriptions are bounded.
#[test]
fn names_and_subscriptions_are_bounded() {
    let (agent, _provider) = agent();
    let long = "n".repeat(MAX_OBJECT_NAME_BYTES + 1);
    let error = agent
        .create_channel(long.clone(), Direction::Both)
        .expect_err("a channel name is bounded");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
    let error = agent
        .create_lane(long, Budget::default())
        .expect_err("a lane name is bounded");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A send is lane traffic: it consumes the lane's byte budget and a call.
#[test]
fn a_send_is_lane_traffic() {
    let (agent, _provider) = agent();
    let lane = agent
        .create_lane(
            "tight",
            Budget {
                max_bytes: 32,
                max_calls: 1,
                ..Budget::default()
            },
        )
        .expect("lane");
    let channel = agent
        .create_channel("tight", Direction::Both)
        .expect("channel");
    agent
        .send(lane, channel, Value::text("first"), &[])
        .expect("within the grant");
    let error = agent
        .send(lane, channel, Value::text("second"), &[])
        .expect_err("the lane call budget is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    let state = agent.lane(lane).expect("lane");
    assert_eq!(state.completed, 1);
    assert_eq!(state.pending, 0);
}

/// A destroyed channel releases its queued accounting, so the next channel can
/// use the full budget.
#[test]
fn a_destroyed_channel_releases_its_bytes() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("churn", Budget::default()).expect("lane");
    let first = agent
        .create_channel("first", Direction::Both)
        .expect("channel");
    let value = Value::text("y".repeat(1 << 20));
    agent.send(lane, first, value.clone(), &[]).expect("send");
    agent.destroy_channel(first).expect("destroy");
    let second = agent
        .create_channel("second", Direction::Both)
        .expect("channel");
    agent
        .send(lane, second, value, &[])
        .expect("send after destroy");
}

/// A refusal is counted, and the counter is not a queue length.
#[test]
fn refusals_are_counted() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("refuse", Budget::calls(1)).expect("lane");
    let channel = agent
        .create_channel("refuse", Direction::Both)
        .expect("channel");
    agent
        .send(lane, channel, Value::text("one"), &[])
        .expect("first");
    let before = agent.metrics().calls_refused;
    let error = agent
        .send(lane, channel, Value::text("two"), &[])
        .expect_err("the lane budget is spent");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    assert_eq!(
        agent.metrics().calls_refused,
        before + 1,
        "a refused send is not counted"
    );
}

/// Guard: the channel byte counter is exposed and exact.
#[test]
fn channel_bytes_are_exact() {
    let (agent, _provider) = agent();
    let lane = agent.create_lane("exact", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("exact", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");
    let value = Value::text("payload");
    let size = value.wire_size();
    agent.send(lane, channel, value, &[]).expect("send");
    assert_eq!(agent.channel(channel).expect("channel").queued_bytes, size);
    agent.recv(lane, channel).expect("recv").expect("message");
    assert_eq!(agent.channel(channel).expect("channel").queued_bytes, 0);
}
