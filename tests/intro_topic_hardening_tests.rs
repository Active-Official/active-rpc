//! Hardening of introduction and pub/sub (R-17): a lane can only read what it
//! subscribed to, publishing is an explicit grant that attenuation cannot add,
//! a topic is bounded text, and an introduction is canonical whatever order the
//! caller used.

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, Error};

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
        Ok(Response::Value(Value::Text(call.method.clone())))
    }
}

fn fixture() -> (Agent, active_rpc::CapHandle, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x6a; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).allow_publish())
        .expect("mint");
    let lane = agent.create_lane("topic", Budget::default()).expect("lane");
    (agent, cap, lane)
}

// ---------------------------------------------------------------------------
// T1: reading a channel is a subscription
// ---------------------------------------------------------------------------

#[test]
fn a_lane_that_did_not_subscribe_cannot_read_a_channel() {
    let (agent, cap, reader) = fixture();
    let stranger = agent
        .create_lane("stranger", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("private", Direction::Both)
        .expect("channel");
    agent.subscribe(reader, channel).expect("subscribe");
    agent
        .publish(reader, channel, &cap, "news", Value::text("secret"))
        .expect("publish");

    // The stranger holds a channel id and nothing else. The refusal is the same
    // as an unknown channel, so the id is not a membership oracle.
    let error = agent
        .recv(stranger, channel)
        .expect_err("a non-subscriber cannot drain the channel");
    assert_eq!(error.code(), "rpc/unknown-channel");

    // The message is still there for the lane that subscribed.
    let message = agent
        .recv_topic(reader, channel, "news")
        .expect("recv")
        .expect("message");
    assert_eq!(message.payload, Value::text("secret"));
}

// ---------------------------------------------------------------------------
// T3: publishing is a grant of its own
// ---------------------------------------------------------------------------

#[test]
fn publishing_requires_an_explicit_grant() {
    let agent = Agent::with_secret([0x6b; 32]);
    let provider = agent.register(Box::new(Echo));
    // A capability for a provider is not a licence to speak on a channel.
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let lane = agent.create_lane("plain", Budget::default()).expect("lane");
    let channel = agent.create_channel("c", Direction::Both).expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");

    let error = agent
        .publish(lane, channel, &cap, "news", Value::text("x"))
        .expect_err("a capability without the grant cannot publish");
    assert_eq!(error.code(), "rpc/method-not-granted");
}

#[test]
fn attenuation_cannot_add_the_publish_grant() {
    let agent = Agent::with_secret([0x6c; 32]);
    let provider = agent.register(Box::new(Echo));
    let parent = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let error = agent
        .attenuate(&parent, CapAttrs::new(&["echo"]).allow_publish())
        .expect_err("a child cannot add publishing");
    assert!(matches!(error, Error::Escalation(_)), "{error:?}");
}

// ---------------------------------------------------------------------------
// T4: the topic is bounded, printable text
// ---------------------------------------------------------------------------

#[test]
fn a_topic_must_be_bounded_and_printable() {
    let (agent, cap, lane) = fixture();
    let channel = agent
        .create_channel("topics", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");

    for topic in ["", "x".repeat(200).as_str(), "line\nbreak"] {
        let error = agent
            .publish(lane, channel, &cap, topic, Value::text("x"))
            .expect_err("an unrepresentable topic is refused");
        assert_eq!(error.code(), "rpc/invalid-argument", "topic {topic:?}");
    }
    // The grant-time check refuses the same names, so a capability cannot be
    // minted for a topic the channel would reject.
    let provider = agent.register(Box::new(Echo));
    let error = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["echo"]).restrict_topics(&["bad\ntopic"]),
        )
        .expect_err("an unprintable topic cannot be granted");
    assert_eq!(error.code(), "rpc/invalid-argument");
}

// ---------------------------------------------------------------------------
// T6/T9: the introduction is canonical and printable
// ---------------------------------------------------------------------------

#[test]
fn an_introduction_is_canonical_whatever_order_the_caller_used() {
    let budget = Budget::default();
    let ordered = active_rpc::intro::build(
        "peer-a",
        &[
            (
                "alpha".to_string(),
                vec!["one".to_string(), "two".to_string()],
            ),
            ("beta".to_string(), vec!["three".to_string()]),
        ],
        &budget,
    )
    .expect("build");
    let shuffled = active_rpc::intro::build(
        "peer-a",
        &[
            ("beta".to_string(), vec!["three".to_string()]),
            (
                "alpha".to_string(),
                vec!["two".to_string(), "one".to_string()],
            ),
        ],
        &budget,
    )
    .expect("build");
    assert_eq!(
        ordered, shuffled,
        "provider and method order must not matter"
    );

    // A duplicate method is the same surface, so it is the same bytes.
    let duplicated = active_rpc::intro::build(
        "peer-a",
        &[(
            "alpha".to_string(),
            vec!["one".to_string(), "one".to_string()],
        )],
        &budget,
    )
    .expect("build");
    let single = active_rpc::intro::build(
        "peer-a",
        &[("alpha".to_string(), vec!["one".to_string()])],
        &budget,
    )
    .expect("build");
    assert_eq!(
        duplicated, single,
        "a duplicate method is not a new surface"
    );
}

#[test]
fn an_introduction_refuses_an_unprintable_name() {
    let budget = Budget::default();
    for (peer, providers) in [
        ("bad\npeer", vec![]),
        ("peer", vec![("bad\nprovider".to_string(), vec![])]),
        (
            "peer",
            vec![("p".to_string(), vec!["bad\nmethod".to_string()])],
        ),
        ("", vec![]),
    ] {
        let error = active_rpc::intro::build(peer, &providers, &budget)
            .expect_err("an unprintable name is refused");
        assert_eq!(error.code(), "rpc/invalid-argument", "{peer:?}");
    }
}
