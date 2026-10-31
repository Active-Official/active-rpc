//! Capability-filtered pub/sub topics on channels.

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::kernel::Provider;
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, LaneId};

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

struct Fixture {
    agent: Agent,
    provider: active_rpc::ProviderId,
    lane: LaneId,
}

fn fixture() -> Fixture {
    let agent = Agent::with_secret([0x7e; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent
        .create_lane("topics", Budget::default())
        .expect("lane");
    Fixture {
        agent,
        provider,
        lane,
    }
}

fn cap(fixture: &Fixture, attrs: CapAttrs) -> CapHandle {
    fixture
        .agent
        .mint(fixture.provider, 0, attrs)
        .expect("mint")
}

#[test]
fn an_unrestricted_capability_publishes_any_topic() {
    let fixture = fixture();
    let cap = cap(&fixture, CapAttrs::new(&["echo"]));
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    fixture
        .agent
        .publish(fixture.lane, channel, &cap, "alerts", Value::text("hi"))
        .expect("publish");
    let message = fixture
        .agent
        .recv_topic(channel, "alerts")
        .expect("recv")
        .expect("message");
    assert_eq!(message.topic.as_deref(), Some("alerts"));
    assert_eq!(message.payload, Value::text("hi"));
}

#[test]
fn a_topic_outside_the_capability_is_refused() {
    let fixture = fixture();
    let cap = cap(
        &fixture,
        CapAttrs::new(&["echo"]).restrict_topics(&["a", "b"]),
    );
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    fixture
        .agent
        .publish(fixture.lane, channel, &cap, "a", Value::text("ok"))
        .expect("allowed topic");
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &cap, "c", Value::text("no"))
        .expect_err("topic outside the set");
    assert_eq!(error.code(), "rpc/topic-not-granted");
}

#[test]
fn attenuation_narrows_the_topic_set() {
    let fixture = fixture();
    let parent = cap(
        &fixture,
        CapAttrs::new(&["echo"]).restrict_topics(&["a", "b"]),
    );
    let child = fixture
        .agent
        .attenuate(&parent, CapAttrs::new(&["echo"]).restrict_topics(&["a"]))
        .expect("narrowed child");
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    fixture
        .agent
        .publish(fixture.lane, channel, &child, "a", Value::text("child"))
        .expect("child topic");
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &child, "b", Value::text("no"))
        .expect_err("the child dropped b");
    assert_eq!(error.code(), "rpc/topic-not-granted");
    // The parent still publishes b.
    fixture
        .agent
        .publish(fixture.lane, channel, &parent, "b", Value::text("parent"))
        .expect("parent topic");
}

#[test]
fn attenuation_cannot_widen_or_drop_the_topic_set() {
    let fixture = fixture();
    let parent = cap(&fixture, CapAttrs::new(&["echo"]).restrict_topics(&["a"]));
    let wider = fixture.agent.attenuate(
        &parent,
        CapAttrs::new(&["echo"]).restrict_topics(&["a", "b"]),
    );
    assert!(
        matches!(wider, Err(active_rpc::Error::Escalation(_))),
        "{wider:?}"
    );
    let unrestricted = fixture.agent.attenuate(&parent, CapAttrs::new(&["echo"]));
    assert!(
        matches!(unrestricted, Err(active_rpc::Error::Escalation(_))),
        "{unrestricted:?}"
    );
    // An unrestricted parent may be narrowed.
    let root = cap(&fixture, CapAttrs::new(&["echo"]));
    fixture
        .agent
        .attenuate(&root, CapAttrs::new(&["echo"]).restrict_topics(&["a"]))
        .expect("narrowing an unrestricted parent");
}

#[test]
fn a_subscriber_receives_only_its_topic_and_others_stay_queued() {
    let fixture = fixture();
    let cap = cap(
        &fixture,
        CapAttrs::new(&["echo"]).restrict_topics(&["a", "b"]),
    );
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    for topic in ["a", "b", "a"] {
        fixture
            .agent
            .publish(fixture.lane, channel, &cap, topic, Value::text(topic))
            .expect("publish");
    }
    let first_b = fixture
        .agent
        .recv_topic(channel, "b")
        .expect("recv b")
        .expect("b message");
    assert_eq!(first_b.payload, Value::text("b"));
    // The two "a" messages remain, in order.
    let one = fixture.agent.recv(channel).expect("recv").expect("a");
    let two = fixture.agent.recv(channel).expect("recv").expect("a");
    assert_eq!(one.topic.as_deref(), Some("a"));
    assert_eq!(two.topic.as_deref(), Some("a"));
    assert!(fixture.agent.recv(channel).expect("empty").is_none());
}

#[test]
fn a_revoked_capability_cannot_publish() {
    let fixture = fixture();
    let cap = cap(&fixture, CapAttrs::new(&["echo"]));
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    fixture.agent.revoke(&cap);
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &cap, "a", Value::text("no"))
        .expect_err("revoked");
    assert_eq!(error.code(), "rpc/revoked");
    // Nothing was queued.
    assert!(fixture.agent.recv(channel).expect("recv").is_none());
}

#[test]
fn an_expired_capability_cannot_publish() {
    let fixture = fixture();
    fixture.agent.set_latency(100);
    let cap = cap(&fixture, CapAttrs::new(&["echo"]).with_ttl_ms(100));
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    // Advance the clock with one admitted call.
    let promise = fixture
        .agent
        .call(fixture.lane, &cap, "echo", Vec::new())
        .expect("call");
    fixture.agent.run();
    promise.value().expect("value");
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &cap, "a", Value::text("no"))
        .expect_err("expired");
    assert_eq!(error.code(), "rpc/revoked");
}

#[test]
fn a_capability_from_another_kernel_cannot_publish() {
    let fixture = fixture();
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    let other = Agent::with_secret([0x7f; 32]);
    let provider = other.register(Box::new(Echo));
    let foreign = other
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &foreign, "a", Value::text("no"))
        .expect_err("foreign cap");
    assert_eq!(error.code(), "rpc/unknown-capability");
}

#[test]
fn plain_send_and_recv_still_carry_no_topic() {
    let fixture = fixture();
    let channel = fixture
        .agent
        .create_channel("news", Direction::Both)
        .expect("channel");
    fixture
        .agent
        .send(fixture.lane, channel, Value::text("plain"), &[])
        .expect("send");
    let message = fixture.agent.recv(channel).expect("recv").expect("message");
    assert_eq!(message.topic, None);
    assert_eq!(message.payload, Value::text("plain"));
    let _ = Arg::text("unused");
    let _ = Budget::default();
}

#[test]
fn a_receive_only_channel_refuses_publishing() {
    let fixture = fixture();
    let cap = cap(&fixture, CapAttrs::new(&["echo"]));
    let channel = fixture
        .agent
        .create_channel("sink", Direction::Receive)
        .expect("channel");
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &cap, "a", Value::text("no"))
        .expect_err("receive-only");
    assert_eq!(error.code(), "rpc/invalid-argument");
}
