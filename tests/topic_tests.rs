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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
    // Every capability in this file is a publishing grant: the tests vary the
    // topic set, not whether publishing is allowed at all.
    fixture
        .agent
        .mint(fixture.provider, 0, attrs.allow_publish())
        .expect("mint")
}

/// Create a channel and subscribe the fixture lane to it.
///
/// Receiving is a subscription: a lane that did not subscribe cannot drain a
/// channel, so every test that reads one subscribes here.
fn channel(fixture: &Fixture, name: &str) -> active_rpc::ChannelId {
    let channel = fixture
        .agent
        .create_channel(name, Direction::Both)
        .expect("channel");
    fixture
        .agent
        .subscribe(fixture.lane, channel)
        .expect("subscribe");
    channel
}

#[test]
fn an_unrestricted_capability_publishes_any_topic() {
    let fixture = fixture();
    let cap = cap(&fixture, CapAttrs::new(&["echo"]));
    let channel = channel(&fixture, "news");
    fixture
        .agent
        .publish(fixture.lane, channel, &cap, "alerts", Value::text("hi"))
        .expect("publish");
    let message = fixture
        .agent
        .recv_topic(fixture.lane, channel, "alerts")
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
    let channel = channel(&fixture, "news");
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
    let channel = channel(&fixture, "news");
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
fn the_empty_topic_set_is_the_narrowest_grant() {
    // `Some(empty)` is a subset of `Some(empty)`: attenuating it to itself is
    // not a widening, and the child still publishes nothing. This is the one
    // case where "same set" is a legal attenuation of a restricted grant.
    let fixture = fixture();
    let parent = cap(&fixture, CapAttrs::new(&["echo"]).restrict_topics(&[]));
    let child = fixture
        .agent
        .attenuate(&parent, CapAttrs::new(&["echo"]).restrict_topics(&[]))
        .expect("an empty set attenuated to itself");
    let channel = channel(&fixture, "empty");
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &child, "any", Value::text("x"))
        .expect_err("an empty topic grant publishes nothing");
    assert_eq!(error.code(), "rpc/topic-not-granted");
    // It still cannot be widened, though.
    let error = fixture
        .agent
        .attenuate(&child, CapAttrs::new(&["echo"]).restrict_topics(&["any"]))
        .expect_err("widening an empty set must be refused");
    assert_eq!(error.code(), "rpc/attenuation-escalation");
}

#[test]
fn a_subscriber_receives_only_its_topic_and_others_stay_queued() {
    let fixture = fixture();
    let cap = cap(
        &fixture,
        CapAttrs::new(&["echo"]).restrict_topics(&["a", "b"]),
    );
    let channel = channel(&fixture, "news");
    for topic in ["a", "b", "a"] {
        fixture
            .agent
            .publish(fixture.lane, channel, &cap, topic, Value::text(topic))
            .expect("publish");
    }
    let first_b = fixture
        .agent
        .recv_topic(fixture.lane, channel, "b")
        .expect("recv b")
        .expect("b message");
    assert_eq!(first_b.payload, Value::text("b"));
    // The two "a" messages remain, in order.
    let one = fixture
        .agent
        .recv(fixture.lane, channel)
        .expect("recv")
        .expect("a");
    let two = fixture
        .agent
        .recv(fixture.lane, channel)
        .expect("recv")
        .expect("a");
    assert_eq!(one.topic.as_deref(), Some("a"));
    assert_eq!(two.topic.as_deref(), Some("a"));
    assert!(fixture
        .agent
        .recv(fixture.lane, channel)
        .expect("empty")
        .is_none());
}

#[test]
fn a_revoked_capability_cannot_publish() {
    let fixture = fixture();
    let cap = cap(&fixture, CapAttrs::new(&["echo"]));
    let channel = channel(&fixture, "news");
    fixture.agent.revoke(&cap).expect("revoke");
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &cap, "a", Value::text("no"))
        .expect_err("revoked");
    assert_eq!(error.code(), "rpc/revoked");
    // Nothing was queued.
    assert!(fixture
        .agent
        .recv(fixture.lane, channel)
        .expect("recv")
        .is_none());
}

#[test]
fn an_expired_capability_cannot_publish() {
    let fixture = fixture();
    fixture.agent.set_latency(100);
    let cap = cap(&fixture, CapAttrs::new(&["echo"]).with_ttl_ms(100));
    let channel = channel(&fixture, "news");
    // Advance the clock past the deadline. The call is itself refused at
    // dispatch (the deadline is re-checked there), and the round trip still
    // moves the virtual clock to the expiry instant.
    let promise = fixture
        .agent
        .call(fixture.lane, &cap, "echo", Vec::new())
        .expect("queued");
    fixture.agent.run();
    assert_eq!(
        promise.value().expect_err("expired at dispatch").code(),
        "rpc/revoked"
    );
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &cap, "a", Value::text("no"))
        .expect_err("expired");
    assert_eq!(error.code(), "rpc/revoked");
}

#[test]
fn a_capability_from_another_kernel_cannot_publish() {
    let fixture = fixture();
    let channel = channel(&fixture, "news");
    let other = Agent::with_secret([0x7f; 32]);
    let provider = other.register(Box::new(Echo)).expect("register provider");
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
    let channel = channel(&fixture, "news");
    fixture
        .agent
        .send(fixture.lane, channel, Value::text("plain"), &[])
        .expect("send");
    let message = fixture
        .agent
        .recv(fixture.lane, channel)
        .expect("recv")
        .expect("message");
    assert_eq!(message.topic, None);
    assert_eq!(message.payload, Value::text("plain"));
    let _ = Arg::text("unused");
    let _ = Budget::default();
}

#[cfg(feature = "test-utils")]
#[test]
fn a_capability_bound_to_a_peer_publishes_only_through_that_peer() {
    use active_rpc::identity::{IdentityPolicy, PeerIdentity};

    let fixture = fixture();
    let owner = PeerIdentity::from_certificate_for_test(b"topic-owner");
    let stranger = PeerIdentity::from_certificate(b"topic-stranger");
    let admitted = IdentityPolicy::default()
        .admit(Some(&owner), true)
        .expect("admit");
    let cap = fixture
        .agent
        .mint_bound(
            &admitted,
            fixture.provider,
            0,
            CapAttrs::new(&["echo"]).allow_publish(),
        )
        .expect("bound cap");
    let channel = channel(&fixture, "bound");

    // An unauthenticated publish cannot exercise a bound capability: a channel
    // cannot prove who published.
    let error = fixture
        .agent
        .publish(fixture.lane, channel, &cap, "news", Value::text("x"))
        .expect_err("a bound capability must not publish without a peer");
    assert_eq!(error.code(), "rpc/identity");

    let error = fixture
        .agent
        .publish_as(
            Some(&stranger),
            fixture.lane,
            channel,
            &cap,
            "news",
            Value::text("x"),
        )
        .expect_err("another peer must not publish with it");
    assert_eq!(error.code(), "rpc/identity");

    fixture
        .agent
        .publish_as(
            Some(&owner),
            fixture.lane,
            channel,
            &cap,
            "news",
            Value::text("bound"),
        )
        .expect("the bound peer publishes");
    let message = fixture
        .agent
        .recv_topic(fixture.lane, channel, "news")
        .expect("recv")
        .expect("queued");
    assert_eq!(message.payload, Value::text("bound"));
}

#[test]
fn a_publish_charges_the_capability_byte_budget() {
    let fixture = fixture();
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget.max_bytes = 16;
    let cap = cap(&fixture, attrs);
    let channel = channel(&fixture, "budget");

    let error = fixture
        .agent
        .publish(
            fixture.lane,
            channel,
            &cap,
            "news",
            Value::text("a".repeat(32)),
        )
        .expect_err("a payload over the byte budget must be refused");
    assert_eq!(error.code(), "rpc/budget-exceeded");
    // The refusal did not queue anything.
    assert!(fixture
        .agent
        .recv_topic(fixture.lane, channel, "news")
        .expect("recv")
        .is_none());

    // The topic name is payload too: a short value under a long topic still
    // has to fit the same grant.
    let mut small_attrs = CapAttrs::new(&["echo"]);
    small_attrs.budget.max_bytes = 8;
    let small = self::cap(&fixture, small_attrs);
    let error = fixture
        .agent
        .publish(
            fixture.lane,
            channel,
            &small,
            "a-long-topic-name",
            Value::text("x"),
        )
        .expect_err("the topic name is charged");
    assert_eq!(error.code(), "rpc/budget-exceeded");

    // A payload inside the ceiling is charged and published.
    fixture
        .agent
        .publish(fixture.lane, channel, &cap, "news", Value::text("ok"))
        .expect("publish inside the budget");
    assert!(fixture
        .agent
        .recv_topic(fixture.lane, channel, "news")
        .expect("recv")
        .is_some());
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
