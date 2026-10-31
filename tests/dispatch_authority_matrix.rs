//! Every authority entry point refuses a revoked or expired capability.
//!
//! The maturity work fixed these one at a time; this file is the audit
//! artifact that keeps them fixed together. Each entry point is driven through
//! its real API, and a queued call is checked twice: when it is queued and
//! again when it is dispatched, because a capability can expire in between.
//!
//! Entry points covered: `call`, `call_as`, `call_with_payload`, `publish`,
//! `publish_as`, `send`, `send_as`, `attenuate`, `introduce_to`, plus lane
//! destruction and descendant revocation.

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::kernel::Provider;
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, ChannelId, Error, LaneId};

struct Echo;

impl Provider for Echo {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string(), "mutate".to_string()]
    }

    fn mutating(&self, method: &str) -> bool {
        method == "mutate"
    }

    fn invoke(&mut self, _object: u64, call: &Call) -> active_rpc::Result<Response> {
        if call.method == "mutate" {
            return Ok(Response::Value(Value::Text("mutated".into())));
        }
        Ok(Response::Value(
            call.args
                .iter()
                .find_map(|arg| match arg {
                    active_rpc::value::Arg::Value(value) => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or(Value::Text("ok".into())),
        ))
    }
}

/// A provider that fails the test if it is ever invoked.
struct NeverRun;

impl Provider for NeverRun {
    fn name(&self) -> &'static str {
        "never"
    }

    fn methods(&self) -> Vec<String> {
        vec!["echo".to_string()]
    }

    fn mutating(&self, _method: &str) -> bool {
        false
    }

    fn invoke(&mut self, _object: u64, _call: &Call) -> active_rpc::Result<Response> {
        panic!("a revoked or expired capability reached the provider");
    }
}

struct Fixture {
    agent: Agent,
    cap: CapHandle,
    lane: LaneId,
    channel: ChannelId,
}

fn fixture(ttl_ms: Option<u64>) -> Fixture {
    let agent = Agent::with_secret([0x51; 32]);
    let provider = agent.register(Box::new(Echo));
    let attrs = match ttl_ms {
        Some(ttl) => CapAttrs::new(&["echo", "mutate"]).with_ttl_ms(ttl),
        None => CapAttrs::new(&["echo", "mutate"]),
    };
    let cap = agent.mint(provider, 0, attrs).expect("mint");
    let lane = agent
        .create_lane("matrix", Budget::default())
        .expect("lane");
    let channel = agent
        .create_channel("matrix", Direction::Both)
        .expect("channel");
    Fixture {
        agent,
        cap,
        lane,
        channel,
    }
}

fn admitted(certificate: &[u8]) -> active_rpc::AdmittedIdentity {
    let peer = PeerIdentity::from_certificate(certificate);
    IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit")
}

fn peer(certificate: &[u8]) -> PeerIdentity {
    PeerIdentity::from_certificate(certificate)
}

/// Run one queued call to completion and return its outcome.
fn settle(agent: &Agent, lane: LaneId, cap: &CapHandle, method: &str) -> active_rpc::Result<Value> {
    let promise = agent.call(lane, cap, method, Vec::new())?;
    agent.run();
    promise.value()
}

fn assert_code(result: active_rpc::Result<impl std::fmt::Debug>, expected: &str) {
    let error = result.expect_err("the operation must be refused");
    assert_eq!(error.code(), expected, "{error}");
}

#[test]
fn call_refuses_a_revoked_capability() {
    let fixture = fixture(None);
    settle(&fixture.agent, fixture.lane, &fixture.cap, "echo").expect("live");
    fixture.agent.revoke(&fixture.cap);
    assert_code(
        settle(&fixture.agent, fixture.lane, &fixture.cap, "echo"),
        "rpc/revoked",
    );
    // A borrowed handle (what the wire produces) is refused identically.
    let borrowed = fixture.agent.import(fixture.cap.id());
    assert_code(
        settle(&fixture.agent, fixture.lane, &borrowed, "echo"),
        "rpc/revoked",
    );
}

#[test]
fn call_refuses_an_expired_capability_at_queue_time() {
    let fixture = fixture(Some(100));
    fixture.agent.set_latency(100);
    // A long-lived second capability advances the clock past the first one's
    // deadline without touching it.
    let provider = fixture.agent.register(Box::new(Echo));
    let clock = fixture
        .agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("clock cap");
    settle(&fixture.agent, fixture.lane, &clock, "echo").expect("advance");
    assert_code(
        settle(&fixture.agent, fixture.lane, &fixture.cap, "echo"),
        "rpc/revoked",
    );
}

/// The capability is live when the call is queued and expires during the round
/// trip that dispatches it. The provider must never see it.
#[test]
fn call_that_expires_between_queue_and_dispatch_never_reaches_the_provider() {
    let agent = Agent::with_secret([0x52; 32]);
    let provider = agent.register(Box::new(NeverRun));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(100))
        .expect("mint");
    let lane = agent.create_lane("ttl", Budget::default()).expect("lane");
    agent.set_latency(100);
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.run();
    assert_code(promise.value(), "rpc/revoked");
}

#[test]
fn call_as_refuses_a_bound_capability_for_the_wrong_or_missing_peer() {
    let agent = Agent::with_secret([0x53; 32]);
    let provider = agent.register(Box::new(Echo));
    let owner = admitted(b"dispatch-owner");
    let owner_peer = peer(b"dispatch-owner");
    let stranger = peer(b"dispatch-stranger");
    let cap = agent
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap");
    let lane = agent.create_lane("bound", Budget::default()).expect("lane");

    let promise = agent
        .call_as(Some(&owner_peer), lane, &cap, "echo", Vec::new())
        .expect("owner call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::Text("ok".into()));

    assert_code(
        agent.call_as(Some(&stranger), lane, &cap, "echo", Vec::new()),
        "rpc/identity",
    );
    assert_code(
        agent.call_as(None, lane, &cap, "echo", Vec::new()),
        "rpc/identity",
    );
}

#[test]
fn call_with_payload_shares_the_call_authority_rules() {
    let fixture = fixture(None);
    let promise = fixture
        .agent
        .call_with_payload(fixture.lane, &fixture.cap, "echo", Vec::new(), 8)
        .expect("live");
    fixture.agent.run();
    promise.value().expect("value");
    fixture.agent.revoke(&fixture.cap);
    assert_code(
        fixture
            .agent
            .call_with_payload(fixture.lane, &fixture.cap, "echo", Vec::new(), 8),
        "rpc/revoked",
    );
}

#[test]
fn publish_refuses_a_revoked_capability() {
    let fixture = fixture(None);
    fixture
        .agent
        .publish(
            fixture.lane,
            fixture.channel,
            &fixture.cap,
            "news",
            Value::text("a"),
        )
        .expect("live");
    fixture.agent.revoke(&fixture.cap);
    assert_code(
        fixture.agent.publish(
            fixture.lane,
            fixture.channel,
            &fixture.cap,
            "news",
            Value::text("b"),
        ),
        "rpc/revoked",
    );
}

#[test]
fn publish_refuses_an_expired_capability() {
    let fixture = fixture(Some(100));
    fixture.agent.set_latency(100);
    let provider = fixture.agent.register(Box::new(Echo));
    let clock = fixture
        .agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("clock cap");
    settle(&fixture.agent, fixture.lane, &clock, "echo").expect("advance");
    assert_code(
        fixture.agent.publish(
            fixture.lane,
            fixture.channel,
            &fixture.cap,
            "news",
            Value::text("x"),
        ),
        "rpc/revoked",
    );
}

#[test]
fn publish_as_enforces_the_identity_binding() {
    let agent = Agent::with_secret([0x54; 32]);
    let provider = agent.register(Box::new(Echo));
    let owner = admitted(b"publish-owner");
    let owner_peer = peer(b"publish-owner");
    let stranger = peer(b"publish-stranger");
    let cap = agent
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap");
    let lane = agent.create_lane("bound", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("bound", Direction::Both)
        .expect("channel");

    agent
        .publish_as(
            Some(&owner_peer),
            lane,
            channel,
            &cap,
            "news",
            Value::text("ok"),
        )
        .expect("owner publishes");
    assert_code(
        agent.publish_as(
            Some(&stranger),
            lane,
            channel,
            &cap,
            "news",
            Value::text("x"),
        ),
        "rpc/identity",
    );
    assert_code(
        agent.publish_as(None, lane, channel, &cap, "news", Value::text("x")),
        "rpc/identity",
    );
}

#[test]
fn send_refuses_a_revoked_capability() {
    let fixture = fixture(None);
    fixture
        .agent
        .send(fixture.lane, fixture.channel, Value::text("a"), &[])
        .expect("live send");
    let second = fixture
        .agent
        .mint(
            fixture.agent.register(Box::new(Echo)),
            0,
            CapAttrs::new(&["echo"]),
        )
        .expect("mint");
    fixture
        .agent
        .send(fixture.lane, fixture.channel, Value::text("b"), &[second])
        .expect("live transfer");
    // A cap transferred, then revoked, is still refused for the sender's own
    // use and for a later transfer.
    fixture.agent.revoke(&fixture.cap);
    assert_code(
        fixture.agent.send(
            fixture.lane,
            fixture.channel,
            Value::text("c"),
            std::slice::from_ref(&fixture.cap),
        ),
        "rpc/revoked",
    );
}

#[test]
fn send_as_refuses_revoked_expired_and_bound_capabilities() {
    let agent = Agent::with_secret([0x55; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("send", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("send", Direction::Both)
        .expect("channel");
    agent.set_latency(100);
    let expired = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(100))
        .expect("expired cap");
    let revoked = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("revoked cap");
    agent.revoke(&revoked);
    let owner = admitted(b"send-owner");
    let bound = agent
        .mint_bound(&owner, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap");

    // Advance the clock past the expired capability's deadline.
    let clock = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("clock cap");
    settle(&agent, lane, &clock, "echo").expect("advance");

    assert_code(
        agent.send_as(
            None,
            lane,
            channel,
            Value::text("x"),
            std::slice::from_ref(&expired),
        ),
        "rpc/revoked",
    );
    assert_code(
        agent.send_as(
            None,
            lane,
            channel,
            Value::text("x"),
            std::slice::from_ref(&revoked),
        ),
        "rpc/revoked",
    );
    // A bound capability cannot cross a channel at all, even for its own peer.
    assert_code(
        agent.send_as(
            Some(&peer(b"send-owner")),
            lane,
            channel,
            Value::text("x"),
            std::slice::from_ref(&bound),
        ),
        "rpc/identity",
    );
}

#[test]
fn attenuate_refuses_a_revoked_or_expired_parent() {
    let live = fixture(None);
    let child = live
        .agent
        .attenuate(&live.cap, CapAttrs::new(&["echo"]))
        .expect("live attenuation");
    drop(child);
    let expired_fixture = fixture(Some(100));
    expired_fixture.agent.set_latency(100);
    let provider = expired_fixture.agent.register(Box::new(Echo));
    let clock = expired_fixture
        .agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("clock cap");
    settle(&expired_fixture.agent, expired_fixture.lane, &clock, "echo").expect("advance");
    assert_code(
        expired_fixture
            .agent
            .attenuate(&expired_fixture.cap, CapAttrs::new(&["echo"])),
        "rpc/revoked",
    );

    live.agent.revoke(&live.cap);
    assert_code(
        live.agent.attenuate(&live.cap, CapAttrs::new(&["echo"])),
        "rpc/revoked",
    );
}

#[test]
fn introduce_to_refuses_a_revoked_or_expired_capability() {
    let live = fixture(None);
    let owner = admitted(b"introduce-owner");
    live.agent
        .introduce_to(&live.cap, &owner)
        .expect("live introduction");

    let expired_fixture = fixture(Some(100));
    expired_fixture.agent.set_latency(100);
    let provider = expired_fixture.agent.register(Box::new(Echo));
    let clock = expired_fixture
        .agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("clock cap");
    settle(&expired_fixture.agent, expired_fixture.lane, &clock, "echo").expect("advance");
    assert_code(
        expired_fixture
            .agent
            .introduce_to(&expired_fixture.cap, &owner),
        "rpc/revoked",
    );

    live.agent.revoke(&live.cap);
    assert_code(live.agent.introduce_to(&live.cap, &owner), "rpc/revoked");
}

#[test]
fn destroying_the_lane_refuses_every_entry_point() {
    let fixture = fixture(None);
    let _ = fixture.agent.destroy_lane(fixture.lane);
    assert_code(
        fixture
            .agent
            .call(fixture.lane, &fixture.cap, "echo", Vec::new()),
        "rpc/unknown-lane",
    );
    assert_code(
        fixture.agent.publish(
            fixture.lane,
            fixture.channel,
            &fixture.cap,
            "news",
            Value::text("x"),
        ),
        "rpc/unknown-lane",
    );
    assert_code(
        fixture
            .agent
            .send(fixture.lane, fixture.channel, Value::text("x"), &[]),
        "rpc/unknown-lane",
    );
}

#[test]
fn revoking_a_parent_kills_its_descendants_at_every_entry_point() {
    let fixture = fixture(None);
    let child = fixture
        .agent
        .attenuate(&fixture.cap, CapAttrs::new(&["echo"]))
        .expect("child");
    settle(&fixture.agent, fixture.lane, &child, "echo").expect("child live");
    fixture.agent.revoke(&fixture.cap);
    assert_code(
        settle(&fixture.agent, fixture.lane, &child, "echo"),
        "rpc/revoked",
    );
    assert_code(
        fixture.agent.publish(
            fixture.lane,
            fixture.channel,
            &child,
            "news",
            Value::text("x"),
        ),
        "rpc/revoked",
    );
    assert_code(
        fixture.agent.attenuate(&child, CapAttrs::new(&["echo"])),
        "rpc/revoked",
    );
}

#[test]
fn a_revoked_read_only_grant_still_refuses_its_methods() {
    let agent = Agent::with_secret([0x56; 32]);
    let provider = agent.register(Box::new(Echo));
    let mut attrs = CapAttrs::new(&["mutate"]);
    attrs.read_only = true;
    let cap = agent.mint(provider, 0, attrs).expect("read-only cap");
    let lane = agent.create_lane("ro", Budget::default()).expect("lane");
    let error = agent
        .call(lane, &cap, "mutate", Vec::new())
        .expect_err("read-only mutation");
    assert!(matches!(error, Error::ReadOnly), "{error:?}");
    assert_eq!(error.code(), "rpc/read-only");
}
