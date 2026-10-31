//! Time-bounded capabilities: an expired capability is refused at dispatch
//! exactly like a revoked one, and attenuation can only shorten a lifetime.

use active_rpc::cap::CapAttrs;
use active_rpc::kernel::{Event, Provider};
use active_rpc::value::{Call, Response, Value};
use active_rpc::{Agent, Budget, CapHandle, Error};

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

fn agent() -> (Agent, active_rpc::ProviderId, active_rpc::LaneId) {
    let agent = Agent::with_secret([0x7c; 32]);
    let provider = agent.register(Box::new(Echo));
    let lane = agent.create_lane("ttl", Budget::default()).expect("lane");
    (agent, provider, lane)
}

fn call(agent: &Agent, lane: active_rpc::LaneId, cap: &CapHandle) -> active_rpc::Result<()> {
    let promise = agent.call(lane, cap, "echo", Vec::new())?;
    agent.run();
    promise.value().map(|_| ())
}

#[test]
fn an_expired_capability_is_refused_like_a_revocation() {
    let (agent, provider, lane) = agent();
    agent.set_latency(100);
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(250))
        .expect("mint");
    // Calls are queued at t=0 and t=100; each round trip advances the clock by
    // 100 ms before the provider runs, so both are inside the 250 ms lifetime.
    call(&agent, lane, &cap).expect("t=0, dispatched at t=100");
    call(&agent, lane, &cap).expect("t=100, dispatched at t=200");
    // Queued at t=200 while still live, but dispatch advances to t=300.
    let error = call(&agent, lane, &cap).expect_err("expired at dispatch");
    assert!(matches!(error, Error::Revoked(_)), "{error:?}");
    assert_eq!(error.code(), "rpc/revoked");
    // Queued after expiry: the same refusal at the queue-time check.
    let error = call(&agent, lane, &cap).expect_err("expired at queue");
    assert_eq!(error.code(), "rpc/revoked");
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, Event::CapExpired(id) if *id == cap.id())));
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
        panic!("an expired capability reached the provider");
    }
}

#[test]
fn a_call_that_expires_while_queued_never_reaches_the_provider() {
    // The capability is live when the call is queued and expires during the
    // round trip that dispatches it. Dispatch must re-check the deadline, so
    // the provider is never invoked.
    let agent = Agent::with_secret([0x7d; 32]);
    let provider = agent.register(Box::new(NeverRun));
    let lane = agent.create_lane("ttl", Budget::default()).expect("lane");
    agent.set_latency(100);
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(100))
        .expect("mint");
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.run();
    let error = promise.value().expect_err("expired before dispatch");
    assert_eq!(error.code(), "rpc/revoked");
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, Event::CapExpired(id) if *id == cap.id())));
}

#[test]
fn an_unbounded_capability_never_expires() {
    let (agent, provider, lane) = agent();
    agent.set_latency(1_000);
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("mint");
    for _ in 0..5 {
        call(&agent, lane, &cap).expect("unbounded");
    }
}

#[test]
fn attenuation_cannot_extend_a_lifetime() {
    let (agent, provider, _lane) = agent();
    let parent = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(1_000))
        .expect("parent");
    let longer = agent.attenuate(&parent, CapAttrs::new(&["echo"]).with_ttl_ms(5_000));
    assert!(matches!(longer, Err(Error::Escalation(_))), "{longer:?}");
    let unbounded = agent.attenuate(&parent, CapAttrs::new(&["echo"]));
    assert!(
        matches!(unbounded, Err(Error::Escalation(_))),
        "{unbounded:?}"
    );
}

#[test]
fn a_shortened_child_expires_with_its_own_lifetime() {
    let (agent, provider, lane) = agent();
    agent.set_latency(100);
    let parent = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(10_000))
        .expect("parent");
    let child = agent
        .attenuate(&parent, CapAttrs::new(&["echo"]).with_ttl_ms(200))
        .expect("child");
    // Queued at t=0, dispatched at t=100: inside the child's 200 ms lifetime.
    call(&agent, lane, &child).expect("t=0, dispatched at t=100");
    // Queued at t=100 while live; dispatch advances to t=200, the expiry
    // instant, so the child is refused exactly like a revocation.
    let error = call(&agent, lane, &child).expect_err("child expired at dispatch");
    assert!(matches!(error, Error::Revoked(_)), "{error:?}");
    call(&agent, lane, &parent).expect("parent still valid");
}

#[test]
fn a_child_cannot_outlive_a_parent_that_expires_sooner() {
    let (agent, provider, lane) = agent();
    agent.set_latency(250);
    let parent = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(1_000))
        .expect("parent");
    // Asking for a longer lifetime is an escalation attempt.
    let longer = agent.attenuate(&parent, CapAttrs::new(&["echo"]).with_ttl_ms(2_000));
    assert!(matches!(longer, Err(Error::Escalation(_))), "{longer:?}");
    // The first call advances the kernel clock to t=250.
    call(&agent, lane, &parent).expect("first");
    // A child may ask for the parent's *nominal* lifetime, but the kernel
    // clamps the absolute expiry to the parent's: t=1000, not t=1250.
    let child = agent
        .attenuate(&parent, CapAttrs::new(&["echo"]).with_ttl_ms(1_000))
        .expect("child");
    call(&agent, lane, &child).expect("t=250, dispatched at t=500");
    call(&agent, lane, &child).expect("t=500, dispatched at t=750");
    // t=750: dispatched at t=1000, where both expire together.
    let error = call(&agent, lane, &child).expect_err("expired at dispatch");
    assert!(matches!(error, Error::Revoked(_)), "{error:?}");
    let error = call(&agent, lane, &parent).expect_err("expired at the same instant");
    assert!(matches!(error, Error::Revoked(_)), "{error:?}");
}

/// Every surface that exercises authority refuses an expired capability. A
/// deadline means the same thing to a call, an attenuation, an introduction
/// and a channel send; checking it on only one of them lets an expired grant
/// keep minting or delegating.
#[test]
fn every_authority_path_refuses_an_expired_capability() {
    use active_rpc::channel::Direction;
    use active_rpc::identity::{IdentityPolicy, PeerIdentity};

    let (agent, provider, lane) = agent();
    let channel = agent
        .create_channel("ttl", Direction::Both)
        .expect("channel");
    agent.set_latency(100);
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(100))
        .expect("mint");
    // One round trip advances the clock to the expiry instant. The call itself
    // is refused at dispatch, which is what we assert here.
    let promise = agent.call(lane, &cap, "echo", Vec::new()).expect("queued");
    agent.run();
    assert_eq!(
        promise.value().expect_err("expired at dispatch").code(),
        "rpc/revoked"
    );

    let error = agent
        .attenuate(&cap, CapAttrs::new(&["echo"]))
        .expect_err("an expired parent cannot attenuate");
    assert_eq!(error.code(), "rpc/revoked");

    let peer = PeerIdentity::from_certificate(b"ttl-peer");
    let admitted = IdentityPolicy::default()
        .admit(Some(&peer), true)
        .expect("admit");
    let error = agent
        .introduce_to(&cap, &admitted)
        .expect_err("an expired capability cannot be introduced");
    assert_eq!(error.code(), "rpc/revoked");

    let error = agent
        .send_as(
            None,
            lane,
            channel,
            Value::text("x"),
            std::slice::from_ref(&cap),
        )
        .expect_err("an expired capability cannot be sent");
    assert_eq!(error.code(), "rpc/revoked");

    let error = agent
        .publish(lane, channel, &cap, "topic", Value::text("x"))
        .expect_err("an expired capability cannot publish");
    assert_eq!(error.code(), "rpc/revoked");

    // The expiration is observable on the tape.
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, Event::CapExpired(id) if *id == cap.id())));
}

#[test]
fn the_pure_attenuation_predicate_tracks_the_lifetime_rule() {
    let parent = CapAttrs::new(&["echo"]).with_ttl_ms(500);
    let shorter = CapAttrs::new(&["echo"]).with_ttl_ms(100);
    let longer = CapAttrs::new(&["echo"]).with_ttl_ms(900);
    let unbounded = CapAttrs::new(&["echo"]);
    assert!(shorter.is_attenuation_of(&parent));
    assert!(!longer.is_attenuation_of(&parent));
    assert!(!unbounded.is_attenuation_of(&parent));
    // An unbounded parent accepts both a bounded child and an unbounded one.
    let root = CapAttrs::new(&["echo"]);
    assert!(shorter.is_attenuation_of(&root));
    assert!(unbounded.is_attenuation_of(&root));
}
