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
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(100))
        .expect("mint");
    // The first call starts at t=0 and is within the lifetime.
    call(&agent, lane, &cap).expect("within lifetime");
    // The round trip advanced the kernel clock to 100 ms, the expiry instant.
    let error = call(&agent, lane, &cap).expect_err("expired");
    assert!(matches!(error, Error::Revoked(_)), "{error:?}");
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
    call(&agent, lane, &child).expect("t=0");
    call(&agent, lane, &child).expect("t=100");
    // t=200: the child expires while the parent is still valid.
    let error = call(&agent, lane, &child).expect_err("child expired");
    assert!(matches!(error, Error::Revoked(_)), "{error:?}");
    call(&agent, lane, &parent).expect("parent still valid");
}

#[test]
fn a_child_cannot_outlive_a_parent_that_expires_sooner() {
    let (agent, provider, lane) = agent();
    agent.set_latency(500);
    let parent = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]).with_ttl_ms(1_000))
        .expect("parent");
    // Asking for a longer lifetime is an escalation attempt.
    let longer = agent.attenuate(&parent, CapAttrs::new(&["echo"]).with_ttl_ms(2_000));
    assert!(matches!(longer, Err(Error::Escalation(_))), "{longer:?}");
    // The first call advances the kernel clock to t=500.
    call(&agent, lane, &parent).expect("first");
    // A child may ask for the parent's *nominal* lifetime, but the kernel
    // clamps the absolute expiry to the parent's: t=1000, not t=1500.
    let child = agent
        .attenuate(&parent, CapAttrs::new(&["echo"]).with_ttl_ms(1_000))
        .expect("child");
    call(&agent, lane, &child).expect("t=500, within both");
    // t=1000: both expire together.
    for cap in [&child, &parent] {
        let error = call(&agent, lane, cap).expect_err("expired with the parent");
        assert!(matches!(error, Error::Revoked(_)), "{error:?}");
    }
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
