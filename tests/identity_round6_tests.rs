//! R-11 round 6: a revocation is not an expiry, the foreign-clock state is
//! tested on the rotation half, and identity is answered before the budget
//! shape on the idempotent path too.

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{AdmittedIdentity, IdentityPolicy, PeerIdentity};
use active_rpc::value::{Arg, Call, Response};
use active_rpc::{Agent, Budget, Event, Provider};

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
        let value = call
            .args
            .iter()
            .find_map(|arg| match arg {
                Arg::Value(value) => Some(value.clone()),
                _ => None,
            })
            .unwrap_or(active_rpc::Value::Null);
        Ok(Response::Value(value))
    }
}

fn admitted(certificate: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(certificate)), false)
        .expect("admitted")
}

fn expired_events(agent: &Agent, id: active_rpc::CapId) -> usize {
    agent
        .events()
        .into_iter()
        .filter(|event| matches!(event, Event::CapExpired(cap) if *cap == id))
        .count()
}

/// A revoked capability is reported as revoked, and the tape does not claim a
/// lease expired when the operator revoked it (round 6, F1).
#[test]
fn a_revoked_capability_is_not_reported_as_expired() {
    let agent = Agent::with_secret([0xa1; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = admitted(b"alice-round6");
    let bob = admitted(b"bob-round6");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let id = cap.id();
    agent.revoke(&cap).expect("revoke");
    let before = expired_events(&agent, id);

    let error = agent
        .introduce_to(&cap, &alice)
        .expect_err("a revoked capability cannot be introduced");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
    let error = agent
        .reintroduce_to(&cap, &PeerIdentity::from_certificate(b"bob-round6"), &alice)
        .expect_err("a revoked capability cannot be rotated");
    assert_eq!(error.code(), "rpc/revoked", "{error}");
    let _ = bob;
    assert_eq!(
        expired_events(&agent, id),
        before,
        "a revocation stamped cap.expired"
    );
}

/// A rotation refuses the whole subtree when a descendant's deadline belongs to
/// the other clock domain, and neither record is reported as expired
/// (round 6, F3).
#[test]
fn a_rotation_refuses_a_foreign_clock_descendant() {
    let agent = Agent::with_secret([0xa2; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Echo));
    let bob = admitted(b"bob-round6b");
    let alice = admitted(b"alice-round6b");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let mut leased = CapAttrs::new(&["echo"]);
    leased.ttl_ms = Some(600_000);
    let child = agent.attenuate(&root, leased).expect("leased child");
    agent.introduce_to(&root, &bob).expect("bind root to bob");
    agent.introduce_to(&child, &bob).expect("bind child to bob");

    agent.use_wall_clock(false);
    let error = agent
        .reintroduce_to(
            &root,
            &PeerIdentity::from_certificate(b"bob-round6b"),
            &alice,
        )
        .expect_err("the foreign-clock child refuses the rotation");
    assert_eq!(error.code(), "rpc/identity", "{error}");
    agent.use_wall_clock(true);

    assert_eq!(
        agent.cap_attrs(&root).expect("attrs").bound_to,
        Some(bob.fingerprint())
    );
    assert_eq!(
        agent.cap_attrs(&child).expect("attrs").bound_to,
        Some(bob.fingerprint())
    );
    for id in [root.id(), child.id()] {
        assert_eq!(
            expired_events(&agent, id),
            0,
            "a foreign clock domain stamped cap.expired"
        );
    }
}

/// The idempotent path answers identity before measuring the budget shape
/// (round 6, F2).
#[test]
fn an_idempotent_wrong_peer_is_refused_before_the_shape() {
    let agent = Agent::with_secret([0xa3; 32]);
    let provider = agent.register(Box::new(Echo));
    let bob = admitted(b"bob-round6c");
    let alice = admitted(b"alice-round6c");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.budget.max_bytes = 8;
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    agent.introduce_to(&cap, &bob).expect("bind to bob");
    let lane = agent.create_lane("idem", Budget::default()).expect("lane");
    let wide = Arg::text("this text is longer than eight bytes");
    let error = match agent.call_idempotent_as(
        Some(alice.identity()),
        lane,
        &cap,
        "echo",
        vec![wide],
        "key-1",
    ) {
        Ok(promise) => {
            agent.run();
            promise.value().expect_err("refused")
        }
        Err(error) => error,
    };
    assert_eq!(error.code(), "rpc/identity", "{error}");

    // The control: the same arguments from the bound peer are a budget refusal,
    // so the two orders are distinguishable.
    let again = Arg::text("this text is longer than eight bytes");
    let error = match agent.call_idempotent_as(
        Some(bob.identity()),
        lane,
        &cap,
        "echo",
        vec![again],
        "key-2",
    ) {
        Ok(promise) => {
            agent.run();
            promise.value().expect_err("refused")
        }
        Err(error) => error,
    };
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}
