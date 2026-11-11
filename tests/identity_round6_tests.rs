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

/// A keyed dispatch from a peer's envelope applies the authority-argument guard,
/// so an envelope cannot smuggle a promise or a capability into a provider
/// through a retry (round 7, M-1).
#[test]
fn an_idempotent_envelope_cannot_carry_authority_arguments() {
    use active_rpc::wire::{Envelope, Kind};

    let agent = Agent::with_secret([0xa4; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round7");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &alice).expect("bind to alice");
    let lane = agent
        .create_lane("idem-env", Budget::default())
        .expect("lane");

    for arg in [
        Arg::Promise(active_rpc::PromiseId(0)),
        Arg::Cap(active_rpc::CapId([3; 16])),
    ] {
        let envelope = Envelope::request(1, "echo", vec![arg]);
        assert_eq!(envelope.kind, Kind::Request);
        let error = match agent.call_idempotent_from_envelope(
            Some(alice.identity()),
            lane,
            &cap,
            &envelope,
            "env-key",
        ) {
            Ok(promise) => {
                agent.run();
                promise.value().expect_err("the guard refuses the argument")
            }
            Err(error) => error,
        };
        assert_eq!(error.code(), "rpc/wire", "{error}");
    }

    // The in-process variant with a concrete value still works, and the keyed
    // call is the same one the envelope would carry.
    let promise = agent
        .call_idempotent_as(
            Some(alice.identity()),
            lane,
            &cap,
            "echo",
            vec![Arg::text("ok")],
            "env-key-2",
        )
        .expect("queued");
    agent.run();
    assert_eq!(
        promise.value().expect("the call runs"),
        active_rpc::Value::text("ok")
    );
}

/// The same arguments through the peer-facing envelope guard are refused there
/// too, so the idempotent entry point is not the only line of defence.
#[test]
fn an_envelope_still_refuses_authority_arguments() {
    use active_rpc::wire::Envelope;

    let agent = Agent::with_secret([0xa5; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round7b");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &alice).expect("bind");
    let lane = agent.create_lane("env", Budget::default()).expect("lane");
    let envelope = Envelope::request(1, "echo", vec![Arg::Promise(active_rpc::PromiseId(0))]);
    let error = agent
        .call_from_envelope(Some(alice.identity()), lane, &cap, &envelope)
        .expect_err("the envelope guard refuses it");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

fn admitted(certificate: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(certificate)), false)
        .expect("admitted")
}

/// A pipelined argument may only name a promise the same peer queued, and the
/// capability is unbound so the promise owner is the only possible refusal
/// (round 8, F1; round 9, F4).
#[test]
fn a_promise_of_another_peer_is_refused_at_dispatch() {
    use active_rpc::PromiseId;

    let agent = Agent::with_secret([0xa6; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    // No binding: a peer-identity refusal can only come from the promise.
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let alice = admitted(b"alice-round8");
    let bob = admitted(b"bob-round8");
    let lane = agent
        .create_lane("shared", Budget::default())
        .expect("lane");

    let alice_promise = agent
        .call_as(
            Some(alice.identity()),
            lane,
            &cap,
            "echo",
            vec![Arg::text("secret")],
        )
        .expect("alice queues");
    agent.run();
    alice_promise.value().expect("settles");

    let error = match agent.call_as(
        Some(bob.identity()),
        lane,
        &cap,
        "echo",
        vec![Arg::Promise(PromiseId(alice_promise.id().0))],
    ) {
        Ok(promise) => {
            agent.run();
            promise.value().expect_err("another peer's promise")
        }
        Err(error) => error,
    };
    assert_eq!(error.code(), "rpc/identity", "{error}");

    // The same promise from its own peer is the value, not a refusal.
    let reply = agent
        .call_as(
            Some(alice.identity()),
            lane,
            &cap,
            "echo",
            vec![Arg::Promise(PromiseId(alice_promise.id().0))],
        )
        .expect("alice may pipeline her own promise");
    agent.run();
    assert_eq!(
        reply.value().expect("settles"),
        active_rpc::Value::text("secret")
    );
}

/// An out-of-band answer comes from the peer that queued the call
/// (round 9, F3).
#[test]
fn an_out_of_band_answer_comes_from_the_queueing_peer() {
    let agent = Agent::with_secret([0xaa; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let alice = admitted(b"alice-round9");
    let bob = admitted(b"bob-round9");
    let lane = agent
        .create_lane("resolve", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(
            Some(alice.identity()),
            lane,
            &cap,
            "echo",
            vec![Arg::text("x")],
        )
        .expect("queued");
    // Not run: the call is still pending, so `resolve_as` has a job to settle.
    let error = agent
        .resolve_as(
            Some(bob.identity()),
            &promise,
            active_rpc::Value::text("forged"),
        )
        .expect_err("another peer cannot answer alice's call");
    assert_eq!(error.code(), "rpc/identity", "{error}");
    agent
        .resolve_as(
            Some(alice.identity()),
            &promise,
            active_rpc::Value::text("mine"),
        )
        .expect("the queueing peer answers");
    agent.run();
    assert_eq!(
        promise.value().expect("settles"),
        active_rpc::Value::text("mine")
    );
}

/// A deadline this clock cannot read answers `rpc/identity` on every path and
/// never stamps an expiry (round 9, F1).
#[test]
fn a_foreign_clock_deadline_answers_one_code() {
    let agent = Agent::with_secret([0xab; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let mut attrs = CapAttrs::new(&["echo"]);
    attrs.ttl_ms = Some(600_000);
    let cap = agent.mint(provider, 0, attrs).expect("cap");
    let id = cap.id();
    agent.use_wall_clock(false);
    let lane = agent.create_lane("clock", Budget::default()).expect("lane");

    let error = match agent.call_as(None, lane, &cap, "echo", Vec::new()) {
        Ok(promise) => {
            agent.run();
            promise.value().expect_err("the deadline is unreadable")
        }
        Err(error) => error,
    };
    assert_eq!(error.code(), "rpc/identity", "{error}");
    assert_eq!(
        expired_events(&agent, id),
        0,
        "a foreign clock domain stamped cap.expired"
    );
    // Attenuation answers the same code.
    let error = agent
        .attenuate(&cap, CapAttrs::new(&["echo"]))
        .expect_err("the parent's deadline is unreadable here");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

/// The typed peer gate applies the authority-argument guard too
/// (round 8, F1).
#[test]
fn call_peer_refuses_authority_arguments() {
    use active_rpc::PromiseId;

    let agent = Agent::with_secret([0xa7; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round8b");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &alice).expect("bind");
    let lane = agent.create_lane("gate", Budget::default()).expect("lane");
    let error = agent
        .call_peer(lane, &cap, &alice, "echo", vec![Arg::Promise(PromiseId(0))])
        .expect_err("a peer call cannot carry a promise argument");
    assert_eq!(error.code(), "rpc/wire", "{error}");
}

/// The guard is counted and taped like every other refusal
/// (round 8, F2).
#[test]
fn the_authority_guard_is_counted_and_taped() {
    use active_rpc::wire::Envelope;
    use active_rpc::{Event, PromiseId};

    let agent = Agent::with_secret([0xa8; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round8c");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    agent.introduce_to(&cap, &alice).expect("bind");
    let lane = agent
        .create_lane("counted", Budget::default())
        .expect("lane");
    let before = agent.metrics();
    let envelope = Envelope::request(1, "echo", vec![Arg::Promise(PromiseId(0))]);
    let error = agent
        .call_from_envelope(Some(alice.identity()), lane, &cap, &envelope)
        .expect_err("the guard refuses it");
    assert_eq!(error.code(), "rpc/wire");
    let after = agent.metrics();
    assert_eq!(
        after.calls_refused,
        before.calls_refused + 1,
        "the refusal was not counted"
    );
    let refused: Vec<_> = agent
        .events()
        .into_iter()
        .filter(|event| matches!(event, Event::CallRefused { code, .. } if code == "rpc/wire"))
        .collect();
    assert_eq!(refused.len(), 1, "exactly one refusal event");
}

/// A policy refusal is counted and taped through the shared helper
/// (round 8, F5; the round-7 L4 claim).
#[test]
fn a_policy_refusal_is_counted() {
    use active_rpc::identity::IdentityPolicy;
    use active_rpc::wire::Envelope;

    let agent = Agent::with_secret([0xa9; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("policy", Budget::default())
        .expect("lane");
    let before = agent.metrics();
    let envelope = Envelope::request(1, "echo", Vec::new());
    let error = agent
        .dispatch_envelope(&IdentityPolicy::strict(), None, true, lane, &cap, &envelope)
        .expect_err("an anonymous peer is refused");
    assert_eq!(error.code(), "rpc/identity", "{error}");
    let after = agent.metrics();
    assert_eq!(after.identity_refusals, before.identity_refusals + 1);
    assert_eq!(after.calls_refused, before.calls_refused + 1);
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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
    let provider = agent.register(Box::new(Echo)).expect("register provider");
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
