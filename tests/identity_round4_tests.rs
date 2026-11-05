//! R-11 round 4: an introduction rebinds only live records, and a binding needs
//! a bindable fingerprint.

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{AdmittedIdentity, IdentityPolicy, PeerIdentity};
use active_rpc::value::{Arg, Call, Response};
use active_rpc::{Agent, Budget, Provider};

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

/// The cross-domain variant: a child whose lease only *reads* as expired because
/// the kernel was switched to the virtual clock. Pre-fix, introducing the root
/// rebound that child, and switching back made Alice's capability live — a peer
/// that never received it could call it (round 4, F1, exploit B).
#[test]
fn an_introduction_does_not_revive_a_cross_domain_child_for_the_new_peer() {
    let agent = Agent::with_secret([0x94; 32]);
    agent.use_wall_clock(true);
    let provider = agent.register(Box::new(Echo));
    let bob = admitted(b"bob-round4d");
    let alice = admitted(b"alice-round4d");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let mut leased = CapAttrs::new(&["echo"]);
    leased.ttl_ms = Some(600_000);
    let child = agent.attenuate(&root, leased).expect("leased child");
    agent.introduce_to(&child, &bob).expect("bind child to bob");

    // The lease is wall-clock, so under the virtual clock it cannot be read and
    // the child is treated as expired for the length of the introduction.
    agent.use_wall_clock(false);
    agent
        .introduce_to(&root, &alice)
        .expect("the live root is introduced");
    agent.use_wall_clock(true);

    assert_eq!(
        agent.cap_attrs(&child).expect("attrs").bound_to,
        Some(bob.fingerprint()),
        "a child that only read as expired keeps its binding"
    );

    // Bob still exercises it: the capability is live, not dead.
    let lane = agent.create_lane("split", Budget::default()).expect("lane");
    let bob_call = agent
        .call_as(
            Some(bob.identity()),
            lane,
            &child,
            "echo",
            vec![Arg::text("bob")],
        )
        .expect("bob queues");
    agent.run();
    assert_eq!(
        bob_call.value().expect("bob's own capability"),
        active_rpc::Value::text("bob")
    );

    // Alice never received this capability, and the introduction moved only the
    // live records: her call is refused at dispatch.
    let alice_call = match agent.call_as(
        Some(alice.identity()),
        lane,
        &child,
        "echo",
        vec![Arg::text("alice")],
    ) {
        Ok(promise) => {
            agent.run();
            promise.value()
        }
        Err(error) => Err(error),
    };
    let error = alice_call.expect_err("alice must not use bob's capability");
    assert_eq!(error.code(), "rpc/identity", "{error}");
}

fn admitted(certificate: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(certificate)), false)
        .expect("admitted")
}

/// A revoked child keeps the binding it died with: an introduction must not
/// rewrite a dead record's history, because a clock-domain mismatch can make
/// that record readable again under the new peer (round 4, F1).
#[test]
fn an_introduction_does_not_rebind_a_revoked_child() {
    let agent = Agent::with_secret([0x91; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = admitted(b"alice-round4");
    let bob = admitted(b"bob-round4");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let child = agent
        .attenuate(&root, CapAttrs::new(&["echo"]))
        .expect("child");
    agent.introduce_to(&child, &bob).expect("bind child to bob");
    assert_eq!(
        agent.cap_attrs(&child).expect("attrs").bound_to,
        Some(bob.fingerprint())
    );
    agent.revoke(&child).expect("revoke");

    agent
        .introduce_to(&root, &alice)
        .expect("the live root is introduced");
    assert_eq!(
        agent.cap_attrs(&root).expect("attrs").bound_to,
        Some(alice.fingerprint()),
        "the live root must be bound to the new peer"
    );
    assert_eq!(
        agent.cap_attrs(&child).expect("attrs").bound_to,
        Some(bob.fingerprint()),
        "a revoked child's binding is history, not authority to move"
    );
}

/// The live part of the subtree is still bound: the fix narrows the mutation to
/// live records, it does not disable the feature (round 4, F1).
#[test]
fn a_live_child_is_rebound_with_the_root() {
    let agent = Agent::with_secret([0x92; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = admitted(b"alice-round4b");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let child = agent
        .attenuate(&root, CapAttrs::new(&["echo"]))
        .expect("child");
    agent.introduce_to(&root, &alice).expect("introduce");
    assert_eq!(
        agent.cap_attrs(&child).expect("attrs").bound_to,
        Some(alice.fingerprint())
    );
}

/// A rotation moves the live subtree and leaves a dead child's binding alone
/// (round 4, F1).
#[test]
fn a_rotation_leaves_a_revoked_child_bound_to_the_old_peer() {
    let agent = Agent::with_secret([0x93; 32]);
    let provider = agent.register(Box::new(Echo));
    let bob = admitted(b"bob-round4c");
    let alice = admitted(b"alice-round4c");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    agent.introduce_to(&root, &bob).expect("bind root");
    let dead = agent
        .attenuate(&root, CapAttrs::new(&["echo"]))
        .expect("child");
    agent.introduce_to(&dead, &bob).expect("bind child");
    agent.revoke(&dead).expect("revoke");
    let _ = agent
        .create_lane("rotate", Budget::default())
        .expect("lane");

    agent
        .reintroduce_to(
            &root,
            &PeerIdentity::from_certificate(b"bob-round4c"),
            &alice,
        )
        .expect("rotate");
    assert_eq!(
        agent.cap_attrs(&root).expect("attrs").bound_to,
        Some(alice.fingerprint())
    );
    assert_eq!(
        agent.cap_attrs(&dead).expect("attrs").bound_to,
        Some(bob.fingerprint()),
        "a revoked child is not moved to the successor"
    );
}
