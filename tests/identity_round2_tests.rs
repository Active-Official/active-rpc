//! R-11 round 2: identity is re-checked where authority is exercised, an empty
//! certificate is not an identity, and the policy is a path a transport can use.

use active_rpc::cap::CapAttrs;
use active_rpc::identity::{
    AdmittedIdentity, IdentityKind, IdentityPolicy, PeerIdentity, TrustLevel,
};
use active_rpc::value::{Arg, Call, Response, Value};
use active_rpc::wire::{Envelope, Kind};
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
            .unwrap_or(Value::Null);
        Ok(Response::Value(value))
    }
}

fn admitted(certificate: &[u8]) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(&PeerIdentity::from_certificate(certificate)), false)
        .expect("admitted")
}

/// A call queued before the capability was bound must not run after it: the
/// binding is authority withdrawn from the queued caller, and dispatch is where
/// revocation and expiry are enforced.
#[test]
fn a_queued_call_does_not_survive_a_later_binding() {
    let agent = Agent::with_secret([0x71; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round2");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("queued", Budget::default())
        .expect("lane");

    // Queue as an anonymous caller while the capability is unbound.
    let promise = agent
        .call_as(None, lane, &cap, "echo", vec![Arg::text("queued")])
        .expect("queued");
    // The operator introduces it to Alice before the batch runs.
    agent.introduce_to(&cap, &alice).expect("introduce");
    agent.run();
    let error = promise
        .value()
        .expect_err("the anonymous caller lost authority");
    assert_eq!(error.code(), "rpc/identity");
}

/// The same call, queued by the peer it was bound to, still runs.
#[test]
fn a_queued_call_from_the_bound_peer_still_runs() {
    let agent = Agent::with_secret([0x72; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round2");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("queued", Budget::default())
        .expect("lane");

    let promise = agent
        .call_as(
            Some(alice.identity()),
            lane,
            &cap,
            "echo",
            vec![Arg::text("ok")],
        )
        .expect("queued");
    agent.introduce_to(&cap, &alice).expect("introduce");
    agent.run();
    assert_eq!(
        promise.value().expect("the bound peer keeps its authority"),
        Value::text("ok")
    );
}

/// An empty certificate is evidence of nothing. A `MutualTls` identity for it
/// would hand every caller that passed an empty buffer one shared, bindable
/// fingerprint.
#[test]
fn an_empty_certificate_is_not_a_bindable_identity() {
    let empty = PeerIdentity::from_certificate(&[]);
    assert_eq!(empty.kind(), IdentityKind::Anonymous);
    assert!(empty.is_anonymous());
    assert!(!active_rpc::identity::bindable(empty.fingerprint()));
    assert!(active_rpc::identity::presented_fingerprint(Some(&empty)).is_none());

    let agent = Agent::with_secret([0x73; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let policy = IdentityPolicy::default();
    let admitted_empty = policy
        .admit(Some(&empty), false)
        .expect_err("an anonymous identity is refused when a certificate is required");
    assert_eq!(admitted_empty.code(), "rpc/identity");
    let _ = provider;
}

/// Escaping can multiply a label sixfold (`\u{1b}` is six bytes), so the escaped
/// form has to be bounded too.
#[test]
fn a_subject_stays_bounded_when_every_character_escapes() {
    let identity = PeerIdentity::from_certificate(b"cert-escaping")
        .with_subject("\u{1b}".repeat(active_rpc::identity::MAX_SUBJECT_BYTES));
    assert!(
        identity.subject().len() <= active_rpc::identity::MAX_SUBJECT_BYTES,
        "the escaped label is {} bytes",
        identity.subject().len()
    );
    assert!(!identity.subject().contains('\u{1b}'));
}

/// The label follows the connection: `local()` trusts loopback, so a local
/// caller is a loopback peer, not an anonymous one.
#[test]
fn local_policy_labels_a_loopback_peer_as_loopback() {
    let admitted = IdentityPolicy::local()
        .admit(None, true)
        .expect("loopback is trusted");
    assert_eq!(admitted.identity().kind(), IdentityKind::Loopback);
    assert_eq!(admitted.trust(), TrustLevel::LoopbackRelaxed);
    assert!(!admitted.can_bind());

    // Off-host under `local()` is still nobody in particular.
    let remote = IdentityPolicy::local()
        .admit(None, false)
        .expect("no identity required");
    assert_eq!(remote.identity().kind(), IdentityKind::Anonymous);
}

/// A revoked descendant is dead authority; its binding must not block the
/// introduction of a live parent forever.
#[test]
fn a_revoked_descendant_does_not_block_introduction() {
    let agent = Agent::with_secret([0x74; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round2");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let child = agent
        .attenuate(&root, CapAttrs::new(&["echo"]))
        .expect("child");
    agent.introduce_to(&child, &alice).expect("bind child");
    agent.revoke(&child).expect("revoke child");

    let descriptor = agent
        .introduce_to(&root, &alice)
        .expect("a revoked descendant does not block the introduction");
    assert_eq!(descriptor.id, root.id());
}

/// The predicate models the operation: a child that omits a binding is a valid
/// attenuation because `attenuate` inherits the parent's. A validator that mints
/// foreign attributes must merge first, and the merge is what this pins.
#[test]
fn a_child_that_omits_a_binding_inherits_it() {
    let parent = CapAttrs::new(&["echo"]).bound_to([7u8; 32]);
    let child = CapAttrs::new(&["echo"]);
    assert!(child.is_attenuation_of(&parent));
    let merged = parent.attenuate(child).expect("monotone");
    assert_eq!(merged.bound_to, Some([7u8; 32]));
}

/// A transport-side dispatcher admits the peer under the policy first: strict
/// policy refuses an anonymous peer even on loopback, and the default policy
/// admits it as a loopback peer that cannot bind.
#[test]
fn the_dispatch_helper_admits_before_it_dispatches() {
    let agent = Agent::with_secret([0x75; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent
        .create_lane("dispatch", Budget::default())
        .expect("lane");
    let envelope = Envelope {
        kind: Kind::Request,
        request_id: 1,
        method: "echo".to_string(),
        args: vec![Arg::text("hi")],
        payload: Vec::new(),
        caps: Vec::new(),
        redact: false,
        read_only: false,
        cap_delta: None,
    };

    let error = agent
        .dispatch_envelope(&IdentityPolicy::strict(), None, true, lane, &cap, &envelope)
        .expect_err("strict policy refuses an anonymous peer");
    assert_eq!(error.code(), "rpc/identity");

    let promise = agent
        .dispatch_envelope(
            &IdentityPolicy::default(),
            None,
            true,
            lane,
            &cap,
            &envelope,
        )
        .expect("the default policy trusts loopback");
    agent.run();
    assert_eq!(promise.value().expect("dispatched"), Value::text("hi"));
}

/// Expiry is monotonic, so an expired-and-bound descendant would block the
/// introduction of a live parent forever if it were not skipped.
#[test]
fn an_expired_descendant_does_not_block_introduction() {
    let agent = Agent::with_secret([0x76; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round2");
    let root = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("root");
    let child = agent
        .attenuate(&root, CapAttrs::new(&["echo"]).with_ttl_ms(1))
        .expect("child");
    agent.introduce_to(&child, &alice).expect("bind child");

    // One round trip advances the virtual clock past the child's lifetime.
    agent.set_latency(5);
    let lane = agent
        .create_lane("expiry", Budget::default())
        .expect("lane");
    let promise = agent
        .call_as(Some(alice.identity()), lane, &child, "echo", Vec::new())
        .expect("queued");
    agent.run();
    let _ = promise.value();
    assert!(
        agent.cap_attrs(&child).expect("attrs").bound_to.is_some(),
        "the binding stays on the record; only its effect is dead"
    );

    agent
        .introduce_to(&root, &alice)
        .expect("an expired descendant does not block the introduction");
}

/// An idempotency key names the principal that claimed it: a replay from another
/// peer must be a clean `rpc/identity`, not a cached promise whose job was
/// stamped for the first caller.
#[test]
fn an_idempotency_key_belongs_to_the_peer_that_claimed_it() {
    let agent = Agent::with_secret([0x77; 32]);
    let provider = agent.register(Box::new(Echo)).expect("register provider");
    let alice = admitted(b"alice-round2");
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("idem", Budget::default()).expect("lane");

    // Claimed anonymously while the capability is unbound.
    let first = agent
        .call_idempotent_as(None, lane, &cap, "echo", Vec::new(), "shared-key")
        .expect("claimed");
    agent.run();
    let _ = first.value();

    // Alice presents the same key: not her request.
    let error = agent
        .call_idempotent_as(
            Some(alice.identity()),
            lane,
            &cap,
            "echo",
            Vec::new(),
            "shared-key",
        )
        .expect_err("another peer cannot replay the key");
    assert_eq!(error.code(), "rpc/identity");

    // The same anonymous principal may still retry its own key.
    let again = agent
        .call_idempotent_as(None, lane, &cap, "echo", Vec::new(), "shared-key")
        .expect("the claimer may retry");
    assert_eq!(again.id(), first.id());
}
