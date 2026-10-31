//! Transport identity: policy, capability binding and the QUIC mutual-TLS path.
//!
//! The security property under test is narrow and checkable: a capability
//! introduced to one authenticated peer is refused for every other peer, and a
//! certificate is the only thing that produces a bindable identity.

use active_rpc::cap::CapAttrs;
use active_rpc::channel::Direction;
use active_rpc::identity::{
    AdmittedIdentity, IdentityKind, IdentityPolicy, PeerIdentity, TrustLevel,
};
use active_rpc::value::{Arg, Call, Response, Value};
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

fn identity(seed: &[u8]) -> PeerIdentity {
    PeerIdentity::from_certificate(seed)
}

/// Admit a certificate identity through the production policy.
fn admitted(peer: &PeerIdentity) -> AdmittedIdentity {
    IdentityPolicy::default()
        .admit(Some(peer), true)
        .expect("identity admitted")
}

#[test]
fn a_missing_identity_is_refused_off_loopback() {
    let policy = IdentityPolicy::default();
    let error = policy.admit(None, false).expect_err("must refuse");
    assert_eq!(error.code(), "rpc/identity");
}

#[test]
fn loopback_is_relaxed_by_default_and_strict_policy_refuses_it() {
    let admitted = IdentityPolicy::default()
        .admit(None, true)
        .expect("loopback admitted");
    assert_eq!(admitted.trust(), TrustLevel::LoopbackRelaxed);
    assert_eq!(admitted.identity().kind(), IdentityKind::Loopback);
    assert!(admitted.can_bind());

    let error = IdentityPolicy::strict()
        .admit(None, true)
        .expect_err("strict refuses loopback");
    assert_eq!(error.code(), "rpc/identity");
}

#[test]
fn an_anonymous_peer_is_refused_when_identity_is_required() {
    let anonymous = PeerIdentity::anonymous();
    let error = IdentityPolicy::default()
        .admit(Some(&anonymous), true)
        .expect_err("anonymous refused");
    assert_eq!(error.code(), "rpc/identity");

    let admitted = IdentityPolicy::local()
        .admit(Some(&anonymous), false)
        .expect("local policy admits anonymous");
    assert_eq!(admitted.trust(), TrustLevel::Unauthenticated);
    assert!(
        !admitted.can_bind(),
        "an unauthenticated peer cannot be bound"
    );
}

#[test]
fn a_loopback_identity_presented_off_host_is_refused() {
    let loopback = PeerIdentity::loopback();
    let error = IdentityPolicy::default()
        .admit(Some(&loopback), false)
        .expect_err("loopback label cannot be claimed off-host");
    assert_eq!(error.code(), "rpc/identity");
}

#[test]
fn certificate_identities_are_stable_and_subject_sensitive() {
    let first = PeerIdentity::from_certificate(b"certificate-der-a");
    let again = PeerIdentity::from_certificate(b"certificate-der-a");
    let other = PeerIdentity::from_certificate(b"certificate-der-b");
    assert_eq!(first, again);
    assert_ne!(first.fingerprint(), other.fingerprint());
    assert_eq!(first.kind(), IdentityKind::MutualTls);
    assert_eq!(first.fingerprint_hex().len(), 64);

    let renamed = first.clone().with_subject("agent-alpha");
    assert_ne!(renamed.fingerprint(), first.fingerprint());
    assert_eq!(renamed.subject(), "agent-alpha");
    assert_eq!(renamed.kind(), IdentityKind::MutualTls);
}

#[test]
fn a_capability_bound_to_one_peer_is_refused_for_every_other_peer() {
    let agent = Agent::with_secret([0x51; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice_id = identity(b"alice-cert");
    let bob_id = identity(b"bob-cert");
    let alice = admitted(&alice_id);
    let bob = admitted(&bob_id);
    let cap = agent
        .mint_bound(&alice, provider, 0, CapAttrs::new(&["echo"]))
        .expect("bound cap");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");

    let promise = agent
        .call_as(
            Some(alice.identity()),
            lane,
            &cap,
            "echo",
            vec![Arg::value(Value::text("ok"))],
        )
        .expect("alice may call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::text("ok"));

    let error = agent
        .call_as(Some(bob.identity()), lane, &cap, "echo", vec![])
        .expect_err("bob must be refused");
    assert_eq!(error.code(), "rpc/identity");

    let error = agent
        .call(lane, &cap, "echo", vec![])
        .expect_err("no identity must be refused");
    assert_eq!(error.code(), "rpc/identity");
    assert_eq!(agent.metrics().identity_refusals, 2);
}

#[test]
fn an_unbound_capability_keeps_working_without_an_identity() {
    let agent = Agent::with_secret([0x52; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    let promise = agent
        .call(lane, &cap, "echo", vec![Arg::value(Value::Int(7))])
        .expect("call");
    agent.run();
    assert_eq!(promise.value().expect("value"), Value::Int(7));
}

#[test]
fn introduction_binds_once_and_cannot_move_between_peers() {
    let agent = Agent::with_secret([0x53; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = admitted(&identity(b"alice-cert"));
    let bob = admitted(&identity(b"bob-cert"));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");

    let descriptor = agent.introduce_to(&cap, &alice).expect("introduce");
    assert_eq!(descriptor.id, cap.id());
    assert!(agent.cap_attrs(&cap).expect("attrs").bound_to.is_some());

    let error = agent
        .introduce_to(&cap, &bob)
        .expect_err("rebinding must fail");
    assert_eq!(error.code(), "rpc/identity");

    // Introduction is visible to operators as an event, never as an error.
    assert!(agent
        .events()
        .iter()
        .any(|event| matches!(event, active_rpc::Event::CapIntroduced { .. })));
}

#[test]
fn attenuation_keeps_the_binding_and_refuses_a_rebind() {
    let agent = Agent::with_secret([0x54; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = admitted(&identity(b"alice-cert"));
    let bob = admitted(&identity(b"bob-cert"));
    let cap = agent
        .mint_bound(&alice, provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");

    let child = agent
        .attenuate(&cap, CapAttrs::new(&["echo"]).read_only())
        .expect("attenuate");
    let attrs = agent.cap_attrs(&child).expect("attrs");
    assert_eq!(attrs.bound_to, Some(alice.fingerprint()));

    let error = agent
        .attenuate(&cap, CapAttrs::new(&["echo"]).bound_to(bob.fingerprint()))
        .expect_err("rebinding is escalation");
    assert_eq!(error.code(), "rpc/attenuation-escalation");

    // An unbound parent may be narrowed to one peer.
    let unbound = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let narrowed = agent
        .attenuate(
            &unbound,
            CapAttrs::new(&["echo"]).bound_to(alice.fingerprint()),
        )
        .expect("narrowing");
    assert_eq!(
        agent.cap_attrs(&narrowed).expect("attrs").bound_to,
        Some(alice.fingerprint())
    );
}

#[test]
fn an_anonymous_peer_cannot_receive_an_introduction() {
    let agent = Agent::with_secret([0x55; 32]);
    let provider = agent.register(Box::new(Echo));
    let cap = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");

    let anonymous = IdentityPolicy::local()
        .admit(Some(&PeerIdentity::anonymous()), false)
        .expect("anonymous admitted");
    let error = agent
        .introduce_to(&cap, &anonymous)
        .expect_err("anonymous refused");
    assert_eq!(error.code(), "rpc/identity");
    let error = agent
        .mint_bound(&anonymous, provider, 0, CapAttrs::new(&["echo"]))
        .expect_err("anonymous refused");
    assert_eq!(error.code(), "rpc/identity");
}

#[test]
fn a_bound_capability_cannot_be_transferred_over_a_channel() {
    let agent = Agent::with_secret([0x56; 32]);
    let provider = agent.register(Box::new(Echo));
    let alice = admitted(&identity(b"alice-cert"));
    let cap = agent
        .mint_bound(&alice, provider, 0, CapAttrs::new(&["echo"]))
        .expect("cap");
    let lane = agent.create_lane("main", Budget::default()).expect("lane");
    let channel = agent
        .create_channel("ops", Direction::Both)
        .expect("channel");
    agent.subscribe(lane, channel).expect("subscribe");

    let error = agent
        .send_as(
            Some(alice.identity()),
            lane,
            channel,
            Value::text("x"),
            &[cap],
        )
        .expect_err("bound capabilities do not travel over channels");
    assert_eq!(error.code(), "rpc/identity");

    // A second peer may not even attempt the transfer.
    let unbound = agent
        .mint(provider, 0, CapAttrs::new(&["echo"]))
        .expect("unbound");
    agent
        .send(lane, channel, Value::text("y"), &[unbound])
        .expect("unbound transfer");
}

#[cfg(feature = "quic")]
#[test]
fn quic_mutual_tls_delivers_distinct_peer_identities_and_refuses_anonymous_clients() {
    use std::sync::mpsc;

    use active_rpc::Envelope;

    let (tx, rx) = mpsc::channel::<String>();
    let server =
        active_rpc::transport::quic::QuicServer::start_mutual_tls(2, move |envelope, peer| {
            let hex = peer
                .as_ref()
                .map(|identity| identity.fingerprint_hex())
                .unwrap_or_default();
            let _ = tx.send(hex.clone());
            Envelope::response(envelope.request_id, Value::text(hex))
        })
        .expect("start mutual-tls server");

    let address = server.address().to_string();
    let ca = server.ca_certificate().cloned().expect("ca");
    let (first_cert, first_key) = server.client_credentials().expect("client credentials");

    // A client without a certificate is refused by the handshake.
    let anonymous =
        active_rpc::transport::quic::QuicClient::connect(&address, server.certificate())
            .expect("anonymous client endpoint");
    let error = anonymous
        .call(&Envelope::request(1, "ping", vec![]))
        .expect_err("handshake must fail");
    assert!(matches!(error, active_rpc::Error::Transport(_)));
    drop(anonymous);

    let first_expected = PeerIdentity::from_certificate(first_cert.as_ref()).fingerprint_hex();
    let first = active_rpc::transport::quic::QuicClient::connect_mutual_tls(
        &address, &ca, first_cert, first_key,
    )
    .expect("first client");
    let response = first
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("first call");
    assert_eq!(
        response.first_value(),
        Some(&Value::text(first_expected.clone()))
    );

    let (second_cert, second_key) = server
        .issue_client_credentials("active-rpc client two")
        .expect("second credentials");
    let second_expected = PeerIdentity::from_certificate(second_cert.as_ref()).fingerprint_hex();
    assert_ne!(first_expected, second_expected);
    let second = active_rpc::transport::quic::QuicClient::connect_mutual_tls(
        &address,
        &ca,
        second_cert,
        second_key,
    )
    .expect("second client");
    let response = second
        .call(&Envelope::request(2, "ping", vec![]))
        .expect("second call");
    assert_eq!(
        response.first_value(),
        Some(&Value::text(second_expected.clone()))
    );

    let observed: Vec<String> = rx.iter().take(2).collect();
    assert_eq!(observed, vec![first_expected, second_expected]);
    server.shutdown();
}
