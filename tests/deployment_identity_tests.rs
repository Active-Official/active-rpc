#![cfg(feature = "quic")]

//! Deployment identity: a CA that the deployment owns, a server certificate
//! issued by it, and mutual TLS rooted at it.
//!
//! The test CA in `identity_tests` is generated in-process; this file proves the
//! shipped `start_with_identity` path works with certificates a deployment
//! supplies, that a client from another CA is refused, and that identity stays
//! stable across a soak of many connections.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use active_rpc::transport::quic::{QuicClient, QuicServer, ServerIdentity};
use active_rpc::wire::Envelope;
use active_rpc::PeerIdentity;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct Authority {
    certificate: Certificate,
    key: KeyPair,
}

fn authority(common_name: &str) -> Authority {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    params.distinguished_name = name;
    let key = KeyPair::generate().expect("ca key");
    let certificate = params.self_signed(&key).expect("ca certificate");
    Authority { certificate, key }
}

impl Authority {
    fn leaf(&self, common_name: &str, san: &[&str]) -> (Certificate, KeyPair) {
        let mut params =
            CertificateParams::new(san.iter().map(|name| name.to_string()).collect::<Vec<_>>())
                .expect("leaf params");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        params.distinguished_name = name;
        let key = KeyPair::generate().expect("leaf key");
        let certificate = params
            .signed_by(&key, &self.certificate, &self.key)
            .expect("leaf certificate");
        (certificate, key)
    }
}

fn key_der(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

fn echo_peer(envelope: &Envelope, peer: Option<PeerIdentity>) -> Envelope {
    let hex = peer
        .as_ref()
        .map(PeerIdentity::fingerprint_hex)
        .unwrap_or_default();
    Envelope::response(envelope.request_id, active_rpc::Value::Text(hex))
}

#[test]
fn a_deployment_ca_issues_the_server_and_authenticates_clients() {
    let ca = authority("Active RPC deployment CA");
    let (server_cert, server_key) = ca.leaf("active-rpc server", &["localhost", "127.0.0.1"]);
    let (client_cert, client_key) = ca.leaf("active-rpc client", &["client.active-rpc"]);

    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind address");
    let identity = ServerIdentity {
        chain: vec![server_cert.der().clone()],
        key: key_der(&server_key),
    };
    let server = QuicServer::start_with_identity(
        64,
        move |envelope, peer| {
            counter.fetch_add(1, Ordering::SeqCst);
            echo_peer(&envelope, peer)
        },
        bind,
        identity,
        Some(ca.certificate.der().clone()),
    )
    .expect("start with a deployment identity");
    let address = server.address().to_string();
    assert_eq!(
        server.ca_certificate().map(CertificateDer::as_ref),
        Some(ca.certificate.der().as_ref())
    );

    let expected = PeerIdentity::from_certificate(client_cert.der().as_ref()).fingerprint_hex();
    let client = QuicClient::connect_mutual_tls(
        &address,
        ca.certificate.der(),
        client_cert.der().clone(),
        key_der(&client_key),
    )
    .expect("client trusts the deployment CA");
    let response = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("call");
    assert_eq!(
        response.first_value(),
        Some(&active_rpc::Value::Text(expected.clone()))
    );

    // A second CA is a different trust domain: its client cannot connect.
    let other_ca = authority("Another CA");
    let (other_cert, other_key) = other_ca.leaf("stranger", &["stranger.active-rpc"]);
    let stranger = QuicClient::connect_mutual_tls(
        &address,
        other_ca.certificate.der(),
        other_cert.der().clone(),
        key_der(&other_key),
    )
    .expect("client endpoint");
    let error = stranger
        .call(&Envelope::request(2, "ping", vec![]))
        .expect_err("a certificate from another CA must be refused");
    assert!(
        matches!(error, active_rpc::Error::Transport(_)),
        "{error:?}"
    );
    drop(stranger);

    // Soak: many sequential connections, each authenticated as the same peer.
    for id in 3..28u64 {
        let client = QuicClient::connect_mutual_tls(
            &address,
            ca.certificate.der(),
            client_cert.der().clone(),
            key_der(&client_key),
        )
        .expect("reconnect");
        let response = client
            .call(&Envelope::request(id, "ping", vec![]))
            .expect("call");
        assert_eq!(
            response.first_value(),
            Some(&active_rpc::Value::Text(expected.clone())),
            "identity drifted on call {id}"
        );
    }
    assert_eq!(served.load(Ordering::SeqCst), 26);
    server.shutdown();
}

#[test]
fn an_identity_without_a_chain_is_refused() {
    let bind: SocketAddr = "127.0.0.1:0".parse().expect("bind address");
    let error = QuicServer::start_with_identity(
        1,
        |envelope, _peer| Envelope::response(envelope.request_id, active_rpc::Value::Null),
        bind,
        ServerIdentity {
            chain: Vec::new(),
            key: key_der(&KeyPair::generate().expect("key")),
        },
        None,
    )
    .expect_err("an empty chain must be refused");
    assert!(
        matches!(error, active_rpc::Error::Transport(_)),
        "{error:?}"
    );
}
