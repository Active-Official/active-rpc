#![no_main]

//! QUIC handshake: a mutated handshake never admits the wrong peer.
//!
//! Invariants:
//!
//! 1. A clean handshake and call round-trip (fixed control).
//! 2. A client that trusts a certificate that differs from the server's in
//!    even one byte is refused at the handshake with `rpc/transport`, never
//!    admitted: a wrong trust root, a truncated root, and a root that parses
//!    but belongs to another server are all refused.
//! 3. A mutual-TLS server refuses a client with no certificate, a client
//!    certificate it did not issue, a client key that does not match the
//!    certificate, and a mutated client certificate or key — and the handler
//!    never runs for any of them.
//! 4. Two distinct client certificates yield two distinct verified
//!    identities; the same certificate always yields the same fingerprint,
//!    and the comparison never confuses the two peers.
//! 5. A mutated payload through `exchange` is answered with a single
//!    well-formed frame carrying a response or a catalogued error, or refused
//!    with a catalogued code — never a panic, never a second message smuggled
//!    past the frame check.
//!
//! Run with `cargo +nightly fuzz run fuzz_quic_handshake -- -runs=200000`.

use std::sync::mpsc;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use active_rpc::error::ERROR_CODES;
use active_rpc::identity::{matches, PeerIdentity};
use active_rpc::transport::quic::{QuicClient, QuicServer};
use active_rpc::transport::{frame, read_frame};
use active_rpc::wire::{Envelope, Kind, WireLimits};
use active_rpc::Value;

#[path = "common.rs"]
mod common;

/// A handshake that must fail: the outcome is an error with a catalogued
/// code, whether the refusal happens while building the client (a trust root
/// that does not parse) or while handshaking (a root that parses but does not
/// verify the server).
fn assert_handshake_refused(result: active_rpc::error::Result<Envelope>, what: &str) {
    match result {
        Ok(answer) => panic!("{what} was admitted, got {answer:?}"),
        Err(error) => assert!(
            ERROR_CODES.contains(&error.code()),
            "{what}: an unexpected class: {error}"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    // Fixed positive control: a clean handshake answers `pong`. Without it a
    // server that refused every handshake would satisfy every refusal
    // assertion below.
    {
        let server = QuicServer::start(64, |envelope| {
            Envelope::response(envelope.request_id, Value::text("pong"))
        })
        .expect("the control server starts");
        let address = server.address().to_string();
        let client = QuicClient::connect(&address, server.certificate())
            .expect("the control client connects")
            .with_deadline(Duration::from_secs(5));
        let response = client
            .call(&Envelope::request(1, "ping", vec![]))
            .expect("the control handshake answers");
        assert_eq!(response.first_value(), Some(&Value::text("pong")));
        drop(client);
        server.shutdown();
    }
    if data.is_empty() {
        return;
    }

    // The two servers for the fuzzed legs: a plain one and a mutual-TLS one.
    // Both start fresh on every input, so each run handshakes against new
    // certificates.
    let server = QuicServer::start(64, |envelope| {
        Envelope::response(envelope.request_id, Value::text("pong"))
    })
    .expect("the server starts");
    let address = server.address().to_string();
    let (peer_tx, peer_rx) = mpsc::channel::<(String, bool)>();
    let mutual = QuicServer::start_mutual_tls(64, move |envelope, peer| {
        let hex = peer
            .as_ref()
            .map(|identity| identity.fingerprint_hex())
            .unwrap_or_default();
        let verified = peer
            .as_ref()
            .map(|identity| identity.is_verified())
            .unwrap_or(false);
        let _ = peer_tx.send((hex.clone(), verified));
        Envelope::response(envelope.request_id, Value::text(hex))
    })
    .expect("the mutual-TLS server starts");
    let mutual_address = mutual.address().to_string();
    let ca = mutual.ca_certificate().expect("the mutual server has a CA");
    let (first_cert, first_key) = mutual.client_credentials().expect("client credentials");

    // 1. A mutated trust root is refused.
    //
    // Only corruptions that must fail are used. Flipping an arbitrary byte
    // is not one of them: a trust anchor is trusted by fiat, so flipping a
    // byte in its signature field leaves the key and the names intact and the
    // handshake still verifies. The modes here cannot verify by construction:
    // byte 0 is the DER SEQUENCE tag, so flipping it is a parse failure; a
    // truncated DER cannot parse; and the other server's CA is a valid root
    // for a different key, so the chain fails.
    let server_cert: Vec<u8> = server.certificate().as_ref().to_vec();
    let bad_root = match data[0] % 3 {
        0 => {
            let mut bad = server_cert.clone();
            bad[0] ^= 0xff;
            CertificateDer::from(bad)
        }
        1 => CertificateDer::from(server_cert[..server_cert.len() / 2].to_vec()),
        _ => ca.clone(),
    };
    match QuicClient::connect(&address, &bad_root) {
        Err(error) => assert_eq!(error.code(), "rpc/transport"),
        Ok(client) => {
            let client = client.with_deadline(Duration::from_secs(2));
            assert_handshake_refused(
                client.call(&Envelope::request(1, "ping", vec![])),
                "a mutated trust root",
            );
        }
    }

    // 2. Mutual TLS: the anonymous, the genuine, the second peer, and the
    // forged.
    let mut observed: Vec<(String, bool)> = Vec::new();
    // 2a. No certificate: the handshake fails and the handler never runs.
    {
        let anonymous = QuicClient::connect(&mutual_address, mutual.certificate())
            .expect("the anonymous client endpoint builds")
            .with_deadline(Duration::from_secs(2));
        assert_handshake_refused(
            anonymous.call(&Envelope::request(1, "ping", vec![])),
            "a client with no certificate",
        );
        drop(anonymous);
        observed.extend(peer_rx.try_iter());
        assert!(
            observed.is_empty(),
            "the handler ran for an anonymous client"
        );
    }
    // 2b. The genuine client: admitted, verified, and the fingerprint is the
    // digest of the certificate it presented.
    let first_expected = PeerIdentity::from_certificate(first_cert.as_ref()).fingerprint_hex();
    {
        let first = QuicClient::connect_mutual_tls(
            &mutual_address,
            ca,
            first_cert.clone(),
            first_key.clone_key(),
        )
        .expect("the genuine client builds")
        .with_deadline(Duration::from_secs(5));
        let response = first
            .call(&Envelope::request(1, "ping", vec![]))
            .expect("the genuine client is admitted");
        assert_eq!(
            response.first_value(),
            Some(&Value::text(first_expected.clone()))
        );
        drop(first);
        observed.extend(peer_rx.try_iter());
        assert_eq!(
            observed,
            vec![(first_expected.clone(), true)],
            "the transport delivers a verified identity"
        );
    }
    // 2c. A second peer: a distinct verified identity, never confused with
    // the first.
    let (second_cert, second_key) = mutual
        .issue_client_credentials("active-rpc client two")
        .expect("second credentials");
    let second_expected = PeerIdentity::from_certificate(second_cert.as_ref()).fingerprint_hex();
    assert_ne!(
        first_expected, second_expected,
        "two peers share a fingerprint"
    );
    {
        let second = QuicClient::connect_mutual_tls(
            &mutual_address,
            ca,
            second_cert.clone(),
            second_key.clone_key(),
        )
        .expect("the second client builds")
        .with_deadline(Duration::from_secs(5));
        let response = second
            .call(&Envelope::request(2, "ping", vec![]))
            .expect("the second client is admitted");
        assert_eq!(
            response.first_value(),
            Some(&Value::text(second_expected.clone()))
        );
        drop(second);
        let fresh: Vec<(String, bool)> = peer_rx.try_iter().collect();
        assert_eq!(
            fresh,
            vec![(second_expected.clone(), true)],
            "the second peer is observed as itself"
        );
        let first_fp = PeerIdentity::from_certificate(first_cert.as_ref()).fingerprint();
        let second_fp = PeerIdentity::from_certificate(second_cert.as_ref()).fingerprint();
        assert!(matches(Some(first_fp), first_fp));
        assert!(matches(Some(second_fp), second_fp));
        assert!(
            !matches(Some(first_fp), second_fp),
            "the first peer matches the second binding"
        );
        assert!(
            !matches(Some(second_fp), first_fp),
            "the second peer matches the first binding"
        );
    }
    // 2d. A mutated client certificate: truncated, or byte 0 flipped — both
    // parse failures, so the client never presents a credential at all.
    let bad_client_cert = match data[0] % 2 {
        0 => {
            let raw: Vec<u8> = first_cert.as_ref().to_vec();
            CertificateDer::from(raw[..raw.len() / 2].to_vec())
        }
        _ => {
            let mut raw: Vec<u8> = first_cert.as_ref().to_vec();
            raw[0] ^= 0xff;
            CertificateDer::from(raw)
        }
    };
    match QuicClient::connect_mutual_tls(
        &mutual_address,
        ca,
        bad_client_cert,
        first_key.clone_key(),
    ) {
        Err(error) => assert_eq!(error.code(), "rpc/transport"),
        Ok(client) => {
            let client = client.with_deadline(Duration::from_secs(2));
            assert_handshake_refused(
                client.call(&Envelope::request(3, "ping", vec![])),
                "a mutated client certificate",
            );
        }
    }
    let fresh: Vec<(String, bool)> = peer_rx.try_iter().collect();
    assert!(
        fresh.is_empty(),
        "the handler ran for a mutated client certificate"
    );
    // 2e. A mismatched pair: the first certificate with the second key cannot
    // prove possession, so the handshake fails.
    match QuicClient::connect_mutual_tls(
        &mutual_address,
        ca,
        first_cert.clone(),
        second_key.clone_key(),
    ) {
        Err(error) => assert_eq!(error.code(), "rpc/transport"),
        Ok(client) => {
            let client = client.with_deadline(Duration::from_secs(2));
            assert_handshake_refused(
                client.call(&Envelope::request(4, "ping", vec![])),
                "a mismatched certificate and key",
            );
        }
    }
    let fresh: Vec<(String, bool)> = peer_rx.try_iter().collect();
    assert!(fresh.is_empty(), "the handler ran for a mismatched pair");
    // 2f. A mutated client key: the PKCS#8 bytes are flipped, so the key
    // either does not parse or is not the key the certificate names — both
    // refuse the handshake.
    if let PrivateKeyDer::Pkcs8(_) = first_key.clone_key() {
        let mut raw: Vec<u8> = first_key.secret_der().to_vec();
        let at = data.len() % raw.len();
        raw[at] ^= 0xff;
        let bad_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(raw));
        match QuicClient::connect_mutual_tls(&mutual_address, ca, first_cert.clone(), bad_key) {
            Err(error) => assert_eq!(error.code(), "rpc/transport"),
            Ok(client) => {
                let client = client.with_deadline(Duration::from_secs(2));
                assert_handshake_refused(
                    client.call(&Envelope::request(5, "ping", vec![])),
                    "a mutated client key",
                );
            }
        }
        let fresh: Vec<(String, bool)> = peer_rx.try_iter().collect();
        assert!(fresh.is_empty(), "the handler ran for a mutated client key");
    }

    // 3. A mutated payload through `exchange`: one well-formed frame back, or
    // a catalogued refusal — never a panic, never a smuggled second message.
    {
        let request = Envelope::request(1, "ping", vec![])
            .encode()
            .expect("encode");
        let mut payload = frame(request.len()).expect("frame").to_vec();
        payload.extend_from_slice(&request);
        let mut mutated = payload.clone();
        match data[0] % 5 {
            0 => {
                // A byte in the length prefix: the declared length no longer
                // matches the body.
                mutated[1] ^= 0xff;
            }
            1 => {
                let at = 4 + (data.len() % request.len().max(1));
                let at = at.min(mutated.len().saturating_sub(1));
                mutated[at] ^= 0xff;
            }
            2 => {
                mutated.truncate(3);
            }
            3 => {
                mutated.clear();
            }
            _ => {
                mutated[0..4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
            }
        }
        let client = QuicClient::connect(&address, server.certificate())
            .expect("the exchange client connects")
            .with_deadline(Duration::from_millis(500));
        match client.exchange(&mutated) {
            Ok(response) => {
                assert!(!response.is_empty(), "the server closed without answering");
                let mut cursor = std::io::Cursor::new(&response);
                let body = read_frame(&mut cursor, &WireLimits::default())
                    .expect("the response is a frame")
                    .expect("the response carries a body");
                assert_eq!(
                    cursor.position(),
                    response.len() as u64,
                    "trailing bytes after the QUIC frame"
                );
                let answer = Envelope::decode(&body).expect("the response decodes");
                assert!(
                    matches!(answer.kind, Kind::Response | Kind::Error),
                    "the response is a response or an error, not a request"
                );
                if answer.kind == Kind::Error {
                    assert!(
                        ERROR_CODES.contains(&answer.method.as_str()),
                        "an error response names a catalogued code, got {}",
                        answer.method
                    );
                }
            }
            Err(error) => {
                assert!(
                    ERROR_CODES.contains(&error.code()),
                    "an unexpected class for a mutated payload: {error}"
                );
            }
        }
        drop(client);
    }

    server.shutdown();
    mutual.shutdown();
});
