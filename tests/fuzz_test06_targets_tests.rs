//! Regression gates for TEST-06 (fuzz coverage holes in the highest-risk paths).
//!
//! The finding's fix is three new fuzz targets (`fuzz_quic_handshake`,
//! `fuzz_tcp_framing`, `fuzz_identity_binding`) plus the `common::secret`
//! empty-seed fix (F-R20-3). This file pins them the way
//! `fuzz_domain_module_oracle_tests.rs` pins RPC-26: static gates over the
//! target sources (so a target that stops driving its surface fails here),
//! contract tests for the harness helper, and control-validity probes that
//! drive the same calls the targets' fixed controls drive, through the real
//! production code — so a control that only ever refused would fail here
//! instead of passing silently in the campaign.

use std::path::PathBuf;

use active_rpc::identity::{IdentityPolicy, PeerIdentity};
use active_rpc::{Budget, Value};

#[path = "../fuzz/fuzz_targets/common.rs"]
mod common;

fn target_source(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("fuzz_targets")
        .join(format!("{name}.rs"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "TEST-06: fuzz target {name} does not exist at {}",
            path.display()
        )
    })
}

fn stripped(source: &str) -> String {
    source.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn assert_tokens(name: &str, source: &str, tokens: &[&str]) {
    let squashed = stripped(source);
    for token in tokens {
        assert!(
            squashed.contains(token),
            "TEST-06: {name} does not drive {token} — the target no longer covers its surface"
        );
    }
}

#[test]
fn quic_handshake_target_drives_the_handshake() {
    let source = target_source("fuzz_quic_handshake");
    assert_tokens(
        "fuzz_quic_handshake",
        &source,
        &[
            "QuicServer::start",
            "QuicClient::connect",
            "start_mutual_tls",
            "connect_mutual_tls",
            "exchange(",
        ],
    );
}

#[test]
fn tcp_framing_target_drives_tcp_transport() {
    let source = target_source("fuzz_tcp_framing");
    assert_tokens(
        "fuzz_tcp_framing",
        &source,
        &[
            "TcpTransport::connect_with_timeout",
            "read_frame",
            "serve_connection_within",
            "bind_loopback",
            "rpc/wire",
        ],
    );
}

#[test]
fn identity_binding_target_drives_admit_and_intro() {
    let source = target_source("fuzz_identity_binding");
    assert_tokens(
        "fuzz_identity_binding",
        &source,
        &[
            "IdentityPolicy",
            "admit",
            "intro::build",
            "from_certificate",
            "matches",
            "bindable",
        ],
    );
}

/// F-R20-3: `common::secret` cycled an empty seed into the all-zero secret, so
/// any target that called `common::agent(data)` on empty input built a
/// zero-secret kernel. Every target guards empty input first, so the bug was
/// latent — but a helper that cannot produce a zero secret removes the hazard
/// class entirely instead of relying on every caller remembering the guard.
#[test]
fn empty_seed_does_not_build_a_zero_secret_kernel() {
    assert_ne!(
        common::secret(b""),
        [0u8; 32],
        "TEST-06 (F-R20-3): an empty seed still expands to the all-zero secret"
    );
}

#[test]
fn empty_seed_secret_is_deterministic_and_documented() {
    assert_eq!(
        common::secret(b""),
        common::secret(b""),
        "TEST-06 (F-R20-3): the empty-seed fallback must be deterministic"
    );
    assert_eq!(
        common::secret(b""),
        common::secret(b"fuzz-empty-seed"),
        "TEST-06 (F-R20-3): the empty-seed fallback is the documented constant seed"
    );
}

#[test]
fn nonempty_seeds_expand_exactly_as_before() {
    assert_eq!(common::secret(&[0x06]), [0x06; 32]);
    let pair = common::secret(&[0x01, 0x02]);
    assert_eq!(
        pair,
        [
            0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
            0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02, 0x01, 0x02,
            0x01, 0x02, 0x01, 0x02
        ]
    );
}

/// The `fuzz_quic_handshake` fixed control, driven here so a control that only
/// ever refused would fail in the suite instead of passing silently in the
/// campaign: a clean handshake must answer `pong`.
#[cfg(feature = "quic")]
#[test]
fn quic_plain_handshake_round_trips() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    use active_rpc::wire::Envelope;

    let server = QuicServer::start(64, |envelope| {
        Envelope::response(envelope.request_id, Value::text("pong"))
    })
    .expect("server starts");
    let address = server.address().to_string();
    let client = QuicClient::connect(&address, server.certificate()).expect("client connects");
    let response = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("the clean handshake answers");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));
    drop(client);
    server.shutdown();
}

/// The `fuzz_quic_handshake` mutated-certificate leg, pinned from the test
/// side: a trust root that differs from the server's certificate in even one
/// byte must refuse the handshake with `rpc/transport`, never admit the peer.
/// Byte 0 is the DER SEQUENCE tag, so flipping it is a parse failure, not a
/// mutation the verifier could accept (see the target's comment on why an
/// arbitrary-offset flip is not used here).
#[cfg(feature = "quic")]
#[test]
fn quic_wrong_trust_root_is_refused() {
    use active_rpc::transport::quic::{QuicClient, QuicServer};
    use active_rpc::wire::Envelope;

    let server = QuicServer::start(64, |envelope| {
        Envelope::response(envelope.request_id, Value::text("pong"))
    })
    .expect("server starts");
    let address = server.address().to_string();
    let mut bad: Vec<u8> = server.certificate().as_ref().to_vec();
    bad[0] ^= 0xff;
    let bad = rustls::pki_types::CertificateDer::from(bad);
    match QuicClient::connect(&address, &bad) {
        Err(error) => assert_eq!(error.code(), "rpc/transport"),
        Ok(client) => {
            let error = client
                .call(&Envelope::request(1, "ping", vec![]))
                .expect_err("a wrong trust root must refuse the handshake");
            assert_eq!(error.code(), "rpc/transport");
        }
    }
    server.shutdown();
}

/// The `fuzz_tcp_framing` fixed control, driven here: a clean loopback call
/// over `TcpTransport` must answer `pong`.
#[test]
fn tcp_loopback_call_round_trips() {
    use std::time::Duration;

    use active_rpc::transport::{bind_loopback, serve_connection_within, TcpTransport};
    use active_rpc::wire::Envelope;

    let (listener, address) = bind_loopback().expect("listener binds");
    let served = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let transport =
            TcpTransport::with_timeout(stream, Duration::from_secs(2)).expect("wrap stream");
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        serve_connection_within(
            transport,
            |envelope| Envelope::response(envelope.request_id, Value::text("pong")),
            Some(deadline),
        )
        .expect("serve")
    });
    let mut client =
        TcpTransport::connect_with_timeout(&address, Duration::from_secs(2)).expect("connect");
    let response = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect("the clean call answers");
    assert_eq!(response.first_value(), Some(&Value::text("pong")));
    drop(client);
    assert_eq!(served.join().expect("server thread"), 1);
}

/// The `fuzz_tcp_framing` id-mismatch leg, pinned from the test side: a peer
/// that answers another request's id must be refused with `rpc/wire`, never
/// handed to the caller as this call's result.
#[test]
fn tcp_answer_for_another_request_is_refused() {
    use std::io::Read;
    use std::time::Duration;

    use active_rpc::transport::{bind_loopback, read_frame, write_frame, TcpTransport};
    use active_rpc::wire::{Envelope, WireLimits};

    let (listener, address) = bind_loopback().expect("listener binds");
    let served = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let body = read_frame(&mut stream, &WireLimits::default())
            .expect("read frame")
            .expect("a frame");
        let request = Envelope::decode(&body).expect("decode request");
        let wrong = Envelope::response(request.request_id + 1, Value::text("pong"));
        write_frame(&mut stream, &wrong.encode().expect("encode")).expect("write reply");
        let _ = stream.read(&mut [0u8; 1]);
    });
    let mut client =
        TcpTransport::connect_with_timeout(&address, Duration::from_secs(2)).expect("connect");
    let error = client
        .call(&Envelope::request(1, "ping", vec![]))
        .expect_err("an answer for another request must be refused");
    assert_eq!(error.code(), "rpc/wire");
    drop(client);
    served.join().expect("server thread");
}

/// The `fuzz_identity_binding` fixed control, driven here: the admit matrix
/// admits loopback under a loopback-trusting policy, refuses anonymous peers
/// under `strict()` off loopback, and never produces a verified identity or a
/// bindable admission from the constructors a peer can reach.
#[test]
fn identity_admit_matrix_spot_checks() {
    use active_rpc::identity::{bindable, matches, presented_fingerprint};

    let loopback = PeerIdentity::loopback();
    let anonymous = PeerIdentity::anonymous();
    let claim = PeerIdentity::from_certificate(b"fixed-cert-bytes");

    assert!(
        !claim.is_verified(),
        "an unverified claim must not be verified"
    );
    assert_eq!(
        claim.not_after(),
        None,
        "an unverified claim asserts no expiry"
    );
    assert!(
        !claim.is_expired_at(u64::MAX),
        "an unverified claim never expires"
    );
    assert_eq!(
        claim.fingerprint(),
        claim.fingerprint(),
        "the fingerprint is stable"
    );
    assert_eq!(
        claim.fingerprint_hex().len(),
        64,
        "the fingerprint hex is 32 bytes"
    );
    assert!(
        bindable(claim.fingerprint()),
        "a real certificate digest is bindable"
    );
    assert!(
        !bindable([0u8; 32]),
        "the all-zero fingerprint is not bindable"
    );
    assert!(
        !bindable(loopback.fingerprint()),
        "the loopback fingerprint is not bindable"
    );
    assert!(matches(Some(claim.fingerprint()), claim.fingerprint()));
    assert!(!matches(Some(claim.fingerprint()), loopback.fingerprint()));
    assert!(!matches(None, claim.fingerprint()));
    assert_eq!(
        presented_fingerprint(Some(&claim)),
        Some(claim.fingerprint())
    );
    assert_eq!(presented_fingerprint(Some(&anonymous)), None);
    assert_eq!(presented_fingerprint(None), None);

    let admitted = IdentityPolicy::local()
        .admit(None, true)
        .expect("loopback admits under local()");
    assert_eq!(
        admitted.trust(),
        active_rpc::identity::TrustLevel::LoopbackRelaxed
    );
    assert!(
        !admitted.can_bind(),
        "a loopback admission cannot hold a binding"
    );
    let error = IdentityPolicy::strict()
        .admit(Some(&anonymous), false)
        .expect_err("anonymous off loopback is refused under strict()");
    assert_eq!(error.code(), "rpc/identity");
    let error = IdentityPolicy::strict()
        .admit(Some(&claim), true)
        .expect_err("an unverified certificate claim is refused under every policy");
    assert_eq!(error.code(), "rpc/identity");
    let error = IdentityPolicy::local()
        .admit(Some(&claim), true)
        .expect_err("an unverified certificate claim is refused under local() too");
    assert_eq!(error.code(), "rpc/identity");
}

/// The `fuzz_identity_binding` introduction leg, pinned here: the module an
/// introduction builds is canonical — the same surface always builds the same
/// bytes regardless of input order, and it decodes and re-encodes to itself.
#[test]
fn intro_build_is_canonical_and_order_independent() {
    let providers = vec![
        ("beta".to_string(), vec!["m2".to_string(), "m1".to_string()]),
        ("alpha".to_string(), vec!["z".to_string(), "a".to_string()]),
    ];
    let first =
        active_rpc::intro::build("test-peer", &providers, &Budget::default()).expect("build");
    let again =
        active_rpc::intro::build("test-peer", &providers, &Budget::default()).expect("rebuild");
    assert_eq!(first, again, "the same surface must build the same bytes");
    let mut reversed = providers.clone();
    reversed.reverse();
    let shuffled =
        active_rpc::intro::build("test-peer", &reversed, &Budget::default()).expect("rebuild");
    assert_eq!(first, shuffled, "provider order must not change the bytes");
    let decoded = active_infinity::decode(&first).expect("decode");
    let reencoded = active_infinity::encode(&decoded).expect("re-encode");
    assert_eq!(
        first, reencoded,
        "the introduction must round-trip canonically"
    );

    let long = "p".repeat(1025);
    let error = active_rpc::intro::build(&long, &providers, &Budget::default())
        .expect_err("a peer name over 1024 bytes is refused");
    assert_eq!(error.code(), "rpc/invalid-argument");
    let error = active_rpc::intro::build("bad\nname", &providers, &Budget::default())
        .expect_err("a peer name with a control character is refused");
    assert_eq!(error.code(), "rpc/invalid-argument");
    let huge = Budget {
        max_calls: u64::MAX,
        ..Budget::default()
    };
    let error = active_rpc::intro::build("test-peer", &providers, &huge)
        .expect_err("a ceiling that does not fit the module integer is refused");
    assert_eq!(error.code(), "rpc/invalid-argument");
}
