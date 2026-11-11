#![cfg(feature = "http-tls")]
//! RPC-38: the HTTP provider speaks `https://` via rustls with
//! operator-pinned roots, and carries operator-configured auth headers
//! (never from call args).
//!
//! The TLS stub mints a real test CA and leaf at runtime (rcgen), so no
//! test-only private key is committed: the CA is a CA (`IsCa::Ca`,
//! keyCertSign) and the leaf carries ServerAuth plus DNS `localhost` and
//! IP `127.0.0.1` SANs, so the chain is one a real verifier accepts. A
//! self-signed leaf pinned as its own root also verifies (measured by a
//! scratch probe: the handshake succeeds), so the CA-then-leaf shape is
//! used because it is the production shape — the leaf verifies through
//! the CA — not because a self-signed leaf fails.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use active_rpc::tool::HttpTool;
use active_rpc::{Arg, Call, Provider, Value};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn get_call() -> Call {
    Call::new("get", vec![Arg::Value(Value::path("/health"))])
}

fn text_of(response: active_rpc::value::Response) -> String {
    match response {
        active_rpc::value::Response::Value(Value::Text(text)) => text,
        other => panic!("unexpected response {other:?}"),
    }
}

/// A test CA plus a leaf, minted fresh per test run. `dns_only` issues a
/// leaf with only the `localhost` DNS SAN (no IP SAN) for the
/// hostname-mismatch leg; otherwise the leaf carries both SANs.
struct TestPki {
    ca_pem: String,
    leaf_chain: Vec<CertificateDer<'static>>,
    leaf_key: PrivateKeyDer<'static>,
}

fn test_pki(dns_only: bool) -> TestPki {
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = ca_params.self_signed(&ca_key).expect("CA cert");

    let leaf_key = KeyPair::generate().expect("leaf key");
    let sans = if dns_only {
        vec!["localhost".to_string()]
    } else {
        vec!["localhost".to_string(), "127.0.0.1".to_string()]
    };
    let mut leaf_params = CertificateParams::new(sans).expect("leaf params");
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("leaf cert");

    TestPki {
        ca_pem: ca.pem(),
        leaf_chain: vec![leaf.der().clone(), ca.der().clone()],
        // rcgen serialises ECDSA keys as PKCS#8.
        leaf_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

fn server_config(pki: &TestPki) -> Arc<rustls::ServerConfig> {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(pki.leaf_chain.clone(), pki.leaf_key.clone_key())
        .expect("test server cert");
    Arc::new(config)
}

/// A TLS stub: completes a rustls handshake with the test leaf, reads the
/// request head, and answers 200 `ok` — or 401 when `require_auth` and the
/// request carries no `authorization: Bearer probe-token`. The serving
/// thread is detached: it blocks on `accept` until the test process exits,
/// which is the same pattern the other HTTP stub tests use.
fn stub_tls(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    require_auth: bool,
) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(socket) = stream else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                continue;
            };
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            let mut complete = false;
            while buf.len() < 8192 {
                match tls.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            complete = true;
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            if !complete {
                continue;
            }
            let request = String::from_utf8_lossy(&buf)
                .into_owned()
                .to_ascii_lowercase();
            let authorized = request.contains("authorization: bearer probe-token");
            let (status, body) = if !require_auth || authorized {
                ("200 OK", "ok")
            } else {
                ("401 Unauthorized", "unauthorized")
            };
            let _ = tls.write_all(
                format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
            let _ = tls.flush();
        }
    });
    hits
}

/// A plain-HTTP stub with the same auth gate as `stub_tls`, for the
/// loopback carve-out leg: the credential is allowed over plaintext only
/// because the bytes never leave the host.
fn stub_plain_auth(listener: TcpListener) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut socket) = stream else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n])
                .into_owned()
                .to_ascii_lowercase();
            let authorized = request.contains("authorization: bearer probe-token");
            let (status, body) = if authorized {
                ("200 OK", "ok")
            } else {
                ("401 Unauthorized", "unauthorized")
            };
            let _ = socket.write_all(
                format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    });
    hits
}

/// A stub that accepts a TCP connection and then never sends a byte: the
/// handshake must time out under the call's wall grant, not hang the
/// dispatch thread.
fn stub_silent(listener: TcpListener) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(socket) = stream else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let counted = Arc::clone(&counted);
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(30));
                drop(socket);
                drop(counted);
            });
        }
    });
    hits
}

fn https_tool(port: u16, pki: &TestPki) -> HttpTool {
    let mut tool = HttpTool::try_new(format!("https://localhost:{port}"), &[("GET", "/health")])
        .expect("https");
    tool.pin_tls_roots(&pki.ca_pem).expect("pin the test CA");
    tool
}

/// FAIL-BEFORE leg (a), pass-after: an `https://` base reaches a TLS stub
/// when the test CA is pinned — the provider speaks TLS now.
#[test]
fn an_https_base_reaches_a_tls_stub_with_pinned_roots() {
    let pki = test_pki(false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_tls(listener, server_config(&pki), false);

    let mut tool = https_tool(port, &pki);
    let response = tool.invoke(0, &get_call()).expect("https dials");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
    assert_eq!(text_of(response), "ok");
}

/// The IP-literal leg: the server name is an IP address, so the leaf's IP
/// SAN — not its DNS SAN — is what verifies.
#[test]
fn an_https_base_reaches_a_tls_stub_by_ip_literal() {
    let pki = test_pki(false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_tls(listener, server_config(&pki), false);

    let mut tool = HttpTool::try_new(format!("https://127.0.0.1:{port}"), &[("GET", "/health")])
        .expect("https");
    tool.pin_tls_roots(&pki.ca_pem).expect("pin the test CA");
    let response = tool.invoke(0, &get_call()).expect("https dials by IP");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
    assert_eq!(text_of(response), "ok");
}

/// No pin, no dial: an `https://` call with no pinned root is refused with
/// `rpc/tool-policy` before any socket is opened — the adapter trusts no
/// root it was not explicitly given.
#[test]
fn an_https_call_without_pinned_roots_is_refused_before_any_dial() {
    let pki = test_pki(false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_tls(listener, server_config(&pki), false);

    let mut tool = HttpTool::try_new(format!("https://localhost:{port}"), &[("GET", "/health")])
        .expect("https");
    let error = tool
        .invoke(0, &get_call())
        .expect_err("no pinned root must refuse before any dial");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no connection may reach the stub"
    );
}

/// The pin is the trust: a server whose chain a different CA issued fails
/// the handshake with `http/tls`, after the TCP dial — the refusal is the
/// certificate, not the dial.
#[test]
fn a_wrong_pin_is_refused_with_http_tls() {
    let server_pki = test_pki(false);
    let client_pki = test_pki(false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_tls(listener, server_config(&server_pki), false);

    let mut tool = https_tool(port, &client_pki);
    let error = tool
        .invoke(0, &get_call())
        .expect_err("a wrong pin must fail the handshake");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert!(
        error
            .provider_code()
            .is_some_and(|code| code.starts_with("http/tls")),
        "the failure is the certificate, not the dial: {error:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the TCP dial happened; the handshake refused"
    );
}

/// The name must match the SAN class: a leaf with only the `localhost`
/// DNS SAN does not verify for the `127.0.0.1` IP server name.
#[test]
fn a_hostname_mismatch_is_refused_with_http_tls() {
    let pki = test_pki(true);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_tls(listener, server_config(&pki), false);

    let mut tool = HttpTool::try_new(format!("https://127.0.0.1:{port}"), &[("GET", "/health")])
        .expect("https");
    tool.pin_tls_roots(&pki.ca_pem).expect("pin the test CA");
    let error = tool
        .invoke(0, &get_call())
        .expect_err("an IP name against a DNS-only leaf must fail");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert!(
        error
            .provider_code()
            .is_some_and(|code| code.starts_with("http/tls")),
        "the failure is the name, not the dial: {error:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the TCP dial happened");
}

/// FAIL-BEFORE leg (b), pass-after: the protected endpoint answers 200
/// once the operator-configured `Authorization` header is sent — the
/// credential travels encrypted, and it was never in the URL or the body.
#[test]
fn an_auth_header_reaches_a_protected_endpoint_over_tls() {
    let pki = test_pki(false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_tls(listener, server_config(&pki), true);

    let mut tool = https_tool(port, &pki);
    tool.allow_header("Authorization", "Bearer probe-token")
        .expect("header");
    let response = tool.invoke(0, &get_call()).expect("auth over TLS");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
    assert_eq!(text_of(response), "ok");
}

/// The control for the leg above: the same protected endpoint 401s when
/// no header is configured — the header is what authenticates, and there
/// is no other path.
#[test]
fn a_protected_endpoint_still_401s_without_the_header() {
    let pki = test_pki(false);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_tls(listener, server_config(&pki), true);

    let mut tool = https_tool(port, &pki);
    let error = tool
        .invoke(0, &get_call())
        .expect_err("no header means no authentication");
    assert_eq!(
        error.provider_code(),
        Some("http/401"),
        "the stub refused for lack of a credential: {error:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
}

/// The loopback carve-out, end to end: the same credential over plain
/// HTTP to loopback is allowed, because the bytes never leave the host.
/// The non-loopback half of the rule is pinned by the
/// `plaintext_headers_allowed` unit tests plus the scratch probe on the
/// PC's LAN address — no non-loopback address is diallable in a portable
/// test.
#[test]
fn an_auth_header_reaches_a_loopback_endpoint_over_plaintext() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_plain_auth(listener);

    let mut tool = HttpTool::new(format!("http://127.0.0.1:{port}"), &[("GET", "/health")]);
    tool.allow_header("Authorization", "Bearer probe-token")
        .expect("header");
    let response = tool.invoke(0, &get_call()).expect("auth over loopback");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
    assert_eq!(text_of(response), "ok");
}

/// The public API validates headers the same way the lib unit tests pin:
/// the transport-managed names are refused, and a good header is accepted.
#[test]
fn header_configuration_is_validated_at_the_public_api() {
    let mut tool = HttpTool::new("http://127.0.0.1:80", &[("GET", "/health")]);
    for name in ["host", "Content-Length", "connection", "Transfer-Encoding"] {
        assert!(
            tool.allow_header(name, "x").is_err(),
            "{name} is transport-managed"
        );
    }
    assert_eq!(tool.allow_header("X-Api-Key", "k"), Ok(()));
}

/// `Debug` names the header and its length, and counts the pinned roots —
/// never the bearer token, never the PEM.
#[test]
fn debug_redacts_header_values_and_pinned_roots() {
    let pki = test_pki(false);
    let mut tool =
        HttpTool::try_new("https://localhost:8443", &[("GET", "/health")]).expect("https");
    tool.allow_header("Authorization", "Bearer probe-token")
        .expect("header");
    tool.pin_tls_roots(&pki.ca_pem).expect("pin");
    let debug = format!("{tool:?}");
    assert!(debug.contains("Authorization: <18 bytes>"), "{debug}");
    assert!(
        !debug.contains("probe-token"),
        "the value must never print: {debug}"
    );
    assert!(debug.contains("tls_roots: 1"), "{debug}");
    assert!(
        !debug.contains("BEGIN CERTIFICATE"),
        "roots print as a count: {debug}"
    );
}

/// The handshake is bounded by the call's wall deadline: a peer that
/// accepts TCP and never answers ServerHello is `rpc/timeout` at the
/// grant, not a hung dispatch thread. The base is the 127.0.0.1 literal,
/// not `localhost`: on this PC a connect to an unlistened loopback port
/// takes ~2 s to fail (SYN retries, no prompt RST — see the scratch
/// probe), so a `localhost` base (which resolves to [::1, 127.0.0.1])
/// with a 1500 ms grant burns the whole grant on the ::1 attempt and
/// never tries 127.0.0.1 — that is the pre-existing connect loop, not
/// the handshake, and the literal keeps this leg about the handshake.
#[test]
fn a_tls_server_that_never_answers_is_a_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_silent(listener);

    let pki = test_pki(false);
    let mut tool = HttpTool::try_new(format!("https://127.0.0.1:{port}"), &[("GET", "/health")])
        .expect("https");
    tool.pin_tls_roots(&pki.ca_pem).expect("pin the test CA");
    let mut call = get_call();
    call.budget.max_wall_ms = 1_500;
    let started = std::time::Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("a silent peer must time out");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        elapsed >= std::time::Duration::from_millis(1_000),
        "the wait ended at the deadline, not at once: {elapsed:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_millis(5_000),
        "the wait ended at the deadline, not past it: {elapsed:?}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
}

/// The dial policy runs before TLS: an `https://` base that resolves to a
/// refused address is `rpc/tool-policy`, never a handshake attempt.
#[test]
fn https_to_a_refused_address_is_still_a_policy_refusal() {
    let pki = test_pki(false);
    let mut tool =
        HttpTool::try_new("https://10.255.255.1:81", &[("GET", "/health")]).expect("https");
    tool.pin_tls_roots(&pki.ca_pem).expect("pin");
    let mut call = get_call();
    call.budget.max_wall_ms = 2_000;
    let error = tool
        .invoke(0, &call)
        .expect_err("10.255.255.1 must be refused before any dial");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// Userinfo stays refused for `https://`, exactly as for `http://`: a
/// credential in the URL is the hole this finding closes.
#[test]
fn an_https_base_with_userinfo_is_refused() {
    assert!(HttpTool::try_new("https://user:pass@127.0.0.1:8443", &[("GET", "/health")]).is_err());
}
