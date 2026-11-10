//! RPC-32: the HTTP provider dials any resolvable internal name with no IP
//! allowlist, and resolution time is not charged to the call budget.
//!
//! Default dial policy (see `HttpTool`): a resolved address is dialled only
//! when it is globally routable, or loopback (the loopback carve-out the
//! repo's own stub servers and loopback deployments rely on). Every other
//! resolved address — private, link-local (including the cloud-metadata
//! address 169.254.169.254), shared, unspecified, multicast, reserved,
//! documentation, benchmarking, and the IPv6 translation/tunnel prefixes —
//! is refused with `rpc/tool-policy` before any socket is opened, unless
//! the operator explicitly opts in with `with_allow_non_public(true)`.
//! A name that resolves to a mix of allowed and refused addresses is
//! refused whole: one refused record poisons the call, so a rebinding
//! retarget cannot smuggle a private address past the check on a later
//! address in the list.

use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use active_rpc::tool::HttpTool;
use active_rpc::{Arg, Call, Provider, Value};

/// A stub that answers `ok` to every connection and counts how many
/// connections arrived. The serving thread is detached: it blocks on
/// `accept` until the test process exits, which is the same pattern the
/// verification probes use.
fn stub_ok(listener: TcpListener) -> Arc<AtomicUsize> {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut socket) = stream else { continue };
            counted.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf);
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        }
    });
    hits
}

fn get_call() -> Call {
    Call::new("get", vec![Arg::Value(Value::path("/health"))])
}

/// The loopback carve-out: `localhost` still dials by default. This is the
/// control for the refusals below — the fix must not break the loopback
/// deployments and stub servers the whole suite relies on.
#[test]
fn a_loopback_name_still_dials_by_default() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_ok(listener);

    let mut tool = HttpTool::new(format!("http://localhost:{port}"), &[("GET", "/health")]);
    let response = tool.invoke(0, &get_call()).expect("localhost dials");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
    match response {
        active_rpc::value::Response::Value(Value::Text(text)) => assert_eq!(text, "ok"),
        other => panic!("unexpected response {other:?}"),
    }
}

/// The same carve-out for a loopback literal.
#[test]
fn a_loopback_literal_still_dials_by_default() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_ok(listener);

    let mut tool = HttpTool::new(format!("http://127.0.0.1:{port}"), &[("GET", "/health")]);
    tool.invoke(0, &get_call()).expect("127.0.0.1 dials");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the stub was hit once");
}

// An IPv4-mapped loopback literal spells the same address as 127.0.0.1
// through the IPv6 form, so the classifier must see through the mapping:
// that property is pinned by the unit tests in `src/tool.rs`, not here,
// because the transport itself cannot dial a mapped address on this
// host (Windows refuses the connect with `http/connect`), so an
// end-to-end dial of one is platform-dependent and proves nothing about
// the policy.

/// FAIL-BEFORE (RPC-32 leg a): `0.0.0.0` is the unspecified address. On
/// this host a connect to it reaches the loopback stub, so before the fix
/// the call succeeds and the stub is hit; after the fix the call is
/// refused with `rpc/tool-policy` and the stub is never hit.
#[test]
fn an_unspecified_address_is_refused_before_any_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_ok(listener);

    let mut tool = HttpTool::new(format!("http://0.0.0.0:{port}"), &[("GET", "/health")]);
    let error = tool
        .invoke(0, &get_call())
        .expect_err("0.0.0.0 must be refused before any dial");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no connection may reach the stub"
    );
}

/// FAIL-BEFORE (RPC-32 leg a): an RFC 1918 literal is refused without an
/// operator opt-in. No server is needed: the refusal is decided from the
/// resolved address, before any socket is opened.
#[test]
fn a_private_literal_is_refused_without_an_opt_in() {
    let mut tool = HttpTool::new("http://10.255.255.1:81", &[("GET", "/health")]);
    let mut call = get_call();
    call.budget.max_wall_ms = 2_000;
    let error = tool
        .invoke(0, &call)
        .expect_err("10.255.255.1 must be refused before any dial");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// FAIL-BEFORE (RPC-32 leg a): the cloud-metadata address is link-local
/// and is refused the same way. This is the rebinding target the finding
/// names: a name retargeted at 169.254.169.254 must never be dialled.
#[test]
fn a_link_local_metadata_address_is_refused() {
    let mut tool = HttpTool::new("http://169.254.169.254:80", &[("GET", "/health")]);
    let mut call = get_call();
    call.budget.max_wall_ms = 2_000;
    let error = tool
        .invoke(0, &call)
        .expect_err("169.254.169.254 must be refused before any dial");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// FAIL-BEFORE (RPC-32 leg a): an IPv4-mapped private literal must be
/// classified by the IPv4 it spells, not by the IPv6 form that carries
/// it. `::ffff:10.0.0.1` is 10.0.0.1 and is refused.
#[test]
fn an_ipv4_mapped_private_literal_is_refused() {
    let mut tool = HttpTool::new("http://[::ffff:10.0.0.1]:81", &[("GET", "/health")]);
    let mut call = get_call();
    call.budget.max_wall_ms = 2_000;
    let error = tool
        .invoke(0, &call)
        .expect_err("::ffff:10.0.0.1 must be refused before any dial");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// The operator opt-in: a tool pointed deliberately at an internal
/// endpoint passes the policy gate, and the dial is attempted — the
/// refusal, if any, comes from the transport, not the policy. The test
/// asserts the error is a transport outcome (`rpc/provider` for a
/// refused connect, `rpc/timeout` if the address blackholes), never
/// `rpc/tool-policy`. No non-public address is diallable on every host —
/// `0.0.0.0` does not reach loopback on Windows — so a real server
/// behind the opt-in is proven by the scratch probe on the PC instead,
/// which binds a stub on the LAN address.
#[test]
fn an_operator_opt_in_passes_the_policy_gate() {
    let mut tool =
        HttpTool::new("http://10.255.255.1:81", &[("GET", "/health")]).with_allow_non_public(true);
    let mut call = get_call();
    call.budget.max_wall_ms = 2_000;
    let error = tool
        .invoke(0, &call)
        .expect_err("10.255.255.1 is unroutable");
    assert!(
        matches!(error.code(), "rpc/provider" | "rpc/timeout"),
        "the dial was attempted past the policy gate: {error}"
    );
}

/// Loopback can be forbidden explicitly: the same literal the default
/// policy dials is refused, and the stub is never hit.
#[test]
fn loopback_can_be_forbidden_explicitly() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_ok(listener);

    let mut tool = HttpTool::new(format!("http://127.0.0.1:{port}"), &[("GET", "/health")])
        .with_allow_loopback(false);
    let error = tool
        .invoke(0, &get_call())
        .expect_err("a forbidden loopback must be refused before any dial");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no connection may reach the stub"
    );
}

/// The flags are independent: opting into non-public addresses does not
/// reinstate loopback once it is forbidden.
#[test]
fn an_opt_in_does_not_reinstate_forbidden_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let hits = stub_ok(listener);

    let mut tool = HttpTool::new(format!("http://127.0.0.1:{port}"), &[("GET", "/health")])
        .with_allow_non_public(true)
        .with_allow_loopback(false);
    let error = tool
        .invoke(0, &get_call())
        .expect_err("loopback stays forbidden with the opt-in on");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "no connection may reach the stub"
    );
}
