//! Hostile-input CLI tests (R-18 round 1): a peer reply that is not a response,
//! a reply for another request, a non-ASCII capability, the `=` flag form, and a
//! chunk size that overflows.
//!
//! These live in their own file so the main suite stays about the happy paths;
//! every one of them drives the shipped binary.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_active-rpc-cli"))
}

fn run(args: &[&str]) -> Output {
    cli().args(args).output().expect("spawn cli")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Read one ARP1 frame from a scripted peer, then answer with `reply`.
fn answer_once<F>(reply: F) -> String
where
    F: FnOnce() -> Vec<u8> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).expect("length");
        let mut body = vec![0u8; u32::from_le_bytes(header) as usize];
        stream.read_exact(&mut body).expect("body");
        let encoded = reply();
        stream
            .write_all(&(encoded.len() as u32).to_le_bytes())
            .expect("length");
        stream.write_all(&encoded).expect("write");
        stream.flush().expect("flush");
    });
    address
}

/// A reply that is not a `Response` must not exit 0.
///
/// The peer is untrusted: `Kind` also decodes `Request` and `Hello`, and any
/// non-error kind used to be treated as success, inverting the documented exit
/// contract.
#[test]
fn a_reply_that_is_not_a_response_is_a_refusal() {
    let address = answer_once(|| {
        active_rpc::wire::Envelope::request(42, "echo", Vec::new())
            .encode()
            .expect("encode")
    });
    let output = run(&["call", "--addr", &address, "--cap", &"0".repeat(32)]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("did not answer"),
        "{}",
        stderr(&output)
    );
}

/// A reply for another request id is not this call's answer.
#[test]
fn a_reply_for_another_request_is_a_refusal() {
    let address = answer_once(|| {
        active_rpc::wire::Envelope::response(9_999, active_rpc::value::Value::Null)
            .encode()
            .expect("encode")
    });
    let output = run(&["call", "--addr", &address, "--cap", &"0".repeat(32)]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("instead of 42"),
        "{}",
        stderr(&output)
    );
}

/// A 32-byte capability with a multi-byte character must be a usage error, not
/// a slice panic (exit 101 sits outside the documented 0/1/2/3 contract).
#[test]
fn a_non_ascii_capability_is_a_usage_error() {
    let cap = format!("\u{20ac}{}", "a".repeat(29));
    assert_eq!(cap.len(), 32, "the fixture is 32 bytes, not 32 characters");
    let output = run(&["call", "--addr", "127.0.0.1:1", "--cap", &cap]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("panicked"),
        "the parser must not panic: {}",
        stderr(&output)
    );
}

/// `--name=value` is the form scripts emit; an unknown option is a usage error.
#[test]
fn flags_accept_the_equals_form_and_unknown_options_are_refused() {
    let equal = run(&["peer", "--transport=nonsense", "--limit", "1"]);
    assert_eq!(equal.status.code(), Some(2), "{}", stderr(&equal));

    let unknown = run(&["call", "--addr", "127.0.0.1:1", "--paylod", "x"]);
    assert_eq!(unknown.status.code(), Some(2), "{}", stderr(&unknown));
    assert!(
        stderr(&unknown).contains("unknown option --paylod"),
        "{}",
        stderr(&unknown)
    );
}

/// A chunk size that overflows must be a transport error, not a panic.
#[test]
fn a_hostile_chunk_size_is_a_transport_error() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request);
        let body = "1\r\nA\r\nffffffffffffffff\r\n";
        let head = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).expect("head");
        stream.write_all(body.as_bytes()).expect("body");
        stream.flush().expect("flush");
    });
    let output = run(&["events", "--plane", &format!("http://{address}")]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        !stderr(&output).contains("panicked"),
        "a hostile chunk must not panic: {}",
        stderr(&output)
    );
}
