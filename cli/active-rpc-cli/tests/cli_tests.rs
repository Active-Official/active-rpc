//! End-to-end CLI tests: every command drives the shipped binary and a real
//! kernel peer over a real transport.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Output, Stdio};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_active-rpc-cli"))
}

fn run(args: &[&str]) -> Output {
    cli().args(args).output().expect("spawn cli")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A peer process kept alive until the test drops it.
struct Peer {
    child: Child,
    address: String,
    cap: String,
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_peer(args: &[&str]) -> Peer {
    let mut child = cli()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn peer");
    let stdout = child.stdout.take().expect("peer stdout");
    let mut lines = BufReader::new(stdout).lines();
    let mut address = None;
    let mut cap = None;
    for _ in 0..8 {
        let Some(line) = lines.next() else { break };
        let line = line.expect("peer line");
        if let Some(value) = line.strip_prefix("addr=") {
            address = Some(value.to_string());
        }
        if let Some(value) = line.strip_prefix("cap=") {
            cap = Some(value.to_string());
            break;
        }
    }
    Peer {
        child,
        address: address.expect("addr line"),
        cap: cap.expect("cap line"),
    }
}

#[test]
fn doctor_reports_transports_and_exit_codes() {
    let output = run(&["doctor"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.contains("tcp, connect, http2, quic"));
    assert!(text.contains("exit codes: 0 success, 1 refusal/failure, 2 usage, 3 transport"));
    assert!(text.contains("budget defaults: calls=10000"));
}

#[test]
fn help_lists_every_command() {
    let output = run(&["help"]);
    assert!(output.status.success());
    let text = stdout(&output);
    for command in [
        "doctor", "peer", "call", "pipeline", "loadgen", "bridge", "events",
    ] {
        assert!(text.contains(command), "help is missing {command}");
    }
    assert!(text.contains("Examples:"));
}

#[test]
fn unknown_command_exits_with_the_usage_code() {
    let output = run(&["nonsense"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown command"));
}

#[test]
fn call_without_an_address_is_a_usage_error() {
    let output = run(&["call"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--addr"));
}

#[test]
fn peer_and_call_round_trip() {
    let peer = start_peer(&["peer", "--limit", "1"]);
    let output = run(&[
        "call",
        "--addr",
        &peer.address,
        "--cap",
        &peer.cap,
        "--method",
        "echo",
        "--text",
        "hello",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("kind=response"));
    assert!(text.contains("id=42"));
    assert!(text.contains("payload=5"));
    assert!(text.contains("value=\"ok\""));
}

#[test]
fn refusal_uses_the_refused_exit_code() {
    let peer = start_peer(&["peer", "--limit", "1"]);
    let output = run(&[
        "call",
        "--addr",
        &peer.address,
        "--cap",
        &peer.cap,
        "--method",
        "refuse",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("rpc/method-not-granted"));
}

#[test]
fn a_call_without_a_capability_is_refused() {
    let peer = start_peer(&["peer", "--limit", "1"]);
    let output = run(&[
        "call",
        "--addr",
        &peer.address,
        "--method",
        "echo",
        "--text",
        "x",
    ]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("rpc/unknown-capability"));
}

#[test]
fn a_bad_address_is_a_transport_error() {
    let output = run(&[
        "call",
        "--addr",
        "127.0.0.1:1",
        "--cap",
        "00112233445566778899aabbccddeeff",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(stderr(&output).contains("transport failure"));
}

#[test]
fn pipeline_reports_one_round_trip() {
    let peer = start_peer(&["peer", "--limit", "1"]);
    let output = run(&[
        "pipeline",
        "--addr",
        &peer.address,
        "--cap",
        &peer.cap,
        "--calls",
        "4",
        "--text",
        "pipelined",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("calls=4"), "{text}");
    assert!(text.contains("round_trips=1"), "{text}");
    assert!(text.contains("responses=4"), "{text}");
    assert!(text.contains("refusals=0"), "{text}");
}

#[test]
fn loadgen_reports_percentiles() {
    let peer = start_peer(&["peer", "--limit", "2"]);
    let output = run(&[
        "loadgen",
        "--addr",
        &peer.address,
        "--cap",
        &peer.cap,
        "--requests",
        "6",
        "--concurrency",
        "2",
        "--text",
        "load",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("requests=6"), "{text}");
    assert!(text.contains("ok=6"), "{text}");
    assert!(text.contains("errors=0"), "{text}");
    assert!(text.contains("p50_ms="), "{text}");
    assert!(text.contains("p99_ms="), "{text}");
}

#[test]
fn connect_transport_round_trip() {
    let peer = start_peer(&["peer", "--transport", "connect", "--limit", "1"]);
    let output = run(&[
        "call",
        "--transport",
        "connect",
        "--addr",
        &peer.address,
        "--cap",
        &peer.cap,
        "--text",
        "bridge",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("kind=response"));
}

#[test]
fn http2_transport_round_trip() {
    let peer = start_peer(&["peer", "--transport", "http2", "--limit", "1"]);
    let output = run(&[
        "call",
        "--transport",
        "http2",
        "--addr",
        &peer.address,
        "--cap",
        &peer.cap,
        "--text",
        "multiplexed",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("kind=response"));
}

#[test]
fn bridge_serves_the_connect_adapter() {
    let peer = start_peer(&["bridge", "--limit", "1"]);
    let output = run(&[
        "call",
        "--transport",
        "connect",
        "--addr",
        &peer.address,
        "--cap",
        &peer.cap,
        "--text",
        "bridge",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("kind=response"));
}
