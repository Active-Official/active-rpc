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

/// A fresh temporary directory per test.
fn sandbox(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("active-rpc-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("sandbox");
    dir
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

#[test]
fn replay_dump_and_run_round_trip() {
    let path = std::env::temp_dir().join(format!("active-rpc-replay-{}.arrp", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let dump = run(&["replay", "dump", "--output", path.to_str().expect("utf8")]);
    assert!(dump.status.success(), "{}", stderr(&dump));
    assert!(stdout(&dump).contains("ops="));
    let bytes = std::fs::read(&path).expect("package");
    assert_eq!(&bytes[..4], b"ARRP");

    let replayed = run(&["replay", "run", path.to_str().expect("utf8")]);
    assert!(replayed.status.success(), "{}", stderr(&replayed));
    assert!(stdout(&replayed).contains("ok ops="));

    let mut tampered = bytes;
    tampered[40] ^= 0x01;
    std::fs::write(&path, &tampered).expect("tampered");
    let refused = run(&["replay", "run", path.to_str().expect("utf8")]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("rpc/replay"),
        "{}",
        stderr(&refused)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn replay_without_a_subcommand_is_a_usage_error() {
    let output = run(&["replay"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("replay dump"));
}

#[test]
fn version_prints_the_cli_and_kernel() {
    for flag in ["version", "--version", "-V"] {
        let output = run(&[flag]);
        assert!(output.status.success(), "{flag}: {}", stderr(&output));
        let text = stdout(&output);
        assert!(
            text.contains(concat!("active-rpc-cli ", env!("CARGO_PKG_VERSION"))),
            "{text}"
        );
        assert!(text.contains("(active-rpc "), "{text}");
    }
}

#[test]
fn receipts_dump_verify_and_tamper_paths() {
    let dir = sandbox("receipts");
    let log = dir.join("session.arrl");
    let log_arg = log.to_str().expect("log path");

    let dump = run(&["receipts", "dump", "--output", log_arg]);
    assert!(dump.status.success(), "{}", stderr(&dump));
    assert!(
        stdout(&dump).contains("wrote 3 receipts"),
        "{}",
        stdout(&dump)
    );
    assert!(log.is_file());

    let verify = run(&["receipts", "verify", log_arg]);
    assert!(verify.status.success(), "{}", stderr(&verify));
    let text = stdout(&verify);
    assert!(text.starts_with("ok 3 receipts"), "{text}");
    let head = text
        .split_whitespace()
        .last()
        .expect("head hash")
        .to_string();
    assert_eq!(head.len(), 64);

    let show = run(&["receipts", "show", log_arg, "--limit", "2"]);
    assert!(show.status.success(), "{}", stderr(&show));
    let shown = stdout(&show);
    let lines: Vec<&str> = shown.lines().collect();
    assert_eq!(lines.len(), 2, "{shown}");
    assert!(lines[0].starts_with("1 "), "{}", lines[0]);
    assert!(lines[1].starts_with("2 "), "{}", lines[1]);

    // A tampered record fails verification with the receipt class.
    let mut bytes = std::fs::read(&log).expect("read log");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(&log, &bytes).expect("tamper");
    let refused = run(&["receipts", "verify", log_arg]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("rpc/receipt"),
        "{}",
        stderr(&refused)
    );

    // A missing log is a usage error, not a panic.
    let missing = run(&[
        "receipts",
        "verify",
        dir.join("nope.arrl").to_str().unwrap(),
    ]);
    assert_eq!(missing.status.code(), Some(2));
}
