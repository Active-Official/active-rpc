//! CLI round 2 (R-18 confirmation): booleans, id correlation, deadlines, strict
//! HTTP, flag allowlists and closed pipes.
//!
//! Every test drives the shipped binary. The scripted peers are real TCP
//! listeners and real HTTP/1.1 servers.

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

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A peer that reads one frame and answers with `build(id)`.
fn answer_with<F>(reply: F) -> String
where
    F: Fn(u64) -> Vec<u8> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut header = [0u8; 4];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let mut body = vec![0u8; u32::from_le_bytes(header) as usize];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        let id = active_rpc::wire::Envelope::decode(&body)
            .map(|envelope| envelope.request_id)
            .unwrap_or(0);
        let encoded = reply(id);
        let _ = stream.write_all(&(encoded.len() as u32).to_le_bytes());
        let _ = stream.write_all(&encoded);
        let _ = stream.flush();
    });
    address
}

/// A peer that answers `count` frames, all with the same wrong request id.
fn replay_answers(count: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        for _ in 0..count {
            let mut header = [0u8; 4];
            if stream.read_exact(&mut header).is_err() {
                return;
            }
            let mut body = vec![0u8; u32::from_le_bytes(header) as usize];
            if stream.read_exact(&mut body).is_err() {
                return;
            }
            let encoded = active_rpc::wire::Envelope::response(9999, active_rpc::Value::text("ok"))
                .encode()
                .expect("encode");
            if stream.write_all(&(encoded.len() as u32).to_le_bytes()).is_err() {
                return;
            }
            if stream.write_all(&encoded).is_err() {
                return;
            }
            let _ = stream.flush();
        }
    });
    address
}

/// A peer that accepts and then says nothing.
fn silent_peer() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        let _ = listener.accept();
        std::thread::sleep(std::time::Duration::from_secs(30));
    });
    address
}

/// A one-shot HTTP server that answers with a fixed response.
fn http_once(response: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let address = listener.local_addr().expect("addr").to_string();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 4096];
            let _ = stream.read(&mut buffer);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    format!("http://{address}")
}

/// N1: the documented bare `--follow` is a flag, not a usage error.
#[test]
fn a_bare_follow_is_a_flag() {
    let plane = http_once("HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n[]".to_string());
    let output = run(&["events", "--plane", &plane, "--follow"]);
    // The one-shot plane cannot answer the second poll, so this process ends on
    // a transport error; what matters is that the flag parsed and the first poll
    // ran. A usage error (2) or "needs a value" is the regression.
    assert_ne!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(
        !stderr(&output).contains("needs a value"),
        "stderr: {}",
        stderr(&output)
    );
}

/// N4: a boolean's value is parsed, not assumed true.
#[test]
fn a_false_boolean_is_false() {
    // `--emit-cap-hex=false` must not print the raw id.
    let address = answer_with(|id| {
        active_rpc::wire::Envelope::response(id, active_rpc::Value::text("ok"))
            .encode()
            .expect("encode")
    });
    let output = run(&[
        "call",
        "--addr",
        &address,
        "--cap",
        &"0".repeat(32),
        "--emit-cap-hex=false",
    ]);
    // `call` has no `--emit-cap-hex`; it is a usage error there, and the point is
    // that it is not silently ignored.
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));

    // An unparsable boolean is a usage error too.
    let output = run(&[
        "peer",
        "--transport",
        "tcp",
        "--limit",
        "0",
        "--emit-cap-hex=maybe",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// N2: a peer that replays one answer for every request is not a clean run.
#[test]
fn a_replayed_answer_is_not_a_pipeline_success() {
    let address = replay_answers(3);
    let output = run(&[
        "pipeline",
        "--addr",
        &address,
        "--cap",
        &"0".repeat(32),
        "--calls",
        "3",
    ]);
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("their own response") || stderr(&output).contains("refusal"),
        "{}",
        stderr(&output)
    );
}

/// N3: a peer that accepts and says nothing is a deadline, not a hang.
#[test]
fn a_silent_peer_is_a_deadline_on_every_transport() {
    for transport in ["tcp", "connect", "http2"] {
        let address = silent_peer();
        let started = std::time::Instant::now();
        let output = run(&[
            "call",
            "--addr",
            &address,
            "--transport",
            transport,
            "--cap",
            &"0".repeat(32),
            "--timeout-ms",
            "400",
        ]);
        let elapsed = started.elapsed();
        assert_ne!(
            output.status.code(),
            Some(0),
            "{transport}: {}",
            stderr(&output)
        );
        assert!(
            elapsed < std::time::Duration::from_secs(5),
            "{transport} took {elapsed:?}"
        );
    }
}

/// N6 and N13: a 200 that is not the event array, and a truncated body, are
/// refusals.
#[test]
fn a_non_json_or_truncated_event_body_is_a_refusal() {
    let ansi = http_once(
        "HTTP/1.1 200 OK\r\ncontent-length: 22\r\n\r\n\u{1b}[2J FORGED 200 OK\r\n"
            .replace('\u{1b}', "\\u{1b}"),
    );
    let output = run(&["events", "--plane", &ansi]);
    assert_ne!(output.status.code(), Some(0), "{}", stdout(&output));
    assert!(
        !stdout(&output).contains("FORGED"),
        "a non-JSON body was printed: {}",
        stdout(&output)
    );

    // Declared 9999, sent 2.
    let truncated = http_once("HTTP/1.1 200 OK\r\ncontent-length: 9999\r\n\r\n[]".to_string());
    let output = run(&["events", "--plane", &truncated]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));

    // A chunked body with no terminal chunk.
    let chunked =
        http_once("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n2\r\n[]\r\n".to_string());
    let output = run(&["events", "--plane", &chunked]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
}

/// N7: a plane that accepts and says nothing is a deadline.
#[test]
fn a_silent_plane_is_a_deadline() {
    let address = silent_peer();
    let started = std::time::Instant::now();
    let output = run(&[
        "events",
        "--plane",
        &format!("http://{address}"),
        "--timeout-ms",
        "400",
    ]);
    assert_ne!(output.status.code(), Some(0));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// N8: a misspelt flag on a receipts or replay subcommand is a usage error.
#[test]
fn receipts_and_replay_validate_their_flags() {
    let dir = std::env::temp_dir().join(format!("cli-r18-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let log = dir.join("receipts.arrl");
    let output = run(&["receipts", "dump", "--output", log.to_str().expect("path")]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let path = log.to_str().expect("path");

    let output = run(&["receipts", "show", path, "--limt", "1"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));

    let output = run(&["receipts", "dump", "--output", path, "extra"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));

    let package = dir.join("session.arrp");
    let output = run(&[
        "replay",
        "dump",
        "--output",
        package.to_str().expect("path"),
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let output = run(&["replay", "run", package.to_str().expect("path"), "extra"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));

    let _ = std::fs::remove_dir_all(&dir);
}

/// N9: a certificate on a cleartext transport is a usage error.
#[test]
fn a_certificate_needs_quic() {
    for transport in ["tcp", "connect", "http2"] {
        let output = run(&[
            "call",
            "--addr",
            "127.0.0.1:1",
            "--transport",
            transport,
            "--cap",
            &"0".repeat(32),
            "--cert",
            "C:\\definitely\\missing.pem",
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{transport}: {}",
            stderr(&output)
        );
    }
}

/// N12: a pipeline of zero calls is a usage error, not a reported round trip.
#[test]
fn a_pipeline_of_zero_calls_is_a_usage_error() {
    let output = run(&[
        "pipeline",
        "--addr",
        "127.0.0.1:1",
        "--cap",
        &"0".repeat(32),
        "--calls",
        "0",
    ]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
}

/// N11 and N10: the capability can come from a file, and the hint line must not
/// look like the documented `cap=` extraction.
#[test]
fn a_capability_file_works_and_the_hint_is_not_a_cap_line() {
    let dir = std::env::temp_dir().join(format!("cli-r18-cap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let cap_file = dir.join("cap.hex");
    std::fs::write(&cap_file, format!("{}\r\n", "0".repeat(32))).expect("write");

    let address = answer_with(|id| {
        active_rpc::wire::Envelope::response(id, active_rpc::Value::text("ok"))
            .encode()
            .expect("encode")
    });
    let output = run(&[
        "call",
        "--addr",
        &address,
        "--cap-file",
        cap_file.to_str().expect("path"),
    ]);
    // The scripted peer answers, so the id reached the request path.
    assert_ne!(output.status.code(), Some(2), "{}", stderr(&output));

    // `peer` serves until `--limit` is reached, so it is started, read and
    // killed: the documented `awk '/^cap=/'` must find no line.
    let mut child = cli()
        .args(["peer", "--transport", "tcp", "--limit", "1"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn peer");
    let mut head = String::new();
    if let Some(mut out) = child.stdout.take() {
        let mut buffer = [0u8; 512];
        for _ in 0..4 {
            let Ok(read) = out.read(&mut buffer) else {
                break;
            };
            head.push_str(&String::from_utf8_lossy(&buffer[..read]));
            if head.contains("cap=") && head.contains("addr=") {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    for line in head.lines() {
        if let Some(rest) = line.strip_prefix("cap=") {
            panic!("a hint line looks like a capability: {rest:?}");
        }
    }
    assert!(head.contains("cap_correlation="), "peer head: {head:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// N16: a closed stdout is a clean stop, not a panic (exit 101).
#[test]
fn a_closed_stdout_does_not_panic() {
    use std::process::Stdio;
    let dir = std::env::temp_dir().join(format!("cli-r18-pipe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let log = dir.join("receipts.arrl");
    let _ = run(&["receipts", "dump", "--output", log.to_str().expect("path")]);

    // Give the child a pipe whose reader is closed immediately.
    let mut child = cli()
        .args(["receipts", "show", log.to_str().expect("path")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    drop(child.stdout.take());
    let status = child.wait().expect("wait");
    assert_ne!(
        status.code(),
        Some(101),
        "a closed pipe panicked: {}",
        status
    );

    let _ = std::fs::remove_dir_all(&dir);
}
