//! End-to-end CLI tests: every command drives the shipped binary and a real
//! kernel peer over a real transport.

use active_rpc::transport::{TcpTransport, Transport};
use active_rpc::wire::{CapDescriptor, Envelope, Kind};
use active_rpc::{Budget, CapId};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

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

/// Windows only: run `icacls` and fail the test if it refuses — a test bug,
/// not a CLI bug, so the failure says which invocation failed.
#[cfg(windows)]
fn icacls(args: &[&str]) {
    let output = Command::new("icacls")
        .args(args)
        .output()
        .expect("spawn icacls");
    assert!(
        output.status.success(),
        "icacls {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Windows only: the account running the test, as `icacls` spells it
/// (`DOMAIN\user`).
#[cfg(windows)]
fn current_user() -> String {
    let output = Command::new("whoami").output().expect("spawn whoami");
    assert!(output.status.success(), "whoami failed");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Windows only: restrict a key file to its owner — the Windows mirror of
/// the unix `chmod 600` blocks below. A file created under `%TEMP%` inherits
/// an ACL that lets other accounts read it (XPL-RPC-09), so a test that
/// needs the CLI to accept the key must drop the inherited ACEs first
/// (`/inheritance:r` only removes inherited ACEs; a later `/grant` only
/// adds), then grant the owner full control.
#[cfg(windows)]
fn restrict_key_to_owner(path: &std::path::Path) {
    let path_arg = path.to_str().expect("key path");
    icacls(&[path_arg, "/inheritance:r"]);
    let grant = format!("{}:(F)", current_user());
    icacls(&[path_arg, "/grant:r", &grant]);
}

/// Windows only: grant `BUILTIN\Users` read access to a key file, by SID —
/// the group's name is localised (`Usuarios` on this machine), the SID is
/// not. This is the attack shape of XPL-RPC-09: a key any local account
/// can read.
#[cfg(windows)]
fn grant_users_read(path: &std::path::Path) {
    let path_arg = path.to_str().expect("key path");
    icacls(&[path_arg, "/grant", "*S-1-5-32-545:(R)"]);
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
    // The default announcement prints the correlation id, not the caller id: the
    // raw id is bearer authority and is opt-in. A test that drives the peer
    // needs the caller form.
    let mut full: Vec<&str> = args.to_vec();
    full.push("--emit-cap-hex");
    let mut child = cli()
        .args(&full)
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
    // Every command the dispatcher knows: the list used to stop at `events`, so
    // "every command" was never verified for `replay`, `receipts` or `version`.
    for command in [
        "doctor", "peer", "call", "pipeline", "loadgen", "bridge", "events", "replay", "receipts",
        "version",
    ] {
        assert!(text.contains(command), "help is missing {command}");
    }
    assert!(text.contains("Examples:"));
    // The raw caller id is bearer authority and must be described as such.
    assert!(
        text.contains("bearer authority"),
        "help must warn about the id"
    );
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

/// RPC-49: `--timeout-ms` bounds the whole `loadgen` run, not one request.
/// A peer that accepts and never answers used to cost one full timeout per
/// request (8 requests x 2000 ms = ~16 s); the run must now fail at the
/// total deadline (~2 s) with a transport error. The audit's suggested
/// probe (a `pipeline` against a silent peer exiting within ~5 s) does not
/// prove this: `pipeline` aborts on its first failed call, so it already
/// exited in ~2 s before the fix.
#[test]
fn loadgen_against_a_silent_peer_fails_at_the_total_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent-peer listener");
    let address = listener.local_addr().expect("listener address");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    // Drain what the client sends so its writes never block;
                    // never write anything back.
                    let mut buffer = [0u8; 4096];
                    while let Ok(read) = stream.read(&mut buffer) {
                        if read == 0 {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
    let started = Instant::now();
    let output = run(&[
        "loadgen",
        "--addr",
        &address.to_string(),
        "--cap",
        "00112233445566778899aabbccddeeff",
        "--requests",
        "8",
        "--concurrency",
        "1",
        "--timeout-ms",
        "2000",
    ]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "loadgen against a silent peer took {elapsed:?}, expected the ~2 s total deadline"
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no answer within 2000 ms"),
        "{}",
        stderr(&output)
    );
}

/// RPC-49: `--timeout-ms` bounds the whole `pipeline` run, not one reply.
/// A peer that answers one frame every 600 ms is healthy per request but
/// takes ~4.8 s for 8 calls; against a 2000 ms total deadline the run must
/// fail at ~2 s. Pre-fix this completed in ~4.8 s with exit 0: the
/// behaviour change is the fix, so this test pins it on purpose.
#[test]
fn pipeline_against_a_slow_peer_fails_at_the_total_deadline() {
    // A proxy between the CLI and the real peer: requests pass through at
    // once, each response frame is held back 600 ms. Frames are length
    // prefixed with a 4-byte little-endian length, as the transport writes
    // them.
    let peer = start_peer(&["peer", "--limit", "1"]);
    let proxy = TcpListener::bind("127.0.0.1:0").expect("bind proxy listener");
    let proxy_address = proxy.local_addr().expect("proxy address");
    let peer_address = peer.address.clone();
    std::thread::spawn(move || {
        let Ok((mut client, _)) = proxy.accept() else {
            return;
        };
        let Ok(mut upstream) = TcpStream::connect(&peer_address) else {
            return;
        };
        // Client to peer: forward at once.
        let mut upstream_write = upstream.try_clone().expect("clone upstream");
        let mut client_read = client.try_clone().expect("clone client");
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut client_read, &mut upstream_write);
        });
        // Peer to client: one frame, then 600 ms, then the next.
        let mut header = [0u8; 4];
        loop {
            if upstream.read_exact(&mut header).is_err() {
                break;
            }
            let len = u32::from_le_bytes(header) as usize;
            let mut body = vec![0u8; len];
            if upstream.read_exact(&mut body).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(600));
            if client.write_all(&header).is_err() {
                break;
            }
            if client.write_all(&body).is_err() {
                break;
            }
        }
    });
    let started = Instant::now();
    let output = run(&[
        "pipeline",
        "--addr",
        &proxy_address.to_string(),
        "--cap",
        &peer.cap,
        "--calls",
        "8",
        "--text",
        "pipelined",
        "--timeout-ms",
        "2000",
    ]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "pipeline against a slow peer took {elapsed:?}, expected the ~2 s total deadline"
    );
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("no answer within 2000 ms"),
        "{}",
        stderr(&output)
    );
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
        stdout(&dump).contains("wrote 4 receipts"),
        "{}",
        stdout(&dump)
    );
    assert!(log.is_file());

    // The demo's kernel is fixed, so the test can derive the same receipt key
    // the CLI sealed with: `receipts::derive_receipt_key(&[0x5e; 32])`.
    let receipt_key = active_rpc::receipts::derive_receipt_key(&[0x5e; 32]);
    let key_path = dir.join("receipt.key");
    let key_hex: String = receipt_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(&key_path, format!("{key_hex}\n")).expect("write key");
    // The reader refuses a key file other accounts can read: mode `0o600`
    // on unix, an owner-only DACL on Windows (XPL-RPC-09).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod the key");
    }
    #[cfg(windows)]
    restrict_key_to_owner(&key_path);
    let key_arg = key_path.to_str().expect("key path");

    // An unauthenticated check is not offered as "ok": it proves the chain and
    // nothing about who wrote it, so the operator has to ask for it.
    let unauth = run(&["receipts", "verify", log_arg]);
    assert_eq!(unauth.status.code(), Some(2), "{}", stderr(&unauth));
    assert!(
        stderr(&unauth).contains("--receipt-key-file"),
        "{}",
        stderr(&unauth)
    );

    let chain_only = run(&["receipts", "verify", log_arg, "--chain-only"]);
    assert!(chain_only.status.success(), "{}", stderr(&chain_only));
    let text = stdout(&chain_only);
    assert!(text.starts_with("ok 4 receipts"), "{text}");
    assert!(
        text.contains("chain-only (unauthenticated)"),
        "a chain-only verify must say what it did not check: {text}"
    );
    let head = text
        .split_whitespace()
        .skip_while(|token| *token != "head")
        .nth(1)
        .expect("head hash")
        .trim_end_matches(',')
        .to_string();
    assert_eq!(head.len(), 64);

    // The owner path: the receipt key checks every MAC.
    let authed = run(&["receipts", "verify", log_arg, "--receipt-key-file", key_arg]);
    assert!(authed.status.success(), "{}", stderr(&authed));
    assert!(
        stdout(&authed).contains("macs verified"),
        "{}",
        stdout(&authed)
    );

    // The pinned head detects a truncated tail that chain-only verification
    // cannot see.
    let pinned = run(&["receipts", "verify", log_arg, "--expect-head", &head]);
    assert!(pinned.status.success(), "{}", stderr(&pinned));
    let wrong = "00".repeat(32);
    let mismatch = run(&["receipts", "verify", log_arg, "--expect-head", &wrong]);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(
        stderr(&mismatch).contains("rpc/receipt"),
        "{}",
        stderr(&mismatch)
    );

    // A wrong key is a refusal, not a pass.
    let foreign_path = dir.join("foreign.key");
    let foreign_key = active_rpc::receipts::derive_receipt_key(&[0x6d; 32]);
    let foreign_hex: String = foreign_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::fs::write(&foreign_path, foreign_hex).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&foreign_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod the key");
    }
    #[cfg(windows)]
    restrict_key_to_owner(&foreign_path);
    let forged = run(&[
        "receipts",
        "verify",
        log_arg,
        "--receipt-key-file",
        foreign_path.to_str().unwrap(),
    ]);
    assert_eq!(forged.status.code(), Some(1));
    assert!(
        stderr(&forged).contains("not produced by this kernel"),
        "{}",
        stderr(&forged)
    );

    // A non-ASCII key is a usage error, not a panic in the slicing code.
    let bad_key = dir.join("bad.key");
    std::fs::write(&bad_key, format!("a\u{20ac}{}", "0".repeat(60))).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bad_key, std::fs::Permissions::from_mode(0o600))
            .expect("chmod the key");
    }
    // Without this the Windows refusal would be the ACL, not the format,
    // and the assertion below would fail for the wrong reason.
    #[cfg(windows)]
    restrict_key_to_owner(&bad_key);
    let panic_free = run(&[
        "receipts",
        "verify",
        log_arg,
        "--receipt-key-file",
        bad_key.to_str().unwrap(),
    ]);
    assert_eq!(panic_free.status.code(), Some(2), "{}", stderr(&panic_free));
    assert!(
        stderr(&panic_free).contains("64 hex characters"),
        "the refusal names the format, not a slice panic: {}",
        stderr(&panic_free)
    );

    let show = run(&["receipts", "show", log_arg, "--limit", "2"]);
    assert!(show.status.success(), "{}", stderr(&show));
    let shown = stdout(&show);
    let lines: Vec<&str> = shown.lines().collect();
    // The first line says the listing is unverified structure, so a reader
    // cannot mistake it for the authenticated report `verify` produces.
    assert!(
        lines[0].starts_with("# 4 record(s), structure unverified"),
        "{}",
        lines[0]
    );
    assert_eq!(lines.len(), 3, "{shown}");
    assert!(lines[1].starts_with("1 "), "{}", lines[1]);
    assert!(lines[2].starts_with("2 "), "{}", lines[2]);

    // `--limit 0` used to print nothing and exit 0, which reads as success.
    let zero = run(&["receipts", "show", log_arg, "--limit", "0"]);
    assert_eq!(zero.status.code(), Some(2), "{}", stderr(&zero));

    // The demo ends with a dispatch refusal, and the log says so.
    let last = run(&["receipts", "show", log_arg, "--limit", "4"]);
    let shown = stdout(&last);
    let tail = shown.lines().last().expect("last record");
    assert!(tail.contains("refused"), "{tail}");
    assert!(tail.contains("rpc/revoked"), "{tail}");

    // A tampered record fails verification with the receipt class.
    let mut bytes = std::fs::read(&log).expect("read log");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0x01;
    std::fs::write(&log, &bytes).expect("tamper");
    let refused = run(&["receipts", "verify", log_arg, "--chain-only"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(
        stderr(&refused).contains("rpc/receipt"),
        "{}",
        stderr(&refused)
    );

    // A torn trailing write is repairable: the CLI cuts it and keeps the chain.
    let dir2 = sandbox("receipts-repair");
    let torn = dir2.join("torn.arrl");
    let torn_arg = torn.to_str().expect("path");
    let dump = run(&["receipts", "dump", "--output", torn_arg]);
    assert!(dump.status.success(), "{}", stderr(&dump));
    let mut bytes = std::fs::read(&torn).expect("read");
    bytes.truncate(bytes.len() - 5);
    std::fs::write(&torn, &bytes).expect("tear");
    let repaired = run(&["receipts", "repair", torn_arg]);
    assert!(repaired.status.success(), "{}", stderr(&repaired));
    assert!(
        stdout(&repaired).contains("3 receipts kept"),
        "{}",
        stdout(&repaired)
    );
    let after = run(&["receipts", "verify", torn_arg, "--chain-only"]);
    assert!(after.status.success(), "{}", stderr(&after));

    // A missing log is a usage error, not a panic.
    let missing = run(&[
        "receipts",
        "verify",
        dir.join("nope.arrl").to_str().unwrap(),
    ]);
    assert_eq!(missing.status.code(), Some(2));
}

/// The finding (XPL-RPC-09, Windows only): a receipt key readable by other
/// accounts was silently accepted — the permission check was unix-only, so
/// a key with a world-readable ACL verified MACs and the CLI printed `ok`.
///
/// Control arm first: the same key, restricted to its owner, verifies.
/// Then the attack: the same key, readable by `BUILTIN\Users`, is refused
/// with exit 2, and the refusal names the offending SID.
#[cfg(windows)]
#[test]
fn a_world_readable_receipt_key_is_refused() {
    let dir = sandbox("world-readable-key");
    let log = dir.join("session.arrl");
    let log_arg = log.to_str().expect("log path");

    let dump = run(&["receipts", "dump", "--output", log_arg]);
    assert!(dump.status.success(), "{}", stderr(&dump));
    assert!(log.is_file());

    // The demo's kernel is fixed, so the test can derive the same receipt key
    // the CLI sealed with: `receipts::derive_receipt_key(&[0x5e; 32])`.
    let receipt_key = active_rpc::receipts::derive_receipt_key(&[0x5e; 32]);
    let key_hex: String = receipt_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let key_path = dir.join("receipt.key");
    std::fs::write(&key_path, format!("{key_hex}\n")).expect("write key");
    let key_arg = key_path.to_str().expect("key path");

    // Control arm: owner-only, the CLI verifies the MACs.
    restrict_key_to_owner(&key_path);
    let owned = run(&["receipts", "verify", log_arg, "--receipt-key-file", key_arg]);
    assert!(owned.status.success(), "{}", stderr(&owned));
    assert!(
        stdout(&owned).contains("macs verified"),
        "{}",
        stdout(&owned)
    );

    // The finding: the same key, readable by every local account, is
    // refused before any MAC is checked.
    grant_users_read(&key_path);
    let world_readable = run(&["receipts", "verify", log_arg, "--receipt-key-file", key_arg]);
    assert_eq!(
        world_readable.status.code(),
        Some(2),
        "{}",
        stderr(&world_readable)
    );
    assert!(
        stderr(&world_readable).contains("readable by other accounts"),
        "{}",
        stderr(&world_readable)
    );
    assert!(
        stderr(&world_readable).contains("S-1-5-32-545"),
        "the refusal names the account that can read the key: {}",
        stderr(&world_readable)
    );
}

/// The finding (RPC-50, unix): a cap file is bearer credentials -- whoever
/// holds the 16 bytes can call -- but `cap_from_file` never checked the
/// file's mode, so a world-readable cap file was silently accepted. The
/// doc promised the same world-readable check as a receipt key; the code
/// did not perform it.
///
/// Control arm first: the same cap, owner-only (`chmod 600`), completes
/// a round trip against a live peer. Then the attack: the same cap,
/// world-readable (`chmod 644`), is refused with exit 2 before any
/// connection is attempted, and the refusal tells the operator to
/// `chmod 600` it.
#[cfg(unix)]
#[test]
fn a_world_readable_cap_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let peer = start_peer(&["peer", "--limit", "2"]);
    let dir = sandbox("world-readable-cap");
    let cap_path = dir.join("cap.hex");
    std::fs::write(&cap_path, format!("{}\n", peer.cap)).expect("write cap");
    let cap_arg = cap_path.to_str().expect("cap path");

    // Control arm: owner-only, the call completes.
    std::fs::set_permissions(&cap_path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    let owned = run(&[
        "call",
        "--addr",
        &peer.address,
        "--cap-file",
        cap_arg,
        "--method",
        "echo",
        "--text",
        "hello",
    ]);
    assert!(owned.status.success(), "{}", stderr(&owned));
    assert!(
        stdout(&owned).contains("kind=response"),
        "{}",
        stdout(&owned)
    );

    // The finding: the same cap, readable by every local account, is
    // refused before any connection is attempted.
    std::fs::set_permissions(&cap_path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
    let world_readable = run(&[
        "call",
        "--addr",
        &peer.address,
        "--cap-file",
        cap_arg,
        "--method",
        "echo",
        "--text",
        "hello",
    ]);
    assert_eq!(
        world_readable.status.code(),
        Some(2),
        "{}",
        stderr(&world_readable)
    );
    assert!(
        stderr(&world_readable).contains("readable by other accounts"),
        "{}",
        stderr(&world_readable)
    );
    assert!(
        stderr(&world_readable).contains("chmod 600"),
        "the refusal tells the operator how to fix the file: {}",
        stderr(&world_readable)
    );
}

/// The finding (RPC-50, Windows): the same missing check as the unix arm
/// above, on the other platform -- a cap file readable by `BUILTIN\Users`
/// was silently accepted. The fix routes the cap file through the same
/// DACL gate as a receipt key (XPL-RPC-09's `check_key_file_acl`).
///
/// Control arm first: the same cap, restricted to its owner, completes a
/// round trip against a live peer. Then the attack: the same cap, readable
/// by `BUILTIN\Users`, is refused with exit 2, and the refusal names the
/// offending SID.
#[cfg(windows)]
#[test]
fn a_world_readable_cap_file_is_refused() {
    let peer = start_peer(&["peer", "--limit", "2"]);
    let dir = sandbox("world-readable-cap");
    let cap_path = dir.join("cap.hex");
    std::fs::write(&cap_path, format!("{}\n", peer.cap)).expect("write cap");
    let cap_arg = cap_path.to_str().expect("cap path");

    // Control arm: owner-only, the call completes.
    restrict_key_to_owner(&cap_path);
    let owned = run(&[
        "call",
        "--addr",
        &peer.address,
        "--cap-file",
        cap_arg,
        "--method",
        "echo",
        "--text",
        "hello",
    ]);
    assert!(owned.status.success(), "{}", stderr(&owned));
    assert!(
        stdout(&owned).contains("kind=response"),
        "{}",
        stdout(&owned)
    );

    // The finding: the same cap, readable by every local account, is
    // refused before any connection is attempted.
    grant_users_read(&cap_path);
    let world_readable = run(&[
        "call",
        "--addr",
        &peer.address,
        "--cap-file",
        cap_arg,
        "--method",
        "echo",
        "--text",
        "hello",
    ]);
    assert_eq!(
        world_readable.status.code(),
        Some(2),
        "{}",
        stderr(&world_readable)
    );
    assert!(
        stderr(&world_readable).contains("readable by other accounts"),
        "{}",
        stderr(&world_readable)
    );
    assert!(
        stderr(&world_readable).contains("S-1-5-32-545"),
        "the refusal names the account that can read the cap: {}",
        stderr(&world_readable)
    );
}

// ---------------------------------------------------------------------------
// RPC-51 regression tests.
// ---------------------------------------------------------------------------

/// (a) A closed stdout is success, not a transport error.
///
/// `receipts show` piped to a reader that has already gone away must exit
/// 0: the operator closed the pipe on purpose (`| head -c 0`), so there is
/// nothing to refuse. The reader is dropped the moment the child is
/// spawned, so even the first line hits the closed pipe -- the same shape
/// the Docker probe proved with `head -c 0` (exit 3 before the fix).
#[test]
fn a_closed_pipe_is_success_not_a_transport_error() {
    let dir = sandbox("epipe");
    let log = dir.join("demo.arrl");
    let dumped = run(&["receipts", "dump", "--output", log.to_str().unwrap()]);
    assert!(dumped.status.success(), "dump: {}", stderr(&dumped));
    let mut child = cli()
        .args(["receipts", "show", log.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cli");
    drop(child.stdout.take());
    let output = child.wait_with_output().expect("wait");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// (b) `parse_cap` refuses a leading `+`: `u8::from_str_radix` accepts an
/// optional sign, so `+f00...` used to parse and the call then tried to
/// connect (exit 3). Now it is a usage error before any connection.
#[test]
fn parse_cap_refuses_a_plus_sign() {
    let output = run(&[
        "call",
        "--addr",
        "127.0.0.1:1",
        "--cap",
        "+f000000000000000000000000000000",
        "--method",
        "echo",
        "--text",
        "hi",
    ]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("not valid hex"),
        "stderr: {}",
        stderr(&output)
    );
}

/// (d) `loadgen --cap-file` is honoured, not silently ignored (unix): the
/// load generator reads the capability from the file -- with the RPC-50
/// owner-only mode check -- and completes its requests.
#[cfg(unix)]
#[test]
fn loadgen_reads_the_cap_from_a_file() {
    use std::os::unix::fs::PermissionsExt;
    let peer = start_peer(&["peer", "--limit", "4"]);
    let dir = sandbox("loadgen-capfile");
    let cap_path = dir.join("cap.hex");
    std::fs::write(&cap_path, format!("{}\n", peer.cap)).expect("write cap");
    std::fs::set_permissions(&cap_path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    let cap_arg = cap_path.to_str().expect("cap path");
    let output = run(&[
        "loadgen",
        "--addr",
        &peer.address,
        "--cap-file",
        cap_arg,
        "--requests",
        "2",
        "--concurrency",
        "1",
    ]);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("requests=2"),
        "stdout: {}",
        stdout(&output)
    );
}

/// (d) The same `--cap-file` honouring on Windows: the cap file is
/// restricted to its owner first, mirroring the RPC-50 test.
#[cfg(windows)]
#[test]
fn loadgen_reads_the_cap_from_a_file() {
    let peer = start_peer(&["peer", "--limit", "4"]);
    let dir = sandbox("loadgen-capfile");
    let cap_path = dir.join("cap.hex");
    std::fs::write(&cap_path, format!("{}\n", peer.cap)).expect("write cap");
    restrict_key_to_owner(&cap_path);
    let cap_arg = cap_path.to_str().expect("cap path");
    let output = run(&[
        "loadgen",
        "--addr",
        &peer.address,
        "--cap-file",
        cap_arg,
        "--requests",
        "2",
        "--concurrency",
        "1",
    ]);
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr(&output));
    assert!(
        stdout(&output).contains("requests=2"),
        "stdout: {}",
        stdout(&output)
    );
}

/// (d) `--cap` and `--cap-file` together are refused: one capability per
/// invocation, and the refusal names both flags.
#[test]
fn loadgen_refuses_both_cap_and_cap_file() {
    let output = run(&[
        "loadgen",
        "--addr",
        "127.0.0.1:1",
        "--cap",
        "00112233445566778899aabbccddeeff",
        "--cap-file",
        "cap.hex",
        "--requests",
        "1",
    ]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("not both"),
        "stderr: {}",
        stderr(&output)
    );
}

/// (h) `--limit 0` means "serve until stopped" on tcp: two calls both
/// complete, so the peer served more than one connection.
#[test]
fn peer_limit_zero_serves_until_stopped_on_tcp() {
    let peer = start_peer(&["peer", "--transport", "tcp", "--limit", "0"]);
    for _ in 0..2 {
        let output = run(&[
            "call",
            "--addr",
            &peer.address,
            "--cap",
            &peer.cap,
            "--method",
            "echo",
            "--text",
            "hi",
        ]);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(
            stdout(&output).contains("kind=response"),
            "stdout: {}",
            stdout(&output)
        );
    }
}

/// (h) `--limit 0` means "serve until stopped" on http2 too: before the
/// fix `serve(0)` served exactly one connection, so the second call hit a
/// closed listener. The calls carry a short timeout so the fail-before
/// shape fails fast instead of hanging on the dead listener.
#[test]
fn peer_limit_zero_serves_until_stopped_on_http2() {
    let peer = start_peer(&["peer", "--transport", "http2", "--limit", "0"]);
    for _ in 0..2 {
        let output = run(&[
            "call",
            "--addr",
            &peer.address,
            "--transport",
            "http2",
            "--cap",
            &peer.cap,
            "--method",
            "echo",
            "--text",
            "hi",
            "--timeout-ms",
            "2000",
        ]);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(
            stdout(&output).contains("kind=response"),
            "stdout: {}",
            stdout(&output)
        );
    }
}

/// (h) `--limit 0` means "serve until stopped" on quic too: before the
/// fix `peer_quic` refused 0 outright, so the peer never started.
#[test]
fn peer_limit_zero_serves_until_stopped_on_quic() {
    let dir = sandbox("quic-limit-zero");
    let cert_path = dir.join("peer.cert");
    let cert_arg = cert_path.to_str().expect("cert path");
    let peer = start_peer(&[
        "peer",
        "--transport",
        "quic",
        "--limit",
        "0",
        "--cert-out",
        cert_arg,
    ]);
    for _ in 0..2 {
        let output = run(&[
            "call",
            "--addr",
            &peer.address,
            "--transport",
            "quic",
            "--cert",
            cert_arg,
            "--cap",
            &peer.cap,
            "--method",
            "echo",
            "--text",
            "hi",
            "--timeout-ms",
            "5000",
        ]);
        assert!(output.status.success(), "stderr: {}", stderr(&output));
        assert!(
            stdout(&output).contains("kind=response"),
            "stdout: {}",
            stdout(&output)
        );
    }
}

/// (h) `peer_quic` refuses to overwrite an existing cert file: the first
/// peer creates it, and the second peer with the same `--cert-out` is
/// refused with exit 1 before it starts serving.
#[test]
fn quic_cert_out_refuses_an_existing_file() {
    let dir = sandbox("quic-cert-exists");
    let cert_path = dir.join("peer.cert");
    let cert_arg = cert_path.to_str().expect("cert path");
    let peer = start_peer(&[
        "peer",
        "--transport",
        "quic",
        "--limit",
        "1",
        "--cert-out",
        cert_arg,
    ]);
    assert!(cert_path.exists(), "the first peer writes the cert");
    let output = run(&[
        "peer",
        "--transport",
        "quic",
        "--limit",
        "1",
        "--cert-out",
        cert_arg,
    ]);
    assert_eq!(output.status.code(), Some(1), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("already exists"),
        "stderr: {}",
        stderr(&output)
    );
    drop(peer);
}

/// A 16-byte capability id parsed from the 32 hex digits a peer prints.
fn cap_id(hex: &str) -> CapId {
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("cap hex");
    }
    CapId(bytes)
}

/// (h) `dispatch` refuses an envelope carrying two capabilities: the
/// kernel serves one capability per call, so extra authority descriptors
/// are a refusal (`rpc/wire`), not silently ignored. The control arm
/// sends the same envelope with one capability and gets a response.
#[test]
fn dispatch_refuses_an_envelope_with_two_caps() {
    let peer = start_peer(&["peer", "--limit", "4"]);
    let descriptor = CapDescriptor {
        id: cap_id(&peer.cap),
        methods: ["echo".to_string()].into_iter().collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    let mut envelope = Envelope::request(1, "echo", vec![]);
    // The second descriptor must carry a DIFFERENT id: the wire codec
    // refuses an envelope with two descriptors for the same id at encode
    // time ("duplicate capability id"), so the send itself would fail
    // before the peer's dispatch ever saw the envelope. Dispatch refuses
    // on the count before it looks at any id, so any second id exercises
    // the refusal.
    let other = CapDescriptor {
        id: CapId([0x11; 16]),
        methods: ["echo".to_string()].into_iter().collect(),
        budget: Budget::default(),
        read_only: false,
        redact: false,
        path_scope: None,
    };
    envelope.caps = vec![descriptor.clone(), other];
    let mut transport = TcpTransport::connect(&peer.address).expect("connect");
    transport.send(&envelope).expect("send");
    let response = transport.recv().expect("recv").expect("a reply arrives");
    assert_eq!(
        response.kind,
        Kind::Error,
        "a two-cap envelope must be refused"
    );
    assert_eq!(
        response.method, "rpc/wire",
        "the refusal code: {response:?}"
    );
    // Control arm: the same envelope with one capability is answered.
    let mut single = Envelope::request(1, "echo", vec![]);
    single.caps = vec![descriptor];
    let mut transport = TcpTransport::connect(&peer.address).expect("connect");
    transport.send(&single).expect("send");
    let response = transport.recv().expect("recv").expect("a reply arrives");
    assert_eq!(
        response.kind,
        Kind::Response,
        "a one-cap envelope is answered: {response:?}"
    );
}

/// (h) `split_args` refuses a flag passed twice: the last one used to win
/// silently, so a typo could change which capability a call used without
/// any warning.
#[test]
fn split_args_refuses_a_duplicate_flag() {
    let output = run(&[
        "call",
        "--addr",
        "127.0.0.1:1",
        "--cap",
        "00112233445566778899aabbccddeeff",
        "--cap",
        "ffeeddccbbaa99887766554433221100",
        "--method",
        "echo",
        "--text",
        "hi",
    ]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("was passed twice"),
        "stderr: {}",
        stderr(&output)
    );
}

/// (h) `loadgen --concurrency 0` is refused: it used to be silently
/// rewritten to 1, so a typo changed the shape of the load without any
/// warning.
#[test]
fn loadgen_refuses_zero_concurrency() {
    let output = run(&[
        "loadgen",
        "--addr",
        "127.0.0.1:1",
        "--cap",
        "00112233445566778899aabbccddeeff",
        "--concurrency",
        "0",
        "--requests",
        "1",
    ]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("must be at least 1"),
        "stderr: {}",
        stderr(&output)
    );
}

/// (h) `events --interval-ms` below the 50 ms floor is refused: below it
/// the follow loop would busy-spin, polling faster than a loopback round
/// trip can answer.
#[test]
fn events_refuses_an_interval_below_the_floor() {
    for interval in ["0", "10"] {
        let output = run(&["events", "--interval-ms", interval]);
        assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
        assert!(
            stderr(&output).contains("must be at least 50"),
            "stderr: {}",
            stderr(&output)
        );
    }
}

/// (h) `http_get` refuses a plane URL carrying CR or LF: the URL is
/// interpolated into the request line, so a line break in it would let
/// the operator smuggle a second request line.
#[test]
fn events_refuses_a_url_with_crlf() {
    let output = run(&[
        "events",
        "--plane",
        "http://127.0.0.1:8787/activity\r\nInjected: x",
    ]);
    assert_eq!(output.status.code(), Some(2), "stderr: {}", stderr(&output));
    assert!(
        stderr(&output).contains("must not contain CR or LF"),
        "stderr: {}",
        stderr(&output)
    );
}

/// (h) `doctor` prints the features the binary was compiled with, not a
/// hardcoded list: the line is built from the lib's `enabled_features()`,
/// so a build without quic says so.
#[test]
fn doctor_reports_the_compiled_in_features() {
    let output = run(&["doctor"]);
    assert!(output.status.success());
    assert!(
        stdout(&output).contains("features: quic http2"),
        "stdout: {}",
        stdout(&output)
    );
}

/// RPC-56: `receipts show` prints the caller's 128-bit prefix for a peer
/// call, and nothing for a local or anonymous one.
#[test]
fn receipts_show_names_the_caller() {
    use active_rpc::receipts::{Decision, Receipt, ReceiptLog};
    let dir = sandbox("rpc56-caller");
    let path = dir.join("caller.arrl");
    let log = ReceiptLog::create(&path).expect("create");
    log.append(
        &Receipt {
            sequence: 1,
            cap: "0011223344556677".to_string(),
            method: "echo".to_string(),
            at_ms: 1,
            decision: Decision::Admitted,
            mac: [0u8; 32],
            caller: Some([0xabu8; 16]),
        },
    )
    .expect("append peer receipt");
    log.append(
        &Receipt {
            sequence: 2,
            cap: "0011223344556677".to_string(),
            method: "echo".to_string(),
            at_ms: 2,
            decision: Decision::Admitted,
            mac: [0u8; 32],
            caller: None,
        },
    )
    .expect("append local receipt");
    drop(log);
    let show = run(&["receipts", "show", path.to_str().expect("log path")]);
    assert!(show.status.success(), "{}", stderr(&show));
    let shown = stdout(&show);
    let lines: Vec<&str> = shown.lines().collect();
    assert_eq!(lines.len(), 3, "{shown}");
    assert!(
        lines[1].contains(&format!("caller={}", "ab".repeat(16))),
        "the peer receipt names its caller: {}",
        lines[1]
    );
    assert!(
        !lines[2].contains("caller="),
        "the local receipt names no caller: {}",
        lines[2]
    );
}
