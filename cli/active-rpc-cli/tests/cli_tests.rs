//! End-to-end CLI tests: every command drives the shipped binary and a real
//! kernel peer over a real transport.

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
