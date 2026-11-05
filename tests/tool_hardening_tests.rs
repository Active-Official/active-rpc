//! R-08 round 2: program identity, request framing and the process tree.
//!
//! Each test drives the shipped adapter (no re-implementation): a bare program
//! name is refused, a GET carries no body, and a timeout kills the whole
//! process group.

use std::net::TcpListener;

use active_rpc::tool::{HttpTool, LocalProcess};
use active_rpc::value::Response;
use active_rpc::{Arg, Call, Provider, Value};

// ---------------------------------------------------------------------------
// Program identity
// ---------------------------------------------------------------------------

/// A bare name is resolved from the parent's `PATH`, which is ambient
/// authority: whoever writes an earlier `PATH` entry picks the binary.
#[test]
fn a_bare_program_name_is_refused() {
    for bare in [
        "cmd.exe",
        "sh",
        "echo",
        "./tool",
        "bin/tool",
        "..\\tool",
        "C:tool.exe",
    ] {
        let error = LocalProcess::new(bare, &[])
            .err()
            .unwrap_or_else(|| panic!("{bare:?} must be refused"));
        assert_eq!(error.code(), "rpc/invalid-argument", "{bare:?}: {error}");
    }

    // An absolute path is accepted, and the working directory must be absolute
    // too: a relative one would resolve against whatever the parent's directory
    // happens to be at spawn time.
    let tool = LocalProcess::new(absolute_shell(), &[]).expect("an absolute program");
    assert!(
        tool.working_directory().is_absolute(),
        "{:?}",
        tool.working_directory()
    );
    let error = tool
        .with_current_dir("relative")
        .expect_err("a relative working directory must be refused");
    assert_eq!(error.code(), "rpc/invalid-argument");
}

/// An absolute interpreter path that exists on this host.
fn absolute_shell() -> &'static str {
    #[cfg(windows)]
    {
        "C:\\Windows\\System32\\cmd.exe"
    }
    #[cfg(not(windows))]
    {
        "/bin/sh"
    }
}

// ---------------------------------------------------------------------------
// HTTP request framing
// ---------------------------------------------------------------------------

/// Accept one connection, read the head, and report whether content followed
/// the empty line. Trailing bytes are read with a short timeout so a client
/// that already sent a body is caught even when it wrote in one segment.
fn record_one_request(listener: TcpListener) -> std::thread::JoinHandle<(String, usize)> {
    std::thread::spawn(move || {
        use std::io::{Read, Write};

        let (mut socket, _) = listener.accept().expect("one connection");
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(750)))
            .expect("read timeout");
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match socket.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => head.push(byte[0]),
            }
        }
        let mut trailing = [0u8; 64];
        // A timeout means nothing followed the head, which is the point of the
        // test for a method defined without content.
        let body = socket.read(&mut trailing).unwrap_or_default();
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
        (String::from_utf8_lossy(&head).to_string(), body)
    })
}

#[test]
fn a_get_request_has_no_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = record_one_request(listener);

    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/safe")]);
    let call = Call::new("get", vec![Arg::Value(Value::path("/safe"))]);
    let response = tool.invoke(0, &call).expect("GET answers");

    let (head, body) = server.join().expect("server thread");
    let lower = head.to_ascii_lowercase();
    assert!(lower.starts_with("get /safe http/1.1"), "{head}");
    assert!(
        !lower.contains("content-length"),
        "a GET must not send a content-length: {head}"
    );
    assert_eq!(body, 0, "a GET carried a body: {head}");
    match response {
        Response::Value(Value::Text(text)) => assert_eq!(text, "ok"),
        other => panic!("unexpected response {other:?}"),
    }
}

/// The allowlist stores methods in the case the request is compared in
/// (round 16, F-8): a lowercase entry used to match nothing.
#[test]
fn a_lowercase_allowlist_entry_matches() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = record_one_request(listener);

    let mut tool = HttpTool::new(format!("http://{address}"), &[("get", "/safe")]);
    let call = Call::new("get", vec![Arg::Value(Value::path("/safe"))]);
    tool.invoke(0, &call).expect("a lowercase entry matches");
    let (head, _) = server.join().expect("server thread");
    assert!(head.to_ascii_lowercase().starts_with("get /safe"), "{head}");
}

#[test]
fn a_post_carries_its_body_and_length() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = record_one_request(listener);

    let mut tool = HttpTool::new(format!("http://{address}"), &[("POST", "/submit")]);
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("k".to_string(), Value::text("v"));
    let call = Call::new(
        "post",
        vec![
            Arg::Value(Value::path("/submit")),
            Arg::Value(Value::Map(entries)),
        ],
    );
    tool.invoke(0, &call).expect("POST answers");

    let (head, body) = server.join().expect("server thread");
    assert!(
        head.to_ascii_lowercase().contains("content-length: 9"),
        "a POST declares its body: {head}"
    );
    assert_eq!(body, 9, "the POST body follows the head: {head}");
}

// ---------------------------------------------------------------------------
// Process tree
// ---------------------------------------------------------------------------

/// A timeout kills the whole process group: a descendant that the direct child
/// started in the background must not outlive the call.
#[cfg(unix)]
#[test]
fn a_timeout_kills_the_descendant_tree() {
    use std::time::{Duration, Instant};

    let directory = std::env::temp_dir().join(format!(
        "active-rpc-process-group-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&directory).expect("scratch directory");
    let marker = directory.join("marker");
    let _ = std::fs::remove_file(&marker);

    // The background subshell writes the marker two seconds after the call has
    // already timed out. Only a group signal reaches it.
    let script = format!("(sleep 2; echo late > '{}') & sleep 30", marker.display());
    let mut tool = LocalProcess::new("/bin/sh", &["-c", script.as_str()])
        .expect("an absolute program")
        .with_timeout(300);
    tool.env
        .insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let mut call = Call::new("run", vec![Arg::text("-c"), Arg::text(script)]);
    call.tool_allows_process = true;

    let started = Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("the child outlives the ceiling");
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the call returned after {:?}",
        started.elapsed()
    );

    std::thread::sleep(Duration::from_millis(2_500));
    assert!(
        !marker.exists(),
        "a descendant survived the timeout and wrote {marker:?}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// The leader can exit at once and leave a descendant holding the pipes. The
/// call then times out in the reader wait, which must kill the tree too: a
/// refunded call must not leave a process acting on the capability's behalf.
#[cfg(unix)]
#[test]
fn a_timeout_after_the_leader_exits_kills_the_tree() {
    use std::time::{Duration, Instant};

    let directory = std::env::temp_dir().join(format!(
        "active-rpc-process-group-exit-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&directory).expect("scratch directory");
    let marker = directory.join("marker");
    let _ = std::fs::remove_file(&marker);

    // The leader exits immediately; the background subshell keeps the pipes and
    // writes the marker two seconds later.
    let script = format!("(sleep 2; echo late > '{}') & exit 0", marker.display());
    let mut tool = LocalProcess::new("/bin/sh", &["-c", script.as_str()])
        .expect("an absolute program")
        .with_timeout(300);
    tool.env
        .insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let mut call = Call::new("run", vec![Arg::text("-c"), Arg::text(script)]);
    call.tool_allows_process = true;

    let started = Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("the inherited pipes outlive the ceiling");
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the call returned after {:?}",
        started.elapsed()
    );

    std::thread::sleep(Duration::from_millis(2_500));
    assert!(
        !marker.exists(),
        "a descendant of an exited leader survived the timeout"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

// ---------------------------------------------------------------------------
// HTTP: wall ceiling, framing, request line
// ---------------------------------------------------------------------------

/// Accept one connection, discard the request head, then write `response` one
/// byte per `gap`.
fn slow_response(listener: TcpListener, response: Vec<u8>, gap: std::time::Duration) {
    std::thread::spawn(move || {
        use std::io::{Read, Write};

        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .ok();
        let mut scratch = [0u8; 4096];
        let _ = socket.read(&mut scratch);
        for byte in response {
            if socket.write_all(&[byte]).is_err() {
                return;
            }
            let _ = socket.flush();
            if !gap.is_zero() {
                std::thread::sleep(gap);
            }
        }
    });
}

fn http_get(path: &str, ceiling_ms: u64) -> Call {
    let mut call = Call::new("get", vec![Arg::Value(Value::path(path))]);
    call.budget.max_wall_ms = ceiling_ms;
    call
}

/// The ceiling is one deadline for the exchange, not a timeout per read: a
/// server that drips a byte per period cannot stretch a 150 ms grant to seconds.
#[test]
fn a_dripping_server_cannot_stretch_the_wall_ceiling() {
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    slow_response(
        listener,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok".to_vec(),
        Duration::from_millis(40),
    );

    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/slow")]);
    let mut call = http_get("/slow", 150);
    call.read_only = true;
    let started = Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("the drip exceeds the ceiling");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        elapsed < Duration::from_millis(1_500),
        "a 150 ms grant waited {elapsed:?}"
    );
}

/// A HEAD reply describes a representation it does not carry. Reading
/// `content-length` bytes would stall the dispatcher until the ceiling.
#[test]
fn a_head_response_has_no_body() {
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    slow_response(
        listener,
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\n".to_vec(),
        Duration::ZERO,
    );

    let mut tool = HttpTool::new(format!("http://{address}"), &[("HEAD", "/probe")]);
    let mut call = Call::new(
        "request",
        vec![
            Arg::Value(Value::text("head")),
            Arg::Value(Value::path("/probe")),
        ],
    );
    call.budget.max_wall_ms = 1_000;
    let started = Instant::now();
    let response = tool.invoke(0, &call).expect("a HEAD reply is bodyless");
    assert!(started.elapsed() < Duration::from_millis(800));
    match response {
        Response::Value(Value::Text(text)) => assert!(text.is_empty(), "{text:?}"),
        other => panic!("unexpected response {other:?}"),
    }
}

/// A JSON answer whose only fault is a number with no `Value` form is refused
/// as `http/bad-number`; an answer that is not JSON at all stays text
/// (round 15, F-1).
#[test]
fn a_json_body_with_an_unrepresentable_number_is_refused() {
    use std::time::Duration;

    for body in [
        r#"{"amount": 1e400}"#,
        r#"{"amount": 18446744073709551617}"#,
        r#"{"debit": -9223372036854775809}"#,
        // A bare scalar is still JSON: it must not be downgraded to text
        // (round 16, F-1).
        "1e400",
        " -1e400 ",
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        slow_response(listener, response.into_bytes(), Duration::ZERO);
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/number")]);
        let error = tool
            .invoke(0, &http_get("/number", 2_000))
            .expect_err("a number with no Value form is refused");
        assert_eq!(
            error.provider_code(),
            Some("http/bad-number"),
            "{body}: {error}"
        );
    }

    // A plain-text body that happens to look like a lone minus sign is text.
    for body in ["-", "- not json"] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        );
        slow_response(listener, response.into_bytes(), Duration::ZERO);
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/text")]);
        let response = tool
            .invoke(0, &http_get("/text", 2_000))
            .expect("plain text answers");
        match response {
            Response::Value(Value::Text(text)) => assert_eq!(text, body),
            other => panic!("unexpected response {other:?}"),
        }
    }
}

/// Accept one connection, read the head, then write `response` in one call.
///
/// `slow_response` writes a byte per iteration, which is deliberate for the
/// ceiling tests and far too slow for a multi-megabyte body.
fn fixed_response(listener: TcpListener, response: Vec<u8>) {
    std::thread::spawn(move || {
        use std::io::{Read, Write};

        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .ok();
        let mut scratch = [0u8; 4096];
        let _ = socket.read(&mut scratch);
        let _ = socket.write_all(&response);
    });
}

/// A JSON body past the token ceiling is `http/too-complex`; a large body that
/// is not an object or an array stays text (round 15, F-5/F-6).
#[test]
fn a_json_body_past_the_token_ceiling_is_too_complex() {
    let mut body = String::with_capacity(2 << 20);
    body.push('[');
    for _ in 0..((1usize << 20) + 8) {
        body.push_str("0,");
    }
    body.push('0');
    body.push(']');
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    fixed_response(listener, response.into_bytes());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/big")]);
    tool.max_body = 4 << 20;
    let error = tool
        .invoke(0, &http_get("/big", 20_000))
        .expect_err("a body past the token ceiling is refused");
    assert_eq!(error.provider_code(), Some("http/too-complex"), "{error}");

    // A leading byte-order mark is ignored, so the same body is still gated
    // (round 17, F-5).
    // Any run of a byte-order mark and whitespace is skipped, so repeated
    // or spaced marks cannot hide the body from the gate (round 18, L-2).
    for prefix in ["\u{feff}", "\u{feff}\u{feff}", " \u{feff}"] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let scripted = format!("{prefix}{body}");
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{scripted}",
            scripted.len()
        );
        fixed_response(listener, response.into_bytes());
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/bom")]);
        tool.max_body = 4 << 20;
        let error = tool
            .invoke(0, &http_get("/bom", 20_000))
            .expect_err("a prefix does not hide a huge body");
        assert_eq!(
            error.provider_code(),
            Some("http/too-complex"),
            "{prefix:?}: {error}"
        );
    }

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let scripted = format!("\u{feff}{body}");
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{scripted}",
        scripted.len()
    );
    fixed_response(listener, response.into_bytes());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/bom")]);
    tool.max_body = 4 << 20;
    let error = tool
        .invoke(0, &http_get("/bom", 20_000))
        .expect_err("a BOM does not hide a huge body");
    assert_eq!(error.provider_code(), Some("http/too-complex"), "{error}");

    // A small BOM-prefixed object is still JSON.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let small = "\u{feff}{\"a\":1}";
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{small}",
        small.len()
    );
    fixed_response(listener, response.into_bytes());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/bom-small")]);
    let response = tool
        .invoke(0, &http_get("/bom-small", 2_000))
        .expect("a BOM-prefixed object answers");
    match response {
        Response::Value(Value::Map(entries)) => assert_eq!(entries.len(), 1),
        other => panic!("a BOM-prefixed object became {other:?}"),
    }

    // A CSV report is not JSON: its commas do not make it a JSON tree.
    let mut csv = String::with_capacity(2 << 20);
    for _ in 0..((1usize << 20) / 2) {
        csv.push_str("a,b;");
        if csv.len() >= (1 << 20) + 64 {
            break;
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{csv}",
        csv.len()
    );
    fixed_response(listener, response.into_bytes());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/csv")]);
    tool.max_body = 4 << 20;
    let response = tool
        .invoke(0, &http_get("/csv", 20_000))
        .expect("a CSV answer is text");
    match response {
        Response::Value(Value::Text(text)) => assert_eq!(text.len(), csv.len()),
        other => panic!("a CSV answer became {other:?}"),
    }
}

/// A body shorter than its declared length, and a head that never ends, keep
/// their own codes (round 15, F-10).
#[test]
fn a_truncated_head_or_body_has_its_own_code() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    fixed_response(
        listener,
        b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\nconnection: close\r\n\r\nabc".to_vec(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/short")]);
    let mut short = http_get("/short", 2_000);
    short.read_only = true;
    let error = tool.invoke(0, &short).expect_err("a short body is refused");
    assert_eq!(
        error.provider_code(),
        Some("http/read:truncated-body"),
        "{error}"
    );

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    fixed_response(listener, b"HTTP/1.1 200".to_vec());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/head")]);
    let mut head = http_get("/head", 2_000);
    head.read_only = true;
    let error = tool
        .invoke(0, &head)
        .expect_err("a truncated head is refused");
    assert_eq!(
        error.provider_code(),
        Some("http/read:truncated"),
        "{error}"
    );
}

/// The capability's byte grant bounds the response the adapter buffers, not
/// only what the kernel charges on egress (round 19, M2).
#[test]
fn a_response_past_the_byte_grant_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let body = "x".repeat(128);
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    fixed_response(listener, response.into_bytes());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/big")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/big"))]);
    call.read_only = true;
    // The head fits; the 128-byte body does not. The grant is the binding
    // ceiling, so the refusal names the budget (round 25, #3).
    call.budget.max_bytes = 64;
    let error = tool.invoke(0, &call).expect_err("past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// The two process streams share the capability's byte grant
/// (round 20, M2).
#[test]
fn both_process_streams_share_the_byte_grant() {
    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    #[cfg(windows)]
    let argv = ["-NoProfile", "-Command", "for /L %i in (1,1,64) do @echo a"];
    #[cfg(not(windows))]
    let argv = [
        "-c",
        "i=0; while [ $i -lt 64 ]; do echo a; echo b 1>&2; i=$((i+1)); done",
    ];
    // Exact rules: a prefix rule would refuse the script's shell syntax before
    // the output ceiling was ever reached. The script prints about 256 bytes
    // between the two streams, more than the grant below, while the argument
    // line itself fits.
    let allowed = argv;
    #[cfg(windows)]
    let mut env = std::collections::BTreeMap::new();
    #[cfg(windows)]
    env.insert(
        "SystemRoot".to_string(),
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
    );
    #[cfg(not(windows))]
    let env = std::collections::BTreeMap::new();
    let mut tool = LocalProcess::new(program, &allowed).expect("an absolute program");
    tool.env.extend(env);
    let mut call = Call::new(
        "run",
        argv.iter().map(|argument| Arg::text(*argument)).collect(),
    );
    call.tool_allows_process = true;
    // The argument line fits (about 60 bytes); the two streams together
    // (about 260) do not.
    call.budget.max_bytes = 80;
    let error = tool
        .invoke(0, &call)
        .expect_err("both streams over the grant");
    // The child ran, so the class says the reply was withheld and a retry does
    // not fork it again (round 43, F-4).
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
}

/// The response head is bounded by the byte grant too (round 20, M3).
#[test]
fn a_response_head_past_the_byte_grant_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let response = "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
    fixed_response(listener, response.as_bytes().to_vec());
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/small")]);
    // The adapter's own ceiling binds here, so the refusal is a provider
    // framing fault; a grant-bound cap answers `rpc/budget-exceeded` instead
    // (round 25, #7).
    tool.max_body = 40;
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/small"))]);
    call.read_only = true;
    call.budget.max_bytes = 4096;
    let error = tool
        .invoke(0, &call)
        .expect_err("the head is past the adapter ceiling");
    assert_eq!(error.provider_code(), Some("http/headers"), "{error}");
}

/// A repeated `content-length` is a framing ambiguity; the adapter refuses the
/// message instead of picking one.
#[test]
fn a_repeated_content_length_is_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    slow_response(
        listener,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
            .to_vec(),
        std::time::Duration::ZERO,
    );

    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/dup")]);
    let mut call = http_get("/dup", 1_000);
    call.read_only = true;
    let error = tool.invoke(0, &call).expect_err("ambiguous framing");
    assert_eq!(error.code(), "rpc/provider");
    assert!(format!("{error}").contains("http/headers"), "{error}");
}

/// A path is interpolated into the request line, so a control character is
/// refused before the allow-list is even consulted.
#[test]
fn a_path_with_a_control_character_is_refused() {
    // The allow-list admits the path: the refusal has to come from the request
    // line check, not from the policy comparison.
    let mut tool = HttpTool::new("http://127.0.0.1:1", &[("GET", "/safe\r\nx")]);
    let call = http_get("/safe\r\nx", 100);
    let error = tool.invoke(0, &call).expect_err("request splitting");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

// ---------------------------------------------------------------------------
// Local process: argument shape and stream identity
// ---------------------------------------------------------------------------

/// A `*` rule is a command-line prefix. With a shell as the program the rest of
/// the line is code, so a prefix-matched argument may not carry shell syntax.
#[test]
fn a_prefix_argument_cannot_smuggle_a_command() {
    #[cfg(windows)]
    let (program, flag) = ("C:\\Windows\\System32\\cmd.exe", "/C");
    #[cfg(not(windows))]
    let (program, flag) = ("/bin/sh", "-c");
    let mut tool = LocalProcess::new(program, &[flag, "echo*"]).expect("an absolute program");
    for injected in [
        "echo ok & echo pwned",
        "echo ok | more",
        "echo ok; echo pwned",
        "echo %PATH%",
        "echo $(id)",
    ] {
        let mut call = Call::new("run", vec![Arg::text(flag), Arg::text(injected)]);
        call.tool_allows_process = true;
        let error = tool
            .invoke(0, &call)
            .expect_err("a command line is not an argument");
        assert_eq!(error.code(), "rpc/tool-policy", "{injected:?}: {error}");
    }
}

/// Two readers share one channel; labelling by arrival order swaps the streams
/// whenever stderr reports first. The adapter tags each stream instead.
#[test]
fn stdout_and_stderr_are_not_swapped() {
    #[cfg(windows)]
    let (program, flag, script) = (
        "C:\\Windows\\System32\\cmd.exe",
        "/C",
        "echo OUT& echo ERR 1>&2",
    );
    #[cfg(not(windows))]
    let (program, flag, script) = ("/bin/sh", "-c", "echo OUT; echo ERR 1>&2");

    let mut tool = LocalProcess::new(program, &[flag, script])
        .expect("an absolute program")
        .with_timeout(5_000);
    for attempt in 0..20 {
        let mut call = Call::new("run", vec![Arg::text(flag), Arg::text(script)]);
        call.tool_allows_process = true;
        let response = tool.invoke(0, &call).expect("the child runs");
        let Response::Value(Value::Map(entries)) = response else {
            panic!("expected a map");
        };
        let stdout = match entries.get("stdout") {
            Some(Value::Text(text)) => text.trim().to_string(),
            other => panic!("unexpected stdout {other:?}"),
        };
        let stderr = match entries.get("stderr") {
            Some(Value::Text(text)) => text.trim().to_string(),
            other => panic!("unexpected stderr {other:?}"),
        };
        assert_eq!(
            stdout, "OUT",
            "attempt {attempt}: streams swapped ({stderr:?})"
        );
        assert_eq!(
            stderr, "ERR",
            "attempt {attempt}: streams swapped ({stdout:?})"
        );
    }
}

// ---------------------------------------------------------------------------
// R-08 round 3: a drip cannot stretch the body, a stalled pipe cannot block the
// send, and a request that cannot be delivered is refused instead of dropped.
// ---------------------------------------------------------------------------

/// Headers at once, then the declared body one byte per `gap`: the old reader
/// armed the socket timeout once and each byte reset it, so a 150 ms grant could
/// be held for minutes.
#[test]
fn a_dripping_body_cannot_stretch_the_wall_ceiling() {
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        use std::io::{Read, Write};

        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let mut scratch = [0u8; 4096];
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .ok();
        let _ = socket.read(&mut scratch);
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2000\r\nconnection: close\r\n\r\n");
        let _ = socket.flush();
        for _ in 0..2000 {
            if socket.write_all(b"x").is_err() {
                return;
            }
            let _ = socket.flush();
            std::thread::sleep(Duration::from_millis(40));
        }
    });

    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/drip")]);
    let mut call = http_get("/drip", 150);
    call.tool_allows_process = true;
    call.read_only = true;
    let started = Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("the body never arrives in time");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        elapsed < Duration::from_secs(2),
        "a 150 ms grant took {elapsed:?} to refuse a dripping body"
    );
}

/// A server that stops reading fills the pipe; the send must not block the
/// kernel past the ceiling.
#[test]
fn a_stalled_mcp_reader_cannot_block_the_send() {
    use std::time::{Duration, Instant};

    use active_rpc::tool::{McpTransport, StdioTransport};

    #[cfg(windows)]
    let (program, args, env) = {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let mut env = std::collections::BTreeMap::new();
        // The transport clears the environment; a Windows child without
        // `SystemRoot` exits at once.
        env.insert("SystemRoot".to_string(), root.clone());
        (
            format!("{root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            vec!["-NoProfile", "-Command", "Start-Sleep -Seconds 30"],
            env,
        )
    };
    #[cfg(not(windows))]
    let (program, args, env) = (
        "/bin/sh".to_string(),
        vec!["-c", "sleep 30"],
        std::collections::BTreeMap::new(),
    );
    let mut transport = StdioTransport::spawn(&program, &args, &env).expect("spawn");
    // Larger than any pipe buffer, so the writer blocks on a child that never
    // reads.
    let line = "x".repeat(1 << 20);
    let started = Instant::now();
    let error = transport
        .send_line_within(&line, Some(Instant::now() + Duration::from_millis(200)))
        .expect_err("the write never completes");
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "a 200 ms write deadline took {:?}",
        started.elapsed()
    );
}

/// `to_uppercase` maps `ß` to `SS`, so a lower-case name could alias an
/// allowlisted method; the RFC 9110 token set also admits `M-SEARCH`.
#[test]
fn the_http_method_is_ascii_and_a_token() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("SS", "/x"), ("M-SEARCH", "/y")]);
    let mut call = Call::new(
        "request",
        vec![Arg::text("\u{00df}"), Arg::Value(Value::path("/x"))],
    );
    call.tool_allows_process = true;
    let error = tool
        .invoke(0, &call)
        .expect_err("a non-ASCII method is refused");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");

    // Two method arguments cannot mean two methods.
    let mut call = Call::new(
        "request",
        vec![
            Arg::text("GET"),
            Arg::text("POST"),
            Arg::Value(Value::path("/x")),
        ],
    );
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("one method");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A body map on a method defined without content, and an envelope payload,
/// used to be dropped silently: the caller believed data was delivered.
#[test]
fn an_undeliverable_request_is_refused() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x"), ("POST", "/y")]);
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("a".to_string(), Value::Int(1));
    let mut call = Call::new(
        "get",
        vec![
            Arg::Value(Value::path("/x")),
            Arg::Value(Value::Map(entries)),
        ],
    );
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("a GET carries no body");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    let mut call = Call::new("get", vec![Arg::Value(Value::path("/x"))]);
    call.tool_allows_process = true;
    call.payload = b"a payload this adapter cannot send".to_vec();
    let error = tool.invoke(0, &call).expect_err("the payload is refused");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A secret travels as the marker, which is not the value: an external peer that
/// acts on it acts on data the caller never approved.
#[test]
fn a_secret_argument_is_not_sent_to_a_peer() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/x"))]);
    call.args.push(Arg::Value(Value::Secret));
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("a secret is refused");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// A status outside 200..=599 and a header line without a colon are framing
/// faults, not a success and a skipped line.
#[test]
fn a_malformed_http_answer_is_refused() {
    fn answer(response: &'static [u8]) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            let mut scratch = [0u8; 4096];
            socket
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .ok();
            let _ = socket.read(&mut scratch);
            let _ = socket.write_all(response);
            let _ = socket.flush();
        });
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/x")]);
        let mut call = http_get("/x", 1_000);
        call.tool_allows_process = true;
        tool.invoke(0, &call).expect_err("malformed").code().len() as u16
    }
    // Both are refused; the code is the adapter's, not a transport failure.
    assert!(answer(b"HTTP/1.1 099 Odd\r\ncontent-length: 0\r\n\r\n") > 0);
    assert!(answer(b"HTTP/1.1 200 OK\r\nnot-a-header\r\ncontent-length: 2\r\n\r\nok") > 0);
}

/// Glob, brace and tilde expansion are shell syntax too: with a prefix grant
/// `echo /*` lists the filesystem through stdout.
#[test]
fn a_prefix_argument_cannot_expand_a_glob() {
    #[cfg(windows)]
    let (program, flag) = ("C:\\Windows\\System32\\cmd.exe", "/C");
    #[cfg(not(windows))]
    let (program, flag) = ("/bin/sh", "-c");
    let mut tool = LocalProcess::new(program, &[flag, "echo*"]).expect("an absolute program");
    for injected in ["echo /*", "echo ~", "echo a{b,c}", "echo #x"] {
        let mut call = Call::new("run", vec![Arg::text(flag), Arg::text(injected)]);
        call.tool_allows_process = true;
        let error = tool
            .invoke(0, &call)
            .expect_err("expansion syntax is not an argument");
        assert_eq!(error.code(), "rpc/tool-policy", "{injected:?}: {error}");
    }
}

/// A server that reads the head and then stops reading fills the socket: the
/// write must report the ceiling, not a transport fault, or a caller retries a
/// call that ran out of its grant.
#[test]
fn a_stalled_http_reader_reports_the_ceiling() {
    use std::time::{Duration, Instant};

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        use std::io::Read;
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        // Read the head, then never read again: the client's body write fills
        // the socket buffer and hits its write timeout.
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .ok();
        while !head.ends_with(b"\r\n\r\n") {
            match socket.read(&mut byte) {
                Ok(0) | Err(_) => break,
                Ok(_) => head.push(byte[0]),
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    });

    let mut tool = HttpTool::new(format!("http://{address}"), &[("POST", "/stall")]);
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("blob".to_string(), Value::text("x".repeat(256 << 10)));
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::path("/stall")),
            Arg::Value(Value::Map(entries)),
        ],
    );
    call.read_only = true;
    call.tool_allows_process = true;
    call.budget.max_wall_ms = 200;
    let started = Instant::now();
    let error = tool
        .invoke(0, &call)
        .expect_err("the write never completes");
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "a 200 ms grant took {:?}",
        started.elapsed()
    );
}

/// An adapter that cannot deliver an argument refuses the request instead of
/// calling the peer with the rest.
#[test]
fn an_undeliverable_argument_is_refused() {
    use active_rpc::cap::CapId;
    use active_rpc::value::Arg;

    // HTTP: an integer argument is not a method, a path or a body.
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x")]);
    let mut call = Call::new(
        "get",
        vec![Arg::Value(Value::path("/x")), Arg::Value(Value::Int(1))],
    );
    call.tool_allows_process = true;
    let error = tool
        .invoke(0, &call)
        .expect_err("an integer is not deliverable");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    // MCP: a capability argument is authority, not JSON.
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Cap(CapId([0x11; 16]))]);
    call.tool_allows_process = true;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("a capability is not deliverable");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// The base is part of the request line and the `Host` header.
#[test]
fn a_non_ascii_base_is_refused() {
    let mut tool = HttpTool::new("http://ex\u{00e4}mple.test", &[("GET", "/x")]);
    let mut call = http_get("/x", 500);
    call.tool_allows_process = true;
    let error = tool
        .invoke(0, &call)
        .expect_err("a non-ASCII base is refused");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// A zero wall grant is a refusal, before any work or spawn.
#[test]
fn a_zero_wall_grant_is_a_budget_refusal() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/x"))]);
    call.tool_allows_process = true;
    call.budget.max_wall_ms = 0;
    let error = tool.invoke(0, &call).expect_err("a zero grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");

    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\cmd.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    let mut process = LocalProcess::new(program, &["*"]).expect("an absolute program");
    let mut call = Call::new("run", Vec::new());
    call.tool_allows_process = true;
    call.budget.max_wall_ms = 0;
    let error = process.invoke(0, &call).expect_err("a zero grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

// ---------------------------------------------------------------------------
// Round 5
// ---------------------------------------------------------------------------

/// A stub MCP server that lists one `echo` tool and answers a call.
fn echo_session() -> active_rpc::tool::McpSession<active_rpc::tool::MemoryTransport> {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#
            .to_string(),
    );
    McpSession::handshake(MemoryTransport::new(responses)).expect("handshake")
}

/// An MCP result whose number has no `Value` form is `mcp/bad-number` and
/// poisons the session: the next line would belong to an answer already
/// abandoned (round 15, F-1).
#[test]
fn an_mcp_result_with_an_unrepresentable_number_is_refused() {
    use active_rpc::tool::{McpSession, McpTransport};

    /// Answers each sent line with the next canned line, byte for byte.
    ///
    /// `MemoryTransport` re-encodes a response to echo the request id, which
    /// would rewrite the very literal under test: the point here is the raw
    /// bytes a server emits.
    struct RawLines(std::collections::VecDeque<String>);

    impl McpTransport for RawLines {
        fn send_line(&mut self, _line: &str) -> active_rpc::error::Result<()> {
            Ok(())
        }

        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.0.pop_front().ok_or(active_rpc::error::Error::Timeout)
        }
    }

    for literal in ["1e400", "18446744073709551617", "-9223372036854775809"] {
        let mut lines = std::collections::VecDeque::new();
        lines.push_back(
            r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
                .to_string(),
        );
        lines.push_back(
            r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
                .to_string(),
        );
        lines.push_back(format!(
            r#"{{"jsonrpc":"2.0","id":3,"result":{{"value":{literal}}}}}"#
        ));
        let mut session = McpSession::handshake(RawLines(lines)).expect("handshake");
        let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
        call.read_only = true;
        call.tool_allows_process = true;
        let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
            .expect_err("a number with no Value form is refused");
        assert_eq!(
            error.provider_code(),
            Some("mcp/bad-number"),
            "{literal}: {error}"
        );
    }
}

/// `get` and `post` name their method in the capability. A text argument used to
/// reach them and be dropped, so the peer acted without data the caller
/// approved.
#[test]
fn a_text_argument_on_a_named_method_is_refused() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x"), ("POST", "/y")]);
    for (method, path) in [("get", "/x"), ("post", "/y")] {
        let mut call = Call::new(
            method,
            vec![Arg::Value(Value::path(path)), Arg::text("idempotency-key")],
        );
        call.tool_allows_process = true;
        let error = tool
            .invoke(0, &call)
            .expect_err("a text is not deliverable");
        assert_eq!(error.code(), "rpc/invalid-argument", "{method}: {error}");
    }
}

/// The JSON form of a module is its byte length, not its content: a peer that
/// receives it acts on a request the caller never made. Nested too.
#[test]
fn a_module_argument_is_not_sent() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("POST", "/y")]);
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("m".to_string(), Value::Module(vec![1, 2, 3]));
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::path("/y")),
            Arg::Value(Value::Map(entries)),
        ],
    );
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("a module body");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    let mut session = echo_session();
    let mut call = Call::new("echo", vec![Arg::Value(Value::Module(vec![1, 2, 3]))]);
    call.tool_allows_process = true;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("a module argument");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A POST with no body object sends no bytes. It used to send the four bytes
/// `null` under `content-length: 4`, which a lax peer acts on.
#[test]
fn a_bodyless_post_sends_no_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let server = record_one_request(listener);

    let mut tool = HttpTool::new(format!("http://{address}"), &[("POST", "/submit")]);
    let mut call = Call::new("post", vec![Arg::Value(Value::path("/submit"))]);
    call.tool_allows_process = true;
    tool.invoke(0, &call).expect("POST answers");

    let (head, body) = server.join().expect("server thread");
    assert!(
        head.to_ascii_lowercase().contains("content-length: 0"),
        "an empty body is declared: {head}"
    );
    assert_eq!(body, 0, "a bodyless POST carried bytes: {head}");
}

/// The reader hands back a line of exactly the cap and refuses one that fills
/// the read window without a newline; trimming alone would accept an overlong
/// frame and leave its tail in the pipe (round 16, F-7).
#[test]
fn the_stdio_reader_bounds_one_line() {
    use active_rpc::tool::{McpTransport, StdioTransport, MAX_MCP_LINE_BYTES};

    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    #[cfg(windows)]
    let mut env = std::collections::BTreeMap::new();
    #[cfg(windows)]
    env.insert(
        "SystemRoot".to_string(),
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
    );
    #[cfg(not(windows))]
    let env = std::collections::BTreeMap::new();

    #[cfg(windows)]
    let exact = format!(
        "$m={MAX_MCP_LINE_BYTES}; [Console]::Out.Write('a' * $m); [Console]::Out.Write([char]10); [Console]::Out.Flush(); Start-Sleep -Seconds 10"
    );
    #[cfg(not(windows))]
    let exact =
        format!("head -c {MAX_MCP_LINE_BYTES} /dev/zero | tr '\\0' a; printf '\\n'; sleep 10");
    #[cfg(windows)]
    let args = vec!["-NoProfile", "-Command", exact.as_str()];
    #[cfg(not(windows))]
    let args = vec!["-c", exact.as_str()];
    let mut transport = StdioTransport::spawn(program, &args, &env).expect("spawn");
    let line = transport.recv_line().expect("an exact-cap line arrives");
    assert_eq!(line.len(), MAX_MCP_LINE_BYTES, "the cap is inclusive");
    drop(transport);

    #[cfg(windows)]
    let over = format!(
        "$m={}; [Console]::Out.Write('b' * ($m + 2)); [Console]::Out.Flush(); Start-Sleep -Seconds 10",
        MAX_MCP_LINE_BYTES
    );
    #[cfg(not(windows))]
    let over = format!(
        "head -c {} /dev/zero | tr '\\0' b; sleep 10",
        MAX_MCP_LINE_BYTES + 2
    );
    #[cfg(windows)]
    let args = vec!["-NoProfile", "-Command", over.as_str()];
    #[cfg(not(windows))]
    let args = vec!["-c", over.as_str()];
    let mut transport = StdioTransport::spawn(program, &args, &env).expect("spawn");
    let error = transport
        .recv_line()
        .expect_err("an unterminated line past the cap");
    assert_eq!(error.provider_code(), Some("mcp/line-too-long"), "{error}");
}

/// A ceiling already spent writes nothing: the transport stays usable instead
/// of the next call reading the previous answer.
#[test]
fn a_spent_deadline_does_not_write_a_line() {
    use active_rpc::tool::{McpTransport, StdioTransport};

    #[cfg(windows)]
    let mut env = std::collections::BTreeMap::new();
    #[cfg(not(windows))]
    let env = std::collections::BTreeMap::new();
    #[cfg(windows)]
    let (program, args) = (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        vec!["-NoProfile", "-Command", "Start-Sleep -Seconds 20"],
    );
    #[cfg(not(windows))]
    let (program, args) = ("/bin/sh", vec!["-c", "sleep 20"]);
    #[cfg(windows)]
    env.insert(
        "SystemRoot".to_string(),
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
    );
    let mut transport = StdioTransport::spawn(program, &args, &env).expect("spawn");
    let error = transport
        .send_line_within("{\"jsonrpc\":\"2.0\"}", Some(std::time::Instant::now()))
        .expect_err("a spent deadline");
    // Nothing was written, and the session can tell that from an ack timeout
    // (round 34, #7).
    assert_eq!(error.provider_code(), Some("mcp/not-sent"), "{error}");
    transport
        .send_line_within("{\"jsonrpc\":\"2.0\"}", None)
        .expect("the transport still writes");
}

/// A program that does not resolve is refused at construction, so a symlink
/// planted before the first spawn cannot choose the binary (round 17, F-3).
#[test]
fn a_program_that_does_not_resolve_is_refused() {
    #[cfg(windows)]
    let missing = "C:\\nonexistent-active-rpc-program.exe";
    #[cfg(not(windows))]
    let missing = "/nonexistent-active-rpc-program";
    let error = LocalProcess::new(missing, &[]).expect_err("a missing program");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A working directory with an interior NUL never reaches `Command`, which
/// would panic; it is an argument fault (round 18, L-5).
#[test]
fn a_nul_working_directory_is_refused() {
    #[cfg(windows)]
    let (program, bad) = ("C:\\Windows\\System32\\cmd.exe", "C:\\x\0");
    #[cfg(not(windows))]
    let (program, bad) = ("/bin/sh", "/x\0");
    let tool = LocalProcess::new(program, &["*"]).expect("an absolute program");
    let error = tool.with_current_dir(bad).expect_err("a NUL directory");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    // A directory that does not exist is refused at construction rather than
    // at spawn, and the field is private so it cannot be repointed later
    // (audit ARPC-005).
    let tool = LocalProcess::new(program, &["*"]).expect("an absolute program");
    #[cfg(windows)]
    let missing = "C:\\nonexistent-active-rpc-directory";
    #[cfg(not(windows))]
    let missing = "/nonexistent-active-rpc-directory";
    let error = tool
        .with_current_dir(missing)
        .expect_err("a missing directory");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A frame handed over after the deadline is not queued at all, so the echo
/// child never sees it (round 19, L1).
#[test]
fn a_spent_deadline_does_not_enqueue_the_frame() {
    use active_rpc::tool::{McpTransport, StdioTransport};

    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    #[cfg(windows)]
    let mut env = std::collections::BTreeMap::new();
    #[cfg(windows)]
    env.insert(
        "SystemRoot".to_string(),
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
    );
    #[cfg(not(windows))]
    let env = std::collections::BTreeMap::new();
    #[cfg(windows)]
    let args = vec![
        "-NoProfile",
        "-Command",
        "$line=[Console]::In.ReadLine(); [Console]::Out.WriteLine($line)",
    ];
    #[cfg(not(windows))]
    let args = vec!["-c", "read line; echo \"$line\""];
    let mut transport = StdioTransport::spawn(program, &args, &env).expect("spawn");
    let error = transport
        .send_line_within("{\"jsonrpc\":\"2.0\"}", Some(std::time::Instant::now()))
        .expect_err("a spent deadline");
    assert_eq!(error.provider_code(), Some("mcp/not-sent"), "{error}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(400);
    let error = transport
        .recv_line_within(Some(deadline))
        .expect_err("the frame must not have been written");
    assert_eq!(error.code(), "rpc/timeout", "{error}");
}

/// `Command` panics on an interior NUL. A caller-supplied argument and a
/// configured environment entry must be refusals.
#[test]
fn a_nul_argument_is_refused() {
    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\cmd.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    let mut tool = LocalProcess::new(program, &["*"]).expect("an absolute program");
    let mut call = Call::new(
        "run",
        vec![Arg::text("/C"), Arg::text("echo"), Arg::text("a\0b")],
    );
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("a NUL argument");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");

    tool.env
        .insert("ACTIVE_TEST".to_string(), "a\0b".to_string());
    let mut call = Call::new("run", vec![Arg::text("/C"), Arg::text("echo")]);
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("a NUL environment value");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// `Command::env` rejects an empty key, a `=` in a key, or a NUL on either
/// side. Round 5 refused the NUL cases; an empty or `=`-bearing key still
/// reaches `Command` and fails at spawn as a provider fault (or, for `=` on
/// Windows, is silently mangled into another variable) instead of being
/// refused up front.
#[test]
fn an_invalid_environment_key_is_refused() {
    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\cmd.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    for key in ["", "A=B"] {
        let mut tool = LocalProcess::new(program, &["*"]).expect("an absolute program");
        tool.env.insert(key.to_string(), "x".to_string());
        let mut call = Call::new("run", vec![Arg::text("echo")]);
        call.tool_allows_process = true;
        let error = tool.invoke(0, &call).expect_err("a bad environment key");
        assert_eq!(error.code(), "rpc/invalid-argument", "{key:?}: {error}");
    }

    #[cfg(windows)]
    {
        use active_rpc::tool::StdioTransport;

        for key in ["", "A=B"] {
            let mut env = std::collections::BTreeMap::new();
            env.insert(
                "SystemRoot".to_string(),
                std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
            );
            env.insert(key.to_string(), "x".to_string());
            let result = StdioTransport::spawn(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                &["-NoProfile", "-Command", "Start-Sleep -Seconds 20"],
                &env,
            );
            let error = match result {
                Ok(_) => panic!("a bad transport environment key must not spawn"),
                Err(error) => error,
            };
            assert_eq!(error.code(), "rpc/invalid-argument", "{key:?}: {error}");
        }
    }
}

/// `serde_json` has no non-finite numbers: `value_to_json` maps NaN and the
/// infinities to `null`, so a peer would act on a null nobody wrote. The
/// adapters refuse them like a module: same doctrine, same position.
#[test]
fn a_nonfinite_float_is_not_sent() {
    use std::collections::BTreeMap;

    for number in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut session = echo_session();
        let mut call = Call::new("echo", vec![Arg::Value(Value::Float(number))]);
        call.tool_allows_process = true;
        let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
            .expect_err("a non-finite argument");
        assert_eq!(error.code(), "rpc/invalid-argument", "{number:?}: {error}");

        let mut entries = BTreeMap::new();
        entries.insert("x".to_string(), Value::Float(number));
        let mut tool = HttpTool::new("http://127.0.0.1:9", &[("POST", "/y")]);
        let mut call = Call::new(
            "post",
            vec![
                Arg::Value(Value::path("/y")),
                Arg::Value(Value::Map(entries)),
            ],
        );
        call.tool_allows_process = true;
        let error = tool.invoke(0, &call).expect_err("a non-finite body");
        assert_eq!(error.code(), "rpc/invalid-argument", "{number:?}: {error}");
    }
}

/// Round 5 refuses a module recursively: a module nested in a list or a map
/// argument must not reach the wire either.
#[test]
fn a_module_nested_in_a_container_is_not_sent() {
    for value in [
        Value::list([Value::Module(vec![1])]),
        Value::map([("m".to_string(), Value::Module(vec![1]))]),
        Value::map([(
            "outer".to_string(),
            Value::list([Value::map([("m".to_string(), Value::Module(vec![1]))])]),
        )]),
    ] {
        let mut session = echo_session();
        let mut call = Call::new("echo", vec![Arg::Value(value)]);
        call.tool_allows_process = true;
        let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
            .expect_err("a nested module");
        assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
    }
}

/// A handshake against an already-spent ceiling refuses before any frame
/// leaves (round 5, #5, session side).
#[test]
fn a_spent_handshake_deadline_sends_nothing() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    let result = McpSession::handshake_within(
        MemoryTransport::new(responses),
        Some(std::time::Instant::now()),
    );
    let error = match result {
        Ok(_) => panic!("a spent handshake must not succeed"),
        Err(error) => error,
    };
    // Nothing was written, so the refusal says so (round 35, N3).
    assert_eq!(error.provider_code(), Some("mcp/not-sent"), "{error}");
}

// ---------------------------------------------------------------------------
// Round 7
// ---------------------------------------------------------------------------

/// A handshake that advertises a tool without a name is malformed, not empty.
#[test]
fn a_nameless_tool_entry_is_refused() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"description":"nameless"}]}}"#.to_string(),
    );
    let error = match McpSession::handshake(MemoryTransport::new(responses)) {
        Ok(_) => panic!("a nameless tool is refused"),
        Err(error) => error,
    };
    assert_eq!(
        error.provider_code(),
        Some("mcp/tool-name"),
        "the refusal names the list fault: {error}"
    );
}

// ---------------------------------------------------------------------------
// Round 8
// ---------------------------------------------------------------------------

/// An obsolete-space header name used to slip past the framing checks: the name
/// is a token, and a length is digits (round 8, F2).
#[test]
fn a_header_name_is_a_token_and_a_length_is_digits() {
    for answer in [
        b"HTTP/1.1 200 OK\r\ntransfer-encoding : chunked\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\ncontent-length : 5\r\n\r\nhello".as_slice(),
        b"HTTP/1.1 200 OK\r\ncontent-length: +2\r\n\r\nok".as_slice(),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            let Ok((mut socket, _)) = listener.accept() else {
                return;
            };
            let mut scratch = [0u8; 4096];
            socket
                .set_read_timeout(Some(std::time::Duration::from_millis(200)))
                .ok();
            let _ = socket.read(&mut scratch);
            let _ = socket.write_all(answer);
            let _ = socket.flush();
        });
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/x")]);
        let mut call = http_get("/x", 1_000);
        call.tool_allows_process = true;
        let error = tool
            .invoke(0, &call)
            .expect_err("a hidden framing field is refused");
        assert!(
            error.code() == "rpc/provider" || error.code() == "rpc/tool-policy",
            "unexpected refusal: {error}"
        );
    }
}

/// A relative working directory is refused at construction; the field is
/// private, so no in-process assignment can repoint it (audit ARPC-005).
#[test]
fn a_relative_workdir_is_refused_at_construction() {
    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\cmd.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    let tool = LocalProcess::new(program, &["/C", "echo"]).expect("an absolute program");
    let error = tool
        .with_current_dir("relative")
        .expect_err("a relative directory");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
    // The pinned directory is canonical: an absolute path, no dot segments.
    let tool = LocalProcess::new(program, &["/C", "echo"]).expect("an absolute program");
    assert!(tool.working_directory().is_absolute());
}

/// A NUL in an MCP program or argument is a configuration refusal, not a
/// spawn-time provider fault (round 8, F5).
#[test]
fn a_nul_in_an_mcp_spawn_is_refused() {
    use active_rpc::tool::StdioTransport;

    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\cmd.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    let env = std::collections::BTreeMap::new();
    let error = match StdioTransport::spawn(program, &["a\0b"], &env) {
        Ok(_) => panic!("a NUL argument is refused"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
    let error = match StdioTransport::spawn("a\0b", &[], &env) {
        Ok(_) => panic!("a NUL program is refused"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

// ---------------------------------------------------------------------------
// Round 9
// ---------------------------------------------------------------------------

/// A text-only adapter cannot enforce a path scope (round 9, F-1).
#[test]
fn a_scoped_process_or_mcp_call_is_refused() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\cmd.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    let mut tool = LocalProcess::new(program, &["*"]).expect("an absolute program");
    let mut call = Call::new("run", Vec::new());
    call.tool_allows_process = true;
    call.path_scope = Some("srv/allowed".to_string());
    let error = tool.invoke(0, &call).expect_err("a scope is inert here");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut call = Call::new("echo", Vec::new());
    call.tool_allows_process = true;
    call.path_scope = Some("srv".to_string());
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("a scope is inert here");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// A whitespace-only line is obsolete folding, not the end of the header block
/// (round 9, F-3).
#[test]
fn a_whitespace_only_line_does_not_end_the_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        let mut scratch = [0u8; 4096];
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .ok();
        let _ = socket.read(&mut scratch);
        let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nx: 1\r\n \r\ncontent-length: 5\r\n\r\nhello");
        let _ = socket.flush();
    });
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/x")]);
    let mut call = http_get("/x", 1_000);
    call.tool_allows_process = true;
    call.read_only = true;
    let error = tool
        .invoke(0, &call)
        .expect_err("a folded line is a framing fault");
    assert_eq!(error.provider_code(), Some("http/headers"), "{error}");
}

/// A NUL in a program path is a construction refusal for both adapters
/// (round 9, F-7).
#[test]
fn a_nul_program_is_refused() {
    let error = LocalProcess::new("C:\\a\0b.exe", &[]).expect_err("a NUL program");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// The advertised argument cap is a deliverable wire size, not a frame size
/// (round 9, F-2).
#[test]
fn the_advertised_cap_leaves_escaping_room() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let policy = session.policy();
    assert!(
        policy.max_arg_bytes <= (active_rpc::tool::MAX_MCP_LINE_BYTES as u64) / 6,
        "the cap must survive JSON escaping: {}",
        policy.max_arg_bytes
    );
}

// ---------------------------------------------------------------------------
// Round 10
// ---------------------------------------------------------------------------

/// A child that floods its output is refused instead of waited out (round 10,
/// F-2).
#[test]
fn an_output_flood_is_refused_not_waited_out() {
    use std::time::{Duration, Instant};

    #[cfg(windows)]
    let (program, args) = (
        "C:\\Windows\\System32\\cmd.exe",
        vec![
            "/C",
            "for /L %i in (1,1,200000) do @echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ],
    );
    #[cfg(not(windows))]
    let (program, args) = (
        "/bin/sh",
        vec!["-c", "yes xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"],
    );
    let mut tool = LocalProcess::new(program, &["*"]).expect("an absolute program");
    let mut call = Call::new("run", args.iter().map(|arg| Arg::text(*arg)).collect());
    call.tool_allows_process = true;
    call.budget.max_wall_ms = 5_000;
    let started = Instant::now();
    let error = tool.invoke(0, &call).expect_err("the flood is refused");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the refusal waited {:?}",
        started.elapsed()
    );
}

/// A malformed JSON-RPC error object is a bad response, not code 0
/// (round 10, F-7).
#[test]
fn a_malformed_error_object_is_a_bad_response() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        r#"{"jsonrpc":"2.0","id":3,"error":{}}"#.to_string(),
    );
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut call = Call::new("echo", Vec::new());
    call.tool_allows_process = true;
    // A read-only call has no effect to withhold, so the answer's own code
    // survives (round 43, F-3).
    call.read_only = true;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("a malformed error object");
    assert_eq!(error.provider_code(), Some("mcp/bad-response"), "{error}");
}

/// A timeout after the frame left poisons the session: the answer is still in
/// flight (round 10, F-3).
#[test]
fn a_post_send_timeout_poisons_the_session() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};

    /// Answers the handshake, then never answers again.
    struct Silent {
        inner: MemoryTransport,
        answers: usize,
    }

    impl McpTransport for Silent {
        fn send_line(&mut self, line: &str) -> active_rpc::Result<()> {
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::Result<String> {
            self.recv_line_within(None)
        }
        fn recv_line_within(
            &mut self,
            deadline: Option<std::time::Instant>,
        ) -> active_rpc::Result<String> {
            if self.answers == 0 {
                return Err(active_rpc::Error::Timeout);
            }
            self.answers -= 1;
            self.inner.recv_line_within(deadline)
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(Silent {
        inner: MemoryTransport::new(responses),
        answers: 2,
    })
    .expect("handshake");
    let mut call = Call::new("echo", Vec::new());
    call.read_only = true;
    call.tool_allows_process = true;
    call.budget.max_wall_ms = 50;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the answer never arrives");
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("a poisoned session refuses");
    assert!(
        error
            .provider_code()
            .is_some_and(|code| code == "mcp/desync"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// Round 11
// ---------------------------------------------------------------------------

/// A `request` with no method text is refused instead of guessing GET
/// (round 11, #5).
#[test]
fn a_request_without_a_method_is_refused() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x")]);
    let mut call = Call::new("request", vec![Arg::Value(Value::path("/x"))]);
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("no method is named");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A u64 past `i64::MAX` in a JSON body is not rounded through `f64`
/// (round 11, #3).
#[test]
fn a_json_integer_past_i64_is_not_rounded() {
    let json = serde_json::json!({ "id": 18_446_744_073_709_551_615u64 });
    assert!(
        active_rpc::tool::json_has_unrepresentable_number(&json),
        "a u64 past i64::MAX has no Value form"
    );
    // Past `u64::MAX` and below `i64::MIN` the decoder rounds or refuses, so
    // the literal is checked on the text, before and beside the decode
    // (round 14, F-1; round 15, F-1). An overflowing float is in the same
    // class: `f64` has no finite value for it.
    for literal in [
        r#"{"debit": -9223372036854775809}"#,
        r#"{"amount": 18446744073709551617}"#,
        r#"{"amount": 1e400}"#,
    ] {
        assert!(active_rpc::tool::json_text_bad_number(literal), "{literal}");
    }
    // The scan runs outside strings only, and an ordinary decimal is
    // representable: `Value::Float` is its form.
    for literal in [r#"{"price": 9.99, "scaled": 1e3}"#, r#"["-", 0]"#] {
        assert!(
            !active_rpc::tool::json_text_bad_number(literal),
            "{literal}"
        );
    }
    let json = serde_json::json!({ "price": 9.99, "scaled": 1e3 });
    assert!(!active_rpc::tool::json_has_unrepresentable_number(&json));

    // `serde_json/arbitrary_precision` makes this key decode to a number and
    // would let a peer choose the type of its answer; the feature stays off
    // (round 15, F-2).
    let magic: serde_json::Value =
        serde_json::from_str(r#"{"$serde_json::private::Number":"7"}"#).expect("parse");
    assert!(magic.is_object(), "{magic}");
    match active_rpc::tool::json_to_value(&magic) {
        Value::Map(entries) => assert_eq!(entries.len(), 1),
        other => panic!("the magic key became {other:?}"),
    }
    // A flat array past the node ceiling is refused by the size predicate, not
    // by the number predicate (a wide tree, not a deep one: doubling would
    // build 2^40 values) (round 16, F-2).
    let wide = serde_json::Value::Array(vec![serde_json::Value::from(0); 1_100_000]);
    assert!(active_rpc::tool::json_too_many_nodes(&wide));
    assert!(!active_rpc::tool::json_has_unrepresentable_number(&wide));

    // A direct caller gets `Null` for the one number with no `Value` form, and
    // never an invented float (round 17, F-4).
    let past = serde_json::json!({ "id": 18_446_744_073_709_551_615u64 });
    match active_rpc::tool::json_to_value(&past) {
        Value::Map(entries) => match entries.get("id") {
            Some(Value::Null) => {}
            other => panic!("a u64 past i64 became {other:?}"),
        },
        other => panic!("unexpected {other:?}"),
    }
}

/// A scoped wasm capability is refused (round 11, #13).
#[cfg(feature = "wasm-tools")]
#[test]
fn a_scoped_wasm_call_is_refused() {
    use active_rpc::wasm_tool::WasmTool;

    // A minimal guest: the module returns a constant, so admission is the only
    // thing under test.
    let bytes: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f,
        0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01, 0x03, 0x72, 0x75, 0x6e, 0x00, 0x00, 0x0a, 0x06,
        0x01, 0x04, 0x00, 0x41, 0x07, 0x0b,
    ];
    let mut tool = WasmTool::from_bytes(bytes, active_rpc::wasm_tool::WasmLimits::default())
        .expect("a tiny module");
    let mut call = Call::new("run", Vec::new());
    call.tool_allows_process = true;
    call.path_scope = Some("app".to_string());
    let error = active_rpc::kernel::Provider::invoke(&mut tool, 0, &call)
        .expect_err("a wasm adapter cannot enforce a scope");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

// ---------------------------------------------------------------------------
// Round 24
// ---------------------------------------------------------------------------

/// A secret argument reaches the process policy. The shape loop refuses every
/// non-text argument, so checking the secret after it reported the secret as a
/// malformed argument and the policy branch never ran (round 24, #1).
#[test]
fn a_secret_process_argument_is_a_policy_refusal() {
    let mut tool = LocalProcess::new(absolute_shell(), &["*"]).expect("an absolute program");
    let mut call = Call::new("run", vec![Arg::Value(Value::Text("x".to_string()))]);
    call.args.push(Arg::Value(Value::Secret));
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("a secret is refused");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// A child killed by a signal has no exit status. Reporting `-1` as the status
/// made an externally killed mutating tool read as a success (round 24, #3).
#[cfg(unix)]
#[test]
fn a_signalled_child_is_a_provider_fault() {
    let mut tool =
        LocalProcess::new("/bin/sh", &["-c", "kill -TERM $$"]).expect("an absolute program");
    tool.timeout_ms = 5_000;
    let mut call = Call::new(
        "run",
        vec![
            Arg::Value(Value::Text("-c".to_string())),
            Arg::Value(Value::Text("kill -TERM $$".to_string())),
        ],
    );
    call.tool_allows_process = true;
    let error = tool
        .invoke(0, &call)
        .expect_err("a signalled child is not a success");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(error.provider_code(), Some("process/signalled"), "{error}");
}

/// A byte grant below the shortest possible answer can never carry one, so the
/// refusal names the budget instead of a provider framing fault (round 24, #4).
#[test]
fn a_grant_below_the_smallest_answer_is_a_budget_refusal() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/x"))]);
    call.read_only = true;
    call.tool_allows_process = true;
    call.budget.max_bytes = 8;
    let error = tool.invoke(0, &call).expect_err("no answer fits the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A JSON-RPC frame carrying both `result` and `error` is malformed. Preferring
/// `error` let the peer choose which outcome the caller saw (round 24, #6).
#[test]
fn an_mcp_frame_with_both_result_and_error_is_refused() {
    use active_rpc::tool::{McpSession, McpTransport};

    struct RawLines(std::collections::VecDeque<String>);

    impl McpTransport for RawLines {
        fn send_line(&mut self, _line: &str) -> active_rpc::error::Result<()> {
            Ok(())
        }

        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.0.pop_front().ok_or(active_rpc::error::Error::Timeout)
        }
    }

    let mut lines = std::collections::VecDeque::new();
    lines.push_back(
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    lines.push_back(
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    lines.push_back(
        r#"{"jsonrpc":"2.0","id":3,"result":{"ok":true},"error":{"code":-32000,"message":"no"}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(RawLines(lines)).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.read_only = true;
    call.tool_allows_process = true;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("both members are refused");
    assert_eq!(error.provider_code(), Some("mcp/bad-response"), "{error}");
}

/// A zero-byte grant is a budget refusal for every argument size; a large
/// request used to be reported as a line-ceiling violation first
/// (round 24, #9).
#[test]
fn a_zero_grant_mcp_call_is_a_budget_refusal_at_any_size() {
    let mut session = echo_session();
    let big = "x".repeat(1 << 20);
    let mut call = Call::new("echo", vec![Arg::Value(Value::Text(big))]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 0;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("a zero-byte grant does no work");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

// ---------------------------------------------------------------------------
// Round 25
// ---------------------------------------------------------------------------

/// `value_to_json` recurses, so an adapter that accepts a caller-built value
/// has to gate its depth: a 100k-deep list aborted the stack outside any
/// `catch_unwind` (round 25, #1).
#[test]
fn a_deep_mcp_argument_is_refused_not_aborted() {
    let mut session = echo_session();
    let mut value = Value::Null;
    for _ in 0..200 {
        value = Value::list([value]);
    }
    let mut call = Call::new("echo", vec![Arg::Value(value)]);
    call.tool_allows_process = true;
    let error = Provider::invoke(&mut session, 0, &call).expect_err("too deep");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// A request body past the capability grant is a budget refusal, not a tool
/// policy: the grant is the tighter authority (round 25, #2).
#[test]
fn an_http_request_past_the_grant_is_a_budget_refusal() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("POST", "/submit")]);
    let mut entries = std::collections::BTreeMap::new();
    entries.insert("k".to_string(), Value::text("v".repeat(64)));
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::path("/submit")),
            Arg::Value(Value::Map(entries)),
        ],
    );
    call.tool_allows_process = true;
    call.budget.max_bytes = 8;
    let error = tool
        .invoke(0, &call)
        .expect_err("the body is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// Output past the capability grant is a budget refusal; only an adapter
/// setting that binds reports the tool policy (round 25, #3).
#[test]
fn process_output_past_the_grant_is_a_budget_refusal() {
    #[cfg(windows)]
    let (program, flag, script) = ("C:\\Windows\\System32\\cmd.exe", "/C", "echo hello");
    #[cfg(not(windows))]
    let (program, flag, script) = ("/bin/sh", "-c", "echo hello");

    let mut tool = LocalProcess::new(program, &[flag, script])
        .expect("an absolute program")
        .with_timeout(5_000);
    let mut call = Call::new("run", vec![Arg::text(flag), Arg::text(script)]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 2;
    let error = tool
        .invoke(0, &call)
        .expect_err("the output is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A zero-byte grant is checked before the argument allowlist, so a direct
/// caller cannot use the refusal class as an allowlist oracle (round 25, #4).
#[test]
fn a_zero_grant_does_not_reveal_the_allowlist() {
    let mut tool = LocalProcess::new(absolute_shell(), &["ok"]).expect("an absolute program");
    let mut call = Call::new("run", vec![Arg::text("not-allowed")]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 0;
    let error = tool.invoke(0, &call).expect_err("a zero grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// The status line, every header line and the empty line all count against the
/// grant, so a body that fits exactly succeeds and one byte less is refused
/// (round 25, #5).
#[test]
fn the_head_and_body_share_the_grant_exactly() {
    let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
    let head = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("head end")
        + 4;
    let total = response.len();
    assert_eq!(total - head, 2, "the fixture body is two bytes");

    for (grant, should_fit) in [(total, true), (total - 1, false)] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        fixed_response(listener, response.to_vec());
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/exact")]);
        let mut call = Call::new("get", vec![Arg::Value(Value::path("/exact"))]);
        call.read_only = true;
        call.tool_allows_process = true;
        call.budget.max_bytes = grant as u64;
        match tool.invoke(0, &call) {
            Ok(_) => assert!(should_fit, "grant {grant} should not fit (head {head})"),
            Err(error) => {
                assert!(!should_fit, "grant {grant} should fit: {error}");
                assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Round 26
// ---------------------------------------------------------------------------

/// The HTTP adapter refuses a path scope: the kernel compares dotted paths,
/// which cannot confine a URL path, so a scoped capability would look confined
/// while only the allow-list confined it (round 26, #1).
#[test]
fn a_scoped_http_capability_is_refused() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/safe")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/safe"))]);
    call.tool_allows_process = true;
    call.path_scope = Some("safe".to_string());
    let error = tool
        .invoke(0, &call)
        .expect_err("a scope cannot be enforced");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
}

/// The request head is charged before the connection: an allowlisted long path
/// or an operator `base` must not write past a tiny grant (round 26, #2).
#[test]
fn an_http_request_head_past_the_grant_is_a_budget_refusal() {
    let long_path = format!("/{}", "a".repeat(512));
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", &long_path)]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path(&long_path))]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 64;
    let error = tool
        .invoke(0, &call)
        .expect_err("the head is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A request past both ceilings reports the budget: the static line ceiling
/// used to mask it (round 26, #4).
#[test]
fn an_mcp_request_past_the_grant_and_the_line_ceiling_is_a_budget_refusal() {
    let mut session = echo_session();
    let big = "x".repeat(1 << 20);
    let mut call = Call::new("echo", vec![Arg::Value(Value::Text(big))]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 8;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the request is refused");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A huge declared `content-length` under a tiny grant is a budget refusal
/// (round 26, #6).
#[test]
fn a_declared_length_past_the_grant_is_a_budget_refusal() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    fixed_response(
        listener,
        b"HTTP/1.1 200 OK\r\ncontent-length: 104857600\r\nconnection: close\r\n\r\n".to_vec(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/huge")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/huge"))]);
    call.read_only = true;
    call.tool_allows_process = true;
    call.budget.max_bytes = 256;
    let error = tool
        .invoke(0, &call)
        .expect_err("the body is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

// ---------------------------------------------------------------------------
// Round 27
// ---------------------------------------------------------------------------

/// A request inside the grant but past the static line ceiling is a bad
/// argument, not a budget: no budget can make the line legal (round 27, #1).
#[test]
fn an_mcp_request_past_only_the_line_ceiling_is_an_argument_refusal() {
    let mut session = echo_session();
    let big = "x".repeat(1 << 20);
    let mut call = Call::new("echo", vec![Arg::Value(Value::Text(big))]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 64 << 20;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the line is past the static ceiling");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
}

/// The process grant and the scope are checked before the argument allowlist,
/// so a direct caller without the grant cannot read allowlist membership from
/// the refusal reason (round 27, #3).
#[test]
fn a_missing_process_grant_precedes_the_argument_allowlist() {
    let mut tool = LocalProcess::new(absolute_shell(), &["allowed"]).expect("an absolute program");
    let call = Call::new("run", vec![Arg::text("not-allowed")]);
    let error = tool.invoke(0, &call).expect_err("no process grant");
    assert_eq!(error.code(), "rpc/tool-policy", "{error}");
    assert!(
        format!("{error}").contains("process execution not granted"),
        "{error}"
    );
}

/// A path with a dot segment, escape, query or fragment is refused before the
/// allowlist: the peer normalizes, so an allowlisted string can name a
/// different resource (round 27, #4).
#[test]
fn an_ambiguous_http_path_is_refused() {
    for path in [
        "/safe/../secret",
        "/safe/./secret",
        "/a%2fb",
        "/a//b",
        "/safe?x=1",
        "/safe#frag",
    ] {
        let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", path)]);
        let mut call = Call::new("get", vec![Arg::Value(Value::path(path))]);
        call.tool_allows_process = true;
        let error = tool.invoke(0, &call).expect_err("an ambiguous path");
        assert_eq!(error.code(), "rpc/tool-policy", "{path}: {error}");
    }
}

// ---------------------------------------------------------------------------
// Round 29
// ---------------------------------------------------------------------------

/// A queue-full refusal happens before the writer takes the frame, so the
/// session must survive it; poisoning made transient backpressure kill the
/// session until a re-handshake (round 29, F1).
#[test]
fn a_queue_full_mcp_send_does_not_poison_the_session() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};

    struct QueueOnce {
        inner: MemoryTransport,
        sends: usize,
        fail_at: usize,
    }

    impl McpTransport for QueueOnce {
        fn send_line(&mut self, line: &str) -> active_rpc::error::Result<()> {
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.inner.recv_line()
        }
        fn send_line_within(
            &mut self,
            line: &str,
            deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<()> {
            self.sends += 1;
            if self.sends == self.fail_at {
                return Err(active_rpc::error::Error::Provider {
                    code: "mcp/queue".to_string(),
                });
            }
            self.inner.send_line_within(line, deadline)
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#
            .to_string(),
    );
    // The third send is the first `tools/call`; the fourth is the retry.
    let transport = QueueOnce {
        inner: MemoryTransport::new(responses),
        sends: 0,
        fail_at: 3,
    };
    let mut session = McpSession::handshake(transport).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.tool_allows_process = true;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the queue was full");
    assert_eq!(error.provider_code(), Some("mcp/queue"), "{error}");
    active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect("the session survived the queue refusal");
}

/// The HTTP constructor refuses an ambiguous allowlist entry through
/// `try_new`, and `new` drops one rather than keeping a widening alive
/// (round 29, F4).
#[test]
fn an_ambiguous_allowlist_entry_is_refused_at_construction() {
    for path in ["/a/../b", "/a\\b", "/a?q", "/a%2f"] {
        let error = HttpTool::try_new("http://127.0.0.1:9", &[("GET", path)])
            .expect_err("an ambiguous entry");
        assert_eq!(error.code(), "rpc/tool-policy", "{path}: {error}");
        // `new` keeps only the unambiguous entries: the dropped one is refused
        // at the allowlist check.
        let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", path)]);
        let mut call = Call::new("get", vec![Arg::Value(Value::path(path))]);
        call.tool_allows_process = true;
        let error = tool.invoke(0, &call).expect_err("not allowlisted");
        assert_eq!(error.code(), "rpc/tool-policy", "{path}: {error}");
    }
}

/// A tiny adapter `max_body` with a large grant is a configuration refusal,
/// not a budget one: no budget can enlarge the adapter's own ceiling
/// (round 30, #3).
#[test]
fn a_configured_tiny_body_ceiling_is_a_provider_refusal() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    fixed_response(
        listener,
        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok".to_vec(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/tiny")]);
    tool.max_body = 8;
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/tiny"))]);
    call.read_only = true;
    call.tool_allows_process = true;
    call.budget.max_bytes = 4096;
    let error = tool.invoke(0, &call).expect_err("no answer fits");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert!(
        format!("{error}").contains("http/body-too-large"),
        "{error}"
    );
}

// ---------------------------------------------------------------------------
// Round 31
// ---------------------------------------------------------------------------

/// A bare date or score is plain text, not a number with no `Value` form: the
/// repair heuristic used to rewrite it to `0` and answer `http/bad-number`
/// (round 31, F3).
#[test]
fn a_bare_date_answer_is_text_not_a_bad_number() {
    let body = "2024-01-01";
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    fixed_response(
        listener,
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/date")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/date"))]);
    call.tool_allows_process = true;
    let response = tool.invoke(0, &call).expect("a date is text");
    assert_eq!(response, Response::Value(Value::text(body)));
}

/// A request target must be an absolute path: a relative or single-slash form
/// could reach the wire as an absolute-form target (round 31, F8).
#[test]
fn a_request_target_without_a_leading_slash_is_refused() {
    for path in ["noslash", "http:/evil", "http://evil/x"] {
        let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", path)]);
        let mut call = Call::new("get", vec![Arg::Value(Value::path(path))]);
        call.tool_allows_process = true;
        let error = tool.invoke(0, &call).expect_err("not an absolute path");
        assert_eq!(error.code(), "rpc/tool-policy", "{path}: {error}");
    }
}

/// A refused call is not a served call (round 31, F7).
#[test]
fn a_refused_call_does_not_increment_the_served_counter() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path("/x"))]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 0;
    let error = tool.invoke(0, &call).expect_err("a zero grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    assert_eq!(tool.calls, 0, "a refusal is not a served call");
}

/// The argument line is charged against the grant before the child starts: a
/// direct caller cannot pass a large argv under a one-byte grant (round 32,
/// #1).
#[test]
fn a_process_argument_line_is_bounded_by_the_grant() {
    let mut tool = LocalProcess::new(absolute_shell(), &["*"]).expect("an absolute program");
    let big = "x".repeat(64 * 1024);
    let mut call = Call::new("run", vec![Arg::text(big)]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 1;
    let error = tool
        .invoke(0, &call)
        .expect_err("the argv is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A line past the static MCP ceiling poisons the session even when a small
/// grant is also exceeded: the peer wrote an illegal line, and the grant must
/// not make a hostile frame look like a budget inconvenience (round 32, #3).
#[test]
fn a_line_past_the_static_ceiling_poisons_even_under_a_small_grant() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};

    struct Huge {
        inner: MemoryTransport,
        replies: usize,
    }
    impl McpTransport for Huge {
        fn send_line(&mut self, line: &str) -> active_rpc::error::Result<()> {
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.inner.recv_line()
        }
        fn recv_line_within(
            &mut self,
            deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<String> {
            self.replies += 1;
            if self.replies <= 2 {
                // The handshake's initialize and tools/list answers.
                return self.inner.recv_line_within(deadline);
            }
            Ok(format!(
                r#"{{"jsonrpc":"2.0","id":3,"result":"{}"}}"#,
                "x".repeat(2 << 20)
            ))
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(Huge {
        inner: MemoryTransport::new(responses),
        replies: 0,
    })
    .expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.read_only = true;
    call.tool_allows_process = true;
    // Enough for the request line, far less than the 2 MiB answer.
    call.budget.max_bytes = 4096;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the line is illegal");
    assert_eq!(error.provider_code(), Some("mcp/line-too-long"), "{error}");
    let again = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the session is poisoned");
    assert_eq!(again.provider_code(), Some("mcp/desync"), "{again}");
}

// ---------------------------------------------------------------------------
// Round 33
// ---------------------------------------------------------------------------

/// A number with a leading zero is not a JSON number token, so a body like
/// `00` is text rather than a provider fault (round 33, M1).
#[test]
fn a_zero_padded_number_is_text_not_a_bad_number() {
    for body in ["00", "01", "-00"] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        fixed_response(
            listener,
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        );
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/p")]);
        let mut call = Call::new("get", vec![Arg::Value(Value::path("/p"))]);
        call.tool_allows_process = true;
        let response = tool.invoke(0, &call).expect("a padded number is text");
        assert_eq!(response, Response::Value(Value::text(body)), "{body}");
    }
}

/// The repair heuristic replaces a span only when the span is one number
/// token: `1-2` and `1e` are framing faults in the answer, not out-of-range
/// numbers (round 33, M2).
#[test]
fn a_malformed_number_group_is_text_not_a_bad_number() {
    for body in ["[1-2]", "[1e]", "{\"n\":1-2}"] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        fixed_response(
            listener,
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        );
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/p")]);
        let mut call = Call::new("get", vec![Arg::Value(Value::path("/p"))]);
        call.tool_allows_process = true;
        let response = tool.invoke(0, &call).expect("not a number");
        assert_eq!(response, Response::Value(Value::text(body)), "{body}");
    }
}

/// The argument line spends part of the capability's grant: what it costs is
/// not available to the child's output (round 33, H1).
#[test]
fn an_argument_line_spends_part_of_the_process_grant() {
    #[cfg(windows)]
    let argv: Vec<&str> = vec![
        "/C",
        "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    #[cfg(not(windows))]
    let argv: Vec<&str> = vec!["-c", "printf '%060d' 0"];
    let arguments: Vec<Arg> = argv.iter().map(|argument| Arg::text(*argument)).collect();
    let argv_bytes: u64 = arguments.iter().map(Arg::wire_size).sum();

    let mut tool = LocalProcess::new(absolute_shell(), &argv).expect("an absolute program");
    #[cfg(windows)]
    tool.env.insert(
        "SystemRoot".to_string(),
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
    );
    let mut call = Call::new("run", arguments);
    call.tool_allows_process = true;
    // The line fits with about 20 bytes to spare; the child prints 60.
    call.budget.max_bytes = argv_bytes + 20;
    let error = tool
        .invoke(0, &call)
        .expect_err("the output is past what the line left");
    // The child ran, so the class says the reply was withheld and a retry does
    // not fork it again (round 43, F-4).
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
}

/// The response head spends part of the capability's grant: a body that fits
/// the grant but not what the head left is refused (round 33, H1).
#[test]
fn a_response_body_is_bounded_by_what_the_head_left() {
    let path = format!("/{}", "p".repeat(300));
    let body = "y".repeat(120);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    fixed_response(
        listener,
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", &path)]);
    let mut call = Call::new("get", vec![Arg::Value(Value::path(&path))]);
    call.tool_allows_process = true;
    // The long allowlisted path puts about 60 bytes of the head past the free
    // allowance; 200 covers the head but not the head and the body together.
    call.budget.max_bytes = 200;
    let error = tool
        .invoke(0, &call)
        .expect_err("the body is past the head");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// The MCP request line spends part of the capability's grant: an answer that
/// fits the grant but not what the request left is refused (round 33, H1).
#[test]
fn an_mcp_answer_is_bounded_by_what_the_request_left() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};
    use std::sync::{Arc, Mutex};

    struct Recorder {
        inner: MemoryTransport,
        lengths: Arc<Mutex<Vec<usize>>>,
    }
    impl McpTransport for Recorder {
        fn send_line(&mut self, line: &str) -> active_rpc::error::Result<()> {
            self.lengths.lock().expect("lock").push(line.len());
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.inner.recv_line()
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        format!(
            r#"{{"jsonrpc":"2.0","id":3,"result":{{"content":[{{"type":"text","text":"{}"}}]}}}}"#,
            "z".repeat(40)
        ),
    );
    let lengths = Arc::new(Mutex::new(Vec::new()));
    let mut session = McpSession::handshake(Recorder {
        inner: MemoryTransport::new(responses),
        lengths: Arc::clone(&lengths),
    })
    .expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.read_only = true;
    call.tool_allows_process = true;
    // A generous grant measures the request line on the shipped path.
    call.budget.max_bytes = 1 << 20;
    active_rpc::kernel::Provider::invoke(&mut session, 0, &call).expect("the first call");
    let request = *lengths
        .lock()
        .expect("lock")
        .last()
        .expect("a request line");
    // The answer line fits the grant as a whole, so only the request's share
    // makes the difference: room for the request and 30 bytes more, while the
    // answer line is longer than 30.
    let answer = format!(
        r#"{{"jsonrpc":"2.0","id":3,"result":{{"content":[{{"type":"text","text":"{}"}}]}}}}"#,
        "z".repeat(40)
    )
    .len();
    assert!(
        answer > 30 && answer <= request + 30,
        "the fixture must fit the grant and not what the request leaves: \
         request {request}, answer {answer}"
    );
    call.budget.max_bytes = (request + 30) as u64;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the answer is past what the request left");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A far deadline does not buy a longer enqueue wait: a full queue is
/// backpressure, so the cap refuses inside five seconds (round 33, M3).
#[test]
fn a_far_deadline_does_not_extend_the_enqueue_wait() {
    use active_rpc::tool::{McpTransport, StdioTransport};
    use std::time::{Duration, Instant};

    #[cfg(windows)]
    let (program, args): (&str, Vec<&str>) = (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        vec!["-NoProfile", "-Command", "Start-Sleep -Seconds 20"],
    );
    #[cfg(unix)]
    let (program, args): (&str, Vec<&str>) = ("/bin/sh", vec!["-c", "sleep 20"]);
    #[cfg(windows)]
    let env: std::collections::BTreeMap<String, String> =
        [("SystemRoot".to_string(), "C:\\Windows".to_string())]
            .into_iter()
            .collect();
    #[cfg(unix)]
    let env: std::collections::BTreeMap<String, String> =
        [("PATH".to_string(), "/usr/bin:/bin".to_string())]
            .into_iter()
            .collect();
    let mut transport = StdioTransport::spawn(program, &args, &env).expect("spawn a silent server");
    // The child never reads: a line larger than the pipe buffer holds the
    // writer thread, and the next line fills the capacity-one queue.
    let filler = "x".repeat(512 * 1024);
    let short = Instant::now() + Duration::from_millis(50);
    let _ = transport.send_line_within(&filler, Some(short));
    std::thread::sleep(Duration::from_millis(200));
    let mut queued = false;
    for _ in 0..3 {
        let deadline = Instant::now() + Duration::from_millis(50);
        match transport.send_line_within(&filler, Some(deadline)) {
            Err(active_rpc::Error::Timeout) => {
                queued = true;
                break;
            }
            _ => std::thread::sleep(Duration::from_millis(200)),
        }
    }
    assert!(queued, "the queue never filled");
    let far = Instant::now() + Duration::from_secs(20);
    let started = Instant::now();
    let error = transport
        .send_line_within("x", Some(far))
        .expect_err("the queue is full");
    let elapsed = started.elapsed();
    assert_eq!(error.provider_code(), Some("mcp/queue"), "{error}");
    assert!(
        elapsed < Duration::from_secs(8),
        "the enqueue waited {elapsed:?} instead of the five-second cap"
    );
}

// ---------------------------------------------------------------------------
// Round 34
// ---------------------------------------------------------------------------

/// A grant at or above the static line ceiling still bounds the whole exchange:
/// request plus answer must fit it (round 34, #1).
#[test]
fn an_mcp_grant_above_the_line_ceiling_still_bounds_the_sum() {
    use active_rpc::tool::{McpSession, MemoryTransport, MAX_MCP_LINE_BYTES};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        format!(
            r#"{{"jsonrpc":"2.0","id":3,"result":{{"content":[{{"type":"text","text":"{}"}}]}}}}"#,
            // Just under the static ceiling: legal on its own, over the
            // remainder the request left.
            "z".repeat(MAX_MCP_LINE_BYTES - 200)
        ),
    );
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut call = Call::new("echo", vec![Arg::text("x".repeat(800 * 1024))]);
    call.read_only = true;
    call.tool_allows_process = true;
    // The request is under the static ceiling; together with the 1 MiB answer
    // it is over the grant.
    call.budget.max_bytes = (MAX_MCP_LINE_BYTES as u64 * 3) / 2;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("request plus answer exceeds the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    // The refused frame may have been a notification with the answer still
    // queued, so the session is poisoned rather than reused (round 42, H-1).
    let mut small = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    small.tool_allows_process = true;
    small.budget.max_bytes = (MAX_MCP_LINE_BYTES as u64 * 3) / 2;
    let poisoned = active_rpc::kernel::Provider::invoke(&mut session, 0, &small)
        .expect_err("the session is poisoned");
    assert_eq!(poisoned.provider_code(), Some("mcp/desync"), "{poisoned}");
}

/// A process refusal is a budget one when the share left by the argument line
/// is what bounds the read, and a policy one when the adapter's ceiling does
/// (round 34, #2).
#[test]
fn a_process_share_under_the_static_ceiling_is_a_budget_refusal() {
    #[cfg(windows)]
    let argv: Vec<&str> = vec!["/C", "for /L %i in (1,1,200) do @echo aaaa"];
    #[cfg(not(windows))]
    let argv: Vec<&str> = vec![
        "-c",
        "i=0; while [ $i -lt 200 ]; do echo aaaa; i=$((i+1)); done",
    ];
    let arguments: Vec<Arg> = argv.iter().map(|argument| Arg::text(*argument)).collect();
    let argv_bytes: u64 = arguments.iter().map(Arg::wire_size).sum();

    let mut tool = LocalProcess::new(absolute_shell(), &argv).expect("an absolute program");
    #[cfg(windows)]
    tool.env.insert(
        "SystemRoot".to_string(),
        std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()),
    );
    tool.max_output = 1_000;
    let mut call = Call::new("run", arguments);
    call.tool_allows_process = true;
    // A grant exactly at the adapter's ceiling leaves a share under it once the
    // argument line is charged; the child prints about 1 200 bytes, more than
    // the share. Pre-fix the token compared the raw grant and reported a policy
    // refusal.
    call.budget.max_bytes = 1_000;
    assert!(argv_bytes < 200, "the fixture argv is small: {argv_bytes}");
    let error = tool
        .invoke(0, &call)
        .expect_err("the output is past the share");
    // The child ran, so the class says the reply was withheld and a retry does
    // not fork it again (round 43, F-4).
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
}

/// The HTTP refusal follows the same rule: the share, not the raw grant,
/// decides whether the budget or the adapter's ceiling refused
/// (round 34, #3).
#[test]
fn an_http_share_under_the_static_ceiling_is_a_budget_refusal() {
    let path = format!("/{}", "p".repeat(600));
    let body = "y".repeat(950);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    fixed_response(
        listener,
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", &path)]);
    tool.max_body = 1_000;
    let mut call = Call::new("get", vec![Arg::Value(Value::path(&path))]);
    call.read_only = true;
    call.tool_allows_process = true;
    // The long path charges more than 200 bytes of the head, so the share is
    // under the 1 000-byte adapter ceiling while the grant is over it.
    call.budget.max_bytes = 1_200;
    let error = tool
        .invoke(0, &call)
        .expect_err("the body is past the share");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// A number with no fraction digit is not a JSON number: `1.` is text
/// (round 34, #5).
#[test]
fn a_dangling_fraction_point_is_text_not_a_bad_number() {
    for body in ["1.", "0.e1"] {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        fixed_response(
            listener,
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        );
        let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/n")]);
        let mut call = Call::new("get", vec![Arg::Value(Value::path("/n"))]);
        call.tool_allows_process = true;
        let response = tool.invoke(0, &call).expect("not a number");
        assert_eq!(response, Response::Value(Value::text(body)), "{body}");
    }
}

/// A frame that was never sent does not poison the session: the transport says
/// so with its own code rather than a bare timeout (round 34, #7).
#[test]
fn a_frame_that_was_never_sent_leaves_the_session_usable() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};

    struct NotSentOnce {
        inner: MemoryTransport,
        sends: usize,
    }
    impl McpTransport for NotSentOnce {
        fn send_line(&mut self, line: &str) -> active_rpc::error::Result<()> {
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.inner.recv_line()
        }
        fn send_line_within(
            &mut self,
            line: &str,
            deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<()> {
            self.sends += 1;
            if self.sends == 3 {
                return Err(active_rpc::error::Error::Provider {
                    code: "mcp/not-sent".to_string(),
                });
            }
            self.inner.send_line_within(line, deadline)
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    responses.insert(
        "tools/call".to_string(),
        r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(NotSentOnce {
        inner: MemoryTransport::new(responses),
        sends: 0,
    })
    .expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.tool_allows_process = true;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the frame was not sent");
    assert_eq!(error.provider_code(), Some("mcp/not-sent"), "{error}");
    active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect("the session survived a frame that never left");
}

// ---------------------------------------------------------------------------
// Round 35
// ---------------------------------------------------------------------------

/// A skipped MCP notification is bytes the call buffered, so it spends the
/// grant; sixteen of them under a small grant used to fit freely
/// (round 35, N1).
#[test]
fn an_mcp_notification_spends_the_grant() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};

    struct Chatty {
        inner: MemoryTransport,
        answers: usize,
    }
    impl McpTransport for Chatty {
        fn send_line(&mut self, line: &str) -> active_rpc::error::Result<()> {
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.inner.recv_line()
        }
        fn recv_line_within(
            &mut self,
            deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<String> {
            self.answers += 1;
            if self.answers <= 2 {
                // The handshake's initialize and tools/list answers.
                return self.inner.recv_line_within(deadline);
            }
            // Progress notifications are legal before the answer.
            if self.answers <= 6 {
                return Ok(format!(
                    r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"note":"{}"}}}}"#,
                    "p".repeat(1_000)
                ));
            }
            Ok(
                r#"{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"ok"}]}}"#
                    .to_string(),
            )
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(Chatty {
        inner: MemoryTransport::new(responses),
        answers: 0,
    })
    .expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.read_only = true;
    call.tool_allows_process = true;
    call.budget.max_bytes = 2_048;
    // Four 1 KiB notifications do not fit the grant, so each is refused before
    // the parse. The line was consumed, so the session stays frame-aligned and
    // the answer is reachable once the frames are drained (round 41, F1 moved
    // this check before the parse, which makes it non-poisoning).
    // Each call's request line leaves room for one 1 KiB notification and not
    // the next, so the two calls drain the four frames and each ends in the
    // budget refusal.
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the notifications are over the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
    // The refused frame may have been a notification, so the session is
    // poisoned rather than reused (round 42, H-1).
    let poisoned = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the session is poisoned");
    assert_eq!(poisoned.provider_code(), Some("mcp/desync"), "{poisoned}");
}

/// A notification past the grant fails the same way the answer does, and the
/// session is refused afterwards rather than reading a stale frame as its
/// answer (round 35, N1).
#[test]
fn an_mcp_answer_beyond_the_notifications_is_a_budget_refusal() {
    use active_rpc::tool::{McpSession, McpTransport, MemoryTransport};

    struct OneNotification {
        inner: MemoryTransport,
        answers: usize,
    }
    impl McpTransport for OneNotification {
        fn send_line(&mut self, line: &str) -> active_rpc::error::Result<()> {
            self.inner.send_line(line)
        }
        fn recv_line(&mut self) -> active_rpc::error::Result<String> {
            self.inner.recv_line()
        }
        fn recv_line_within(
            &mut self,
            deadline: Option<std::time::Instant>,
        ) -> active_rpc::error::Result<String> {
            self.answers += 1;
            if self.answers <= 2 {
                return self.inner.recv_line_within(deadline);
            }
            if self.answers == 3 {
                return Ok(format!(
                    r#"{{"jsonrpc":"2.0","method":"notifications/progress","params":{{"note":"{}"}}}}"#,
                    "q".repeat(200)
                ));
            }
            Ok(format!(
                r#"{{"jsonrpc":"2.0","id":3,"result":{{"content":[{{"type":"text","text":"{}"}}]}}}}"#,
                "r".repeat(900)
            ))
        }
    }

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(OneNotification {
        inner: MemoryTransport::new(responses),
        answers: 0,
    })
    .expect("handshake");
    let mut call = Call::new("echo", vec![Arg::Value(Value::Int(1))]);
    call.read_only = true;
    call.tool_allows_process = true;
    // The request and the 200-byte notification fit; the 900-byte answer does
    // not fit what they left.
    call.budget.max_bytes = 1_100;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the answer is past the remainder");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

// ---------------------------------------------------------------------------
// Round 39
// ---------------------------------------------------------------------------

/// The grant bounds the argument bytes before an adapter serializes them
/// (round 39, F2). A direct call with a one-byte grant and a large map is a
/// budget refusal, not a serialization.
#[test]
fn a_large_argument_under_a_small_grant_is_refused_before_serializing() {
    use active_rpc::tool::{McpSession, MemoryTransport};

    let mut responses = std::collections::BTreeMap::new();
    responses.insert(
        "initialize".to_string(),
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"stub"}}}"#
            .to_string(),
    );
    responses.insert(
        "tools/list".to_string(),
        r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo"}]}}"#
            .to_string(),
    );
    let mut session = McpSession::handshake(MemoryTransport::new(responses)).expect("handshake");
    let mut map = std::collections::BTreeMap::new();
    for index in 0..10_000 {
        map.insert(format!("k{index}"), Value::text("v".repeat(64)));
    }
    let mut call = Call::new("echo", vec![Arg::Value(Value::Map(map))]);
    call.tool_allows_process = true;
    call.budget.max_bytes = 1;
    let error = active_rpc::kernel::Provider::invoke(&mut session, 0, &call)
        .expect_err("the argument is past the grant");
    assert_eq!(error.code(), "rpc/budget-exceeded", "{error}");
}

/// The HTTP adapter reports the method refusal before an argument-shape
/// refusal, as the other three adapters do (round 39, F3).
#[test]
fn the_http_adapter_checks_the_method_before_the_argument_shape() {
    let mut tool = HttpTool::new("http://127.0.0.1:9", &[("GET", "/x")]);
    let mut call = Call::new("not-a-method", vec![Arg::Value(Value::Int(1))]);
    call.tool_allows_process = true;
    let error = tool
        .invoke(0, &call)
        .expect_err("the method is not granted");
    assert_eq!(error.code(), "rpc/method-not-granted", "{error}");
}
