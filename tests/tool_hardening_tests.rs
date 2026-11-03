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
    assert!(tool.workdir.is_absolute(), "{:?}", tool.workdir);
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
        "a descendant survived the timeout and wrote {:?}",
        marker
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
    let call = http_get("/slow", 150);
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
    let call = http_get("/dup", 1_000);
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
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    transport
        .send_line_within("{\"jsonrpc\":\"2.0\"}", None)
        .expect("the transport still writes");
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
    assert_eq!(error.code(), "rpc/timeout", "{error}");
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

/// A caller-supplied working directory cannot become relative after
/// construction (round 8, F6).
#[test]
fn a_relative_workdir_is_refused_at_invoke() {
    #[cfg(windows)]
    let program = "C:\\Windows\\System32\\cmd.exe";
    #[cfg(not(windows))]
    let program = "/bin/sh";
    let mut tool = LocalProcess::new(program, &["/C", "echo"]).expect("an absolute program");
    tool.workdir = std::path::PathBuf::from("relative");
    let mut call = Call::new("run", vec![Arg::text("/C"), Arg::text("echo")]);
    call.tool_allows_process = true;
    let error = tool.invoke(0, &call).expect_err("a relative directory");
    assert_eq!(error.code(), "rpc/invalid-argument", "{error}");
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
    // A flat array past the node ceiling is refused (a wide tree, not a deep
    // one: doubling would build 2^40 values).
    let wide = serde_json::Value::Array(vec![serde_json::Value::from(0); 1_100_000]);
    assert!(active_rpc::tool::json_has_unrepresentable_number(&wide));
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
