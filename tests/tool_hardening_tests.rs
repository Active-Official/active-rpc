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
