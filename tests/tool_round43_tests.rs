//! R-08 round 43: the withheld-reply axis is the method's effect, pre-send
//! failures keep their class, an unparseable answer to a mutating call is
//! withheld, and a process that outlived its ceiling is withheld too.

use std::io::{Read, Write};
use std::net::TcpListener;

use active_rpc::budget::Budget;
use active_rpc::kernel::Provider;
use active_rpc::tool::HttpTool;
use active_rpc::value::{Arg, Call, Value};

fn serve_once(response: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address").to_string();
    let handle = std::thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return;
        };
        socket
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .ok();
        let mut scratch = [0u8; 8192];
        let _ = socket.read(&mut scratch);
        let _ = socket.write_all(&response);
        let _ = socket.flush();
        let _ = socket.shutdown(std::net::Shutdown::Write);
        let _ = socket.read(&mut scratch);
    });
    (address, handle)
}

/// A GET that returns 404 has not changed anything, whatever the capability
/// flag says: the status survives (round 43, F-1).
#[test]
fn a_get_404_on_a_writable_capability_keeps_its_status() {
    let (address, server) = serve_once(
        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/missing")]);
    let mut call = Call::new("get", vec![Arg::Value(Value::Path("/missing".to_string()))]);
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("a 404 is not a completed call");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(error.provider_code(), Some("http/404"), "{error}");
    drop(server);
}

/// A POST that never reached the peer keeps its pre-send class: a resolve or
/// connect failure must not burn the caller's idempotency key as an applied
/// write (round 43, F-2).
#[test]
fn a_pre_send_http_failure_is_not_a_withheld_reply() {
    let mut tool = HttpTool::new("http://127.0.0.1:1", &[("POST", "/safe")]);
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::Path("/safe".to_string())),
            Arg::Value(Value::Map(
                [("note".to_string(), Value::Text("x".to_string()))]
                    .into_iter()
                    .collect(),
            )),
        ],
    );
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("nothing listens on the discard port");
    assert_eq!(error.provider_code(), Some("http/connect"), "{error}");
}

/// A mutating call whose 2xx answer cannot be parsed has already reached the
/// peer: the class says the reply was withheld, so a retry does not repeat the
/// write (round 43, F-3).
#[test]
fn a_mutating_call_with_an_unparseable_answer_withholds_the_reply() {
    let (address, server) = serve_once(
        b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\n1e400".to_vec(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("POST", "/safe")]);
    let mut call = Call::new(
        "post",
        vec![
            Arg::Value(Value::Path("/safe".to_string())),
            Arg::Value(Value::Map(
                [("note".to_string(), Value::Text("x".to_string()))]
                    .into_iter()
                    .collect(),
            )),
        ],
    );
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("the number is not representable");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
    drop(server);
}

/// A child that outlived its ceiling has run: the refusal says the reply was
/// withheld, so an idempotent retry does not fork it again (round 43, F-4).
#[test]
fn a_process_that_outlived_its_ceiling_withholds_the_reply() {
    use active_rpc::tool::LocalProcess;

    #[cfg(windows)]
    let (program, args) = (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        vec!["-NoProfile", "-Command", "Start-Sleep -Seconds 5"],
    );
    #[cfg(not(windows))]
    let (program, args) = ("/bin/sh", vec!["-c", "sleep 5"]);

    let mut tool = LocalProcess::new(program, &args).expect("an absolute program");
    let mut call = Call::new("run", args.iter().map(|arg| Arg::text(*arg)).collect());
    call.tool_allows_process = true;
    call.budget = Budget {
        max_wall_ms: 1,
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("the child outlived the grant");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
}

/// The wasm adapter refuses an argument that cannot fit its input area before
/// it copies it (round 43, F-10).
#[cfg(feature = "wasm-tools")]
#[test]
fn the_wasm_adapter_refuses_an_input_past_its_abi_area() {
    use active_rpc::wasm_tool::{WasmLimits, WasmTool};

    let module = wat::parse_str(
        r#"(module
             (memory (export "memory") 2)
             (func (export "run") (param i32) (result i32) i32.const 0))"#,
    )
    .expect("valid WAT");
    let mut tool =
        WasmTool::from_bytes(&module, WasmLimits::default()).expect("the fixture compiles");
    let mut call = Call::new("run", vec![Arg::Value(Value::Text("x".repeat(100 * 1024)))]);
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("the input is past the ABI area");
    assert_eq!(error.provider_code(), Some("wasm/input"), "{error}");
}

/// A child that kills itself has run: the refusal is a withheld reply, not a
/// call that did not happen (round 44, M-2).
#[cfg(not(windows))]
#[test]
fn a_child_killed_by_a_signal_withholds_the_reply() {
    use active_rpc::tool::LocalProcess;

    let script = "kill -9 $$";
    let mut tool = LocalProcess::new("/bin/sh", &["-c", script]).expect("an absolute program");
    let mut call = Call::new("run", vec![Arg::text("-c"), Arg::text(script)]);
    call.tool_allows_process = true;
    call.budget = Budget {
        max_wall_ms: 5_000,
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("a signalled child has no exit status");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
}

/// Windows has no signals, so a child terminated by another process still
/// yields an exit code — `taskkill` terminates with code 1 — and the
/// `process/signalled` guard never fires there (XPL-RPC-12). The reply is
/// NOT withheld: the termination code is reported as an ordinary status,
/// because Windows cannot tell a termination code from a code the child
/// exited with itself. That is the documented residual, pinned here so a
/// future change to the guard cannot silently reclassify it.
#[cfg(windows)]
#[test]
fn a_child_terminated_by_another_process_reports_its_exit_code() {
    use active_rpc::tool::LocalProcess;

    // The child kills itself with `taskkill` (TerminateProcess, code 1)
    // after a short sleep; the `exit 77` after it only runs if the kill
    // failed, so a status of 1 proves the termination happened and a
    // status of 77 would prove it did not. The script is an exact
    // allowlist entry (not a prefix match), which is the shape that may
    // carry shell metacharacters. `taskkill` is named, not pathed: a
    // bare `C:\...\\taskkill.exe` statement is parsed by PowerShell as a
    // string expression (and as a document in a pipeline), so it never
    // runs — the name resolves through `PATH` + `PATHEXT` instead.
    let script = "Start-Sleep -Milliseconds 400; taskkill /F /PID $PID > $null; exit 77";
    let mut tool = LocalProcess::new(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        &["-NoProfile", "-Command", script],
    )
    .expect("an absolute program");
    tool.timeout_ms = 5_000;
    // The adapter spawns with an empty environment (`env_clear`), and
    // Windows PowerShell's managed host cannot load without a user
    // profile (it fails with 8009001d, "keyset does not exist"): the
    // profile variables are provisioned explicitly from this process.
    // `PATHEXT` is load-bearing too: without it an extensionless name
    // such as `taskkill` never resolves to `taskkill.exe`. `SystemDrive`
    // and `ProgramData` are load-bearing as well: without them a Windows
    // component that expands `%SystemDrive%\ProgramData` (the font cache)
    // falls back to the literal string as a relative path and writes
    // `%SystemDrive%\ProgramData\...` under the child's working directory.
    for key in [
        "SystemRoot",
        "SystemDrive",
        "ProgramData",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "PATH",
        "PATHEXT",
    ] {
        if let Ok(value) = std::env::var(key) {
            tool.env.insert(key.to_string(), value);
        }
    }
    let mut call = Call::new(
        "run",
        vec![
            Arg::text("-NoProfile"),
            Arg::text("-Command"),
            Arg::text(script),
        ],
    );
    call.tool_allows_process = true;
    call.budget = Budget {
        max_wall_ms: 5_000,
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let response = tool
        .invoke(0, &call)
        .expect("a terminated child reports its exit code on Windows, it is not a signalled child");
    let active_rpc::Response::Value(Value::Map(entries)) = response else {
        panic!("a terminated child answers with a value map, got {response:?}");
    };
    let Some(Value::Int(status)) = entries.get("status") else {
        panic!("the reply carries the child's exit code, got {entries:?}");
    };
    assert_eq!(
        *status, 1,
        "taskkill terminates with code 1; 77 would mean the kill failed: {entries:?}"
    );
}

/// The mutating axis is the capability's method, not the resolution: a
/// `request` capability stays conservative even when the method text is `GET`,
/// which is the axis the kernel sees (round 45, finding 1).
#[test]
fn a_request_call_with_a_get_method_is_withheld() {
    let (address, server) = serve_once(
        b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec(),
    );
    let mut tool = HttpTool::new(format!("http://{address}"), &[("GET", "/missing")]);
    let mut call = Call::new(
        "request",
        vec![
            Arg::Value(Value::Text("GET".to_string())),
            Arg::Value(Value::Path("/missing".to_string())),
        ],
    );
    call.budget = Budget {
        max_bytes: 1 << 20,
        ..Budget::default()
    };
    let error = tool
        .invoke(0, &call)
        .expect_err("a 404 is not a completed call");
    assert_eq!(
        error.provider_code(),
        Some("provider/reply-withheld"),
        "{error}"
    );
    drop(server);
}

/// An exact allowlist entry is the natural home of a fixed credential: the
/// handle's `Debug` names the method and the entry's length, never the path
/// (round 48, F-1).
#[test]
fn an_http_debug_does_not_print_an_allowlisted_path() {
    let canary = "/hooks/6f1c2b9a-secret-token";
    // The base can carry a token in its path too (round 49, L-1).
    let tool = HttpTool::new("http://127.0.0.1:9/hooks/base-canary", &[("GET", canary)]);
    let rendered = format!("{tool:?}");
    assert!(rendered.contains("HttpTool"), "{rendered}");
    assert!(
        !rendered.contains("base-canary"),
        "the base leaked: {rendered}"
    );
    assert!(
        rendered.contains("127.0.0.1:9"),
        "the authority stays visible: {rendered}"
    );
    assert!(
        !rendered.contains("secret-token"),
        "the allowlisted path leaked: {rendered}"
    );
    assert!(
        !rendered.contains(canary),
        "the allowlisted path leaked: {rendered}"
    );
}
