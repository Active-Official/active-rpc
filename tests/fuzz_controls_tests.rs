//! The fixed positive controls the decoder fuzz targets assert, driven through
//! the same shipped API from a test CI runs on every push.
//!
//! A fuzz target's control only fails inside a campaign; these tests make the
//! same claim breakable by `scripts/negative_controls.py`, so a decoder that
//! regresses to "refuse every input" is caught immediately (R-20 round 5,
//! F3/F4/F7).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use active_rpc::receipts::{Decision, ReceiptLog};
use active_rpc::transport::connect::{grpc_frame, grpc_unframe};
use active_rpc::transport::shm::SharedSegment;
use active_rpc::Receipt;

fn scratch(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "active-rpc-fuzz-control-{}-{nanos}-{tag}.log",
        std::process::id()
    ))
}

/// The `ARRL` reader must accept a log the shipped writer produced and return
/// exactly the sealed records (the target's `fuzz_receipt_log` control).
#[test]
fn a_well_formed_receipt_log_reads_back() {
    let path = scratch("receipt");
    let _ = std::fs::remove_file(&path);
    let log = ReceiptLog::create(&path).expect("create");
    let first = Receipt {
        sequence: 1,
        cap: "0011223344556677".to_string(),
        method: "echo".to_string(),
        at_ms: 1,
        decision: Decision::Admitted,
        mac: [0u8; 32],
    };
    let second = Receipt {
        sequence: 2,
        cap: "8899aabbccddeeff".to_string(),
        method: "ping".to_string(),
        at_ms: 2,
        decision: Decision::Refused("rpc/unknown-capability".to_string()),
        mac: [1u8; 32],
    };
    log.append(&first).expect("append the first receipt");
    log.append(&second).expect("append the second receipt");
    let bytes = std::fs::read(&path).expect("read the log");
    let read = ReceiptLog::verify_bytes(&bytes).expect("the fixed log verifies");
    assert_eq!(read, vec![first, second]);
    let _ = std::fs::remove_file(&path);
}

/// A frame written into a shared-memory ring is readable, and advancing it
/// releases exactly the bytes written (the target's `fuzz_transport_framing`
/// ring control).
#[test]
fn a_written_shared_memory_frame_reads_back() {
    let ring = SharedSegment::new(1024);
    ring.write(b"frame").expect("the fixed frame fits");
    let read = ring.read().expect("read").expect("a frame");
    assert_eq!(read, b"frame");
    ring.advance().expect("advance");
    assert_eq!(ring.consumed(), ring.produced());
}

/// The gRPC length prefix round-trips (the target's framing control).
#[test]
fn a_framed_grpc_message_unframes_to_itself() {
    let framed = grpc_frame(b"hello").expect("frame");
    let (message, tail) = grpc_unframe(&framed).expect("unframe");
    assert_eq!(message, b"hello");
    assert!(tail.is_empty());
}

// ---------------------------------------------------------------------------
// The adapter controls the campaign asserts, driven here as well.
// ---------------------------------------------------------------------------

/// The process control runs a real child and reads its output: a canned `Ok`
/// or a policy that refuses every argument fails here (R-20 round 6, finding 5).
#[cfg(unix)]
#[test]
fn a_process_control_runs_the_child() {
    use active_rpc::tool::LocalProcess;
    use active_rpc::{Arg, Budget, CapAttrs, ToolPolicy, Value};

    let policy = ToolPolicy {
        allowed: ["run"].iter().map(|name| name.to_string()).collect(),
        max_arg_bytes: 64,
        allow_process: true,
    };
    let tool = LocalProcess::new("/bin/echo", &["ok"]).expect("an absolute program");
    let agent = active_rpc::Agent::new();
    let provider = agent.register(Box::new(tool));
    let lane = agent
        .create_lane("control", Budget::default())
        .expect("lane");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["run"])
                .with_budget(Budget::default())
                .with_tool_policy(policy),
        )
        .expect("cap");
    let promise = agent
        .call(lane, &cap, "run", vec![Arg::text("ok")])
        .expect("queued");
    agent.run();
    let value = promise.value().expect("the child ran");
    let Value::Map(fields) = value else {
        panic!("the process reply is a map: {value:?}");
    };
    assert!(
        matches!(fields.get("status"), Some(Value::Int(0))),
        "{fields:?}"
    );
    assert!(
        matches!(fields.get("stdout"), Some(Value::Text(text)) if text == "ok\n"),
        "{fields:?}"
    );
}

/// The HTTP control reaches a real loopback endpoint and reads its body: a
/// pre-network provider error fails here (R-20 round 6, finding 6).
#[test]
fn an_http_control_reaches_the_endpoint() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use active_rpc::tool::HttpTool;
    use active_rpc::{Arg, Budget, CapAttrs, ToolPolicy, Value};

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let address = listener.local_addr().expect("address");
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer);
            let body = r#"{"ok":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let tool = HttpTool::new(format!("http://{address}"), &[("GET", "/safe")]);
    let policy = tool.policy();
    let agent = active_rpc::Agent::new();
    let provider = agent.register(Box::new(tool));
    let lane = agent
        .create_lane("control", Budget::default())
        .expect("lane");
    let cap = agent
        .mint(
            provider,
            0,
            CapAttrs::new(&["get"])
                .with_budget(Budget::default())
                .with_tool_policy(ToolPolicy {
                    allowed: policy.allowed.clone(),
                    max_arg_bytes: 1024,
                    allow_process: false,
                }),
        )
        .expect("cap");
    let promise = agent
        .call(
            lane,
            &cap,
            "get",
            vec![Arg::Value(Value::path("/safe".to_string()))],
        )
        .expect("queued");
    agent.run();
    assert_eq!(
        promise.value().expect("the endpoint answered"),
        Value::map([("ok", Value::Bool(true))])
    );
}
