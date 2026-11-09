//! R2-R08B-01: a `setsid` descendant escapes the process-group timeout kill.
//!
//! Linux-only (setsid, /bin/sh, pgrep). The tests assert the descendant is
//! dead after the kill and the reader slots come back; without the fix the
//! descendant survives and the 256-slot pool exhausts after 128 calls.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use active_rpc::kernel::Provider;
use active_rpc::tool::{LocalProcess, StdioTransport};
use active_rpc::value::{Arg, Call, Response};

fn run_call(tool: &mut LocalProcess, args: Vec<Arg>) -> active_rpc::Result<Response> {
    let mut call = Call::new("run", args);
    call.tool_allows_process = true;
    Provider::invoke(tool, 0, &call)
}

fn process_matching(pattern: &str) -> bool {
    std::process::Command::new("pgrep")
        .args(["-f", pattern])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn setsid_tool(sleep_secs: u32, timeout_ms: u64) -> LocalProcess {
    let script = format!("setsid sleep {sleep_secs} & exit 0");
    let mut tool = LocalProcess::new("/bin/sh", &["-c", &script])
        .expect("an absolute program")
        .with_timeout(timeout_ms);
    tool.env
        .insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    tool
}

/// R2-R08B-01 (LocalProcess half): the timeout kill must reach the setsid
/// descendant, not just the leader's process group. The call still times
/// out correctly -- but the descendant must be dead when it returns.
#[test]
fn a_setsid_descendant_is_killed_at_timeout() {
    let mut tool = setsid_tool(47, 300);
    let started = Instant::now();
    let error = run_call(
        &mut tool,
        vec![Arg::text("-c"), Arg::text("setsid sleep 47 & exit 0")],
    )
    .expect_err("the inherited pipes outlive the ceiling");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the call must return on the timeout, not on the descendant's schedule"
    );
    assert_eq!(error.code(), "rpc/provider");
    assert_eq!(error.provider_code(), Some("provider/reply-withheld"));
    assert!(
        !process_matching("sleep 47"),
        "the setsid descendant must be dead after the timeout kill"
    );
}

/// One setsid call that must time out. A genuine timeout waits out its
/// 50 ms deadline; a call refused at spawn for lack of a reader slot
/// returns at once. The withheld reply discards the inner code, so the
/// elapsed time is the only signal -- and the only benign cause of a fast
/// refusal is a reader thread that has not finished exiting yet, which one
/// retry after a short sleep separates from a real leak (a leaked slot
/// never comes back, because the descendant sleeps 48 s).
fn timed_out_setsid_call(i: usize) -> active_rpc::Result<Response> {
    let mut tool = setsid_tool(48, 50);
    let started = Instant::now();
    let outcome = run_call(
        &mut tool,
        vec![Arg::text("-c"), Arg::text("setsid sleep 48 & exit 0")],
    );
    match outcome {
        Ok(_) => panic!("call {i}: a setsid call must time out, not succeed"),
        Err(error) if started.elapsed() < Duration::from_millis(20) => {
            std::thread::sleep(Duration::from_millis(200));
            let mut retry = setsid_tool(48, 50);
            let retry_started = Instant::now();
            match run_call(
                &mut retry,
                vec![Arg::text("-c"), Arg::text("setsid sleep 48 & exit 0")],
            ) {
                Ok(_) => panic!("call {i}: a setsid call must time out, not succeed"),
                Err(retry_error) if retry_started.elapsed() < Duration::from_millis(20) => {
                    panic!("call {i}: reader slots exhausted: {error} then {retry_error}")
                }
                Err(retry_error) => Err(retry_error),
            }
        }
        Err(error) => Err(error),
    }
}

/// R2-R08B-01 (slot half): without the kill, each timed-out call pins two
/// reader slots until its descendant exits on its own schedule; 128 such
/// calls exhaust the 256-slot pool and every later process call fails.
/// With the kill, the slots return with the call, so 130 calls in a row
/// all time out cleanly. The descendant sleeps far longer than the whole
/// loop, so no slot frees by expiry: only the kill can keep the pool open.
#[test]
fn reader_slots_are_not_pinned_by_setsid_descendants() {
    for i in 0..130 {
        let error = timed_out_setsid_call(i).expect_err(&format!("call {i} must time out"));
        assert_eq!(error.code(), "rpc/provider", "call {i}: {error}");
        assert_eq!(
            error.provider_code(),
            Some("provider/reply-withheld"),
            "call {i}: {error}"
        );
        // Let the killed call's reader threads finish exiting before the
        // next spawn, so a scheduling delay is not read as a leak.
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !process_matching("sleep 48"),
        "no setsid descendant may survive the loop"
    );
}

/// R2-R08B-01 (StdioTransport half): dropping the transport must kill the
/// setsid descendant the MCP server started, not just the leader's group.
#[test]
fn a_setsid_descendant_is_killed_when_the_stdio_transport_drops() {
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    let transport = StdioTransport::spawn(
        "/bin/sh",
        &["-c", "setsid sleep 49 & exit 0"],
        &env,
    )
    .expect("spawn MCP server");
    // The leader exits at once; give the transport a moment to settle, then
    // drop it (which kills the leader's process group).
    std::thread::sleep(Duration::from_millis(300));
    drop(transport);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        !process_matching("sleep 49"),
        "the setsid MCP descendant must be dead after the transport drop"
    );
}
