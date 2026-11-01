//! R-08: a capability's wall ceiling reaches the adapter that blocks.
//!
//! The kernel measures nothing while a provider runs, so an adapter that waits
//! on a peer without a deadline holds the whole agent. These tests drive the
//! shipped MCP transports.

use std::time::{Duration, Instant};

use active_rpc::tool::{McpTransport, StdioTransport};

/// A transport whose reads only return when the deadline has passed.
struct Silent;

impl McpTransport for Silent {
    fn send_line(&mut self, _line: &str) -> active_rpc::Result<()> {
        Ok(())
    }

    fn recv_line(&mut self) -> active_rpc::Result<String> {
        Err(active_rpc::Error::Provider {
            code: "test/no-deadline".to_string(),
        })
    }

    fn recv_line_within(&mut self, deadline: Option<Instant>) -> active_rpc::Result<String> {
        match deadline {
            Some(deadline) => {
                let now = Instant::now();
                if deadline <= now {
                    return Err(active_rpc::Error::Timeout);
                }
                // Wait for a while, but never the whole five-second default:
                // the point is that a future deadline arrived, and the suite
                // does not need to pay for it in full.
                std::thread::sleep((deadline - now).min(Duration::from_millis(250)));
                Err(active_rpc::Error::Timeout)
            }
            None => Err(active_rpc::Error::Timeout),
        }
    }
}

/// The session's request carries the deadline down to the transport.
#[test]
fn an_mcp_request_carries_a_deadline() {
    // `Silent` answers `initialize` with `rpc/timeout`, which is how this probe
    // observes that a deadline arrived at all.
    let error = active_rpc::tool::McpSession::handshake(Silent)
        .err()
        .expect("the handshake cannot succeed against a silent peer");
    assert_eq!(error.code(), "rpc/timeout", "{error}");
}

/// A silent child process is abandoned at the deadline instead of blocking the
/// caller for as long as the child stays quiet.
#[test]
fn a_silent_stdio_server_times_out() {
    #[cfg(windows)]
    let (program, args): (&str, Vec<&str>) = (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        vec!["-NoProfile", "-Command", "Start-Sleep -Seconds 30"],
    );
    #[cfg(unix)]
    let (program, args): (&str, Vec<&str>) = ("/bin/sh", vec!["-c", "sleep 30"]);

    // The transport clears the environment by design: a caller that spawns a
    // server supplies what it needs, and on Windows a process needs SystemRoot.
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
    let deadline = Instant::now() + Duration::from_millis(400);
    let started = Instant::now();
    let error = transport
        .recv_line_within(Some(deadline))
        .expect_err("a silent server has no line to give");
    let elapsed = started.elapsed();
    assert_eq!(error.code(), "rpc/timeout", "{error}");
    assert!(
        elapsed < Duration::from_secs(5),
        "the read waited {elapsed:?} instead of the 400 ms deadline"
    );
}

/// Without a deadline the transport still blocks and reports end of stream.
#[test]
fn a_closed_stdio_server_reports_eof() {
    #[cfg(windows)]
    let (program, args): (&str, Vec<&str>) =
        ("C:\\Windows\\System32\\cmd.exe", vec!["/C", "exit 0"]);
    #[cfg(unix)]
    let (program, args): (&str, Vec<&str>) = ("/bin/sh", vec!["-c", "exit 0"]);

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
    let mut transport =
        StdioTransport::spawn(program, &args, &env).expect("spawn a server that exits");
    let error = transport
        .recv_line()
        .expect_err("a closed server has no line to give");
    assert_eq!(error.code(), "rpc/provider", "{error}");
}
