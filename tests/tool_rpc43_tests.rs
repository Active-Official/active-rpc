//! RPC-43: pinning is content, not just path; the Unix kill must not
//! signal a reused pid.
//!
//! Pin half (cross-platform): a `LocalProcess` pins its program by
//! canonical path only, so a binary replaced in place after construction
//! runs at the next invoke. The fix records a BLAKE3 hash at
//! construction and re-verifies it before every spawn; a mismatch is a
//! refusal (`process/program-changed`), never a silent re-pin.
//!
//! Kill half (Linux-only): the group kill used to signal `-<pid>` through
//! an external `/bin/kill`, so a leader that had exited and whose pid
//! had been reused as a new process-group leader would take an unrelated
//! group down with it. The fix signals through the `killpg` syscall
//! and only when the group is still provably ours (live leader, or a
//! dead leader with a member still carrying the pgid in /proc).

use active_rpc::kernel::Provider;
use active_rpc::tool::LocalProcess;
use active_rpc::value::{Arg, Call, Response, Value};

fn run_call(tool: &mut LocalProcess, args: Vec<Arg>) -> active_rpc::Result<Response> {
    let mut call = Call::new("run", args);
    call.tool_allows_process = true;
    Provider::invoke(tool, 0, &call)
}

fn stdout_of(response: Response) -> String {
    let Response::Value(Value::Map(map)) = response else {
        panic!("a run returns a map: {response:?}")
    };
    match map.get("stdout") {
        Some(Value::Text(text)) => text.clone(),
        other => panic!("unexpected stdout {other:?}"),
    }
}

/// The shell this host runs a trivial command through, and the flag
/// that makes it run one command line.
fn shell() -> (&'static str, &'static str) {
    #[cfg(windows)]
    {
        ("C:\\Windows\\System32\\cmd.exe", "/C")
    }
    #[cfg(not(windows))]
    {
        ("/bin/sh", "-c")
    }
}

/// A second, different executable whose output cannot be confused with
/// the first program's: on Linux a shell script (the pinned file keeps
/// its execute bit when overwritten in place, and the shebang makes it
/// runnable); on Windows `whoami.exe`, which ignores the arguments and
/// prints the user instead of the marker.
fn version_two_bytes() -> Vec<u8> {
    #[cfg(windows)]
    {
        std::fs::read("C:\\Windows\\System32\\whoami.exe").expect("read whoami.exe")
    }
    #[cfg(not(windows))]
    {
        b"#!/bin/sh\necho PIN-VERSION-2\n".to_vec()
    }
}

/// A scratch directory that removes itself when the test ends, even
/// on a mid-test panic: the pinned program's copies live here, and a
/// failed test must not leave them behind.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("active-rpc-rpc43-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("scratch directory");
        Self(path)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// RPC-43, pin half (W2's reproduction, as a regression test): pin a
/// copy of the shell, run it (prints `PIN-VERSION-1`), replace the
/// file in place with a different program, and invoke the SAME
/// `LocalProcess` again. Without the fix the second invoke runs the
/// new binary; with it the spawn is refused with
/// `process/program-changed` before anything executes.
#[test]
fn a_program_replaced_in_place_is_refused_at_spawn() {
    let (program, flag) = shell();
    let directory = ScratchDir::new();
    let pinned = directory.0.join("pinned-program");
    let original = std::fs::read(program).expect("read the shell binary");
    std::fs::write(&pinned, &original).expect("copy the shell binary");
    // The copy keeps its execute bit on Unix (the write creates the
    // file; the mode comes from the umask, and the owner-execute bit
    // is what the copy needs — set it explicitly so the test does not
    // depend on the umask).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pinned, std::fs::Permissions::from_mode(0o755))
            .expect("make the copy executable");
    }

    let mut tool = LocalProcess::new(
        pinned.to_string_lossy().into_owned(),
        &[flag, "echo PIN-VERSION-1"],
    )
    .expect("an absolute program");
    let first = run_call(
        &mut tool,
        vec![Arg::text(flag), Arg::text("echo PIN-VERSION-1")],
    )
    .expect("the pinned program runs");
    assert!(
        stdout_of(first).contains("PIN-VERSION-1"),
        "the first invoke runs the pinned program"
    );

    // A byte-identical rewrite is the same program: content
    // identity, not mtime or inode. The second invoke still runs.
    std::fs::write(&pinned, &original).expect("rewrite the same bytes");
    let second = run_call(
        &mut tool,
        vec![Arg::text(flag), Arg::text("echo PIN-VERSION-1")],
    )
    .expect("an identical rewrite is still the pinned program");
    assert!(
        stdout_of(second).contains("PIN-VERSION-1"),
        "an identical rewrite still runs"
    );

    // Replace the file in place with a different program. The
    // write truncates the same inode (the pin's path, mode and
    // inode all survive), so only a content check can see it.
    std::fs::write(&pinned, version_two_bytes()).expect("replace the program in place");
    let error = run_call(
        &mut tool,
        vec![Arg::text(flag), Arg::text("echo PIN-VERSION-1")],
    )
    .expect_err("a replaced program must be refused before it runs");
    assert_eq!(error.code(), "rpc/provider", "{error}");
    assert_eq!(
        error.provider_code(),
        Some("process/program-changed"),
        "{error}"
    );
}

/// RPC-43, kill half (Linux-only): the leader exits at once, leaving a
/// descendant asleep in the leader's process group. Dropping the
/// transport must still kill that descendant — the ownership guard
/// must not mistake "leader dead" for "group gone" — while the group
/// kill itself now goes through the `killpg` syscall, not an external
/// `/bin/kill`. At the base commit this passes too (the old code killed
/// unconditionally); it pins the dead-leader path against the guard
/// regressing it. The reused-pgid skip itself is covered by the
/// in-crate `process_group_still_ours` tests, where the group can be
/// drained deterministically.
#[cfg(target_os = "linux")]
#[test]
fn a_dead_leaders_group_descendant_is_still_killed() {
    use active_rpc::tool::StdioTransport;
    use std::collections::BTreeMap;

    /// Whether any process's command line contains `pattern`, read
    /// through `/proc` rather than `pgrep`: no external binary stands
    /// between the test and the answer (and a missing `pgrep` would
    /// make the assertion pass vacuously).
    fn process_matching(pattern: &str) -> bool {
        let Ok(proc) = std::fs::read_dir("/proc") else {
            return false;
        };
        for entry in proc.flatten() {
            let name = entry.file_name();
            if name.to_string_lossy().parse::<u32>().is_err() {
                continue;
            }
            let Ok(cmdline) =
                std::fs::read_to_string(format!("/proc/{}/cmdline", name.to_string_lossy()))
            else {
                continue;
            };
            if cmdline.replace('\0', " ").contains(pattern) {
                return true;
            }
        }
        false
    }

    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    // No `setsid`: the sleeper stays in the leader's process group,
    // so only the group kill can reach it after the leader exits.
    let transport = StdioTransport::spawn("/bin/sh", &["-c", "sleep 47 & exit 0"], &env)
        .expect("spawn MCP server");
    std::thread::sleep(std::time::Duration::from_millis(300));
    drop(transport);
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(
        !process_matching("sleep 47"),
        "the dead leader's group descendant must be dead after the transport drop"
    );
}
