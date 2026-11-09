//! Whether a pid names a live process, on the platforms that need an OS call.
//!
//! `active-rpc` keeps `#![forbid(unsafe_code)]`: the receipt log's steal rule
//! needs to know whether the pid a lock names is alive, and on Linux that is
//! a `/proc` directory test the library does itself. On Windows the only exact
//! probe is `OpenProcess` + `GetExitCodeProcess`, and on macOS it is
//! `kill(pid, 0)` — both are FFI the library cannot call. This crate is the
//! boundary for those two calls: its whole public API is one safe function,
//! the `unsafe` is confined to one function per platform, and each call site
//! carries its safety argument. Nothing else in the workspace needs process
//! liveness through FFI, so nothing else needs this crate (XPL-RPC-02).
//!
//! Contract of [`process_is_alive`]: `true` means the OS reports a live
//! process with that pid, or reports one the caller may not inspect (an
//! access-denied `OpenProcess` on Windows, an `EPERM` `kill` on macOS — the
//! process exists, only the query is refused, so treating it as dead would
//! steal a live holder's lock). `false` means no such process. It never
//! panics and never allocates. Pid 0 never names a process: on Windows the
//! System Idle Process is not openable, and on macOS `kill(0, 0)` would test
//! the caller's whole process group, so it is refused outright.

#![deny(missing_docs)]

/// Whether `pid` names a live process.
///
/// Windows asks the kernel with `OpenProcess` and reads the exit code: a
/// handle that opens and reports `STILL_ACTIVE` is a live process; a handle
/// that opens and reports any other exit code is a process that already
/// exited (a process that exits with code 259 is misread as live until the
/// lock's grace expires — the same bounded residual as a reused pid on
/// Linux, and the grace is what bounds it). `OpenProcess` failing with
/// access denied means a live process the caller may not inspect, so it
/// reports alive; any other failure means no such process.
///
/// macOS sends signal 0: success is alive, `ESRCH` is dead, `EPERM` is a
/// live process owned by someone else, and any other error is not a live
/// process.
///
/// On any other platform there is no probe, so every pid reports dead and
/// the caller's age rule is the whole test.
#[cfg(windows)]
pub fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: `OpenProcess` takes only values, no pointers, and returns
    // either a null handle or a valid process handle; `GetExitCodeProcess`
    // takes that handle and a valid `&mut u32`, and writes one `u32`
    // through it; `CloseHandle` takes the same handle, which is not used
    // after it. The handle is closed on every path out of this block, so
    // no handle leaks, and it is never duplicated or stored.
    unsafe {
        let handle = windows_sys::Win32::System::Threading::OpenProcess(
            windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        );
        if handle.is_null() {
            // A dead pid fails with `ERROR_INVALID_PARAMETER`; a live pid
            // the caller may not inspect fails with `ERROR_ACCESS_DENIED`
            // (a Protected Process, a SYSTEM process from a non-admin
            // caller). Only the second case is a live process, so only it
            // reports alive — matching the Linux `/proc` check, which sees
            // every pid regardless of owner.
            return windows_sys::Win32::Foundation::GetLastError()
                == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
        }
        let mut exit_code: u32 = 0;
        let ok = windows_sys::Win32::System::Threading::GetExitCodeProcess(handle, &mut exit_code);
        let _ = windows_sys::Win32::Foundation::CloseHandle(handle);
        // `GetExitCodeProcess` fails only on a bad handle, which this is
        // not (`OpenProcess` just returned it): a failure is a broken probe,
        // not a live process, and the caller's age rule is the fallback.
        ok != 0 && exit_code == windows_sys::Win32::Foundation::STILL_ACTIVE as u32
    }
}

/// See the Windows implementation: the probe is `kill(pid, 0)`, which
/// performs no action and only reports whether the pid exists and whether
/// the caller may signal it.
#[cfg(target_os = "macos")]
pub fn process_is_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // `pid_t` is `i32`: a `u32` pid past `i32::MAX` is not a pid at all.
    // Passing it through `as pid_t` would wrap to a negative value, and
    // `kill(-1, 0)` signals every process the caller may signal — so the
    // range is checked before the cast, not after.
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: `kill` with signal 0 performs no action; it only reports
    // whether the pid exists and whether the caller may signal it. The pid
    // was range-checked above, so no process group is ever addressed.
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return true;
    }
    // -1: `ESRCH` means no such process; `EPERM` means it exists but the
    // caller may not signal it (another user's process) — alive, as on
    // Linux, where `/proc` sees every pid. Any other errno (`EINVAL` for a
    // pid the kernel refuses) is not a live process.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// See the Windows implementation: no OS probe exists here, so every pid
/// reports dead and the caller's age rule is the whole test.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn process_is_alive(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::process_is_alive;

    /// The caller's own pid is alive on every platform that probes.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn the_callers_own_pid_is_alive() {
        assert!(process_is_alive(std::process::id()));
    }

    /// A pid no host hands out is dead. `u32::MAX` also exercises the
    /// range guard: on macOS it must not wrap into a negative `pid_t`.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn an_impossible_pid_is_dead() {
        assert!(!process_is_alive(u32::MAX));
    }

    /// A reaped child is dead: the pid existed, the process is gone, and
    /// no live process has taken the number yet.
    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn a_reaped_child_pid_is_dead() {
        #[cfg(windows)]
        let mut command = {
            let mut command = std::process::Command::new("cmd");
            command.args(["/C", "exit", "0"]);
            command
        };
        #[cfg(not(windows))]
        let mut command = std::process::Command::new("/bin/true");
        let mut child = command.spawn().expect("spawn a trivial child");
        let pid = child.id();
        child.wait().expect("reap the child");
        assert!(!process_is_alive(pid), "a reaped pid is dead");
    }

    /// Where there is no probe, every pid reports dead: the fallback is
    /// the documented behaviour, not an accident of the `cfg`.
    #[cfg(not(any(windows, target_os = "macos")))]
    #[test]
    fn without_a_probe_every_pid_reports_dead() {
        assert!(!process_is_alive(std::process::id()));
        assert!(!process_is_alive(u32::MAX));
    }
}
