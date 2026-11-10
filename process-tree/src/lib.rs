//! A Windows job object for a tool child, behind one safe API.
//!
//! `active-rpc` keeps `#![forbid(unsafe_code)]`: a tool timeout kill must end
//! the whole process tree, and on Windows the only atomic way to do that is
//! a job object — `CreateJobObjectW`, `AssignProcessToJobObject`,
//! `TerminateJobObject` — which are FFI the library cannot call. This crate
//! is the boundary for those calls: its whole public API is two safe
//! functions and one safe struct, the `unsafe` is confined to this file, and
//! each call site carries its safety argument. Nothing else in the workspace
//! needs a job object, so nothing else needs this crate (XPL-RPC-04).
//!
//! The shape of the fix, and why it has to be this shape:
//!
//! * The child is spawned **suspended** ([`prepare_command`]) and is only
//!   resumed once it is in the job ([`Job::assign_and_resume`]). A child
//!   spawned running and assigned afterwards leaves a window — however
//!   small — in which it can start a grandchild that never joins the job
//!   and escapes the kill. Suspending first closes that window by
//!   construction: the child has not run a single instruction before the
//!   assignment lands.
//! * The job is created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so the
//!   members die when the last job handle closes too — the explicit
//!   [`Job::terminate`] is the kill, and dropping the job is the backstop
//!   for any path that forgets to terminate.
//! * Breakaway is never allowed: the job is created without
//!   `JOB_OBJECT_LIMIT_BREAKAWAY_OK`, so a descendant cannot opt its own
//!   children out of the job with `CREATE_BREAKAWAY_FROM_JOB`. Job
//!   membership is inherited by default, so grandchildren join the job
//!   without any action by the parent.
//! * The resume is a single `NtResumeProcess` call on the child's process
//!   handle ([`Job::assign_and_resume`]), never a system-wide thread
//!   enumeration (F1-NF-08). The first version of this crate resumed by
//!   snapshotting every thread on the machine
//!   (`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`) and walking the list
//!   to find the child's one thread: ~90 ms per spawn even uncontended,
//!   and ~55 s per spawn under a 130-way concurrent spawn storm, because
//!   the snapshot serializes against the whole system's thread list. The
//!   snapshot walk survives only as the fallback when ntdll does not
//!   export `NtResumeProcess` — no real Windows — so the spawn still
//!   succeeds there, slowly, rather than failing outright.
//!
//! On any other platform there is no job object: the process group is the
//! mechanism there, so [`Job`] is a zero-sized stub whose methods do
//! nothing and [`prepare_command`] is a no-op. The caller keeps one code
//! path on every platform instead of a `cfg` at each of the thirteen kill
//! sites.
//!
//! The Unix half of the same primitive lives here too
//! ([`kill_process_group`], [`kill_pid`], RPC-43): the group kill used
//! to shell out to an external `/bin/kill` with a bare `-<pid>`, so a
//! leader that had exited and whose pid had been reused as a new
//! process-group leader took an unrelated group down with it. The
//! signal is now the `killpg`/`kill` syscall, and the caller only
//! signals a group it has proven still to be its own — the check lives
//! in `active-rpc` (it needs `/proc`), the signal lives here.

#![deny(missing_docs)]

/// Prepare `command` to spawn its child inside a job object.
///
/// On Windows this sets `CREATE_SUSPENDED` on the spawn, so the child is
/// born suspended and [`Job::assign_and_resume`] can put it in the job
/// before it runs. On any other platform this is a no-op: the process
/// group carries the tree, and no suspension is needed.
pub fn prepare_command(command: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // `CREATE_SUSPENDED` (0x00000004): the primary thread starts
        // suspended. Only [`Job::assign_and_resume`] resumes it, after the
        // assignment — a child that never runs cannot have started a
        // grandchild outside the job.
        const CREATE_SUSPENDED: u32 = 0x0000_0004;
        command.creation_flags(CREATE_SUSPENDED);
    }
    #[cfg(not(windows))]
    {
        let _ = command;
    }
}

/// SIGKILL one process group through the `killpg` syscall (RPC-43, Unix).
///
/// `pgid` is the group the caller created at spawn (the leader's pid).
/// Returns true when the signal was delivered to at least one member.
/// A zero pgid is refused outright: `killpg(0, …)` signals the caller's
/// own group, which is never what a tree kill means — and a pgid that
/// does not fit `pid_t` cannot name a group, so it is refused the same
/// way instead of truncated.
///
/// Outside Unix there is no process group to signal, so this returns
/// false and does nothing: the Windows job object is the mechanism
/// there, and the caller never calls this on that platform.
///
/// # Safety boundary
///
/// The `unsafe` is one syscall taking two integers — no pointer, no
/// buffer, no handle. The only effect is the signal itself.
#[cfg(unix)]
pub fn kill_process_group(pgid: u32) -> bool {
    if pgid == 0 {
        return false;
    }
    let Ok(pgid) = libc::pid_t::try_from(pgid) else {
        return false;
    };
    // SAFETY: `killpg` takes a process-group id and a signal number,
    // both plain integers; `SIGKILL` is a valid signal, and the call
    // touches no memory through any pointer.
    unsafe { libc::killpg(pgid, libc::SIGKILL) == 0 }
}

/// SIGKILL one pid through the `kill` syscall (RPC-43, Unix).
///
/// Returns true when the signal was delivered. A zero pid is refused
/// outright: `kill(0, …)` signals the caller's own process group. A
/// pid that does not fit `pid_t` cannot name a process, so it is
/// refused the same way instead of truncated.
///
/// Outside Unix this returns false and does nothing, as in
/// [`kill_process_group`].
///
/// # Safety boundary
///
/// As in [`kill_process_group`]: one syscall taking two integers, no
/// pointer, no buffer. The only effect is the signal itself.
#[cfg(unix)]
pub fn kill_pid(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: as in [`kill_process_group`]: `kill` takes a pid and a
    // signal number, both plain integers, and touches no memory
    // through any pointer.
    unsafe { libc::kill(pid, libc::SIGKILL) == 0 }
}

/// See the Unix implementation: outside Unix there is no process group
/// to signal, so this returns false and does nothing.
#[cfg(not(unix))]
pub fn kill_process_group(_pgid: u32) -> bool {
    false
}

/// See the Unix implementation: outside Unix there is no pid to signal
/// through this API, so this returns false and does nothing.
#[cfg(not(unix))]
pub fn kill_pid(_pid: u32) -> bool {
    false
}

/// A job object holding one tool child and every descendant it starts.
///
/// Created by [`Job::assign_and_resume`], which is the only constructor:
/// a job that was never assigned to a child cannot exist, so no code path
/// can terminate a job it did not spawn a child into.
///
/// Dropping the job closes the job handle. The job was created with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so closing the last handle also
/// kills any member still alive — the explicit [`Job::terminate`] is the
/// kill, the drop is the backstop.
#[cfg(windows)]
pub struct Job {
    handle: windows_sys::Win32::Foundation::HANDLE,
}

/// See the Windows implementation: outside Windows there is no job object,
/// so the job is a zero-sized stub and every method is a no-op.
#[cfg(not(windows))]
pub struct Job;

#[cfg(windows)]
impl Job {
    /// Assign `child` — spawned suspended by [`prepare_command`] — to a new
    /// job object, and resume it.
    ///
    /// The job is created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and
    /// nothing else: no breakaway flag, so no descendant can opt out. The
    /// child is assigned before it is resumed, so no grandchild can exist
    /// outside the job yet. On any failure the job handle is closed, the
    /// child is left suspended, and the error is returned: the caller kills
    /// the suspended child and refuses the spawn, so a tool child never
    /// runs ungrouped.
    ///
    /// On any other platform this returns a stub job: there is no job
    /// object there, and the process group is the mechanism.
    pub fn assign_and_resume(child: &std::process::Child) -> std::io::Result<Self> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        // SAFETY: every call below takes only values, valid pointers to
        // stack slots this function owns, or handles this function just
        // created and closes on every path out. `CreateJobObjectW` takes a
        // null security descriptor and a null name (an unnamed job);
        // `SetInformationJobObject` takes a pointer to `info` and its size,
        // and `info` lives until the call returns; `AssignProcessToJobObject`
        // takes the job handle and the child's process handle, which
        // `as_raw_handle` reports for a live `Child`. The resume is one
        // `NtResumeProcess` call on that same handle (see
        // [`resume_child_process`]); no handle is duplicated or stored,
        // and the job handle is closed on every error path.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let setup = (|| {
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let set = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                        as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if set == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let assigned = AssignProcessToJobObject(
                    job,
                    child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                );
                if assigned == 0 {
                    return Err(std::io::Error::last_os_error());
                }
                resume_child_process(child)?;
                Ok(())
            })();
            if let Err(error) = setup {
                let _ = CloseHandle(job);
                return Err(error);
            }
            Ok(Self { handle: job })
        }
    }

    /// Terminate every process in the job, including the leader and every
    /// descendant it started.
    ///
    /// Best effort: the result is ignored because the caller always
    /// follows with a leader kill and a reap, and dropping the job closes
    /// the last handle, which kills any member still alive
    /// (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).
    ///
    /// On any other platform this is a no-op.
    pub fn terminate(&self) {
        // SAFETY: `TerminateJobObject` takes the job handle this struct
        // owns, which is alive for as long as `self` is borrowed, and an
        // exit code. It kills every process in the job; it never touches
        // memory through the handle.
        unsafe {
            let _ = windows_sys::Win32::System::JobObjects::TerminateJobObject(self.handle, 1);
        }
    }
}

/// Resume `child`, which was spawned suspended, without enumerating the
/// system (F1-NF-08).
///
/// One `NtResumeProcess` call on the child's process handle resumes every
/// thread of the process — exactly what [`resume_main_threads`] did by
/// walking the system thread list, and at suspended-spawn time the child
/// has exactly one thread, its primary, so one resume starts it. No
/// snapshot, no walk: the ~90 ms per-spawn tax and the ~55 s storm stall
/// of the snapshot resume are both gone (bisect probe, this host: the
/// 130-way storm wall time fell from 53.8 s to 0.22 s, and the sequential
/// assign-and-resume from 94–167 ms to a ~2 ms floor — 11.8 ms mean,
/// dominated by spawn jitter, with the resume itself adding ~0.04 ms).
///
/// `NtResumeProcess` has no typed windows-sys binding, so it is resolved
/// at runtime from ntdll.dll (see [`nt_resume_process`]); ntdll has
/// exported it since NT 3.1, so the resolution only ever fails on an
/// exotic Windows. When it does fail, the old snapshot walk runs instead:
/// the spawn still succeeds, slowly, rather than failing outright. A
/// `NtResumeProcess` call that resolves but returns a failure status is
/// a real error and is returned as-is, never retried through the
/// fallback: resuming twice would corrupt the suspend-count accounting,
/// and a failed resume means the process handle is bad or the child is
/// already dying.
#[cfg(windows)]
fn resume_child_process(child: &std::process::Child) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;

    let Some(resume) = nt_resume_process() else {
        return resume_main_threads(child.id());
    };
    // SAFETY: `NtResumeProcess` takes the child's process handle, which
    // `as_raw_handle` reports for a live `Child` and which this function
    // neither duplicates nor stores. It resumes every thread of that one
    // process — the child, and only the child — and touches no memory
    // through the handle. The return is an `NTSTATUS`: 0 is success.
    let status = unsafe { resume(child.as_raw_handle() as HANDLE) };
    if status == 0 {
        Ok(())
    } else {
        Err(ntstatus_to_io_error(status))
    }
}

/// `NTSTATUS NtResumeProcess(HANDLE ProcessHandle)` — an ntdll export with
/// no typed windows-sys binding, resolved once per process and cached.
#[cfg(windows)]
type NtResumeProcessFn = unsafe extern "system" fn(windows_sys::Win32::Foundation::HANDLE) -> i32;

/// `ULONG RtlNtStatusToDosError(NTSTATUS Status)` — the NTSTATUS-to-Win32
/// error translation, also resolved once per process and cached.
#[cfg(windows)]
type RtlNtStatusToDosErrorFn = unsafe extern "system" fn(i32) -> u32;

/// Resolve `NtResumeProcess` from ntdll.dll, once, and cache the result
/// — including the failure, so a host without the export pays one lookup
/// per process, not one per spawn. A function pointer is `Send` + `Sync`,
/// so the `OnceLock` needs no further synchronization.
#[cfg(windows)]
fn nt_resume_process() -> Option<NtResumeProcessFn> {
    static NT_RESUME_PROCESS: std::sync::OnceLock<Option<NtResumeProcessFn>> =
        std::sync::OnceLock::new();
    *NT_RESUME_PROCESS.get_or_init(|| {
        ntdll_export(b"NtResumeProcess\0")
            .map(|address| unsafe { std::mem::transmute::<usize, NtResumeProcessFn>(address) })
    })
}

/// Translate an `NTSTATUS` from `NtResumeProcess` into the `io::Error` the
/// caller reports. `RtlNtStatusToDosError` is resolved the same way as
/// `NtResumeProcess`; if that export is missing too, the raw status is
/// carried in the message instead of being squeezed through
/// `from_raw_os_error`, which would misread an NTSTATUS as a Win32 error.
#[cfg(windows)]
fn ntstatus_to_io_error(status: i32) -> std::io::Error {
    static RTL_NT_STATUS_TO_DOS_ERROR: std::sync::OnceLock<Option<RtlNtStatusToDosErrorFn>> =
        std::sync::OnceLock::new();
    let mapper = *RTL_NT_STATUS_TO_DOS_ERROR.get_or_init(|| {
        ntdll_export(b"RtlNtStatusToDosError\0").map(|address| unsafe {
            std::mem::transmute::<usize, RtlNtStatusToDosErrorFn>(address)
        })
    });
    match mapper {
        Some(map) => {
            // SAFETY: `RtlNtStatusToDosError` is a pure translation of one
            // integer to another; it takes no pointer and no handle.
            let code = unsafe { map(status) };
            std::io::Error::from_raw_os_error(code as i32)
        }
        None => std::io::Error::other(format!(
            "NtResumeProcess failed with NTSTATUS {status:#010x}"
        )),
    }
}

/// Resolve one export of ntdll.dll by its NUL-terminated name, returning
/// its address, or `None` when the module or the export is missing.
/// ntdll is loaded into every Windows process, so `None` only ever means
/// an exotic Windows without that export.
#[cfg(windows)]
fn ntdll_export(name: &[u8]) -> Option<usize> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    // SAFETY: `GetModuleHandleA` takes a NUL-terminated module name and
    // returns null when the module is not loaded; `GetProcAddress` takes
    // that handle and a NUL-terminated export name — every caller passes
    // a `b"...\0"` literal — and returns null when the export is missing.
    // Neither call touches memory through a pointer the caller owns.
    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr() as *const u8);
        if ntdll.is_null() {
            return None;
        }
        GetProcAddress(ntdll, name.as_ptr()).map(|function| function as usize)
    }
}

/// Resume every thread of `pid`, which was spawned suspended — the
/// fallback when ntdll does not export `NtResumeProcess`
/// (see [`resume_child_process`]).
///
/// At suspended-spawn time the child has exactly one thread, its primary;
/// resuming every thread the snapshot reports for the pid is the same
/// thing, and it stays correct if that ever changes. Finding no thread at
/// all is an error — the child cannot have run, so the caller must not
/// treat the spawn as live.
///
/// This is the fallback only: it snapshots every thread on the machine
/// (`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`), which costs ~90 ms
/// per spawn uncontended and ~55 s per spawn under a concurrent spawn
/// storm (F1-NF-08) — the defect the `NtResumeProcess` resume exists to
/// remove. It is kept because a spawn that succeeds slowly beats a spawn
/// that fails outright on a Windows without the export.
#[cfg(windows)]
fn resume_main_threads(pid: u32) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};

    // SAFETY: as in [`Job::assign_and_resume`]: the snapshot handle is
    // created here and closed on every path; `entry` is a stack slot with
    // `dwSize` set before the first enumeration call; each thread handle
    // comes from `OpenThread` on a thread id the snapshot reported for
    // this pid, is resumed once, and is closed before the next iteration.
    // A thread that exits between the snapshot and the open fails the
    // open, and the loop continues to the next id rather than failing the
    // spawn for a thread that is already gone.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }
        let mut entry: THREADENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut resumed = 0u32;
        let mut ok = Thread32First(snapshot, &mut entry);
        while ok != 0 {
            if entry.th32OwnerProcessID == pid {
                let thread = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                if !thread.is_null() {
                    // `ResumeThread` returns the thread's previous suspend
                    // count, and `u32::MAX` on failure. A thread created
                    // suspended has count 1, so one resume starts it.
                    if ResumeThread(thread) != u32::MAX {
                        resumed += 1;
                    }
                    let _ = CloseHandle(thread);
                }
            }
            ok = Thread32Next(snapshot, &mut entry);
        }
        let _ = CloseHandle(snapshot);
        if resumed == 0 {
            return Err(std::io::Error::other(
                "a suspended child has no resumable thread",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: `CloseHandle` takes the job handle this struct owns,
        // which is not used after this call. Closing the last handle also
        // kills any member still alive (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`),
        // which is the backstop for a path that forgot `terminate`.
        unsafe {
            let _ = windows_sys::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

#[cfg(not(windows))]
impl Job {
    /// See the Windows implementation: outside Windows there is no job
    /// object, so this returns a stub job and does nothing.
    pub fn assign_and_resume(_child: &std::process::Child) -> std::io::Result<Self> {
        Ok(Self)
    }

    /// See the Windows implementation: outside Windows there is no job
    /// object, so this is a no-op.
    pub fn terminate(&self) {}
}

#[cfg(test)]
mod tests {
    use super::{prepare_command, Job};

    /// The caller can always build a command and a job: `prepare_command`
    /// is a no-op outside Windows, and a stub job assigns on the spot.
    #[cfg(not(windows))]
    #[test]
    fn the_stub_assigns_and_terminates_without_effect() {
        let mut command = std::process::Command::new("/bin/true");
        prepare_command(&mut command);
        let mut child = command.spawn().expect("spawn a trivial child");
        let job = Job::assign_and_resume(&child).expect("a stub job assigns");
        job.terminate();
        let status = child.wait().expect("reap the child");
        assert!(status.success(), "a stubbed child still runs to completion");
    }

    /// `kill_pid` delivers SIGKILL to one process: the sleeper dies by
    /// signal (no exit code), and the call reports the delivery.
    /// The wait is bounded, so a missed signal fails the test instead
    /// of hanging it; the signal is re-sent defensively on the way out.
    #[cfg(unix)]
    #[test]
    fn kill_pid_kills_one_process() {
        use super::kill_pid;

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn a sleeper");
        assert!(kill_pid(child.id()), "the signal must be delivered");
        let started = std::time::Instant::now();
        loop {
            match child.try_wait().expect("poll the child") {
                Some(status) => {
                    assert!(status.code().is_none(), "a SIGKILL leaves no exit code");
                    break;
                }
                None => {
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(5),
                        "a missed signal would wait forever"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }

    /// `kill_process_group` delivers SIGKILL to the whole group, not
    /// just the leader: the leader runs `sleep` in its own group, the
    /// signal takes the group, and the leader dies by signal.
    #[cfg(unix)]
    #[test]
    fn kill_process_group_kills_the_group() {
        use super::kill_process_group;
        use std::os::unix::process::CommandExt;

        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .process_group(0)
            .spawn()
            .expect("spawn a grouped sleeper");
        assert!(
            kill_process_group(child.id()),
            "the group signal must be delivered"
        );
        let started = std::time::Instant::now();
        loop {
            match child.try_wait().expect("poll the child") {
                Some(status) => {
                    assert!(status.code().is_none(), "a SIGKILL leaves no exit code");
                    break;
                }
                None => {
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(5),
                        "a missed signal would wait forever"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }

    /// A signal to a group or pid that does not exist reports false
    /// instead of signalling anything — and a zero id never signals
    /// the caller's own group (`killpg(0, …)` / `kill(0, …)` would).
    /// A pid that cannot fit `pid_t` is refused the same way instead
    /// of truncated into a live one.
    #[cfg(unix)]
    #[test]
    fn killing_a_dead_group_or_pid_reports_false() {
        use super::{kill_pid, kill_process_group};

        let dead = i32::MAX as u32;
        assert!(!kill_process_group(dead), "no such group exists");
        assert!(!kill_pid(dead), "no such process exists");
        assert!(!kill_process_group(0), "a zero pgid must never signal");
        assert!(!kill_pid(0), "a zero pid must never signal");
        assert!(
            !kill_process_group(u32::MAX),
            "a pgid past pid_t must be refused, not truncated"
        );
        assert!(
            !kill_pid(u32::MAX),
            "a pid past pid_t must be refused, not truncated"
        );
    }

    /// Outside Unix the signal functions are stubs that report false
    /// and do nothing: the job object is the mechanism there.
    #[cfg(not(unix))]
    #[test]
    fn the_signal_stubs_report_false() {
        use super::{kill_pid, kill_process_group};

        assert!(!kill_process_group(1), "no group signal outside Unix");
        assert!(!kill_pid(1), "no pid signal outside Unix");
    }

    /// A child spawned suspended does not run until it is assigned and
    /// resumed — and once it is, it runs to completion. If the resume were
    /// missing, the wait below would hang, so the wait is bounded.
    #[cfg(windows)]
    #[test]
    fn a_suspended_child_is_assigned_and_resumed() {
        let mut command = std::process::Command::new("C:\\Windows\\System32\\cmd.exe");
        command.args(["/C", "exit", "0"]);
        prepare_command(&mut command);
        let mut child = command.spawn().expect("spawn a trivial child");
        let _job = Job::assign_and_resume(&child).expect("assign and resume");
        let started = std::time::Instant::now();
        loop {
            match child.try_wait().expect("poll the child") {
                Some(status) => {
                    assert!(status.success(), "the resumed child exits 0");
                    break;
                }
                None => {
                    assert!(
                        started.elapsed() < std::time::Duration::from_secs(5),
                        "a child that was never resumed would wait forever"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }

    /// The resume is not a system-wide enumeration (F1-NF-08): assigning
    /// and resuming a suspended child costs under 50 ms each, every time.
    /// The old Toolhelp-snapshot resume floored at ~84 ms per spawn even
    /// uncontended (93.7 ms minimum re-measured the morning of the fix)
    /// and took ~55 s under a 130-way storm; the `NtResumeProcess` resume
    /// is a single call on a handle the crate already holds, so 50 ms is
    /// 50x headroom over the new path and still fails the old one
    /// outright. The storm leg of the proof is the bisect binary, not
    /// this test — a 130-way storm does not belong in the crate suite.
    #[cfg(windows)]
    #[test]
    fn assign_and_resume_costs_no_snapshot_tax() {
        for _ in 0..5 {
            let mut command = std::process::Command::new("C:\\Windows\\System32\\cmd.exe");
            command.args(["/C", "exit", "0"]);
            prepare_command(&mut command);
            let mut child = command.spawn().expect("spawn a trivial child");
            let started = std::time::Instant::now();
            let _job = Job::assign_and_resume(&child).expect("assign and resume");
            let elapsed = started.elapsed();
            assert!(
                elapsed < std::time::Duration::from_millis(50),
                "assign-and-resume took {elapsed:?}: the snapshot tax is back"
            );
            let _ = child.wait();
        }
    }

    /// Terminating the job kills the whole tree, not just the leader: the
    /// leader exits at once, the grandchild holds the pipes and would write
    /// the marker two seconds later, and the marker must never appear.
    /// The batch file keeps the grandchild's command line free of nested
    /// quoting, and `ping` is the wait because `timeout` fails when stdin
    /// is redirected.
    #[cfg(windows)]
    #[test]
    fn terminate_kills_the_whole_tree() {
        let directory =
            std::env::temp_dir().join(format!("active-rpc-process-tree-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let marker = directory.join("marker");
        let _ = std::fs::remove_file(&marker);
        let script = directory.join("leader.bat");
        std::fs::write(
            &script,
            "@echo off\r\nstart /b cmd /c \"ping -n 3 127.0.0.1 >nul & echo late > %1\"\r\nexit /b 0\r\n",
        )
        .expect("write leader batch file");

        let mut command = std::process::Command::new("C:\\Windows\\System32\\cmd.exe");
        command.args([
            "/C",
            script.to_string_lossy().as_ref(),
            marker.to_string_lossy().as_ref(),
        ]);
        prepare_command(&mut command);
        let mut child = command.spawn().expect("spawn the leader");
        let job = Job::assign_and_resume(&child).expect("assign and resume");
        // The leader exits at once; the grandchild is still sleeping.
        let _ = child.wait();
        job.terminate();
        std::thread::sleep(std::time::Duration::from_millis(2_500));
        assert!(
            !marker.exists(),
            "a grandchild survived the job terminate and wrote {marker:?}"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}
