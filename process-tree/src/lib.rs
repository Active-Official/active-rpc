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
//!
//! On any other platform there is no job object: the process group is the
//! mechanism there, so [`Job`] is a zero-sized stub whose methods do
//! nothing and [`prepare_command`] is a no-op. The caller keeps one code
//! path on every platform instead of a `cfg` at each of the thirteen kill
//! sites.

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
        // `as_raw_handle` reports for a live `Child`; the Toolhelp calls
        // take a snapshot handle this function created, and `entry` is a
        // stack slot whose `dwSize` is set before the first call, as the
        // API requires; `OpenThread`/`ResumeThread` take a thread id the
        // snapshot just reported for this child's pid, and the returned
        // thread handle is closed before the next iteration. No handle is
        // duplicated or stored, and the job handle is closed on every
        // error path.
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
                resume_main_threads(child.id())?;
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

/// Resume every thread of `pid`, which was spawned suspended.
///
/// At suspended-spawn time the child has exactly one thread, its primary;
/// resuming every thread the snapshot reports for the pid is the same
/// thing, and it stays correct if that ever changes. Finding no thread at
/// all is an error — the child cannot have run, so the caller must not
/// treat the spawn as live.
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
