//! Sync a file's parent directory to durable storage, on every platform.
//!
//! `active-rpc` keeps `#![forbid(unsafe_code)]`: the receipt log's create
//! path and the CLI's replay dump both fsync the parent directory after
//! installing a file, so the directory entry is durable and not just the
//! file's bytes. On Unix that is `File::open(dir)` + `sync_all()`, which
//! the standard library already does. On Windows there is no such call in
//! `std`: a directory is flushed by opening its handle with
//! `FILE_FLAG_BACKUP_SEMANTICS` and calling `FlushFileBuffers` on it —
//! the documented equivalent, and the same shape SQLite uses. That is FFI
//! the library cannot call, so it lives in this one-function helper crate
//! with a safe API, in the same shape as the liveness helper (XPL-RPC-12).
//!
//! Contract of [`sync_parent_dir`]: `true` means the parent directory was
//! flushed; `false` means the flush was attempted and failed, or there is
//! no flush on this platform. Callers treat it as best
//! effort, exactly as the Unix `sync_all` call sites already did: a
//! failed directory sync never refuses a log that is otherwise valid, and
//! the file's own `sync_all` is what orders the bytes. It never panics
//! and never allocates more than the wide path it opens.
//!
//! Residual, stated honestly: no test can prove crash durability short of
//! pulling the plug. What the tests prove is that the documented Windows
//! equivalent is invoked and reports success — the same guarantee level
//! as the Unix `sync_all` it mirrors. A directory that cannot be opened
//! (a missing parent, a bare name in a deleted working directory) reports
//! `false`; the caller ignores it, as before.

#![deny(missing_docs)]

use std::path::Path;

/// Sync the parent directory of `path` to durable storage.
///
/// Windows opens the parent directory with `FILE_FLAG_BACKUP_SEMANTICS`
/// and flushes it with `FlushFileBuffers`: a handle that opens and
/// flushes is a durable directory entry; a handle that fails to open (a
/// missing parent) or a flush that fails reports `false`. A bare file
/// name has no parent, so its parent is the current directory.
///
/// A path whose parent is a regular file is still flushed if it opens:
/// `FILE_FLAG_BACKUP_SEMANTICS` opens files as well as directories, and
/// flushing the named file is the closest available meaning — the caller
/// only ever passes a log or dump path, whose parent is a directory.
#[cfg(windows)]
pub fn sync_parent_dir(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_READ,
        FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    // A NUL-terminated wide path: `CreateFileW` reads to the terminator,
    // and a Rust path cannot contain a NUL, so the terminator is the only
    // one. The handle is opened for reading and writing: `FlushFileBuffers`
    // on a directory handle opened read-only fails with `ERROR_ACCESS_DENIED`
    // (proven by probe on this machine: a `FILE_GENERIC_READ` handle opens
    // fine and its flush fails with error 5), so the flush needs the write
    // half too. (`FILE_GENERIC_READ` / `FILE_GENERIC_WRITE` are the
    // file-specific masks the generic `GENERIC_READ` / `GENERIC_WRITE`
    // resolve to; windows-sys provides the file-specific names.) The
    // handle is shared for read, write and delete, so the flush never
    // blocks another handle to the same directory; `OPEN_EXISTING` so a
    // missing parent fails instead of creating anything;
    // `FILE_FLAG_BACKUP_SEMANTICS`, without which a directory cannot be
    // opened at all.
    let mut wide: Vec<u16> = parent.as_os_str().encode_wide().collect();
    wide.push(0);
    // SAFETY: `CreateFileW` takes a NUL-terminated wide path (built
    // above), a null security descriptor, and no template handle, and
    // returns either `INVALID_HANDLE_VALUE` or a valid directory handle;
    // `FlushFileBuffers` takes that handle; `CloseHandle` takes the same
    // handle, which is not used after it. The handle is closed on every
    // path out of this block, so no handle leaks, and it is never
    // duplicated or stored.
    unsafe {
        let handle = CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        );
        if handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let flushed = FlushFileBuffers(handle);
        let _ = CloseHandle(handle);
        flushed != 0
    }
}

/// See the Windows implementation: the probe is `File::open(parent)` +
/// `sync_all()`, which the standard library already maps to the right
/// call on Unix. A bare file name has no parent, so its parent is the
/// current directory.
#[cfg(unix)]
pub fn sync_parent_dir(path: &Path) -> bool {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .is_ok()
}

/// See the Windows implementation: no OS probe exists here, so every
/// parent reports failure and the caller's file sync is the whole
/// durability story.
#[cfg(not(any(windows, unix)))]
pub fn sync_parent_dir(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::sync_parent_dir;
    use std::path::PathBuf;

    /// A fresh directory under the test process's temp dir, removed on
    /// drop so a failed test never leaves its scratch behind.
    struct TempDir(PathBuf);

    impl TempDir {
        fn create(name: &str) -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!("active-rpc-dir-sync-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("create the temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The ordinary case: a file beside a fresh directory syncs.
    #[test]
    fn syncing_an_existing_directory_succeeds() {
        let dir = TempDir::create("existing");
        let file = dir.0.join("log.arrl");
        std::fs::write(&file, b"header").expect("write the file");
        assert!(
            sync_parent_dir(&file),
            "the parent of a file in an existing directory flushes"
        );
    }

    /// Depth is no obstacle: the parent is resolved, not assumed flat.
    #[test]
    fn syncing_a_nested_directory_succeeds() {
        let dir = TempDir::create("nested");
        let nested = dir.0.join("a").join("b");
        std::fs::create_dir_all(&nested).expect("create the nested dirs");
        let file = nested.join("log.arrl");
        std::fs::write(&file, b"header").expect("write the file");
        assert!(
            sync_parent_dir(&file),
            "the parent of a file in a nested directory flushes"
        );
    }

    /// A bare file name has no parent: its directory is the current
    /// directory, and that flushes. The file itself need not exist —
    /// only its parent is synced.
    #[test]
    fn a_bare_filename_syncs_the_current_directory() {
        assert!(
            sync_parent_dir(std::path::Path::new("no-such-log.arrl")),
            "a bare file name syncs the current directory"
        );
    }

    /// A parent that does not exist cannot be flushed, and that is a
    /// `false`, not a panic: the caller treats it as best effort.
    #[test]
    fn a_missing_directory_reports_failure() {
        let mut missing = std::env::temp_dir();
        missing.push(format!(
            "active-rpc-dir-sync-missing-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&missing);
        assert!(
            !sync_parent_dir(&missing.join("log.arrl")),
            "a parent that does not exist reports failure"
        );
    }

    /// The filesystem root flushes too: the parent of a file directly
    /// under it is the root itself, and opening a root directory handle
    /// is an ordinary read.
    #[cfg(windows)]
    #[test]
    fn syncing_a_filesystem_root_succeeds() {
        assert!(
            sync_parent_dir(std::path::Path::new("C:\\no-such-log.arrl")),
            "the parent of a file directly under C:\\ flushes"
        );
    }
}
