//! The stable identity of an open file, on the platform that needs an OS call.
//!
//! `active-rpc` keeps `#![forbid(unsafe_code)]`: the receipt lock's ownership
//! proof is the file itself, and on Windows the only stable identity of a file
//! is the file index plus the volume serial number from
//! `GetFileInformationByHandle`. Stable `std` cannot supply it:
//! `MetadataExt::file_index` needs the unstable `windows_by_handle` feature,
//! so the one call lives in this crate — the boundary for it — with a safe
//! API, one function, and the `unsafe` confined to that function with its
//! safety argument (XPL-RPC-08). Nothing else in the workspace needs file
//! identity through FFI, so nothing else needs this crate.
//!
//! Contract of [`file_identity`]: `Some((volume_serial, file_index))` for a
//! file the OS can identify — the pair that distinguishes a file from a
//! byte-identical recreation of it at the same path (a new file gets a new
//! file index; NTFS reuses the record number only with an incremented
//! sequence number, which is part of the 64-bit index). `None` when the OS
//! reports no identity: the call fails, or the file index is zero (a
//! filesystem that supplies no file IDs — FAT/exFAT — where treating zero
//! as an identity would equate every file on the volume). It never panics
//! and never allocates. The handle is borrowed, never stored, duplicated,
//! or closed.

#![deny(missing_docs)]

/// The stable identity of an open file: `(volume serial, file index)`.
///
/// Windows reads it with `GetFileInformationByHandle` on the file's handle:
/// the volume serial is the volume the file lives on, and the file index is
/// the 64-bit file ID (`nFileIndexHigh` in the high bits,
/// `nFileIndexLow` in the low bits). A file recreated at the same path gets
/// a new file index even when its bytes are identical, and a renamed file
/// keeps its index — identity follows the file, not the path. A zero file
/// index means the filesystem supplied no identity, so it reports `None`
/// instead of an identity that would equate unrelated files.
///
/// On any other platform there is no probe, so every file reports no
/// identity and the caller's text check is the whole test.
#[cfg(windows)]
pub fn file_identity(file: &std::fs::File) -> Option<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: `GetFileInformationByHandle` takes a valid open file handle
    // and a valid `*mut BY_HANDLE_FILE_INFORMATION`, and writes one struct
    // through it. The handle comes from `AsRawHandle` on a live `&File`, so
    // it is valid for the call; the pointer is to a live local; neither is
    // used after the call; the handle is never stored, duplicated, or
    // closed.
    unsafe {
        let mut info =
            windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION::default();
        let ok = windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
            file.as_raw_handle(),
            &mut info,
        );
        if ok == 0 {
            return None;
        }
        let index = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
        if index == 0 {
            return None;
        }
        Some((u64::from(info.dwVolumeSerialNumber), index))
    }
}

/// See the Windows implementation: no OS probe exists here, so every file
/// reports no identity and the caller's text check is the whole test.
#[cfg(not(windows))]
pub fn file_identity(_file: &std::fs::File) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::file_identity;

    /// The caller's own source file has an identity on Windows, and two
    /// opens of it agree: identity is a property of the file, not the open.
    /// (`CARGO_MANIFEST_DIR`, not `file!()`: the test binary's working
    /// directory is the workspace root, not this crate's directory.)
    #[cfg(windows)]
    #[test]
    fn an_open_file_has_a_stable_identity() {
        let this_file = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
        let first = std::fs::File::open(this_file).expect("open this file");
        let second = std::fs::File::open(this_file).expect("open this file again");
        let identity = file_identity(&first).expect("a file on NTFS has an identity");
        assert_eq!(file_identity(&second), Some(identity), "two opens agree");
        assert_eq!(
            file_identity(&first),
            Some(identity),
            "one handle agrees with itself"
        );
    }

    /// Two different files differ, and a deleted-and-recreated file at the
    /// same path differs from the original: the recreation is a new file,
    /// however identical its bytes.
    #[cfg(windows)]
    #[test]
    fn a_recreated_file_is_a_different_file() {
        let dir =
            std::env::temp_dir().join(format!("active-rpc-file-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("file.txt");
        std::fs::write(&path, b"same bytes").expect("write");
        let original = std::fs::File::open(&path).expect("open the original");
        let original_identity = file_identity(&original).expect("the original has an identity");
        let other_path = dir.join("other.txt");
        std::fs::write(&other_path, b"same bytes").expect("write the other");
        let other = std::fs::File::open(&other_path).expect("open the other");
        let other_identity = file_identity(&other).expect("the other file has an identity");
        assert_ne!(other_identity, original_identity, "two files differ");
        drop(original);
        std::fs::remove_file(&path).expect("remove");
        std::fs::write(&path, b"same bytes").expect("recreate");
        let recreated = std::fs::File::open(&path).expect("open the recreation");
        let recreated_identity = file_identity(&recreated).expect("the recreation has an identity");
        assert_ne!(
            recreated_identity, original_identity,
            "a byte-identical recreation is a different file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A renamed file keeps its identity: identity follows the file, not
    /// the path — which is what lets the lock's steal check the moved file
    /// against the judged one.
    #[cfg(windows)]
    #[test]
    fn a_renamed_file_keeps_its_identity() {
        let dir = std::env::temp_dir().join(format!(
            "active-rpc-file-identity-rename-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("before.txt");
        std::fs::write(&path, b"bytes").expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let identity = file_identity(&file).expect("the file has an identity");
        drop(file);
        let moved = dir.join("after.txt");
        std::fs::rename(&path, &moved).expect("rename");
        let reopened = std::fs::File::open(&moved).expect("open the renamed file");
        assert_eq!(
            file_identity(&reopened),
            Some(identity),
            "a rename keeps the identity"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Where there is no probe, every file reports no identity: the
    /// fallback is the documented behaviour, not an accident of the `cfg`.
    #[cfg(not(windows))]
    #[test]
    fn without_a_probe_no_file_has_an_identity() {
        let this_file = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
        let file = std::fs::File::open(this_file).expect("open this file");
        assert_eq!(file_identity(&file), None);
    }
}
