//! The Windows half of the receipt-key permission check (XPL-RPC-09).
//!
//! The CLI refuses a receipt key other accounts can read: on unix the mode
//! must be `0600` (`mode & 0o077 == 0`); on Windows the file's DACL must
//! grant read access to nobody but the file's owner — plus `SYSTEM` and
//! `Administrators`, explicitly allow-listed, because a file created by an
//! ordinary account normally carries their ACEs too and they are the
//! machine's own accounts, not other users. Stable `std` exposes no ACL,
//! so the one probe lives in this crate — the boundary for it — with a safe
//! API, one function, and the `unsafe` confined to that function and its
//! helpers, each with its safety argument (same shape as `file-identity`,
//! XPL-RPC-08). Nothing else in the workspace needs an
//! ACL check through FFI, so nothing else needs this crate.
//!
//! Contract of [`check_key_file_acl`]: `Ok(())` when no ACE in the file's
//! DACL grants read access to any SID but the owner, `SYSTEM`
//! (`S-1-5-18`), `Administrators` (`S-1-5-32-544`), or a member of the
//! local Administrators group; `Err(reason)` — the refusal, naming the
//! offending SID — otherwise, including when the ACL cannot be read at all
//! (fail closed: an unreadable ACL proves nothing). The members count
//! because `Administrators` is allow-listed as a group, and a group
//! allow-list means its members: an administrator can read any file when
//! elevated (taking ownership and the backup privilege bypass the DACL),
//! so the DACL cannot keep administrators out and refusing their ACE
//! would be theater. The check's job is to keep the key from
//! non-administrator accounts — which is also why a file created by an
//! elevated process (owned by `Administrators`, with an ACE for the
//! operator's own account) passes, instead of being refused for granting
//! read to someone who is not the owner SID.
//! "Read access" is `FILE_READ_DATA` or the generic forms that include it
//! (`GENERIC_READ`, `GENERIC_ALL`); an ACE that grants only write,
//! execute, attributes, or `READ_CONTROL` does not leak the key's bytes
//! and passes. Inherited ACEs count exactly like explicit ones: the
//! inherited `BUILTIN\Users:(RX)` on a file created under `%TEMP%` is the
//! finding. A `NULL` DACL (no access control at all — FAT/exFAT, which
//! have no ACLs) is refused: the invariant cannot be established there.
//! A membership lookup that fails for any reason counts as "not a
//! member": fail closed. It never panics. The handle is borrowed, never
//! stored, duplicated, or closed; the security descriptor
//! `GetSecurityInfo` allocates is freed before returning.

#![deny(missing_docs)]

#[cfg(windows)]
use windows_sys::core::PWSTR;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{LocalFree, GENERIC_ALL, GENERIC_READ};
#[cfg(windows)]
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH,
};
#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    AclSizeInformation, CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, IsWellKnownSid,
    LookupAccountSidW, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
    ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::FILE_READ_DATA;
#[cfg(windows)]
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    SYSTEM_ACCESS_FILTER_ACE_TYPE, SYSTEM_ALARM_ACE_TYPE, SYSTEM_ALARM_CALLBACK_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_ALARM_OBJECT_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_OBJECT_ACE_TYPE, SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
};

/// The Windows half of the receipt-key permission check: `Ok(())` when
/// only the file's owner (plus `SYSTEM`, `Administrators`, and members of
/// the local Administrators group) can read the file, `Err(reason)`
/// otherwise — including when the ACL cannot be read at all. See the
/// crate docs for the exact allow-list and the fail-closed rules.
///
/// On any other platform there is no probe, so the check passes and the
/// caller's unix check is the whole test.
#[cfg(windows)]
pub fn check_key_file_acl(file: &std::fs::File) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: `GetSecurityInfo` takes a valid open file handle and writes
    // an owner SID, a DACL pointer, and a security-descriptor pointer
    // through the out-pointers. The handle comes from `AsRawHandle` on a
    // live `&File`, so it is valid for the call — and it carries
    // `READ_CONTROL`, because `File::open` requests `GENERIC_READ`, which
    // includes it — so reading the DACL is permitted. The out-pointers are
    // to live locals; neither the handle nor the returned pointers are
    // used after the call except to free the descriptor, which the API
    // documents as the caller's job (`LocalFree` on a null pointer is a
    // no-op, so freeing before checking the status is safe).
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let status = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        let result = if status != 0 {
            Err(format!(
                "cannot read the file's ACL (GetSecurityInfo error {status}); refusing a key whose permissions cannot be verified"
            ))
        } else {
            check_dacl(owner, dacl)
        };
        let _ = LocalFree(descriptor);
        result
    }
}

/// See the Windows implementation: no ACL probe exists here, so the check
/// passes and the caller's unix check is the whole test.
#[cfg(not(windows))]
pub fn check_key_file_acl(_file: &std::fs::File) -> Result<(), String> {
    Ok(())
}

/// The DACL half of the check, on the owner SID and DACL `GetSecurityInfo`
/// returned. Both are borrowed from the security descriptor; neither is
/// freed here — the caller frees the descriptor. `Ok(())` when no ACE
/// grants read access to any SID but the owner, `SYSTEM`,
/// `Administrators`, or a member of the local Administrators group.
///
/// # Safety
/// `owner` must be a valid owner SID and `dacl` a valid ACL (or null),
/// both live for the call — exactly what `GetSecurityInfo` returns on
/// success. Every pointer read below comes from those two roots (an ACE
/// pointer from `GetAce`, a SID pointer from an ACE's `SidStart`), so no
/// other allocation is touched.
#[cfg(windows)]
unsafe fn check_dacl(owner: PSID, dacl: *mut ACL) -> Result<(), String> {
    if owner.is_null() {
        return Err(
            "the file has no owner SID; refusing a key whose owner cannot be determined"
                .to_string(),
        );
    }
    if dacl.is_null() {
        // No DACL means no access control: anyone who can open the volume
        // can read the file. FAT/exFAT have no ACLs at all, so a key file
        // there is refused outright rather than trusted on faith.
        return Err(
            "the file has no DACL (no access control); refusing a key whose readers cannot be listed"
                .to_string(),
        );
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    let ok = GetAclInformation(
        dacl as *const ACL,
        &mut size as *mut ACL_SIZE_INFORMATION as *mut core::ffi::c_void,
        std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
        AclSizeInformation,
    );
    if ok == 0 {
        return Err(
            "cannot read the file's DACL (GetAclInformation failed); refusing a key whose permissions cannot be verified"
                .to_string(),
        );
    }
    for index in 0..size.AceCount {
        let mut ace_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let ok = GetAce(dacl as *const ACL, index, &mut ace_ptr);
        if ok == 0 || ace_ptr.is_null() {
            return Err(
                "cannot read an ACE of the file's DACL (GetAce failed); refusing a key whose permissions cannot be verified"
                    .to_string(),
            );
        }
        let header = &*(ace_ptr as *const ACE_HEADER);
        let ace_type = u32::from(header.AceType);
        match ace_type {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {
                // An allowed ACE and an allowed callback ACE share the
                // prefix this check reads (header, mask, `SidStart`); the
                // callback data follows the SID and is not read.
                let ace = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
                if !grants_read(ace.Mask) {
                    continue;
                }
                let sid = &ace.SidStart as *const u32 as PSID;
                if EqualSid(sid, owner) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
                    || sid_is_local_admin(sid)
                {
                    continue;
                }
                return Err(format!("ACE grants read to {}", sid_string(sid)));
            }
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE
            | ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                // A granting ACE in a shape this check cannot parse (its
                // SID is not at the allowed-ACE offset): fail closed
                // rather than assume it grants nothing.
                return Err(format!(
                    "the file's DACL has a granting ACE of a type this check cannot parse (type {ace_type}); refusing a key whose readers cannot be listed"
                ));
            }
            ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_ACE_TYPE
            | SYSTEM_ALARM_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_MANDATORY_LABEL_ACE_TYPE
            | SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
            | SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
            | SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE
            | SYSTEM_ACCESS_FILTER_ACE_TYPE => {
                // Deny ACEs and audit/system ACEs grant nothing; they do
                // not make the file world-readable. (A deny ACE does not
                // rescue an allow ACE either: the loop refuses on the
                // allow ACE wherever it sits.)
            }
            _ => {
                return Err(format!(
                    "the file's DACL has an ACE of an unknown type ({ace_type}); refusing a key whose readers cannot be listed"
                ));
            }
        }
    }
    Ok(())
}

/// Whether an access mask grants read access to the file's bytes:
/// `FILE_READ_DATA` itself, or a generic form that includes it.
/// `GENERIC_READ` maps to `FILE_GENERIC_READ`, which has `FILE_READ_DATA`
/// set, and `GENERIC_ALL` grants everything — so checking the generic
/// bits directly is exact here, with no `MapGenericMask` needed. An ACE
/// that grants only write, execute, attributes, or `READ_CONTROL` (which
/// reads the DACL, not the bytes) does not leak the key and passes.
#[cfg(windows)]
fn grants_read(mask: u32) -> bool {
    mask & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) != 0
}

/// Whether a SID is a member of the local Administrators group — the
/// "Administrators" entry of the allow-list, as its members. An
/// administrator can read any file when elevated (taking ownership and the
/// backup privilege bypass the DACL), so refusing an administrator's ACE
/// would be theater; the check's job is to keep the key from
/// non-administrator accounts. Any failure (the group cannot be named,
/// its members cannot be listed) is `false`: fail closed.
///
/// # Safety
/// `sid` must be a valid SID live for the call.
#[cfg(windows)]
unsafe fn sid_is_local_admin(sid: PSID) -> bool {
    // The group's name is localised (`Administrators` in English,
    // `Administradores` here), so resolve the well-known SID to its local
    // name instead of assuming one.
    let Some(name) = administrators_group_name() else {
        return false;
    };
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read: u32 = 0;
        let mut total: u32 = 0;
        let status = NetLocalGroupGetMembers(
            std::ptr::null(),
            name.as_ptr(),
            0,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut read,
            &mut total,
            &mut resume,
        );
        if status != 0 {
            return false;
        }
        // Zero entries may come with a null buffer; there is nothing to
        // compare then.
        let found = if read == 0 || buf.is_null() {
            false
        } else {
            let entries =
                std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_0, read as usize);
            entries
                .iter()
                .any(|entry| EqualSid(sid, entry.lgrmi0_sid) != 0)
        };
        if !buf.is_null() {
            let _ = NetApiBufferFree(buf as _);
        }
        if found {
            return true;
        }
        if resume == 0 {
            return false;
        }
    }
}

/// The local name of the `Administrators` group (`Administradores` on this
/// machine), resolved from the well-known SID so the lookup never assumes
/// an English name. `None` if the SID cannot be built or looked up: fail
/// closed. The returned name is null-terminated, as
/// `NetLocalGroupGetMembers` expects.
#[cfg(windows)]
fn administrators_group_name() -> Option<Vec<u16>> {
    // SAFETY: `CreateWellKnownSid` and `LookupAccountSidW` take valid
    // buffers and write through the length pointers. The SID buffer is a
    // live 68-byte local (a SID is at most `SECURITY_MAX_SID_SIZE` bytes);
    // the name/domain buffers are live 256-unit locals (group names are at
    // most 256 characters), and the lengths are initialised to the buffer
    // sizes. No pointer escapes the calls.
    unsafe {
        let mut admin_sid = [0u8; 68];
        let mut admin_sid_len: u32 = 68;
        let ok = CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            admin_sid.as_mut_ptr() as PSID,
            &mut admin_sid_len,
        );
        if ok == 0 {
            return None;
        }
        let mut name = [0u16; 256];
        let mut name_len: u32 = 256;
        let mut domain = [0u16; 256];
        let mut domain_len: u32 = 256;
        let mut use_: SID_NAME_USE = 0;
        let ok = LookupAccountSidW(
            std::ptr::null(),
            admin_sid.as_mut_ptr() as PSID,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_,
        );
        if ok == 0 {
            return None;
        }
        // `name_len` counts the name's characters, NOT the terminating
        // null: 15 for the 15-letter "Administradores". Slicing
        // `name[..len]` therefore drops the terminator the call wrote, so
        // append it explicitly — a `PCWSTR` without one reads past the
        // allocation, and the lookup then fails with `NERR_GroupNotFound`
        // whenever the following heap word is non-zero (about half the
        // runs, observed). Appending unconditionally is safe under either
        // reading of the count: if the count ever did include the null,
        // the extra terminator just follows it.
        let len = name_len as usize;
        if len == 0 || len > name.len() {
            return None;
        }
        let mut result = name[..len].to_vec();
        result.push(0);
        Some(result)
    }
}

/// The SID as `S-1-5-...`, for the refusal message; falls back to a fixed
/// string if the conversion fails, so the refusal never depends on the
/// formatting call.
///
/// # Safety
/// `sid` must be a valid SID live for the call — exactly what an ACE's
/// `SidStart` points at. The string `ConvertSidToStringSidW` allocates is
/// freed before returning.
#[cfg(windows)]
unsafe fn sid_string(sid: PSID) -> String {
    // `PWSTR` is a `*mut u16` alias here, not a tuple struct.
    let mut wide: PWSTR = std::ptr::null_mut();
    let ok = ConvertSidToStringSidW(sid, &mut wide);
    if ok == 0 || wide.is_null() {
        return "an account this check cannot name".to_string();
    }
    let mut units = Vec::new();
    let mut cursor = wide;
    while *cursor != 0 {
        units.push(*cursor);
        cursor = cursor.add(1);
    }
    let _ = LocalFree(wide as _);
    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::check_key_file_acl;
    #[cfg(windows)]
    use super::{DACL_SECURITY_INFORMATION, SE_FILE_OBJECT};

    /// Windows only: run `icacls`, failing the test if it refuses — a test
    /// bug, not a crate bug, so the failure says which invocation failed.
    #[cfg(windows)]
    fn icacls(args: &[&str]) {
        let output = std::process::Command::new("icacls")
            .args(args)
            .output()
            .expect("spawn icacls");
        assert!(
            output.status.success(),
            "icacls {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Windows only: the account running the test, as `icacls` spells it
    /// (`DOMAIN\user`).
    #[cfg(windows)]
    fn current_user() -> String {
        let output = std::process::Command::new("whoami")
            .output()
            .expect("spawn whoami");
        assert!(output.status.success(), "whoami failed");
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    /// Windows only: a fresh temporary directory per test.
    #[cfg(windows)]
    fn sandbox(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("active-rpc-key-acl-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("sandbox");
        dir
    }

    /// Windows only: restrict a file to its owner — drop the inherited
    /// ACEs, then grant the owner full control. (A file created under
    /// `%TEMP%` inherits an ACL that lets other accounts read it.)
    #[cfg(windows)]
    fn restrict_to_owner(path: &std::path::Path) {
        let path_arg = path.to_str().expect("path");
        icacls(&[path_arg, "/inheritance:r"]);
        let grant = format!("{}:(F)", current_user());
        icacls(&[path_arg, "/grant:r", &grant]);
    }

    /// A file restricted to its owner passes. On this machine the process
    /// runs elevated, so the file is owned by `Administrators` and the
    /// grant names the operator's own account — the pass exercises the
    /// Administrators-membership arm, not owner equality. On a
    /// non-elevated run the same setup passes via owner equality instead:
    /// the file is owned by the operator and the grant names them.
    #[cfg(windows)]
    #[test]
    fn an_owner_only_key_file_passes() {
        let dir = sandbox("owner-only");
        let path = dir.join("key.txt");
        std::fs::write(
            &path,
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("write");
        restrict_to_owner(&path);
        let file = std::fs::File::open(&path).expect("open");
        assert_eq!(check_key_file_acl(&file), Ok(()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The finding's shape: the same owner-only file, once `BUILTIN\Users`
    /// is granted read, is refused — and the refusal names the group's SID.
    #[cfg(windows)]
    #[test]
    fn a_key_file_readable_by_users_is_refused() {
        let dir = sandbox("users-read");
        let path = dir.join("key.txt");
        std::fs::write(
            &path,
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("write");
        restrict_to_owner(&path);
        let path_arg = path.to_str().expect("path");
        // By SID: the group's name is localised (`Usuarios` on this
        // machine), the SID is not.
        icacls(&[path_arg, "/grant", "*S-1-5-32-545:(R)"]);
        let file = std::fs::File::open(&path).expect("open");
        let refused = check_key_file_acl(&file).expect_err("Users can read the key");
        assert!(
            refused.contains("S-1-5-32-545"),
            "the refusal names the account that can read the key: {refused}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file with no DACL at all is refused, not trusted: the invariant
    /// cannot be established where there is no access control (FAT/exFAT).
    /// The `NULL` DACL is set with `SetNamedSecurityInfoW`, the same call
    /// an administrator would use; the file is deleted afterwards, so no
    /// restore is needed.
    #[cfg(windows)]
    #[test]
    fn a_key_file_with_no_dacl_is_refused() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
        let dir = sandbox("no-dacl");
        let path = dir.join("key.txt");
        std::fs::write(
            &path,
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .expect("write");
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        // SAFETY: `SetNamedSecurityInfoW` takes a null-terminated wide
        // path, the object type, and the security information to set; the
        // `NULL` DACL pointer is the documented way to set "no DACL". The
        // path buffer is a live local, null-terminated above; the `NULL`
        // owner/group/SACL pointers mean "leave unchanged". The call
        // returns a Win32 error code, checked below.
        let status = unsafe {
            // `PCWSTR` is a `*const u16` alias here, not a tuple struct.
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(status, 0, "SetNamedSecurityInfoW failed: {status}");
        let file = std::fs::File::open(&path).expect("open");
        let refused = check_key_file_acl(&file).expect_err("no DACL means no access control");
        assert!(
            refused.contains("no DACL"),
            "the refusal says why the key cannot be trusted: {refused}"
        );
        drop(file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Where there is no probe, the check passes: the fallback is the
    /// documented behaviour, not an accident of the `cfg`.
    #[cfg(not(windows))]
    #[test]
    fn without_a_probe_the_check_passes() {
        let this_file = concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs");
        let file = std::fs::File::open(this_file).expect("open this file");
        assert_eq!(check_key_file_acl(&file), Ok(()));
    }
}
