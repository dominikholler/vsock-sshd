use std::ffi::{c_void, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr::{null, null_mut};

use anyhow::{bail, Context, Result};
use windows_sys::core::BOOL;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtOpenFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, RtlNtStatusToDosError, SetHandleInformation, FALSE,
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LUID, NTSTATUS, OBJ_CASE_INSENSITIVE,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND, TRUE, UNICODE_STRING,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetUserGetLocalGroups, LG_INCLUDE_INDIRECT, LOCALGROUP_USERS_INFO_0,
    MAX_PREFERRED_LENGTH,
};
use windows_sys::Win32::Security::Authentication::Identity::{
    LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLogonUser,
    LsaLookupAuthenticationPackage, LsaRegisterLogonProcess, MsV1_0S4ULogon, LSA_STRING,
    MSV1_0_S4U_LOGON, MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS, SECURITY_LOGON_TYPE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, EqualSid, GetAce, IsWellKnownSid, LookupAccountNameW, SecurityImpersonation,
    TokenPrimary, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
    ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID, QUOTA_LIMITS,
    SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_ALL_ACCESS, TOKEN_SOURCE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::Environment::{
    CreateEnvironmentBlock, DestroyEnvironmentBlock, ExpandEnvironmentStringsW,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, INFINITE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::{current_exe_path, SpawnedChild};

const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1024 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[derive(Clone, Debug)]
pub struct OsUser {
    pub username: String,
    pub domain: String,
    pub sid_bytes: Vec<u8>,
    pub sid_string: String,
    pub home: PathBuf,
    pub is_admin: bool,
}

pub fn default_host_key_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("vsock-sshd").join("ssh_host_ed25519_key")
}

pub fn write_host_key_strict(path: &Path, pem: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    file.write_all(pem)?;
    file.sync_all()?;
    Ok(())
}

/// Resolve a Windows local or domain account via `LookupAccountNameW`,
/// check Administrators membership, and locate the user's profile directory.
pub fn lookup_user(username: &str) -> Result<Option<OsUser>> {
    if username.is_empty() || username.contains('\0') {
        return Ok(None);
    }

    let wide_name = to_wide(username);
    let mut sid_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut sid_use: SID_NAME_USE = 0;

    unsafe {
        LookupAccountNameW(
            null(),
            wide_name.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut domain_len,
            &mut sid_use,
        );
    }
    if sid_len == 0 {
        return Ok(None);
    }

    let mut sid_bytes = vec![0u8; sid_len as usize];
    let mut domain_buf = vec![0u16; domain_len as usize];
    let ok = unsafe {
        LookupAccountNameW(
            null(),
            wide_name.as_ptr(),
            sid_bytes.as_mut_ptr().cast(),
            &mut sid_len,
            domain_buf.as_mut_ptr(),
            &mut domain_len,
            &mut sid_use,
        )
    };
    if ok == FALSE {
        return Ok(None);
    }

    let domain = from_wide_nul(&domain_buf);
    let sid_string = sid_to_string(sid_bytes.as_mut_ptr().cast())?;
    let home = lookup_profile_dir(&sid_string)
        .unwrap_or_else(|| PathBuf::from(format!(r"C:\Users\{username}")));
    let is_admin = is_local_administrator(username);

    Ok(Some(OsUser {
        username: username.to_owned(),
        domain,
        sid_bytes,
        sid_string,
        home,
        is_admin,
    }))
}

fn open_child_no_reparse(dir: &File, name: &OsStr, is_dir: bool) -> Result<Option<File>> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    if wide.is_empty()
        || wide.contains(&0)
        || wide.contains(&(b'\\' as u16))
        || wide.contains(&(b'/' as u16))
    {
        bail!("invalid path component '{}'", name.to_string_lossy());
    }
    let byte_len =
        u16::try_from(wide.len() * 2).context("path component exceeds UNICODE_STRING limit")?;
    let unicode_name = UNICODE_STRING {
        Length: byte_len,
        MaximumLength: byte_len,
        Buffer: wide.as_mut_ptr(),
    };
    let obj_attr = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir.as_raw_handle() as HANDLE,
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let desired_access = if is_dir {
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    } else {
        FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    };
    let open_options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if is_dir {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        };

    let mut handle: HANDLE = null_mut();
    let mut iosb = IO_STATUS_BLOCK::default();
    let status = unsafe {
        NtOpenFile(
            &mut handle,
            desired_access,
            &obj_attr,
            &mut iosb,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            open_options,
        )
    };
    if status < 0 {
        if status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_OBJECT_PATH_NOT_FOUND {
            return Ok(None);
        }
        let win32 = unsafe { RtlNtStatusToDosError(status) };
        let err = io::Error::from_raw_os_error(win32 as i32);
        return Err(err).with_context(|| {
            format!(
                "failed to open '{}' without following reparse points",
                name.to_string_lossy()
            )
        });
    }

    let file = unsafe { File::from_raw_handle(handle as _) };
    let meta = file.metadata()?;
    if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        bail!(
            "path component '{}' is a reparse point (refused)",
            name.to_string_lossy()
        );
    }
    Ok(Some(file))
}

fn open_dir_no_reparse(path: &Path) -> Result<Option<File>> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("parent directory traversal ('..') is not permitted in authorized_keys paths");
    }

    let mut components = path.components().peekable();
    let mut root_path = PathBuf::new();
    while let Some(comp) = components.peek() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                root_path.push(comp.as_os_str());
                components.next();
            }
            _ => break,
        }
    }

    if !root_path.as_os_str().is_empty() && !path.has_root() {
        bail!(
            "drive-relative paths without a root directory are not permitted: {}",
            path.display()
        );
    }

    let start_path = if root_path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        root_path.as_path()
    };
    let mut current_dir = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(start_path)
    {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    if root_path.as_os_str().is_empty()
        && (current_dir.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        bail!(
            "directory {} is a reparse point (refused)",
            start_path.display()
        );
    }

    for comp in components {
        match comp {
            Component::Normal(name) => {
                let Some(next) = open_child_no_reparse(&current_dir, name, true)? else {
                    return Ok(None);
                };
                current_dir = next;
            }
            Component::CurDir => continue,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {}
        }
    }
    Ok(Some(current_dir))
}

/// OpenSSH-Win32 strict `authorized_keys` resolution:
/// - Default: Administrators use `%ProgramData%\ssh\administrators_authorized_keys`
///   Standard users use `<ProfileDir>\.ssh\authorized_keys`
/// - Custom: If directory, `<dir>\<username>`. If file, must be owned by authenticating user (or admin).
///
/// Walks directories without following reparse points (symlinks/junctions), opens files relative
/// to the verified directory handle via `NtOpenFile`, and verifies owner SID and DACL write restrictions.
pub fn read_authorized_keys_strict(
    user: &OsUser,
    custom_path: Option<&Path>,
) -> Result<Option<String>> {
    let (dir_file, file_name, is_custom_file) = match custom_path {
        Some(p) => {
            let is_dir = match std::fs::symlink_metadata(p) {
                Ok(m) if (m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 => {
                    bail!(
                        "custom authorized_keys path {} is a reparse point",
                        p.display()
                    );
                }
                Ok(m) => m.is_dir(),
                Err(err) if err.kind() == io::ErrorKind::NotFound => false,
                Err(err) => return Err(err.into()),
            };
            if is_dir {
                let dir_file = open_dir_no_reparse(p)?
                    .with_context(|| format!("custom directory {} not found", p.display()))?;
                verify_owner_sid(dir_file.as_raw_handle() as HANDLE, user, false)?;
                (dir_file, OsString::from(&user.username), false)
            } else {
                let parent = p.parent().unwrap_or_else(|| Path::new("."));
                let parent_dir = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                let parent_file = open_dir_no_reparse(parent_dir)?.with_context(|| {
                    format!("parent directory {} not found", parent_dir.display())
                })?;
                verify_owner_sid(parent_file.as_raw_handle() as HANDLE, user, false)?;
                let file_name = p
                    .file_name()
                    .context("invalid custom authorized_keys file path")?;
                (parent_file, file_name.to_os_string(), true)
            }
        }
        None => {
            let (dir_path, file_name) = if user.is_admin {
                let base = std::env::var_os("ProgramData")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
                (base.join("ssh"), "administrators_authorized_keys")
            } else {
                (user.home.join(".ssh"), "authorized_keys")
            };
            let Some(dir_file) = open_dir_no_reparse(&dir_path)? else {
                return Ok(None);
            };
            (dir_file, OsString::from(file_name), false)
        }
    };

    let Some(file) = open_child_no_reparse(&dir_file, &file_name, false)? else {
        return Ok(None);
    };

    let meta = file.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("authorized_keys is a reparse point (refused)");
    }
    if !meta.is_file() {
        bail!("authorized_keys is not a regular file");
    }
    if meta.len() > MAX_AUTHORIZED_KEYS_BYTES {
        bail!("authorized_keys exceeds 1 MiB limit");
    }

    verify_owner_sid(file.as_raw_handle() as HANDLE, user, is_custom_file)?;

    let mut contents = String::new();
    let mut reader = file.take(MAX_AUTHORIZED_KEYS_BYTES + 1);
    reader.read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_AUTHORIZED_KEYS_BYTES {
        bail!("authorized_keys exceeds 1 MiB limit");
    }
    Ok(Some(contents))
}

fn verify_owner_sid(handle: HANDLE, user: &OsUser, is_custom_file: bool) -> Result<()> {
    struct SdGuard(*mut c_void);
    impl Drop for SdGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }

    let mut owner_sid: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut sd: *mut c_void = null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner_sid,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        bail!("GetSecurityInfo failed with Win32 error {rc}");
    }
    let _sd_guard = SdGuard(sd);

    let trusted = unsafe {
        let is_system = IsWellKnownSid(owner_sid, WinLocalSystemSid) != FALSE;
        let is_admins = IsWellKnownSid(owner_sid, WinBuiltinAdministratorsSid) != FALSE;
        let is_user = EqualSid(owner_sid, user.sid_bytes.as_ptr() as PSID) != FALSE;

        if is_custom_file {
            if user.is_admin {
                is_system || is_admins
            } else {
                is_user
            }
        } else {
            is_system || is_admins || (!user.is_admin && is_user)
        }
    };

    if !trusted {
        bail!("authorized_keys owner SID is not trusted");
    }

    if dacl.is_null() {
        bail!("authorized_keys has NULL DACL (unrestricted write access)");
    }
    let acl = unsafe { &*dacl };
    for i in 0..acl.AceCount {
        let mut ace_ptr: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, i as u32, &mut ace_ptr) } == FALSE {
            bail!("GetAce failed to inspect DACL entry index {i}");
        }
        let ace_header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
        const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
        const ACCESS_DENIED_ACE_TYPE: u8 = 1;
        const SYSTEM_MANDATORY_LABEL_ACE_TYPE: u8 = 17;
        const INHERIT_ONLY_ACE: u8 = 0x08;

        match ace_header.AceType {
            ACCESS_ALLOWED_ACE_TYPE => {
                if (ace_header.AceFlags & INHERIT_ONLY_ACE) != 0 {
                    continue;
                }
                let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
                const WRITE_PERMS: u32 = 0x0002 // FILE_WRITE_DATA / FILE_ADD_FILE
                    | 0x0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
                    | 0x0010 // FILE_WRITE_EA
                    | 0x0040 // FILE_DELETE_CHILD
                    | 0x0100 // FILE_WRITE_ATTRIBUTES
                    | 0x00010000 // DELETE
                    | 0x00040000 // WRITE_DAC
                    | 0x00080000 // WRITE_OWNER
                    | 0x40000000 // GENERIC_WRITE
                    | 0x10000000; // GENERIC_ALL

                if (ace.Mask & WRITE_PERMS) != 0 {
                    let ace_sid = std::ptr::addr_of!(ace.SidStart) as PSID;
                    let ace_trusted = unsafe {
                        IsWellKnownSid(ace_sid, WinLocalSystemSid) != FALSE
                            || IsWellKnownSid(ace_sid, WinBuiltinAdministratorsSid) != FALSE
                            || EqualSid(ace_sid, user.sid_bytes.as_ptr() as PSID) != FALSE
                    };
                    if !ace_trusted {
                        bail!("authorized_keys DACL grants write access to untrusted principal");
                    }
                }
            }
            ACCESS_DENIED_ACE_TYPE | SYSTEM_MANDATORY_LABEL_ACE_TYPE => {}
            other => {
                // Reject conditional callback ACEs (e.g. ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 9),
                // compound ACEs, or object ACEs fail-closed.
                bail!("authorized_keys DACL contains non-standard ACE type {other}");
            }
        }
    }

    Ok(())
}

pub fn spawn_exec(user: &OsUser, command: &str) -> Result<SpawnedChild> {
    let comspec = std::env::var_os("ComSpec")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\cmd.exe"));
    let cmdline = format!("\"{}\" /C {}", comspec.display(), command);
    spawn_as_user(user, Some(&comspec), &cmdline)
}

pub fn spawn_internal_sftp(user: &OsUser) -> Result<SpawnedChild> {
    let exe = current_exe_path()?;
    let cmdline = format!("\"{}\" --internal-sftp", exe.display());
    spawn_as_user(user, Some(&exe), &cmdline)
}

/// Obtain a kernel primary access token for `user` without a password using
/// LSA S4U2Self (`MSV1_0_S4U_LOGON`), then spawn via `CreateProcessAsUserW`.
///
/// Requires the daemon service to run as `NT AUTHORITY\SYSTEM` (matching
/// OpenSSH-Win32). Strictly fail-closed: never falls back to SYSTEM.
fn spawn_as_user(user: &OsUser, application: Option<&Path>, cmdline: &str) -> Result<SpawnedChild> {
    let primary_token = acquire_s4u_primary_token(user)
        .context("strict Windows S4U2Self user token acquisition failed")?;

    let (stdin_child, stdin_parent) = create_pipe_pair(true)?;
    let (stdout_parent, stdout_child) = create_pipe_pair(false)?;
    let (stderr_parent, stderr_child) = create_pipe_pair(false)?;

    let mut env_block: *mut c_void = null_mut();
    unsafe {
        if CreateEnvironmentBlock(
            &mut env_block,
            primary_token.as_raw_handle() as HANDLE,
            FALSE,
        ) == FALSE
        {
            env_block = null_mut();
        }
    }

    let app_wide = application.map(to_wide);
    let mut cmd_wide = to_wide(cmdline);
    let cwd_wide = to_wide(&user.home);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = stdin_child.as_raw_handle() as HANDLE;
    si.hStdOutput = stdout_child.as_raw_handle() as HANDLE;
    si.hStdError = stderr_child.as_raw_handle() as HANDLE;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let flags = CREATE_NO_WINDOW
        | if env_block.is_null() {
            0
        } else {
            CREATE_UNICODE_ENVIRONMENT
        };

    let created = unsafe {
        CreateProcessAsUserW(
            primary_token.as_raw_handle() as HANDLE,
            app_wide.as_ref().map_or(null(), |v| v.as_ptr()),
            cmd_wide.as_mut_ptr(),
            null(),
            null(),
            TRUE,
            flags,
            env_block,
            cwd_wide.as_ptr(),
            &si,
            &mut pi,
        )
    };

    if !env_block.is_null() {
        unsafe { DestroyEnvironmentBlock(env_block) };
    }
    // Close child pipe ends & token handle in parent immediately.
    drop(stdin_child);
    drop(stdout_child);
    drop(stderr_child);
    drop(primary_token);

    if created == FALSE {
        let err = unsafe { GetLastError() };
        bail!("CreateProcessAsUserW failed with Win32 error {err}");
    }

    unsafe { CloseHandle(pi.hThread) };
    let proc_handle = unsafe { OwnedHandle::from_raw_handle(pi.hProcess as _) };

    let stdin_file = tokio::fs::File::from_std(std::fs::File::from(stdin_parent));
    let stdout_file = tokio::fs::File::from_std(std::fs::File::from(stdout_parent));
    let stderr_file = tokio::fs::File::from_std(std::fs::File::from(stderr_parent));

    let wait_fn = Box::pin(async move {
        tokio::task::spawn_blocking(move || unsafe {
            let h = proc_handle.as_raw_handle() as HANDLE;
            WaitForSingleObject(h, INFINITE);
            let mut code: u32 = 1;
            GetExitCodeProcess(h, &mut code);
            code
        })
        .await
        .unwrap_or(1)
    });

    Ok(SpawnedChild::new(
        Box::pin(stdin_file),
        Box::pin(stdout_file),
        Box::pin(stderr_file),
        wait_fn,
    ))
}

/// Passwordless OS logon via LSA S4U2Self (`MSV1_0_S4U_LOGON`), returning a
/// primary `HANDLE` token suitable for `CreateProcessAsUserW`.
fn acquire_s4u_primary_token(user: &OsUser) -> Result<OwnedHandle> {
    let mut lsa_handle: HANDLE = null_mut();
    let mut mode: u32 = 0;

    let proc_name = b"vsock-sshd";
    let lsa_proc = LSA_STRING {
        Length: proc_name.len() as u16,
        MaximumLength: proc_name.len() as u16,
        Buffer: proc_name.as_ptr() as *mut _,
    };

    let status: NTSTATUS =
        unsafe { LsaRegisterLogonProcess(&lsa_proc, &mut lsa_handle, &mut mode) };
    if status != 0 {
        // Fallback when TCB is held via service context without interactive logon registration.
        let status2 = unsafe { LsaConnectUntrusted(&mut lsa_handle) };
        if status2 != 0 {
            bail!("LsaRegisterLogonProcess/LsaConnectUntrusted failed: NTSTATUS 0x{status:08X}");
        }
    }

    let pkg_name = b"MICROSOFT_AUTHENTICATION_PACKAGE_V1_0";
    let lsa_pkg = LSA_STRING {
        Length: pkg_name.len() as u16,
        MaximumLength: pkg_name.len() as u16,
        Buffer: pkg_name.as_ptr() as *mut _,
    };

    let mut auth_pkg: u32 = 0;
    let status = unsafe { LsaLookupAuthenticationPackage(lsa_handle, &lsa_pkg, &mut auth_pkg) };
    if status != 0 {
        unsafe { LsaDeregisterLogonProcess(lsa_handle) };
        bail!("LsaLookupAuthenticationPackage failed: NTSTATUS 0x{status:08X}");
    }

    // Pack MSV1_0_S4U_LOGON + trailing UTF-16 user & domain strings into one contiguous buffer.
    let upn_wide: Vec<u16> = OsStr::new(&user.username).encode_wide().collect();
    let dom_wide: Vec<u16> = OsStr::new(&user.domain).encode_wide().collect();
    let hdr_size = std::mem::size_of::<MSV1_0_S4U_LOGON>();
    let upn_bytes = upn_wide.len() * 2;
    let dom_bytes = dom_wide.len() * 2;

    let mut buf = vec![0u8; hdr_size + upn_bytes + dom_bytes];
    let base_ptr = buf.as_mut_ptr();
    unsafe {
        let upn_ptr = base_ptr.add(hdr_size) as *mut u16;
        let dom_ptr = base_ptr.add(hdr_size + upn_bytes) as *mut u16;
        std::ptr::copy_nonoverlapping(upn_wide.as_ptr(), upn_ptr, upn_wide.len());
        std::ptr::copy_nonoverlapping(dom_wide.as_ptr(), dom_ptr, dom_wide.len());

        let s4u = &mut *(base_ptr as *mut MSV1_0_S4U_LOGON);
        s4u.MessageType = MsV1_0S4ULogon;
        s4u.Flags = MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS;
        s4u.UserPrincipalName.Length = upn_bytes as u16;
        s4u.UserPrincipalName.MaximumLength = upn_bytes as u16;
        s4u.UserPrincipalName.Buffer = upn_ptr;
        s4u.DomainName.Length = dom_bytes as u16;
        s4u.DomainName.MaximumLength = dom_bytes as u16;
        s4u.DomainName.Buffer = dom_ptr;
    }

    let origin_name = b"vsock-sshd";
    let origin = LSA_STRING {
        Length: origin_name.len() as u16,
        MaximumLength: origin_name.len() as u16,
        Buffer: origin_name.as_ptr() as *mut _,
    };
    let token_source = TOKEN_SOURCE {
        SourceName: (*b"vsockssh").map(|b| b as i8),
        SourceIdentifier: LUID {
            LowPart: 1,
            HighPart: 0,
        },
    };

    let mut profile_buf: *mut c_void = null_mut();
    let mut profile_len: u32 = 0;
    let mut logon_id = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let mut raw_token: HANDLE = null_mut();
    let mut quotas: QUOTA_LIMITS = unsafe { std::mem::zeroed() };
    let mut sub_status: NTSTATUS = 0;

    let status = unsafe {
        LsaLogonUser(
            lsa_handle,
            &origin,
            SECURITY_LOGON_TYPE::Network,
            auth_pkg,
            buf.as_ptr().cast(),
            buf.len() as u32,
            null(),
            &token_source,
            &mut profile_buf,
            &mut profile_len,
            &mut logon_id,
            &mut raw_token,
            &mut quotas,
            &mut sub_status,
        )
    };

    if !profile_buf.is_null() {
        unsafe { LsaFreeReturnBuffer(profile_buf) };
    }
    unsafe { LsaDeregisterLogonProcess(lsa_handle) };

    if status != 0 {
        bail!(
            "LsaLogonUser(MSV1_0_S4U_LOGON) failed: NTSTATUS 0x{status:08X} (sub 0x{sub_status:08X})"
        );
    }

    // Duplicate into a primary token required by CreateProcessAsUserW.
    let mut primary: HANDLE = null_mut();
    let dup_ok: BOOL = unsafe {
        DuplicateTokenEx(
            raw_token,
            TOKEN_ALL_ACCESS,
            null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    };
    unsafe { CloseHandle(raw_token) };

    if dup_ok == FALSE || primary == INVALID_HANDLE_VALUE {
        bail!("DuplicateTokenEx failed with Win32 error {}", unsafe {
            GetLastError()
        });
    }

    Ok(unsafe { OwnedHandle::from_raw_handle(primary as _) })
}

/// Create an anonymous pipe where ONLY the child end is inheritable.
fn create_pipe_pair(child_is_read: bool) -> Result<(OwnedHandle, OwnedHandle)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let mut read_h: HANDLE = null_mut();
    let mut write_h: HANDLE = null_mut();
    if unsafe { CreatePipe(&mut read_h, &mut write_h, &sa, 0) } == FALSE {
        bail!("CreatePipe failed");
    }

    let parent_h = if child_is_read { write_h } else { read_h };
    if unsafe { SetHandleInformation(parent_h, HANDLE_FLAG_INHERIT, 0) } == FALSE {
        unsafe {
            CloseHandle(read_h);
            CloseHandle(write_h);
        }
        bail!("SetHandleInformation failed");
    }

    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read_h as _),
            OwnedHandle::from_raw_handle(write_h as _),
        )
    })
}

fn is_local_administrator(username: &str) -> bool {
    let wide = to_wide(username);
    let mut buf: *mut u8 = null_mut();
    let mut entries: u32 = 0;
    let mut total: u32 = 0;

    let rc = unsafe {
        NetUserGetLocalGroups(
            null(),
            wide.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut buf,
            MAX_PREFERRED_LENGTH,
            &mut entries,
            &mut total,
        )
    };
    if rc != 0 || buf.is_null() {
        return false;
    }

    let mut found = false;
    unsafe {
        let slice =
            std::slice::from_raw_parts(buf as *const LOCALGROUP_USERS_INFO_0, entries as usize);
        for item in slice {
            if !item.lgrui0_name.is_null() {
                let mut len = 0;
                while *item.lgrui0_name.add(len) != 0 {
                    len += 1;
                }
                let name = OsString::from_wide(std::slice::from_raw_parts(item.lgrui0_name, len))
                    .to_string_lossy()
                    .into_owned();
                if name.eq_ignore_ascii_case("Administrators") {
                    found = true;
                    break;
                }
            }
        }
        NetApiBufferFree(buf.cast());
    }
    found
}

fn lookup_profile_dir(sid_string: &str) -> Option<PathBuf> {
    let subkey = to_wide(format!(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid_string}"
    ));
    let value_name = to_wide("ProfileImagePath");

    let mut hkey: HKEY = null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.as_ptr(), 0, KEY_READ, &mut hkey) } != 0 {
        return None;
    }

    let mut buf = vec![0u16; 512];
    let mut byte_len = (buf.len() * 2) as u32;
    let rc = unsafe {
        RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            null_mut(),
            null_mut(),
            buf.as_mut_ptr().cast(),
            &mut byte_len,
        )
    };
    unsafe { RegCloseKey(hkey) };
    if rc != 0 {
        return None;
    }

    let mut expanded = vec![0u16; 1024];
    let n = unsafe {
        ExpandEnvironmentStringsW(buf.as_ptr(), expanded.as_mut_ptr(), expanded.len() as u32)
    };
    if n == 0 || n as usize > expanded.len() {
        return Some(PathBuf::from(from_wide_nul(&buf)));
    }
    Some(PathBuf::from(from_wide_nul(&expanded)))
}

fn sid_to_string(sid: PSID) -> Result<String> {
    let mut ptr: *mut u16 = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut ptr) } == FALSE || ptr.is_null() {
        bail!("ConvertSidToStringSidW failed");
    }
    let s = unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let res = OsString::from_wide(std::slice::from_raw_parts(ptr, len))
            .to_string_lossy()
            .into_owned();
        LocalFree(ptr.cast());
        res
    };
    Ok(s)
}

fn to_wide<S: AsRef<OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

fn from_wide_nul(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end])
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{
        AddAccessAllowedAce, AddAce, CreateWellKnownSid, InitializeAcl, WinWorldSid, ACL_REVISION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };

    const GENERIC_READ: u32 = 0x80000000;
    const GENERIC_ALL: u32 = 0x10000000;
    const FILE_WRITE_DATA: u32 = 0x0002;

    fn get_test_user() -> OsUser {
        let candidate = std::env::var("USERNAME")
            .ok()
            .or_else(|| std::env::var("USER").ok());
        if let Some(ref name) = candidate {
            if let Ok(Some(u)) = lookup_user(name) {
                return u;
            }
        }
        for fallback in &["runneradmin", "SYSTEM", "Administrator"] {
            if let Ok(Some(u)) = lookup_user(fallback) {
                return u;
            }
        }
        panic!("could not find a valid test user via USERNAME, runneradmin, or Administrator");
    }

    fn init_acl(buf: &mut [u32]) -> *mut ACL {
        let acl = buf.as_mut_ptr().cast::<ACL>();
        let ok = unsafe { InitializeAcl(acl, std::mem::size_of_val(buf) as u32, ACL_REVISION) };
        assert_ne!(ok, 0, "InitializeAcl failed");
        acl
    }

    fn set_protected_dacl(path: &Path, acl: *const ACL) {
        let wide = to_wide(path);
        let ret = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null_mut(),
            )
        };
        assert_eq!(
            ret, 0,
            "SetNamedSecurityInfoW failed with Win32 error {ret}"
        );
    }

    #[test]
    fn test_lookup_user_rejects_empty_and_nul() {
        assert!(lookup_user("").unwrap().is_none());
        assert!(lookup_user("user\0name").unwrap().is_none());
    }

    #[test]
    fn test_strict_authorized_keys_oversized_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("large_authorized_keys");
        let large_data = vec![b'A'; (MAX_AUTHORIZED_KEYS_BYTES + 10) as usize];
        std::fs::write(&file_path, large_data).unwrap();

        let user = get_test_user();
        let res = read_authorized_keys_strict(&user, Some(&file_path));
        assert!(res.is_err(), "oversized keys file must be rejected");
    }

    #[test]
    fn test_strict_custom_authorized_keys_valid_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("custom_authorized_keys");
        std::fs::write(&file_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();

        let user = get_test_user();
        let content = read_authorized_keys_strict(&user, Some(&file_path))
            .expect("reading valid custom authorized_keys must succeed")
            .expect("custom authorized_keys content must be Some");
        assert!(content.contains("test"));
    }

    #[test]
    fn test_strict_custom_authorized_keys_rejects_null_dacl() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("null_dacl_keys");
        std::fs::write(&file_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();

        set_protected_dacl(&file_path, null());

        let user = get_test_user();
        let res = read_authorized_keys_strict(&user, Some(&file_path));
        assert!(res.is_err(), "NULL DACL file must be rejected");
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("NULL DACL"),
            "expected NULL DACL error, got: {err_msg}"
        );
    }

    #[test]
    fn test_strict_custom_authorized_keys_trusted_dacl_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("trusted_dacl_keys");
        std::fs::write(&file_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();

        let user = get_test_user();
        let mut acl_buf = vec![0u32; 256];
        let acl = init_acl(&mut acl_buf);

        let add_ok = unsafe {
            AddAccessAllowedAce(
                acl,
                ACL_REVISION,
                GENERIC_ALL,
                user.sid_bytes.as_ptr() as PSID,
            )
        };
        assert_ne!(add_ok, 0, "AddAccessAllowedAce failed");

        set_protected_dacl(&file_path, acl);

        let content = read_authorized_keys_strict(&user, Some(&file_path))
            .expect("reading custom authorized_keys with trusted DACL must succeed")
            .expect("content must be Some");
        assert!(content.contains("test"));
    }

    fn set_untrusted_world_write_dacl(path: &Path, user: &OsUser) {
        let mut world_sid = [0u8; 68];
        let mut sid_size = world_sid.len() as u32;
        let sid_ok = unsafe {
            CreateWellKnownSid(
                WinWorldSid,
                null_mut(),
                world_sid.as_mut_ptr() as PSID,
                &mut sid_size,
            )
        };
        assert_ne!(sid_ok, 0, "CreateWellKnownSid for WorldSid failed");

        let mut acl_buf = vec![0u32; 256];
        let acl = init_acl(&mut acl_buf);

        // Ensure the trusted user can open the object so DACL inspection runs
        let add_user_ok = unsafe {
            AddAccessAllowedAce(
                acl,
                ACL_REVISION,
                GENERIC_READ,
                user.sid_bytes.as_ptr() as PSID,
            )
        };
        assert_ne!(add_user_ok, 0, "AddAccessAllowedAce for user failed");

        let add_world_ok = unsafe {
            AddAccessAllowedAce(
                acl,
                ACL_REVISION,
                FILE_WRITE_DATA,
                world_sid.as_ptr() as PSID,
            )
        };
        assert_ne!(add_world_ok, 0, "AddAccessAllowedAce for World failed");

        set_protected_dacl(path, acl);
    }

    #[test]
    fn test_strict_custom_authorized_keys_rejects_untrusted_write_ace() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("untrusted_write_keys");
        std::fs::write(&file_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();

        let user = get_test_user();
        set_untrusted_world_write_dacl(&file_path, &user);

        let res = read_authorized_keys_strict(&user, Some(&file_path));
        assert!(res.is_err(), "untrusted write ACE must be rejected");
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("grants write access to untrusted principal"),
            "expected untrusted principal write error, got: {err_msg}"
        );
    }

    #[test]
    fn test_strict_custom_authorized_keys_directory_mode_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_path = tmp.path().join("keys_dir");
        std::fs::create_dir(&dir_path).unwrap();
        let user = get_test_user();
        let user_file = dir_path.join(&user.username);
        std::fs::write(&user_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA dirtest\n").unwrap();

        let content = read_authorized_keys_strict(&user, Some(&dir_path))
            .expect("reading valid directory-mode authorized_keys must succeed")
            .expect("directory-mode authorized_keys content must be Some");
        assert!(content.contains("dirtest"));
    }

    #[test]
    fn test_strict_custom_authorized_keys_directory_mode_rejects_untrusted_write_ace_on_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_path = tmp.path().join("keys_dir_untrusted_file");
        std::fs::create_dir(&dir_path).unwrap();
        let user = get_test_user();
        let user_file = dir_path.join(&user.username);
        std::fs::write(&user_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA dirtest\n").unwrap();

        set_untrusted_world_write_dacl(&user_file, &user);

        let res = read_authorized_keys_strict(&user, Some(&dir_path));
        assert!(
            res.is_err(),
            "directory-resolved file with untrusted write ACE must be rejected"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("grants write access to untrusted principal"),
            "expected untrusted principal write error, got: {err_msg}"
        );
    }

    #[test]
    fn test_strict_custom_authorized_keys_directory_mode_rejects_untrusted_write_ace_on_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir_path = tmp.path().join("keys_dir_untrusted_dir");
        std::fs::create_dir(&dir_path).unwrap();
        let user = get_test_user();
        let user_file = dir_path.join(&user.username);
        std::fs::write(&user_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA dirtest\n").unwrap();

        set_untrusted_world_write_dacl(&dir_path, &user);

        let res = read_authorized_keys_strict(&user, Some(&dir_path));
        assert!(
            res.is_err(),
            "directory with untrusted write ACE must be rejected"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("grants write access to untrusted principal"),
            "expected untrusted principal write error, got: {err_msg}"
        );
    }

    #[test]
    fn test_strict_custom_authorized_keys_rejects_callback_ace() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("callback_ace_keys");
        std::fs::write(&file_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();

        let user = get_test_user();
        let mut acl_buf = vec![0u32; 256];
        let acl = init_acl(&mut acl_buf);

        // Ensure the trusted user can open the file so DACL inspection runs
        let add_user_ok = unsafe {
            AddAccessAllowedAce(
                acl,
                ACL_REVISION,
                GENERIC_READ,
                user.sid_bytes.as_ptr() as PSID,
            )
        };
        assert_ne!(add_user_ok, 0, "AddAccessAllowedAce for user failed");

        // Append a callback ACE (ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 9)
        const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
        let sid_len = user.sid_bytes.len();
        let ace_bytes =
            (std::mem::size_of::<ACE_HEADER>() + std::mem::size_of::<u32>() + sid_len + 3) & !3;
        let mut ace_words = vec![0u32; ace_bytes / 4];
        let header = ace_words.as_mut_ptr().cast::<ACE_HEADER>();
        unsafe {
            (*header).AceType = ACCESS_ALLOWED_CALLBACK_ACE_TYPE;
            (*header).AceFlags = 0;
            (*header).AceSize = ace_bytes as u16;
            ace_words[1] = FILE_WRITE_DATA;
            std::ptr::copy_nonoverlapping(
                user.sid_bytes.as_ptr(),
                ace_words.as_mut_ptr().add(2).cast::<u8>(),
                sid_len,
            );
        }

        let add_cb_ok = unsafe {
            AddAce(
                acl,
                ACL_REVISION,
                u32::MAX,
                ace_words.as_ptr().cast(),
                ace_bytes as u32,
            )
        };
        assert_ne!(add_cb_ok, 0, "AddAce failed");

        set_protected_dacl(&file_path, acl);

        let res = read_authorized_keys_strict(&user, Some(&file_path));
        assert!(res.is_err(), "callback ACE must be rejected fail-closed");
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("contains non-standard ACE type 9"),
            "expected non-standard ACE type error, got: {err_msg}"
        );
    }

    #[test]
    fn test_strict_custom_authorized_keys_rejects_untrusted_parent_dir_dacl() {
        let tmp = tempfile::tempdir().unwrap();
        let sub_dir = tmp.path().join("untrusted_parent");
        std::fs::create_dir(&sub_dir).unwrap();
        let file_path = sub_dir.join("custom_keys");
        std::fs::write(&file_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();

        let user = get_test_user();
        set_untrusted_world_write_dacl(&sub_dir, &user);

        let res = read_authorized_keys_strict(&user, Some(&file_path));
        assert!(
            res.is_err(),
            "file under parent dir with untrusted write ACE must be rejected"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("grants write access to untrusted principal"),
            "expected untrusted principal write error, got: {err_msg}"
        );
    }

    #[test]
    fn test_strict_custom_authorized_keys_rejects_intermediate_reparse_point() {
        let tmp = tempfile::tempdir().unwrap();
        let real_dir = tmp.path().join("real_root");
        let sub_dir = real_dir.join("sub");
        std::fs::create_dir_all(&sub_dir).unwrap();

        let user = get_test_user();
        let user_file = sub_dir.join(&user.username);
        let custom_file = sub_dir.join("custom_keys");
        std::fs::write(&user_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA junc\n").unwrap();
        std::fs::write(&custom_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA junc\n").unwrap();

        let junction_dir = tmp.path().join("junction_root");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction_dir)
            .arg(&real_dir)
            .status()
            .expect("invoke cmd mklink /J");
        assert!(status.success(), "mklink /J failed");

        let direct_res = read_authorized_keys_strict(&user, Some(&junction_dir));
        let dir_mode_res = read_authorized_keys_strict(&user, Some(&junction_dir.join("sub")));
        let file_mode_res =
            read_authorized_keys_strict(&user, Some(&junction_dir.join("sub").join("custom_keys")));

        let _ = std::fs::remove_dir(&junction_dir);

        assert!(direct_res.is_err(), "direct junction must be rejected");
        assert!(
            dir_mode_res.is_err(),
            "directory mode via intermediate junction must be rejected"
        );
        assert!(
            file_mode_res.is_err(),
            "file mode via intermediate junction must be rejected"
        );
    }

    #[test]
    fn test_strict_custom_authorized_keys_rejects_parent_dir_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let sub_dir = tmp.path().join("sub");
        std::fs::create_dir(&sub_dir).unwrap();
        let file_path = tmp.path().join("custom_keys");
        std::fs::write(&file_path, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();

        let user = get_test_user();
        let traversal_path = sub_dir.join("..").join("custom_keys");
        let res = read_authorized_keys_strict(&user, Some(&traversal_path));
        assert!(res.is_err(), "'..' traversal must be rejected");
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("parent directory traversal"),
            "expected traversal error, got: {err_msg}"
        );
    }
}
