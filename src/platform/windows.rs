use std::ffi::{c_void, OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, SetHandleInformation, BOOL, FALSE, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LUID, NTSTATUS, TRUE,
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
    DuplicateTokenEx, EqualSid, IsWellKnownSid, LookupAccountNameW, SecurityImpersonation,
    TokenPrimary, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION, PSID,
    QUOTA_LIMITS, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_ALL_ACCESS, TOKEN_SOURCE,
};
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
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

use super::{current_exe_path, SpawnedChild};

const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1024 * 1024;

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

/// OpenSSH-Win32 strict `authorized_keys` resolution:
/// - Administrators use `%ProgramData%\ssh\administrators_authorized_keys`
/// - Standard users use `<ProfileDir>\.ssh\authorized_keys`
///
/// Refuses reparse points (symlinks/junctions) and verifies file owner SID.
pub fn read_authorized_keys_strict(user: &OsUser) -> Result<Option<String>> {
    let key_path = if user.is_admin {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("ssh").join("administrators_authorized_keys")
    } else {
        user.home.join(".ssh").join("authorized_keys")
    };

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&key_path)
    {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("authorized_keys is not a regular file (reparse point refused)");
    }
    if meta.len() > MAX_AUTHORIZED_KEYS_BYTES {
        bail!("authorized_keys exceeds 1 MiB limit");
    }

    verify_owner_sid(file.as_raw_handle() as HANDLE, user)?;

    let mut contents = String::new();
    let mut reader = file;
    reader.read_to_string(&mut contents)?;
    Ok(Some(contents))
}

fn verify_owner_sid(handle: HANDLE, user: &OsUser) -> Result<()> {
    let mut owner_sid: PSID = null_mut();
    let mut sd: *mut c_void = null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner_sid,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    if rc != 0 {
        bail!("GetSecurityInfo failed with Win32 error {rc}");
    }

    let trusted = unsafe {
        let is_system = IsWellKnownSid(owner_sid, WinLocalSystemSid) != FALSE;
        let is_admins = IsWellKnownSid(owner_sid, WinBuiltinAdministratorsSid) != FALSE;
        let is_user =
            !user.is_admin && EqualSid(owner_sid, user.sid_bytes.as_ptr() as PSID) != FALSE;
        is_system || is_admins || is_user
    };

    if !sd.is_null() {
        unsafe { LocalFree(sd) };
    }

    if !trusted {
        bail!("authorized_keys owner SID is not trusted");
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
