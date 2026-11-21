use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::process::Command;

use super::{current_exe_path, SpawnedChild};

const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1024 * 1024;
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[derive(Clone, Debug)]
pub struct OsUser {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
    pub shell: PathBuf,
}

pub fn default_host_key_path() -> PathBuf {
    PathBuf::from("/etc/vsock-sshd/ssh_host_ed25519_key")
}

pub fn write_host_key_strict(path: &Path, pem: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(pem)?;
    file.sync_all()?;
    Ok(())
}

/// Thread-safe lookup against system NSS / `/etc/passwd` via `getpwnam_r`.
pub fn lookup_user(username: &str) -> Result<Option<OsUser>> {
    if username.is_empty() || username.contains('\0') {
        return Ok(None);
    }

    let c_name = CString::new(username)?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 4096];

    loop {
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < 65_536 {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc).into());
        }
        break;
    }

    if result.is_null() {
        return Ok(None);
    }

    let home = unsafe { CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    let shell = unsafe { CStr::from_ptr(pwd.pw_shell) }
        .to_string_lossy()
        .into_owned();

    // Refuse accounts explicitly locked out via nologin/false shells.
    if matches!(
        shell.as_str(),
        "/sbin/nologin" | "/usr/sbin/nologin" | "/bin/false" | "/usr/bin/false"
    ) {
        return Ok(None);
    }

    Ok(Some(OsUser {
        username: username.to_owned(),
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: PathBuf::from(home),
        shell: if shell.is_empty() {
            PathBuf::from("/bin/sh")
        } else {
            PathBuf::from(shell)
        },
    }))
}

/// Open and validate `<home>/.ssh/authorized_keys` enforcing OpenSSH StrictModes:
/// - `home`, `.ssh`, and `authorized_keys` must be owned by `user.uid` or root (`0`).
/// - None may be group- or world-writable (`mode & 0o022 == 0`).
/// - `authorized_keys` is opened with `O_NOFOLLOW | O_CLOEXEC` and verified via `fstat`.
pub fn read_authorized_keys_strict(user: &OsUser) -> Result<Option<String>> {
    verify_dir_strict(&user.home, user.uid)?;

    let ssh_dir = user.home.join(".ssh");
    if !ssh_dir.exists() {
        return Ok(None);
    }
    verify_dir_strict(&ssh_dir, user.uid)?;

    let key_path = ssh_dir.join("authorized_keys");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&key_path)
    {
        Ok(f) => f,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("authorized_keys is not a regular file");
    }
    if meta.uid() != user.uid && meta.uid() != 0 {
        bail!("authorized_keys has untrusted owner uid {}", meta.uid());
    }
    if (meta.mode() & 0o022) != 0 {
        bail!(
            "authorized_keys has unsafe permissions {:o}",
            meta.mode() & 0o777
        );
    }
    if meta.len() > MAX_AUTHORIZED_KEYS_BYTES {
        bail!("authorized_keys exceeds 1 MiB limit");
    }

    let mut contents = String::new();
    let mut reader = File::from(file);
    reader.read_to_string(&mut contents)?;
    Ok(Some(contents))
}

fn verify_dir_strict(path: &Path, expected_uid: u32) -> Result<()> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if st.st_uid != expected_uid && st.st_uid != 0 {
        bail!("{} has untrusted owner uid {}", path.display(), st.st_uid);
    }
    if (st.st_mode & 0o022) != 0 {
        bail!(
            "{} is group- or world-writable ({:o})",
            path.display(),
            st.st_mode & 0o777
        );
    }
    Ok(())
}

pub fn spawn_exec(user: &OsUser, command: &str) -> Result<SpawnedChild> {
    spawn_impersonated(user, &user.shell, &["-c", command], false)
}

pub fn spawn_internal_sftp(user: &OsUser) -> Result<SpawnedChild> {
    let exe = current_exe_path()?;
    // Lock down the internal SFTP worker with PR_SET_NO_NEW_PRIVS.
    spawn_impersonated(user, &exe, &["--internal-sftp"], true)
}

/// Spawn a child process strictly impersonating `user`:
/// 1. `initgroups` (clears root supplementary groups and loads user groups)
/// 2. `setresgid` (permanently drops real, effective, saved GID)
/// 3. `setresuid` (permanently drops real, effective, saved UID)
/// 4. Optional `PR_SET_NO_NEW_PRIVS` (enabled for internal SFTP worker)
/// 5. Fail-closed post-drop credential verification before `execve`.
fn spawn_impersonated(
    user: &OsUser,
    program: &Path,
    args: &[&str],
    no_new_privs: bool,
) -> Result<SpawnedChild> {
    let c_user = CString::new(user.username.as_str())?;
    let uid = user.uid;
    let gid = user.gid;

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(&user.home)
        .env_clear()
        .env("HOME", &user.home)
        .env("USER", &user.username)
        .env("LOGNAME", &user.username)
        .env("SHELL", &user.shell)
        .env("PATH", DEFAULT_PATH);

    unsafe {
        cmd.pre_exec(move || {
            if libc::initgroups(c_user.as_ptr(), gid as libc::gid_t) != 0 {
                return Err(io::Error::last_os_error());
            }

            #[cfg(target_os = "linux")]
            {
                if libc::setresgid(gid, gid, gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setresuid(uid, uid, uid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if no_new_privs && libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                let _ = no_new_privs;
                if libc::setgid(gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(uid) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            // Fail-closed invariant check: child must never execute with residual privileges.
            if libc::getuid() != uid
                || libc::geteuid() != uid
                || libc::getgid() != gid
                || libc::getegid() != gid
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "credential drop verification failed",
                ));
            }

            Ok(())
        });
    }

    let mut child = cmd.spawn().with_context(|| {
        format!(
            "failed to spawn {} as {} (uid={})",
            program.display(),
            user.username,
            user.uid
        )
    })?;

    let stdin = child.stdin.take().context("missing child stdin")?;
    let stdout = child.stdout.take().context("missing child stdout")?;
    let stderr = child.stderr.take().context("missing child stderr")?;

    let wait_fn = Box::pin(async move {
        match child.wait().await {
            Ok(status) => status.code().unwrap_or(1) as u32,
            Err(_) => 1,
        }
    });

    Ok(SpawnedChild::new(
        Box::pin(stdin),
        Box::pin(stdout),
        Box::pin(stderr),
        wait_fn,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn current_test_user(home: PathBuf) -> OsUser {
        OsUser {
            username: "testuser".into(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            home,
            shell: PathBuf::from("/bin/sh"),
        }
    }

    #[test]
    fn lookup_user_rejects_empty_and_nul() {
        assert!(lookup_user("").unwrap().is_none());
        assert!(lookup_user("bad\0user").unwrap().is_none());
    }

    #[test]
    fn strict_authorized_keys_accepts_safe_modes_and_rejects_unsafe() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().to_path_buf();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();

        let user = current_test_user(home.clone());
        assert_eq!(read_authorized_keys_strict(&user).unwrap(), None);

        let ssh_dir = home.join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let key_file = ssh_dir.join("authorized_keys");
        std::fs::write(&key_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Valid 0700/0700/0600 passes
        let content = read_authorized_keys_strict(&user).unwrap().unwrap();
        assert!(content.contains("ssh-ed25519"));

        // Group-writable authorized_keys must be rejected
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(read_authorized_keys_strict(&user).is_err());

        // Restore key_file, make .ssh group-writable -> must be rejected
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read_authorized_keys_strict(&user).is_err());

        // Symlinked authorized_keys must be rejected via O_NOFOLLOW
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = home.join("other_keys");
        std::fs::write(&target, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA symlink\n").unwrap();
        std::fs::remove_file(&key_file).unwrap();
        symlink(&target, &key_file).unwrap();
        assert!(read_authorized_keys_strict(&user).is_err());
    }

    #[test]
    fn write_host_key_strict_sets_0700_dir_and_0600_file() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("keys").join("ssh_host_ed25519_key");
        write_host_key_strict(&key_path, b"dummy-host-key").unwrap();

        let dir_mode = std::fs::metadata(key_path.parent().unwrap()).unwrap().mode() & 0o777;
        let file_mode = std::fs::metadata(&key_path).unwrap().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
}

