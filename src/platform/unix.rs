use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
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

fn open_dir_no_symlinks(path: &Path) -> Result<File> {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        bail!("parent directory traversal ('..') is not permitted in authorized_keys paths");
    }

    let mut components = path.components().peekable();
    let mut current_file = match components.peek() {
        Some(std::path::Component::RootDir) => {
            components.next();
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open("/")
                .context("failed to open root directory")?
        }
        _ => OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(".")
            .context("failed to open current working directory")?,
    };

    for comp in components {
        match comp {
            std::path::Component::Normal(name) => {
                let c_name =
                    CString::new(name.as_bytes()).context("invalid directory component in path")?;
                let next_fd = unsafe {
                    libc::openat(
                        current_file.as_raw_fd(),
                        c_name.as_ptr(),
                        libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if next_fd < 0 {
                    return Err(io::Error::last_os_error()).with_context(|| {
                        format!(
                            "failed to open directory component '{}'",
                            name.to_string_lossy()
                        )
                    });
                }
                current_file = unsafe { File::from_raw_fd(next_fd) };
            }
            std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                bail!(
                    "parent directory traversal ('..') is not permitted in authorized_keys paths"
                );
            }
            _ => {}
        }
    }
    Ok(current_file)
}

fn verify_dir_strict(path: &Path, expected_uid: u32) -> Result<File> {
    let dir = open_dir_no_symlinks(path)?;

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if st.st_uid != expected_uid && st.st_uid != 0 {
        bail!(
            "directory {} has untrusted owner uid {} (expected 0 or {})",
            path.display(),
            st.st_uid,
            expected_uid
        );
    }
    if (st.st_mode & 0o022) != 0 {
        bail!(
            "directory {} is group- or world-writable ({:o})",
            path.display(),
            st.st_mode & 0o777
        );
    }
    Ok(dir)
}

/// Open and validate authorized_keys enforcing OpenSSH StrictModes:
/// - Directory and authorized_keys file must be owned by `user.uid` or root (`0`).
/// - Standalone custom files must be owned by `user.uid` (or root for root) to preserve user isolation.
/// - None may be group- or world-writable (`mode & 0o022 == 0`).
/// - `authorized_keys` is opened with `O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC` to prevent symlink traversal and FIFO hangs.
/// - File must be a regular file, size capped at 1 MiB.
pub fn read_authorized_keys_strict(
    user: &OsUser,
    custom_path: Option<&Path>,
) -> Result<Option<String>> {
    let (dir_file, file_name, is_custom_file) = match custom_path {
        Some(p) => {
            let is_dir = match std::fs::symlink_metadata(p) {
                Ok(m) if m.file_type().is_symlink() => {
                    bail!("authorized_keys path {} is a symlink", p.display());
                }
                Ok(m) => m.is_dir(),
                Err(err) if err.kind() == io::ErrorKind::NotFound => false,
                Err(err) => return Err(err.into()),
            };
            if is_dir {
                let dir_file = verify_dir_strict(p, user.uid)?;
                let name = CString::new(user.username.as_bytes())
                    .context("invalid username for authorized_keys lookup")?;
                (dir_file, name, false)
            } else {
                let parent = p.parent().unwrap_or_else(|| Path::new("."));
                let parent_dir = if parent.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    parent
                };
                let parent_file = verify_dir_strict(parent_dir, user.uid)?;
                let file_name = p
                    .file_name()
                    .context("invalid custom authorized_keys file path")?;
                let name = CString::new(file_name.as_bytes())
                    .context("invalid custom authorized_keys file name")?;
                (parent_file, name, true)
            }
        }
        None => {
            let _ = verify_dir_strict(&user.home, user.uid)?;
            let ssh_dir = user.home.join(".ssh");
            if !ssh_dir.exists() {
                return Ok(None);
            }
            let ssh_dir_file = verify_dir_strict(&ssh_dir, user.uid)?;
            let name = CString::new("authorized_keys").unwrap();
            (ssh_dir_file, name, false)
        }
    };

    let fd = unsafe {
        libc::openat(
            dir_file.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(err.into());
    }
    let file = unsafe { File::from_raw_fd(fd) };

    let meta = file.metadata()?;
    if !meta.is_file() {
        bail!("authorized_keys is not a regular file");
    }

    let trusted_owner = if is_custom_file {
        if user.uid == 0 {
            meta.uid() == 0
        } else {
            meta.uid() == user.uid
        }
    } else {
        meta.uid() == user.uid || meta.uid() == 0
    };
    if !trusted_owner {
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
    let mut reader = file.take(MAX_AUTHORIZED_KEYS_BYTES + 1);
    reader.read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_AUTHORIZED_KEYS_BYTES {
        bail!("authorized_keys exceeds 1 MiB limit");
    }
    Ok(Some(contents))
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
            // Only root can change supplementary groups via initgroups.
            if libc::geteuid() == 0 && libc::initgroups(c_user.as_ptr(), gid as libc::gid_t) != 0 {
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
        assert_eq!(read_authorized_keys_strict(&user, None).unwrap(), None);

        let ssh_dir = home.join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let key_file = ssh_dir.join("authorized_keys");
        std::fs::write(&key_file, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test\n").unwrap();
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        // Valid 0700/0700/0600 passes
        let content = read_authorized_keys_strict(&user, None).unwrap().unwrap();
        assert!(content.contains("ssh-ed25519"));

        // Group-writable authorized_keys must be rejected
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(read_authorized_keys_strict(&user, None).is_err());

        // Restore key_file, make .ssh group-writable -> must be rejected
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read_authorized_keys_strict(&user, None).is_err());

        // Symlinked authorized_keys must be rejected via O_NOFOLLOW
        std::fs::set_permissions(&ssh_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let target = home.join("other_keys");
        std::fs::write(&target, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA symlink\n").unwrap();
        std::fs::remove_file(&key_file).unwrap();
        symlink(&target, &key_file).unwrap();
        assert!(read_authorized_keys_strict(&user, None).is_err());
    }

    #[test]
    fn strict_custom_authorized_keys_validation_and_isolation() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        let user = current_test_user(dir.clone());
        let custom_file = dir.join("custom_keys");

        // 1. Valid custom file passes
        std::fs::write(
            &custom_file,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA custom\n",
        )
        .unwrap();
        std::fs::set_permissions(&custom_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let content = read_authorized_keys_strict(&user, Some(&custom_file))
            .unwrap()
            .unwrap();
        assert!(content.contains("custom"));

        // 2. Group/world-writable custom file rejected
        std::fs::set_permissions(&custom_file, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_authorized_keys_strict(&user, Some(&custom_file)).is_err());
        std::fs::set_permissions(&custom_file, std::fs::Permissions::from_mode(0o600)).unwrap();

        // 3. Group/world-writable parent dir rejected
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_authorized_keys_strict(&user, Some(&custom_file)).is_err());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // 4. Symlink custom file rejected
        let sym_file = dir.join("sym_keys");
        symlink(&custom_file, &sym_file).unwrap();
        assert!(read_authorized_keys_strict(&user, Some(&sym_file)).is_err());

        // 5. User isolation: other user cannot use this custom file
        let other_user = OsUser {
            username: "otheruser".into(),
            uid: user.uid + 1,
            gid: user.gid + 1,
            home: dir.clone(),
            shell: PathBuf::from("/bin/sh"),
        };
        assert!(read_authorized_keys_strict(&other_user, Some(&custom_file)).is_err());

        // 6. Directory mode: looks up <dir>/<username>
        let per_user_file = dir.join(&user.username);
        std::fs::write(
            &per_user_file,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA per_user\n",
        )
        .unwrap();
        std::fs::set_permissions(&per_user_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let per_user_content = read_authorized_keys_strict(&user, Some(&dir))
            .unwrap()
            .unwrap();
        assert!(per_user_content.contains("per_user"));

        // 7. Oversized file (> 1 MiB) rejected
        let large_file = dir.join("large_keys");
        let large_data = vec![b'A'; (MAX_AUTHORIZED_KEYS_BYTES + 10) as usize];
        std::fs::write(&large_file, large_data).unwrap();
        std::fs::set_permissions(&large_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_authorized_keys_strict(&user, Some(&large_file)).is_err());

        // 8. Symlinked custom directory rejected
        let sym_dir = tmp.path().join("sym_dir");
        symlink(&dir, &sym_dir).unwrap();
        assert!(read_authorized_keys_strict(&user, Some(&sym_dir)).is_err());

        // 9. Intermediate symlink component rejected in both directory and file modes
        let nested_dir = dir.join("nested");
        std::fs::create_dir(&nested_dir).unwrap();
        std::fs::set_permissions(&nested_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let nested_user_file = nested_dir.join(&user.username);
        std::fs::write(
            &nested_user_file,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA nested\n",
        )
        .unwrap();
        std::fs::set_permissions(&nested_user_file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let sym_nested_dir = sym_dir.join("nested");
        assert!(read_authorized_keys_strict(&user, Some(&sym_nested_dir)).is_err());
        assert!(
            read_authorized_keys_strict(&user, Some(&sym_nested_dir.join(&user.username))).is_err()
        );

        // 10. Parent directory traversal ('..') rejected
        assert!(read_authorized_keys_strict(
            &user,
            Some(&nested_dir.join("..").join("custom_keys"))
        )
        .is_err());

        // 11. Pinned directory descriptor prevents TOCTOU directory replacement:
        // replacing the path after verify_dir_strict still resolves inside the original inode.
        let pinned_dir = verify_dir_strict(&nested_dir, user.uid).unwrap();
        let moved_dir = dir.join("nested_moved");
        std::fs::rename(&nested_dir, &moved_dir).unwrap();
        std::fs::create_dir(&nested_dir).unwrap();
        std::fs::set_permissions(&nested_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let replaced_file = nested_dir.join(&user.username);
        std::fs::write(
            &replaced_file,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA attacker\n",
        )
        .unwrap();
        let c_name = CString::new(user.username.as_bytes()).unwrap();
        let fd = unsafe {
            libc::openat(
                pinned_dir.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0);
        let mut pinned_content = String::new();
        unsafe { File::from_raw_fd(fd) }
            .read_to_string(&mut pinned_content)
            .unwrap();
        assert!(pinned_content.contains("nested"));
        assert!(!pinned_content.contains("attacker"));
    }

    #[test]
    fn write_host_key_strict_sets_0700_dir_and_0600_file() {
        let tmp = tempfile::tempdir().unwrap();
        let key_path = tmp.path().join("keys").join("ssh_host_ed25519_key");
        write_host_key_strict(&key_path, b"dummy-host-key").unwrap();

        let dir_mode = std::fs::metadata(key_path.parent().unwrap())
            .unwrap()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(&key_path).unwrap().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }
}
