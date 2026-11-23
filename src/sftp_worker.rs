//! Privilege-separated internal SFTP v3 worker (`vsock-sshd --internal-sftp`).
//!
//! Spawned by the privileged daemon strictly under the authenticated OS user's
//! credentials (Linux `initgroups` + `setresgid` + `setresuid` + `PR_SET_NO_NEW_PRIVS`;
//! Windows `LsaLogonUser(MSV1_0_S4U_LOGON)` + `CreateProcessAsUserW`).
//!
//! Delegates SFTP v3 wire framing and packet types to `russh-sftp` over raw
//! stdin/stdout so every filesystem call is strictly enforced by the OS kernel.

use std::collections::HashMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use russh_sftp::protocol::{
    Attrs, Data, File as SftpFile, FileAttributes, Handle, Name, OpenFlags, SftpHandle, Status,
    StatusCode, Version,
};
use russh_sftp::server::Handler;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::transport::StdioTransport;

struct TrackedStream<S> {
    inner: S,
    drop_notify: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<S> Drop for TrackedStream<S> {
    fn drop(&mut self) {
        if let Some(tx) = self.drop_notify.take() {
            let _ = tx.send(());
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrackedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrackedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const MAX_READ_LEN: usize = 256 * 1024;
const MAX_OPEN_HANDLES: usize = 256;
const MAX_READDIR_BATCH: usize = 64;

enum HandleEntry {
    File {
        file: File,
        path: PathBuf,
    },
    Dir {
        entries: Vec<(String, PathBuf)>,
        offset: usize,
    },
}

struct WorkerHandler {
    handles: HashMap<SftpHandle, HandleEntry>,
    next_handle: u64,
}

impl WorkerHandler {
    fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next_handle: 1,
        }
    }

    fn alloc_handle(&mut self) -> SftpHandle {
        let id = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1);
        format!("h{id:x}").into()
    }
}

/// Entry point for `vsock-sshd --internal-sftp` running as the impersonated OS user.
pub fn run() -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build SFTP worker runtime")?;

    rt.block_on(async {
        let stream = StdioTransport::from_stdio()
            .context("failed to initialize SFTP worker stdio stream")?;
        run_on_stream(stream).await;
        Ok(())
    })
}

/// Drive the SFTP v3 worker over any async stream (stdio in production, duplex in tests).
pub async fn run_on_stream<S>(stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tracked = TrackedStream {
        inner: stream,
        drop_notify: Some(tx),
    };
    russh_sftp::server::run(tracked, WorkerHandler::new()).await;
    let _ = rx.await;
}

impl Handler for WorkerHandler {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = resolve_sftp_path(&path);
        let canonical = fs::canonicalize(&target).unwrap_or(target);
        let sftp_path = to_sftp_path(&canonical);
        let attrs = fs::metadata(&canonical)
            .map(|m| metadata_to_attrs(&m))
            .unwrap_or_default();

        Ok(Name {
            id,
            files: vec![SftpFile::new(sftp_path, attrs)],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = fs::metadata(resolve_sftp_path(&path)).map_err(io_to_status)?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&meta),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let meta = fs::symlink_metadata(resolve_sftp_path(&path)).map_err(io_to_status)?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&meta),
        })
    }

    async fn fstat(&mut self, id: u32, handle: SftpHandle) -> Result<Attrs, Self::Error> {
        let Some(HandleEntry::File { file, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        let meta = file.metadata().map_err(io_to_status)?;
        Ok(Attrs {
            id,
            attrs: metadata_to_attrs(&meta),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        if self.handles.len() >= MAX_OPEN_HANDLES {
            return Err(StatusCode::Failure);
        }

        let path = resolve_sftp_path(&filename);
        let mut opts = OpenOptions::new();
        opts.read(pflags.contains(OpenFlags::READ));
        opts.write(pflags.contains(OpenFlags::WRITE));
        opts.append(pflags.contains(OpenFlags::APPEND));
        opts.truncate(pflags.contains(OpenFlags::TRUNCATE));
        if pflags.contains(OpenFlags::CREATE) {
            if pflags.contains(OpenFlags::EXCLUDE) {
                opts.create_new(true);
            } else {
                opts.create(true);
            }
        }

        let file = opts.open(&path).map_err(io_to_status)?;
        let handle = self.alloc_handle();
        self.handles
            .insert(handle.clone(), HandleEntry::File { file, path });

        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let Some(HandleEntry::File { file, .. }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };

        file.seek(SeekFrom::Start(offset)).map_err(io_to_status)?;
        let mut buf = vec![0u8; (len as usize).min(MAX_READ_LEN)];
        let n = file.read(&mut buf).map_err(io_to_status)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);

        Ok(Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: SftpHandle,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let Some(HandleEntry::File { file, .. }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };

        file.seek(SeekFrom::Start(offset)).map_err(io_to_status)?;
        file.write_all(&data).map_err(io_to_status)?;
        Ok(ok_status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        if self.handles.len() >= MAX_OPEN_HANDLES {
            return Err(StatusCode::Failure);
        }

        let rd = fs::read_dir(resolve_sftp_path(&path)).map_err(io_to_status)?;
        let entries = rd
            .flatten()
            .map(|item| (item.file_name().to_string_lossy().into_owned(), item.path()))
            .collect();

        let handle = self.alloc_handle();
        self.handles
            .insert(handle.clone(), HandleEntry::Dir { entries, offset: 0 });

        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: SftpHandle) -> Result<Name, Self::Error> {
        let Some(HandleEntry::Dir { entries, offset }) = self.handles.get_mut(&handle) else {
            return Err(StatusCode::Failure);
        };
        if *offset >= entries.len() {
            return Err(StatusCode::Eof);
        }

        let end = (*offset + MAX_READDIR_BATCH).min(entries.len());
        let files = entries[*offset..end]
            .iter()
            .map(|(name, full_path)| {
                let attrs = fs::symlink_metadata(full_path)
                    .map(|m| metadata_to_attrs(&m))
                    .unwrap_or_default();
                SftpFile::new(name.clone(), attrs)
            })
            .collect();
        *offset = end;

        Ok(Name { id, files })
    }

    async fn close(&mut self, id: u32, handle: SftpHandle) -> Result<Status, Self::Error> {
        self.handles
            .remove(&handle)
            .map(|_| ok_status(id))
            .ok_or(StatusCode::Failure)
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        fs::remove_file(resolve_sftp_path(&filename)).map_err(io_to_status)?;
        Ok(ok_status(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        fs::create_dir(resolve_sftp_path(&path)).map_err(io_to_status)?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        fs::remove_dir(resolve_sftp_path(&path)).map_err(io_to_status)?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        fs::rename(resolve_sftp_path(&oldpath), resolve_sftp_path(&newpath))
            .map_err(io_to_status)?;
        Ok(ok_status(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        apply_attrs(&resolve_sftp_path(&path), &attrs).map_err(io_to_status)?;
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: SftpHandle,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let Some(HandleEntry::File { path, .. }) = self.handles.get(&handle) else {
            return Err(StatusCode::Failure);
        };
        apply_attrs(path, &attrs).map_err(io_to_status)?;
        Ok(ok_status(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let dest = fs::read_link(resolve_sftp_path(&path)).map_err(io_to_status)?;
        Ok(Name {
            id,
            files: vec![SftpFile::new(
                to_sftp_path(&dest),
                FileAttributes::default(),
            )],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        let link = resolve_sftp_path(&linkpath);
        let target = resolve_sftp_path(&targetpath);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).map_err(io_to_status)?;
        #[cfg(windows)]
        if target.is_dir() {
            std::os::windows::fs::symlink_dir(&target, &link).map_err(io_to_status)?;
        } else {
            std::os::windows::fs::symlink_file(&target, &link).map_err(io_to_status)?;
        }
        Ok(ok_status(id))
    }
}

// ── Helpers & Cross-Platform Path / Metadata Mapping ─────────────────────────

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "OK".into(),
        language_tag: "en".into(),
    }
}

fn io_to_status(err: io::Error) -> StatusCode {
    match err.kind() {
        io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn apply_attrs(path: &Path, attrs: &FileAttributes) -> io::Result<()> {
    if let Some(size) = attrs.size {
        let f = OpenOptions::new().write(true).open(path)?;
        f.set_len(size)?;
    }
    if let Some(perms) = attrs.permissions {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(perms & 0o7777))?;
        }
        #[cfg(windows)]
        {
            let mut p = fs::metadata(path)?.permissions();
            p.set_readonly((perms & 0o200) == 0);
            fs::set_permissions(path, p)?;
        }
    }
    Ok(())
}

fn metadata_to_attrs(meta: &Metadata) -> FileAttributes {
    #[cfg(unix)]
    let (uid, gid, permissions) = {
        use std::os::unix::fs::MetadataExt;
        (Some(meta.uid()), Some(meta.gid()), Some(meta.mode()))
    };

    #[cfg(windows)]
    let (uid, gid, permissions) = {
        let mode = if meta.is_dir() {
            0o040_755
        } else if meta.permissions().readonly() {
            0o100_444
        } else {
            0o100_644
        };
        (Some(0), Some(0), Some(mode))
    };

    FileAttributes {
        size: Some(meta.len()),
        uid,
        user: None,
        gid,
        group: None,
        permissions,
        atime: Some(to_unix_secs(meta.accessed().ok())),
        mtime: Some(to_unix_secs(meta.modified().ok())),
    }
}

fn to_unix_secs(t: Option<SystemTime>) -> u32 {
    t.and_then(|v| v.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

fn resolve_sftp_path(raw: &str) -> PathBuf {
    if raw.is_empty() || raw == "." {
        return std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    }

    #[cfg(windows)]
    {
        // Translate OpenSSH SFTP Windows paths (`/C:/Users/...`) to native `C:\Users\...`.
        let b = raw.as_bytes();
        if b.len() >= 3 && b[0] == b'/' && b[1].is_ascii_alphabetic() && b[2] == b':' {
            PathBuf::from(raw[1..].replace('/', "\\"))
        } else {
            PathBuf::from(raw.replace('/', "\\"))
        }
    }

    #[cfg(unix)]
    {
        PathBuf::from(raw)
    }
}

fn to_sftp_path(path: &Path) -> String {
    #[cfg(windows)]
    {
        let s = path.to_string_lossy().replace('\\', "/");
        let stripped = s.strip_prefix("//?/").unwrap_or(&s);
        if stripped.len() >= 2 && stripped.as_bytes()[1] == b':' {
            return format!("/{stripped}");
        }
        stripped.to_owned()
    }

    #[cfg(unix)]
    {
        path.to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_io_errors_to_sftp_status_codes() {
        assert_eq!(
            io_to_status(io::Error::new(io::ErrorKind::NotFound, "missing")),
            StatusCode::NoSuchFile
        );
        assert_eq!(
            io_to_status(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
            StatusCode::PermissionDenied
        );
        assert_eq!(io_to_status(io::Error::other("boom")), StatusCode::Failure);
    }

    #[test]
    fn resolves_dot_and_empty_to_cwd() {
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(resolve_sftp_path(""), cwd);
        assert_eq!(resolve_sftp_path("."), cwd);
    }

    #[cfg(windows)]
    #[test]
    fn translates_windows_sftp_drive_paths() {
        assert_eq!(
            resolve_sftp_path("/C:/Users/alice/file.txt"),
            PathBuf::from(r"C:\Users\alice\file.txt")
        );
        assert_eq!(
            to_sftp_path(Path::new(r"\\?\C:\Users\alice")),
            "/C:/Users/alice"
        );
    }

    #[tokio::test]
    async fn enforces_max_open_handles_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("sample.txt");
        fs::write(&file_path, b"abc").unwrap();
        let path_str = file_path.to_string_lossy().into_owned();

        let mut handler = WorkerHandler::new();
        for id in 0..MAX_OPEN_HANDLES {
            handler
                .open(
                    id as u32,
                    path_str.clone(),
                    OpenFlags::READ,
                    FileAttributes::default(),
                )
                .await
                .expect("open within cap");
        }

        let err = handler
            .open(999, path_str, OpenFlags::READ, FileAttributes::default())
            .await
            .expect_err("must reject beyond MAX_OPEN_HANDLES");
        assert_eq!(err, StatusCode::Failure);
    }
}
