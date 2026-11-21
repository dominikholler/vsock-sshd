use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, Stdin, Stdout};

/// Duplex async transport over stdin/stdout (inetd / `sshd -i` model).
///
/// On Linux with systemd (`StandardInput=socket`, `StandardOutput=socket`
/// on a `ListenStream=vsock::22` socket unit), fd 0 and fd 1 refer to the same
/// connected `AF_VSOCK` socket. Detecting `S_ISSOCK` and wrapping fd 0 in
/// `AsyncFd` avoids blocking threadpool reads and supports proper TCP/VSOCK
/// half-close (`shutdown(SHUT_WR)`).
///
/// On Windows (`sshd -i` mode) or Unix pipes, this wraps Tokio's stdin/stdout.
pub enum StdioTransport {
    #[cfg(unix)]
    UnixSocket(unix_socket::AsyncSocketFd),
    Pipes {
        stdin: Stdin,
        stdout: Stdout,
    },
}

impl StdioTransport {
    pub fn from_stdio() -> io::Result<Self> {
        #[cfg(unix)]
        {
            if let Some(sock) = unix_socket::try_from_stdin_socket()? {
                return Ok(Self::UnixSocket(sock));
            }
        }

        Ok(Self::Pipes {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        })
    }
}

impl AsyncRead for StdioTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::UnixSocket(sock) => Pin::new(sock).poll_read(cx, buf),
            Self::Pipes { stdin, .. } => Pin::new(stdin).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for StdioTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            #[cfg(unix)]
            Self::UnixSocket(sock) => Pin::new(sock).poll_write(cx, data),
            Self::Pipes { stdout, .. } => Pin::new(stdout).poll_write(cx, data),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::UnixSocket(sock) => Pin::new(sock).poll_flush(cx),
            Self::Pipes { stdout, .. } => Pin::new(stdout).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::UnixSocket(sock) => Pin::new(sock).poll_shutdown(cx),
            Self::Pipes { stdout, .. } => Pin::new(stdout).poll_shutdown(cx),
        }
    }
}

#[cfg(unix)]
mod unix_socket {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::unix::AsyncFd;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    pub struct AsyncSocketFd {
        inner: AsyncFd<OwnedFd>,
    }

    /// Detect if fd 0 is an inherited socket (e.g. systemd `AF_VSOCK` socket
    /// activation) and duplicate it into a non-blocking `AsyncFd`.
    pub fn try_from_stdin_socket() -> io::Result<Option<AsyncSocketFd>> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(libc::STDIN_FILENO, &mut st) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFSOCK {
            return Ok(None);
        }

        // Duplicate with CLOEXEC so spawned child processes never inherit the
        // raw SSH transport socket.
        let dup_fd: RawFd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if dup_fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let owned = unsafe { OwnedFd::from_raw_fd(dup_fd) };
        let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(Some(AsyncSocketFd {
            inner: unsafe { AsyncFd::register(owned)? },
        }))
    }

    impl AsyncRead for AsyncSocketFd {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            loop {
                let mut guard = match self.inner.poll_read_ready(cx) {
                    Poll::Ready(Ok(g)) => g,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };

                let dst = buf.initialize_unfilled();
                let res = unsafe {
                    libc::recv(
                        self.inner.as_raw_fd(),
                        dst.as_mut_ptr().cast(),
                        dst.len(),
                        0,
                    )
                };

                if res >= 0 {
                    buf.advance(res as usize);
                    return Poll::Ready(Ok(()));
                }

                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }
    }

    impl AsyncWrite for AsyncSocketFd {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            loop {
                let mut guard = match self.inner.poll_write_ready(cx) {
                    Poll::Ready(Ok(g)) => g,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };

                let res = unsafe {
                    libc::send(
                        self.inner.as_raw_fd(),
                        data.as_ptr().cast(),
                        data.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };

                if res >= 0 {
                    return Poll::Ready(Ok(res as usize));
                }

                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(err));
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let res = unsafe { libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_WR) };
            if res == 0 {
                Poll::Ready(Ok(()))
            } else {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOTCONN) {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(err))
                }
            }
        }
    }
}
