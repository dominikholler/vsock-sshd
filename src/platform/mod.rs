#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use std::path::PathBuf;
use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
pub use unix::{
    default_host_key_path, lookup_user, read_authorized_keys_strict, spawn_exec,
    spawn_internal_sftp, write_host_key_strict, OsUser,
};

#[cfg(windows)]
pub use windows::{
    default_host_key_path, lookup_user, read_authorized_keys_strict, spawn_exec,
    spawn_internal_sftp, write_host_key_strict, OsUser,
};

pub type BoxAsyncWrite = Pin<Box<dyn AsyncWrite + Send>>;
pub type BoxAsyncRead = Pin<Box<dyn AsyncRead + Send>>;

/// Platform-agnostic handle to a strictly impersonated child process.
pub struct SpawnedChild {
    pub stdin: BoxAsyncWrite,
    pub stdout: BoxAsyncRead,
    pub stderr: BoxAsyncRead,
    pub wait_fn: Pin<Box<dyn std::future::Future<Output = u32> + Send>>,
}

impl SpawnedChild {
    pub fn new(
        stdin: BoxAsyncWrite,
        stdout: BoxAsyncRead,
        stderr: BoxAsyncRead,
        wait_fn: Pin<Box<dyn std::future::Future<Output = u32> + Send>>,
    ) -> Self {
        Self {
            stdin,
            stdout,
            stderr,
            wait_fn,
        }
    }

    pub async fn wait_exit_code(self) -> u32 {
        self.wait_fn.await
    }
}

/// Resolve our own executable path for spawning `--internal-sftp`.
pub fn current_exe_path() -> anyhow::Result<PathBuf> {
    std::env::current_exe().map_err(Into::into)
}
