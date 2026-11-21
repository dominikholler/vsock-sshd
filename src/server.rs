use std::collections::HashMap;

use anyhow::Result;
use russh::keys::PublicKey;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, CryptoVec, MethodKind, MethodSet};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::auth;
use crate::platform::{self, OsUser, SpawnedChild};

const CHANNEL_STDIN_BUFFER: usize = 32;
const IO_CHUNK_SIZE: usize = 32 * 1024;

fn publickey_only() -> MethodSet {
    MethodSet::from(&[MethodKind::PublicKey][..])
}

fn reject_to_pubkey() -> Auth {
    Auth::Reject {
        proceed_with_methods: Some(publickey_only()),
        partial_success: false,
    }
}

struct ActiveChannel {
    stdin_tx: Option<mpsc::Sender<Vec<u8>>>,
}

pub struct SshSession {
    user: Option<OsUser>,
    channels: HashMap<ChannelId, ActiveChannel>,
    authorized_keys_path: Option<std::path::PathBuf>,
}

impl SshSession {
    pub fn new() -> Self {
        Self {
            user: None,
            channels: HashMap::new(),
            authorized_keys_path: None,
        }
    }

    pub fn with_authorized_keys(path: Option<std::path::PathBuf>) -> Self {
        Self {
            user: None,
            channels: HashMap::new(),
            authorized_keys_path: path,
        }
    }
}

impl Default for SshSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SshSession {
    fn wire_child(
        &mut self,
        channel: ChannelId,
        spawned: SpawnedChild,
        session: &mut Session,
        forward_stderr: bool,
    ) {
        let handle = session.handle();
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_STDIN_BUFFER);

        if let Some(entry) = self.channels.get_mut(&channel) {
            entry.stdin_tx = Some(stdin_tx);
        }

        let SpawnedChild {
            mut stdin,
            mut stdout,
            mut stderr,
            wait_fn,
        } = spawned;

        // Pump SSH channel data -> child stdin.
        tokio::spawn(async move {
            while let Some(chunk) = stdin_rx.recv().await {
                if stdin.write_all(&chunk).await.is_err() {
                    break;
                }
            }
            let _ = stdin.shutdown().await;
        });

        // Pump child stdout -> SSH channel data.
        let out_handle = handle.clone();
        let stdout_task = tokio::spawn(async move {
            let mut buf = vec![0u8; IO_CHUNK_SIZE];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if out_handle
                            .data(channel, CryptoVec::from_slice(&buf[..n]))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Pump child stderr -> SSH extended_data (type 1) for exec, or daemon stderr for SFTP.
        let err_handle = handle.clone();
        let stderr_task = tokio::spawn(async move {
            let mut buf = vec![0u8; IO_CHUNK_SIZE];
            loop {
                match stderr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if forward_stderr {
                            if err_handle
                                .extended_data(channel, 1, CryptoVec::from_slice(&buf[..n]))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        } else {
                            let msg = String::from_utf8_lossy(&buf[..n]);
                            debug!(worker_stderr = %msg.trim_end(), "sftp worker log");
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Wait for child exit & stream drain, then report exit status + EOF + close.
        tokio::spawn(async move {
            let code = wait_fn.await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            let _ = handle.exit_status_request(channel, code).await;
            let _ = handle.eof(channel).await;
            let _ = handle.close(channel).await;
        });
    }
}

impl Handler for SshSession {
    type Error = anyhow::Error;

    // ── Strict Public-Key-Only Authentication ─────────────────────────────────

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(reject_to_pubkey())
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        warn!(user, "rejected password authentication (publickey only)");
        Ok(reject_to_pubkey())
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        _response: Option<russh::server::Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        warn!(user, "rejected keyboard-interactive auth (publickey only)");
        Ok(reject_to_pubkey())
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if auth::authorize_public_key_with_path(
            user,
            public_key,
            self.authorized_keys_path.as_deref(),
        )
        .is_some()
        {
            Ok(Auth::Accept)
        } else {
            Ok(reject_to_pubkey())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        match auth::authorize_public_key_with_path(
            user,
            public_key,
            self.authorized_keys_path.as_deref(),
        ) {
            Some(os_user) => {
                info!(
                    user = %os_user.username,
                    fingerprint = %public_key.fingerprint(Default::default()),
                    "authenticated OS user via public key"
                );
                self.user = Some(os_user);
                Ok(Auth::Accept)
            }
            None => {
                warn!(user, "rejected unauthorized public key");
                Ok(reject_to_pubkey())
            }
        }
    }

    // ── Session Channel Lifecycle ─────────────────────────────────────────────

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        if self.user.is_none() {
            return Ok(false);
        }
        self.channels
            .insert(channel.id(), ActiveChannel { stdin_tx: None });
        Ok(true)
    }

    // Explicitly disallow interactive terminals, shells, X11, and port forwarding.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("rejecting pty_request (non-interactive daemon)");
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("rejecting shell_request (non-interactive daemon)");
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)?;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    // ── Non-Interactive Command Execution (Strict OS Impersonation) ───────────

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(user) = self.user.clone() else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        let command = match std::str::from_utf8(data) {
            Ok(cmd) => cmd,
            Err(_) => {
                session.channel_failure(channel)?;
                return Ok(());
            }
        };

        match platform::spawn_exec(&user, command) {
            Ok(spawned) => {
                info!(user = %user.username, "spawned impersonated exec command");
                session.channel_success(channel)?;
                self.wire_child(channel, spawned, session, true);
            }
            Err(err) => {
                error!(user = %user.username, error = %err, "failed to spawn impersonated exec");
                session.channel_failure(channel)?;
            }
        }

        Ok(())
    }

    // ── Privilege-Separated Internal SFTP Worker ──────────────────────────────

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            debug!(subsystem = name, "rejecting unsupported subsystem");
            session.channel_failure(channel)?;
            return Ok(());
        }

        let Some(user) = self.user.clone() else {
            session.channel_failure(channel)?;
            return Ok(());
        };

        match platform::spawn_internal_sftp(&user) {
            Ok(spawned) => {
                info!(
                    user = %user.username,
                    "spawned privilege-separated internal SFTP worker"
                );
                session.channel_success(channel)?;
                self.wire_child(channel, spawned, session, false);
            }
            Err(err) => {
                error!(
                    user = %user.username,
                    error = %err,
                    "failed to spawn impersonated SFTP worker"
                );
                session.channel_failure(channel)?;
            }
        }

        Ok(())
    }

    // ── Channel Stdin / EOF / Teardown ────────────────────────────────────────

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.channels.get(&channel).and_then(|c| c.stdin_tx.clone()) {
            let _ = tx.send(data.to_vec()).await;
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(entry) = self.channels.get_mut(&channel) {
            entry.stdin_tx = None;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }
}
