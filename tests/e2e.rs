#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct ChildStream {
    reader: tokio::process::ChildStdout,
    writer: tokio::process::ChildStdin,
}

impl AsyncRead for ChildStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

struct TestClientHandler;

impl client::Handler for TestClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

fn get_current_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string())
}

#[tokio::test]
async fn e2e_binary_ssh_command_execution() {
    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    assert!(binary_path.exists(), "binary must exist at {binary_path:?}");

    let tmp_dir = tempfile::tempdir().expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let auth_keys_path = tmp_dir.path().join("authorized_keys");

    // 1. Generate temporary client Ed25519 keypair
    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("client keygen");
    let client_pub = client_key.public_key();
    let client_pub_openssh = client_pub.to_openssh().expect("encode public key");

    // 2. Write client public key to temporary authorized_keys file
    std::fs::write(&auth_keys_path, format!("{client_pub_openssh}\n"))
        .expect("write authorized_keys");

    let username = get_current_username();

    // 3. Spawn vsock-sshd binary with redirected stdio pipes
    let mut child = tokio::process::Command::new(&binary_path)
        .arg("-i")
        .arg("--host-key")
        .arg(&host_key_path)
        .arg("--authorized-keys")
        .arg(&auth_keys_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("failed to spawn vsock-sshd binary");

    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    let stream = ChildStream {
        reader: child_stdout,
        writer: child_stdin,
    };

    // 4. Connect SSH client over stdio stream
    let client_cfg = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });

    let mut session = client::connect_stream(client_cfg, stream, TestClientHandler)
        .await
        .expect("client handshake");

    // 5. Authenticate via generated public key
    let auth_res = session
        .authenticate_publickey(
            &username,
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .expect("publickey auth exchange");
    assert!(
        auth_res.success(),
        "authentication with generated temporary key failed"
    );

    // 6. Execute simple command via SSH channel
    let mut channel = session
        .channel_open_session()
        .await
        .expect("channel open session");

    channel
        .exec(true, "echo 'hello from vsock-sshd e2e'")
        .await
        .expect("exec command");

    let mut stdout_output = Vec::new();
    let mut exit_code = None;

    while let Some(msg) = channel.wait().await {
        match msg {
            russh::ChannelMsg::Data { data } => {
                stdout_output.extend_from_slice(&data);
            }
            russh::ChannelMsg::ExitStatus { exit_status } => {
                exit_code = Some(exit_status);
            }
            _ => {}
        }
    }

    assert_eq!(
        String::from_utf8_lossy(&stdout_output).trim(),
        "hello from vsock-sshd e2e"
    );
    assert_eq!(exit_code, Some(0));

    // 7. Clean teardown and process exit verification
    drop(channel);
    drop(session);

    let status = child.wait().await.expect("child exit status");
    assert!(status.success(), "vsock-sshd exited with non-zero status");
}

#[tokio::test]
async fn e2e_openssh_client_command_execution() {
    // Check if OpenSSH client ('ssh') is available in PATH
    let ssh_check = std::process::Command::new("ssh").arg("-V").output();
    if ssh_check.is_err() {
        eprintln!("Skipping OpenSSH client test: 'ssh' not found in PATH");
        return;
    }

    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    let tmp_dir = tempfile::tempdir().expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let auth_keys_path = tmp_dir.path().join("authorized_keys");
    let client_key_path = tmp_dir.path().join("id_ed25519");

    // Generate client keypair
    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("client keygen");
    let client_priv_openssh = client_key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("encode private key");
    let client_pub_openssh = client_key
        .public_key()
        .to_openssh()
        .expect("encode public key");

    std::fs::write(&client_key_path, client_priv_openssh.as_bytes())
        .expect("write client private key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&client_key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 client key");
    }

    std::fs::write(&auth_keys_path, format!("{client_pub_openssh}\n"))
        .expect("write authorized_keys");

    let username = get_current_username();
    let proxy_cmd = format!(
        "\"{}\" -i --host-key \"{}\" --authorized-keys \"{}\"",
        binary_path.display(),
        host_key_path.display(),
        auth_keys_path.display()
    );

    let output = tokio::process::Command::new("ssh")
        .arg("-i")
        .arg(&client_key_path)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!("ProxyCommand={proxy_cmd}"))
        .arg(format!("{username}@localhost"))
        .arg("echo 'hello from openssh client'")
        .output()
        .await
        .expect("run ssh command");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "ssh command failed with stderr: {stderr_str}"
    );
    assert_eq!(stdout_str.trim(), "hello from openssh client");
}
