#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};
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
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
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

fn write_strict_auth_keys(path: &std::path::Path, content: &str) {
    if let Some(parent) = path.parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    std::fs::write(path, content).expect("write authorized_keys");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("set permissions 0600 on authorized_keys");
    }
}

#[tokio::test]
async fn e2e_binary_ssh_command_execution() {
    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    assert!(binary_path.exists(), "binary must exist at {binary_path:?}");

    let tmp_dir = tempfile::tempdir().expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let auth_keys_path = tmp_dir.path().join("authorized_keys");

    // 1. Generate temporary client Ed25519 keypair
    let mut rng = rand::rng();
    let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("client keygen");
    let client_pub = client_key.public_key();
    let client_pub_openssh = client_pub.to_openssh().expect("encode public key");

    // 2. Write client public key to temporary authorized_keys file
    write_strict_auth_keys(&auth_keys_path, &format!("{client_pub_openssh}\n"));

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
    let mut rng = rand::rng();
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

    write_strict_auth_keys(&auth_keys_path, &format!("{client_pub_openssh}\n"));

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

/// Quotes a path operand for OpenSSH sftp batch commands.
/// OpenSSH sftp parses batch commands using `makeargv` where double-quoted
/// strings unescape `\"` and `\\`, and then `glob(3)` / `undo_glob_escape` unescapes `\\`.
fn sftp_quote_operand(path: &std::path::Path) -> String {
    let s = path.to_string_lossy();
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Quotes a path for POSIX shell argument string inside double quotes.
fn sh_quote_in_double_quotes(path: &std::path::Path) -> String {
    let s = path.to_string_lossy();
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Quotes a string for POSIX shell or Python shlex.split using single quotes.
fn shlex_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[tokio::test]
async fn e2e_openssh_sftp_file_transfer() {
    let sftp_check = std::process::Command::new("sftp").arg("-V").output();
    if sftp_check.is_err() {
        eprintln!("Skipping OpenSSH sftp test: 'sftp' not found in PATH");
        return;
    }

    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    let tmp_dir = tempfile::Builder::new()
        .prefix("sftp test spaces ")
        .tempdir()
        .expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let auth_keys_path = tmp_dir.path().join("authorized_keys");
    let client_key_path = tmp_dir.path().join("id_ed25519");

    let mut rng = rand::rng();
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

    write_strict_auth_keys(&auth_keys_path, &format!("{client_pub_openssh}\n"));

    let local_file = tmp_dir.path().join(if cfg!(windows) {
        "local file with spaces.txt"
    } else {
        "local \"file\" with \\backslash\\ and spaces.txt"
    });
    let remote_file = tmp_dir.path().join(if cfg!(windows) {
        "remote file with spaces.txt"
    } else {
        "remote \"file\" with \\backslash\\ and spaces.txt"
    });
    let downloaded_file = tmp_dir.path().join(if cfg!(windows) {
        "downloaded file with spaces.txt"
    } else {
        "downloaded \"file\" with \\backslash\\ and spaces.txt"
    });
    std::fs::write(&local_file, b"sftp roundtrip verification").expect("write local file");

    let username = get_current_username();
    let proxy_cmd = format!(
        "{} -i --host-key {} --authorized-keys {}",
        sh_quote_in_double_quotes(&binary_path),
        sh_quote_in_double_quotes(&host_key_path),
        sh_quote_in_double_quotes(&auth_keys_path)
    );

    let batch_cmds = format!(
        "put {} {}\nget {} {}\n",
        sftp_quote_operand(&local_file),
        sftp_quote_operand(&remote_file),
        sftp_quote_operand(&remote_file),
        sftp_quote_operand(&downloaded_file)
    );

    let mut child = tokio::process::Command::new("sftp")
        .arg("-b")
        .arg("-")
        .arg("-i")
        .arg(&client_key_path)
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!("ProxyCommand={proxy_cmd}"))
        .arg(format!("{username}@localhost"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sftp command");

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(batch_cmds.as_bytes())
            .await
            .expect("write sftp batch commands");
    }

    let output = child.wait_with_output().await.expect("sftp wait");
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "sftp command failed with stderr: {stderr_str}"
    );

    let downloaded_content =
        std::fs::read_to_string(&downloaded_file).expect("read downloaded file");
    assert_eq!(downloaded_content, "sftp roundtrip verification");
}

#[tokio::test]
async fn e2e_ansible_ping_and_command_execution() {
    let ansible_check = std::process::Command::new("ansible")
        .arg("--version")
        .output();
    if ansible_check.is_err() {
        eprintln!("Skipping Ansible test: 'ansible' not found in PATH");
        return;
    }

    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    let tmp_dir = tempfile::Builder::new()
        .prefix("ansible test spaces ")
        .tempdir()
        .expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let auth_keys_path = tmp_dir.path().join("authorized_keys");
    let client_key_path = tmp_dir.path().join("id_ed25519");

    let mut rng = rand::rng();
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

    write_strict_auth_keys(&auth_keys_path, &format!("{client_pub_openssh}\n"));

    let username = get_current_username();
    let proxy_cmd = format!(
        "{} -i --host-key {} --authorized-keys {}",
        sh_quote_in_double_quotes(&binary_path),
        sh_quote_in_double_quotes(&host_key_path),
        sh_quote_in_double_quotes(&auth_keys_path)
    );
    let ssh_args = format!(
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ProxyCommand={}",
        shlex_quote(&proxy_cmd)
    );

    let hosts_ini_path = tmp_dir.path().join("hosts.ini");
    let ansible_cfg_path = tmp_dir.path().join("ansible.cfg");
    let cp_dir = tmp_dir.path().join("cp");
    let tmp_ansible_dir = tmp_dir.path().join("tmp");
    std::fs::create_dir_all(&cp_dir).expect("create cp dir");
    std::fs::create_dir_all(&tmp_ansible_dir).expect("create tmp dir");

    let hosts_content = format!(
        "[all]\ntestnode ansible_connection=ssh ansible_user=\"{}\" ansible_python_interpreter=/usr/bin/python3 ansible_ssh_private_key_file=\"{}\"\n",
        username,
        client_key_path.display()
    );
    std::fs::write(&hosts_ini_path, hosts_content).expect("write hosts.ini");

    let cfg_content = format!(
        "[defaults]\ninventory = {}\nhost_key_checking = False\nremote_tmp = {}\nlocal_tmp = {}\n[ssh_connection]\ncontrol_path_dir = {}\npipelining = True\nssh_args = {}\n",
        hosts_ini_path.display(),
        tmp_ansible_dir.display(),
        tmp_ansible_dir.display(),
        cp_dir.display(),
        ssh_args
    );
    std::fs::write(&ansible_cfg_path, cfg_content).expect("write ansible.cfg");

    let output = tokio::process::Command::new("ansible")
        .env("ANSIBLE_CONFIG", &ansible_cfg_path)
        .env("ANSIBLE_HOME", &tmp_ansible_dir)
        .env("ANSIBLE_LOCAL_TEMP", &tmp_ansible_dir)
        .arg("all")
        .arg("-m")
        .arg("ping")
        .output()
        .await
        .expect("run ansible ping");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ansible ping failed: stdout={stdout_str}, stderr={stderr_str}"
    );
    assert!(
        stdout_str.contains("\"ping\": \"pong\""),
        "expected ping pong in stdout: {stdout_str}"
    );
}

#[test]
fn test_quoting_helpers() {
    use std::path::Path;

    // Test sftp_quote_operand
    assert_eq!(
        sftp_quote_operand(Path::new("/tmp/normal.txt")),
        "\"/tmp/normal.txt\""
    );
    assert_eq!(
        sftp_quote_operand(Path::new("/tmp/with spaces.txt")),
        "\"/tmp/with spaces.txt\""
    );
    assert_eq!(
        sftp_quote_operand(Path::new("/tmp/with \"quotes\" and \\backslash.txt")),
        "\"/tmp/with \\\"quotes\\\" and \\\\backslash.txt\""
    );

    // Test sh_quote_in_double_quotes
    assert_eq!(
        sh_quote_in_double_quotes(Path::new("/bin/vsock-sshd")),
        "\"/bin/vsock-sshd\""
    );
    assert_eq!(
        sh_quote_in_double_quotes(Path::new("/tmp/path with spaces/bin")),
        "\"/tmp/path with spaces/bin\""
    );
    assert_eq!(
        sh_quote_in_double_quotes(Path::new("/tmp/with \"quotes\" and $VAR/bin")),
        "\"/tmp/with \\\"quotes\\\" and \\$VAR/bin\""
    );

    // Test shlex_quote
    assert_eq!(shlex_quote(""), "''");
    assert_eq!(shlex_quote("simple"), "'simple'");
    assert_eq!(shlex_quote("with space"), "'with space'");
    assert_eq!(shlex_quote("can't stop"), "'can'\\''t stop'");
    assert_eq!(
        shlex_quote("\"/bin/echo\" --arg \"foo bar\""),
        "'\"/bin/echo\" --arg \"foo bar\"'"
    );
}

async fn start_server_and_connect(
    auth_keys_line: &str,
    client_key: &PrivateKey,
) -> (
    tokio::process::Child,
    client::Handle<TestClientHandler>,
    russh::client::AuthResult,
    tempfile::TempDir,
) {
    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    let tmp_dir = tempfile::tempdir().expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let auth_keys_path = tmp_dir.path().join("authorized_keys");

    write_strict_auth_keys(&auth_keys_path, &format!("{auth_keys_line}\n"));

    let username = get_current_username();

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
        .expect("spawn vsock-sshd");

    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");

    let stream = ChildStream {
        reader: child_stdout,
        writer: child_stdin,
    };

    let client_cfg = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(10)),
        ..Default::default()
    });

    let mut session = client::connect_stream(client_cfg, stream, TestClientHandler)
        .await
        .expect("client handshake");

    let auth_res = session
        .authenticate_publickey(
            &username,
            PrivateKeyWithHashAlg::new(Arc::new(client_key.clone()), None),
        )
        .await
        .expect("auth exchange");

    (child, session, auth_res, tmp_dir)
}

#[tokio::test]
async fn e2e_authorized_keys_options_rejected_fail_closed() {
    let mut rng = rand::rng();
    let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("keygen");
    let client_pub = client_key.public_key().to_openssh().expect("to_openssh");

    // Positive baseline: confirm that the same key without options authenticates successfully
    let (mut bare_child, bare_session, bare_auth_res, _bare_tmp) =
        start_server_and_connect(&client_pub, &client_key).await;
    assert!(
        bare_auth_res.success(),
        "expected bare key without options to authenticate successfully"
    );
    drop(bare_session);
    let _ = bare_child.wait().await;

    // All authorized_keys options must be rejected fail-closed (F-01)
    let option_lines = [
        format!("command=\"echo 1\" {client_pub}"),
        format!("from=\"127.0.0.1\" {client_pub}"),
        format!("environment=\"VAR=val\" {client_pub}"),
        format!("expiry-time=\"20200101\" {client_pub}"),
        format!("restrict {client_pub}"),
        format!("no-pty {client_pub}"),
        format!("custom-option=\"val\" {client_pub}"),
        format!("restrict,command=\"echo 1\" {client_pub}"),
    ];

    for line in &option_lines {
        let (mut child, session, auth_res, _tmp) =
            start_server_and_connect(line, &client_key).await;
        assert!(
            !auth_res.success(),
            "expected key with options to fail authentication fail-closed: {line}"
        );
        drop(session);
        let _ = child.wait().await;
    }
}

#[tokio::test]
async fn e2e_custom_authorized_keys_rejects_unsafe_permissions() {
    let mut rng = rand::rng();
    let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("client keygen");
    let client_pub = client_key.public_key().to_openssh().expect("to_openssh");

    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    let tmp_dir = tempfile::tempdir().expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let auth_keys_path = tmp_dir.path().join("authorized_keys");

    write_strict_auth_keys(&auth_keys_path, &format!("{client_pub}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth_keys_path, std::fs::Permissions::from_mode(0o664)).unwrap();
    }

    let username = get_current_username();
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
        .expect("spawn vsock-sshd");

    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");
    let stream = ChildStream {
        reader: child_stdout,
        writer: child_stdin,
    };
    let client_cfg = Arc::new(client::Config::default());
    let mut session = client::connect_stream(client_cfg, stream, TestClientHandler)
        .await
        .expect("client handshake");
    let auth_res = session
        .authenticate_publickey(
            &username,
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .expect("auth exchange");

    #[cfg(unix)]
    assert!(
        !auth_res.success(),
        "group-writable custom authorized_keys must fail"
    );

    drop(session);
    let _ = child.wait().await;
}

#[tokio::test]
async fn e2e_custom_authorized_keys_rejects_symlink() {
    #[cfg(unix)]
    {
        let mut rng = rand::rng();
        let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("client keygen");
        let client_pub = client_key.public_key().to_openssh().expect("to_openssh");

        let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
        let tmp_dir = tempfile::tempdir().expect("create tempdir");
        let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
        let real_keys_path = tmp_dir.path().join("real_keys");
        let sym_keys_path = tmp_dir.path().join("sym_keys");

        write_strict_auth_keys(&real_keys_path, &format!("{client_pub}\n"));
        std::os::unix::fs::symlink(&real_keys_path, &sym_keys_path).unwrap();

        let username = get_current_username();
        let mut child = tokio::process::Command::new(&binary_path)
            .arg("-i")
            .arg("--host-key")
            .arg(&host_key_path)
            .arg("--authorized-keys")
            .arg(&sym_keys_path)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .expect("spawn vsock-sshd");

        let child_stdin = child.stdin.take().expect("child stdin");
        let child_stdout = child.stdout.take().expect("child stdout");
        let stream = ChildStream {
            reader: child_stdout,
            writer: child_stdin,
        };
        let client_cfg = Arc::new(client::Config::default());
        let mut session = client::connect_stream(client_cfg, stream, TestClientHandler)
            .await
            .expect("client handshake");
        let auth_res = session
            .authenticate_publickey(
                &username,
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
            )
            .await
            .expect("auth exchange");

        assert!(
            !auth_res.success(),
            "symlinked custom authorized_keys must fail"
        );

        drop(session);
        let _ = child.wait().await;
    }
}

#[tokio::test]
async fn e2e_custom_authorized_keys_directory_mode() {
    let mut rng = rand::rng();
    let client_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("client keygen");
    let client_pub = client_key.public_key().to_openssh().expect("to_openssh");

    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_vsock-sshd"));
    let tmp_dir = tempfile::tempdir().expect("create tempdir");
    let host_key_path = tmp_dir.path().join("ssh_host_ed25519_key");
    let username = get_current_username();
    let user_keys_path = tmp_dir.path().join(&username);

    write_strict_auth_keys(&user_keys_path, &format!("{client_pub}\n"));

    let mut child = tokio::process::Command::new(&binary_path)
        .arg("-i")
        .arg("--host-key")
        .arg(&host_key_path)
        .arg("--authorized-keys")
        .arg(tmp_dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn vsock-sshd");

    let child_stdin = child.stdin.take().expect("child stdin");
    let child_stdout = child.stdout.take().expect("child stdout");
    let stream = ChildStream {
        reader: child_stdout,
        writer: child_stdin,
    };
    let client_cfg = Arc::new(client::Config::default());
    let mut session = client::connect_stream(client_cfg, stream, TestClientHandler)
        .await
        .expect("client handshake");
    let auth_res = session
        .authenticate_publickey(
            &username,
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .expect("auth exchange");

    assert!(
        auth_res.success(),
        "directory-mode custom authorized_keys should succeed for matching user"
    );

    drop(session);
    let _ = child.wait().await;
}
