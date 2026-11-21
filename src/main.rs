use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use russh::keys::{Algorithm, PrivateKey};
use russh::{MethodKind, MethodSet};
use tracing::{error, info};

use vsock_sshd::{platform, server, sftp_worker, transport};

const USAGE: &str = "\
vsock-sshd — minimal VM SSH/SFTP server (inetd / systemd vsock stdio mode)

USAGE:
    vsock-sshd [-i] [--host-key <PATH>]
    vsock-sshd --internal-sftp

OPTIONS:
    -i, --inetd           Run single SSH session over stdin/stdout (default)
    --host-key <PATH>     Path to OpenSSH Ed25519 host private key
    --internal-sftp       Run unprivileged SFTP v3 worker over stdin/stdout
    -h, --help            Print help
";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Daemon { host_key: PathBuf },
    InternalSftp,
    Help,
}

fn parse_args_from<I, S>(iter: I) -> Result<Mode>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut host_key: Option<PathBuf> = None;
    let mut args = iter.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "--internal-sftp" => return Ok(Mode::InternalSftp),
            "-i" | "--inetd" => {}
            "--host-key" => {
                let p = args.next().context("--host-key requires a path argument")?;
                host_key = Some(PathBuf::from(p.as_ref()));
            }
            "-h" | "--help" => return Ok(Mode::Help),
            other => bail!("unknown argument: {other}\n\n{USAGE}"),
        }
    }

    Ok(Mode::Daemon {
        host_key: host_key.unwrap_or_else(platform::default_host_key_path),
    })
}

fn main() -> Result<()> {
    match parse_args_from(std::env::args().skip(1))? {
        Mode::Help => {
            eprint!("{USAGE}");
            Ok(())
        }

        // Unprivileged worker mode: never loads host keys or runs SSH; serves SFTP v3
        // via russh-sftp over stdio under the already-impersonated OS user credentials.
        Mode::InternalSftp => sftp_worker::run(),

        // Privileged inetd / systemd-vsock daemon mode (one process per connection).
        Mode::Daemon { host_key } => {
            // Log exclusively to stderr so stdout remains a clean binary SSH stream.
            tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
                )
                .init();

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .build()
                .context("failed to build tokio runtime")?;

            rt.block_on(run_daemon(host_key))
        }
    }
}

async fn run_daemon(host_key_path: PathBuf) -> Result<()> {
    let host_key = load_or_create_host_key(&host_key_path)
        .with_context(|| format!("failed to load host key at {}", host_key_path.display()))?;

    let mut config = russh::server::Config::default();
    config.server_id = russh::SshId::Standard("SSH-2.0-vsock-sshd".into());
    config.keys = vec![host_key];
    config.methods = MethodSet::from(&[MethodKind::PublicKey][..]);
    config.auth_rejection_time = Duration::from_millis(250);
    config.auth_rejection_time_initial = Some(Duration::from_millis(0));
    config.inactivity_timeout = Some(Duration::from_secs(600));
    config.max_auth_attempts = 6;

    let stream = transport::StdioTransport::from_stdio()
        .context("failed to initialize stdio/vsock transport")?;

    info!("starting vsock-sshd session on stdio transport");

    let handler = server::SshSession::new();
    match russh::server::run_stream(Arc::new(config), stream, handler).await {
        Ok(session) => {
            if let Err(err) = session.await {
                error!(error = %err, "ssh session terminated with error");
            }
        }
        Err(err) => {
            error!(error = %err, "ssh handshake failed");
        }
    }

    Ok(())
}

fn load_or_create_host_key(path: &PathBuf) -> Result<PrivateKey> {
    if path.exists() {
        let pem = std::fs::read_to_string(path)?;
        return PrivateKey::from_openssh(&pem).context("invalid OpenSSH host key");
    }

    info!(path = %path.display(), "generating new Ed25519 host key");
    let mut rng = russh::keys::ssh_key::rand_core::OsRng;
    let key = PrivateKey::random(&mut rng, Algorithm::Ed25519)
        .context("failed to generate Ed25519 host key")?;
    let pem = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .context("failed to encode host key")?;

    platform::write_host_key_strict(path, pem.as_bytes())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_and_inetd_modes() {
        assert_eq!(
            parse_args_from::<[&str; 0], _>([]).unwrap(),
            Mode::Daemon {
                host_key: platform::default_host_key_path()
            }
        );
        assert_eq!(
            parse_args_from(["-i", "--host-key", "/tmp/host_key"]).unwrap(),
            Mode::Daemon {
                host_key: PathBuf::from("/tmp/host_key")
            }
        );
    }

    #[test]
    fn parses_internal_sftp_and_help_flags() {
        assert_eq!(
            parse_args_from(["--internal-sftp"]).unwrap(),
            Mode::InternalSftp
        );
        assert_eq!(parse_args_from(["--help"]).unwrap(), Mode::Help);
    }

    #[test]
    fn rejects_invalid_arguments() {
        assert!(parse_args_from(["--host-key"]).is_err());
        assert!(parse_args_from(["--unknown-flag"]).is_err());
    }
}
