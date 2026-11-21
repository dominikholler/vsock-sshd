use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};
use russh::{MethodKind, MethodSet};
use vsock_sshd::server::SshSession;

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

fn build_server_config() -> Arc<russh::server::Config> {
    let mut rng = rand::rng();
    let host_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("host key");

    let cfg = russh::server::Config {
        keys: vec![host_key],
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    };
    Arc::new(cfg)
}

#[tokio::test]
async fn rejects_password_none_and_unauthorized_public_key() {
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let server_cfg = build_server_config();
    let server_task = tokio::spawn(async move {
        let session = russh::server::run_stream(server_cfg, server_stream, SshSession::new())
            .await
            .expect("server handshake");
        let _ = session.await;
    });

    let client_cfg = Arc::new(client::Config::default());
    let mut handle = client::connect_stream(client_cfg, client_stream, TestClientHandler)
        .await
        .expect("client handshake");

    // 1. "none" auth must be rejected
    let none_res = handle
        .authenticate_none("nonexistent_vsock_user")
        .await
        .expect("none auth exchange");
    assert!(!none_res.success(), "none auth must never succeed");

    // 2. Password auth must be rejected
    let pw_res = handle
        .authenticate_password("nonexistent_vsock_user", "correct-horse-battery-staple")
        .await
        .expect("password auth exchange");
    assert!(!pw_res.success(), "password auth must be rejected");

    // 3. Unauthorized Ed25519 key must be rejected
    let mut rng = rand::rng();
    let random_key = PrivateKey::random(&mut rng, Algorithm::Ed25519).expect("client key");
    let key_res = handle
        .authenticate_publickey(
            "nonexistent_vsock_user",
            PrivateKeyWithHashAlg::new(Arc::new(random_key), None),
        )
        .await
        .expect("publickey auth exchange");
    assert!(!key_res.success(), "unauthorized key must be rejected");

    drop(handle);
    let _ = server_task.await;
}
