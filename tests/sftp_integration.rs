use std::collections::HashSet;

use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn sftp_roundtrip_file_and_directory_lifecycle() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path().to_path_buf();

    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(vsock_sshd::sftp_worker::run_on_stream(server_stream));

    let sftp = SftpSession::new(client_stream)
        .await
        .expect("SFTP handshake");

    // REALPATH
    let canonical = sftp
        .canonicalize(root.to_string_lossy().as_ref())
        .await
        .expect("canonicalize root");
    assert!(!canonical.is_empty());

    // OPEN (create/write) + WRITE + READ + STAT
    let file_path = root.join("hello.txt");
    let file_str = file_path.to_string_lossy().into_owned();
    {
        let mut f = sftp.create(&file_str).await.expect("create file");
        f.write_all(b"hello over vsock-sftp").await.expect("write");
        f.shutdown().await.expect("shutdown");
    }

    let meta = sftp.metadata(&file_str).await.expect("stat file");
    assert_eq!(meta.size, Some(21));

    let mut read_back = String::new();
    {
        let mut f = sftp.open(&file_str).await.expect("open file");
        f.read_to_string(&mut read_back).await.expect("read");
    }
    assert_eq!(read_back, "hello over vsock-sftp");

    // MKDIR + RENAME + OPENDIR/READDIR
    let sub_dir = root.join("subdir");
    let sub_str = sub_dir.to_string_lossy().into_owned();
    sftp.create_dir(&sub_str).await.expect("mkdir");

    let moved_path = sub_dir.join("renamed.txt");
    let moved_str = moved_path.to_string_lossy().into_owned();
    sftp.rename(&file_str, &moved_str).await.expect("rename");

    let entries: HashSet<String> = sftp
        .read_dir(&sub_str)
        .await
        .expect("readdir")
        .map(|e| e.file_name())
        .collect();
    assert!(entries.contains("renamed.txt"));

    // Missing file returns error
    let missing = root.join("does-not-exist.txt");
    assert!(sftp
        .metadata(missing.to_string_lossy().as_ref())
        .await
        .is_err());

    // REMOVE + RMDIR
    sftp.remove_file(&moved_str).await.expect("remove file");
    sftp.remove_dir(&sub_str).await.expect("rmdir");

    drop(sftp);
    let _ = server_task.await;
}
