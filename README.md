# vsock-sshd

> [!WARNING]
> **Experimental / Playground Project — Not Intended for Real or Production Use**
>
> This repository is an early-stage experimental playground built to explore minimal VM-only SSH/SFTP over `virtio-vsock` and OS privilege separation. It has **not** been security-audited, hardened, or battle-tested, and **must not be used in production or on systems holding sensitive data**. While the goal may be to evolve it toward production readiness in the future, treat it strictly as a prototype for now.

Minimal cross-platform Rust SSH-2 & SFTP v3 server designed exclusively for Linux and Windows virtual machines over `virtio-vsock`.

## Core Design

- **Transport-agnostic stdio (`sshd -i` / systemd socket activation)**:
  - **Linux**: Uses systemd `ListenStream=vsock::22` + `Accept=yes` + `StandardInput=socket` / `StandardOutput=socket`. `StdioTransport` detects `S_ISSOCK` on fd 0, duplicates it with `FD_CLOEXEC`, and drives non-blocking `AF_VSOCK` I/O via `AsyncFd`.
  - **Windows**: Runs in `sshd -i` mode reading/writing binary SSH frames over redirected stdin/stdout handles, ready to be spawned by any vsock listener or host-guest bridge.
- **Public-key authentication only**: Password, keyboard-interactive, and `none` methods are rejected (`MethodKind::PublicKey` only). Authenticates strictly against OS accounts and strictly permission-checked `authorized_keys`.
- **Non-interactive execution only**: Rejects PTY, interactive shells, X11, and TCP forwarding. Supports `exec` commands and the `sftp` subsystem.
- **Strict OS Impersonation & Privilege-Separated Internal SFTP Worker**:
  - Never executes user commands or serves SFTP filesystem operations inside the privileged daemon process (`root` / `NT AUTHORITY\SYSTEM`).
  - Spawns `<current_exe> --internal-sftp` under the authenticated user's OS credentials so the Linux/Windows kernel enforces every file open, stat, read, write, and directory traversal:
    - **Linux**: `initgroups` -> `setresgid` -> `setresuid` -> `prctl(PR_SET_NO_NEW_PRIVS, 1)` (on SFTP worker) -> mandatory credential verification before `execve`.
    - **Windows**: Passwordless LSA S4U2Self (`LsaLogonUser` with `MSV1_0_S4U_LOGON`) -> `DuplicateTokenEx(TokenPrimary)` -> `CreateEnvironmentBlock` -> `CreateProcessAsUserW` (fail-closed; never falls back to `SYSTEM`).

## Building

```bash
# Linux guest
cargo build --release

# Windows guest (native MSVC or cross-compile)
cargo build --release --target x86_64-pc-windows-msvc

# Run unit & in-memory SSH/SFTP integration tests (no root/SYSTEM required)
cargo test
```

## Linux Deployment (systemd)

```bash
sudo install -m 0755 target/release/vsock-sshd /usr/local/sbin/vsock-sshd
sudo install -m 0644 deploy/systemd/vsock-sshd.socket /etc/systemd/system/
sudo install -m 0644 deploy/systemd/vsock-sshd@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vsock-sshd.socket
```

Connect from the host (`systemd-ssh-proxy` or `socat`):

```bash
# Host with systemd-ssh-proxy
ssh user@vsock/3 "uname -a"
sftp user@vsock/3

# Generic host with socat
ssh -o ProxyCommand="socat - VSOCK-CONNECT:3:22" user@vm "id"
sftp -o ProxyCommand="socat - VSOCK-CONNECT:3:22" user@vm
```

## Windows Usage (`sshd -i` Mode)

Run your vsock transport proxy as `NT AUTHORITY\SYSTEM` (required for `LsaLogonUser` S4U2Self + `CreateProcessAsUserW`), spawning per incoming vsock connection with inherited stdin/stdout pipes:

```powershell
"C:\Program Files\vsock-sshd\vsock-sshd.exe" -i --host-key "C:\ProgramData\vsock-sshd\ssh_host_ed25519_key"
```

Authorized keys follow OpenSSH-Win32 strict paths:
- Administrators: `%ProgramData%\ssh\administrators_authorized_keys` (owned by `SYSTEM` or `Administrators`)
- Standard users: `<ProfileDir>\.ssh\authorized_keys` (owned by the user, `SYSTEM`, or `Administrators`)
