use russh::keys::PublicKey;
use tracing::{debug, warn};

use crate::platform::{self, OsUser};

/// Verify that `username` is a valid system OS account and that `presented`
/// matches a key in the user's strictly permission-checked `authorized_keys`.
pub fn authorize_public_key(username: &str, presented: &PublicKey) -> Option<OsUser> {
    authorize_public_key_with_path(username, presented, None)
}

/// Verify public key against `custom_path` if provided, otherwise falling back
/// to the user's strictly permission-checked `authorized_keys`.
pub fn authorize_public_key_with_path(
    username: &str,
    presented: &PublicKey,
    custom_path: Option<&std::path::Path>,
) -> Option<OsUser> {
    let user = match platform::lookup_user(username) {
        Ok(Some(u)) => u,
        Ok(None) => {
            debug!(user = username, "OS account not found or login disabled");
            return None;
        }
        Err(err) => {
            warn!(user = username, error = %err, "OS user lookup failed");
            return None;
        }
    };

    let raw_keys = match platform::read_authorized_keys_strict(&user, custom_path) {
        Ok(Some(contents)) => contents,
        Ok(None) => {
            if let Some(path) = custom_path {
                warn!(
                    user = username,
                    path = %path.display(),
                    "no authorized_keys found at custom path"
                );
            } else {
                debug!(user = username, "no authorized_keys file found");
            }
            return None;
        }
        Err(err) => {
            warn!(
                user = username,
                error = %err,
                "rejected authorized_keys due to security check"
            );
            return None;
        }
    };

    for line in raw_keys.lines() {
        if let Some(authorized) = parse_authorized_key_line(line) {
            if authorized.key_data() == presented.key_data() {
                return Some(user);
            }
        }
    }

    None
}

/// Parse a single OpenSSH `authorized_keys` line, skipping blank lines and comments.
///
/// Enforces fail-closed security (F-01): any entry containing options (such as
/// `command=`, `from=`, `environment=`, `expiry-time=`, or `restrict`) is strictly
/// rejected because vsock-sshd does not enforce key options. Discarding options
/// would risk bypassing administrator restrictions.
pub fn parse_authorized_key_line(line: &str) -> Option<PublicKey> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Fast path: line begins directly with key type (`ssh-ed25519 ...`).
    if let Ok(key) = PublicKey::from_openssh(trimmed) {
        return Some(key);
    }

    // If the line has leading options followed by a key, reject fail-closed
    // so no administrator restriction is ever silently bypassed.
    if let Some(key_slice) = find_key_after_options(trimmed) {
        if PublicKey::from_openssh(key_slice).is_ok() {
            warn!("authorized_keys options are unsupported (rejecting fail-closed)");
        }
    }

    None
}

fn find_key_after_options(line: &str) -> Option<&str> {
    let mut in_quotes = false;
    let mut chars = line.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        match ch {
            '\\' if in_quotes => {
                if let Some(&(_, '"')) = chars.peek() {
                    chars.next();
                }
            }
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                let rest = line[idx..].trim_start_matches([' ', '\t']);
                if !rest.is_empty() {
                    return Some(rest);
                }
            }
            _ => {}
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::{Algorithm, PrivateKey};

    fn gen_key() -> PublicKey {
        let mut rng = rand::rng();
        PrivateKey::random(&mut rng, Algorithm::Ed25519)
            .expect("ed25519 keygen")
            .public_key()
            .clone()
    }

    #[test]
    fn parses_plain_key_and_skips_comments() {
        let key = gen_key();
        let line = format!("{} user@host", key.to_openssh().unwrap());

        assert!(parse_authorized_key_line("").is_none());
        assert!(parse_authorized_key_line("   # comment line").is_none());

        let parsed = parse_authorized_key_line(&line).expect("valid key line");
        assert_eq!(parsed.key_data(), key.key_data());
    }

    #[test]
    fn rejects_keys_with_options_fail_closed() {
        let key = gen_key();
        let pub_str = key.to_openssh().unwrap();

        // Options must all be rejected fail-closed (F-01)
        let command_line = format!(r#"command="echo 1" {pub_str} user@host"#);
        assert!(parse_authorized_key_line(&command_line).is_none());

        let from_line = format!(r#"from="10.0.0.1" {pub_str} user@host"#);
        assert!(parse_authorized_key_line(&from_line).is_none());

        let env_line = format!(r#"environment="FOO=bar" {pub_str} user@host"#);
        assert!(parse_authorized_key_line(&env_line).is_none());

        let expiry_line = format!(r#"expiry-time="20261124" {pub_str} user@host"#);
        assert!(parse_authorized_key_line(&expiry_line).is_none());

        let restrict_line = format!(r#"restrict {pub_str} user@host"#);
        assert!(parse_authorized_key_line(&restrict_line).is_none());

        let multi_opts = format!(r#"restrict,command="dump",from="127.0.0.1" {pub_str} user"#);
        assert!(parse_authorized_key_line(&multi_opts).is_none());
    }

    #[test]
    fn rejects_malformed_lines_and_mismatched_keys() {
        let k1 = gen_key();
        let k2 = gen_key();

        assert!(parse_authorized_key_line("ssh-ed25519 not-valid-base64!!!").is_none());
        assert!(parse_authorized_key_line("restrict,no-pty").is_none());
        assert_ne!(k1.key_data(), k2.key_data());
    }
}
