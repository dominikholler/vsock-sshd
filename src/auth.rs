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

    let raw_keys = match custom_path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) => {
                warn!(path = %path.display(), error = %err, "failed to read custom authorized_keys");
                return None;
            }
        },
        None => match platform::read_authorized_keys_strict(&user) {
            Ok(Some(contents)) => contents,
            Ok(None) => {
                debug!(user = username, "no authorized_keys file found");
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
        },
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

/// Parse a single OpenSSH `authorized_keys` line, skipping blank lines,
/// comments, and optional leading key options (e.g. `restrict,from="..."`).
fn parse_authorized_key_line(line: &str) -> Option<PublicKey> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Fast path: line begins directly with key type (`ssh-ed25519 ...`).
    if let Ok(key) = PublicKey::from_openssh(trimmed) {
        return Some(key);
    }

    // Handle leading comma-separated options, respecting quoted values.
    let key_slice = strip_leading_options(trimmed)?;
    PublicKey::from_openssh(key_slice).ok()
}

fn strip_leading_options(line: &str) -> Option<&str> {
    let mut in_quotes = false;
    let mut escaped = false;

    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            ' ' | '\t' if !in_quotes => {
                let rest = line[idx..].trim_start();
                return (!rest.is_empty()).then_some(rest);
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
    fn parses_key_with_quoted_options_and_spaces() {
        let key = gen_key();
        let pub_str = key.to_openssh().unwrap();
        let line = format!(
            r#"restrict,from="10.0.0.1, 10.0.0.2",environment="MSG=\"hello world\"" {pub_str} ops@vm"#
        );

        let parsed = parse_authorized_key_line(&line).expect("key with options");
        assert_eq!(parsed.key_data(), key.key_data());
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
