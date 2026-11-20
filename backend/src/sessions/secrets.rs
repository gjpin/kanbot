//! Secrets kanbot issues: session tokens (`kbs_`), one-time login codes
//! (`kbc_`), and the random state, nonce, PKCE verifier and browser
//! binding of a login. Only their SHA-256 hashes are stored; a presented
//! value is found by hashing it and looking the hash up, never by comparing
//! secrets in memory.

use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

use crate::base64;

/// Bytes of randomness in every issued secret.
pub const RANDOM_BYTES: usize = 32;
/// Characters of `RANDOM_BYTES` in unpadded base64url.
const ENCODED_LEN: usize = 43;

/// The prefix of a session token.
pub const SESSION_TOKEN: &str = "kbs_";
/// The prefix of a one-time login code.
pub const LOGIN_CODE: &str = "kbc_";

/// The operating system could not provide randomness.
#[derive(Debug, thiserror::Error)]
#[error("no randomness available")]
pub struct NoRandomness;

/// `RANDOM_BYTES` from the operating system.
///
/// # Errors
///
/// [`NoRandomness`] if the operating system cannot provide them.
pub fn random_bytes() -> Result<[u8; RANDOM_BYTES], NoRandomness> {
    let mut bytes = [0; RANDOM_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| NoRandomness)?;
    Ok(bytes)
}

/// A secret value and the hash that is stored for it.
pub struct Issued {
    pub value: SecretString,
    pub hash: [u8; 32],
}

/// A new secret: `prefix` and `RANDOM_BYTES` random bytes in base64url.
///
/// # Errors
///
/// [`NoRandomness`] if the operating system cannot provide randomness.
pub fn issue(prefix: &str) -> Result<Issued, NoRandomness> {
    let value = format!("{prefix}{}", base64::encode_url(&random_bytes()?));
    let hash = hash(&value);
    Ok(Issued {
        value: SecretString::from(value),
        hash,
    })
}

/// The SHA-256 of `value`, as stored.
#[must_use]
pub fn hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// The hash to look up for a presented secret, if it has the shape of one
/// issued with `prefix`. Anything else cannot match and is not hashed.
#[must_use]
pub fn presented(prefix: &str, value: &str) -> Option<[u8; 32]> {
    let encoded = value.strip_prefix(prefix)?;
    (encoded.len() == ENCODED_LEN
        && encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then(|| hash(value))
}

/// The S256 PKCE challenge of `verifier` (RFC 7636, section 4.2).
#[must_use]
pub fn pkce_challenge(verifier: &SecretString) -> String {
    base64::encode_url(&Sha256::digest(verifier.expose_secret().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_prefixed_random_secrets() {
        let token = issue(SESSION_TOKEN).unwrap();
        let value = token.value.expose_secret();
        assert!(value.starts_with("kbs_"), "{value}");
        assert_eq!(value.len(), 4 + ENCODED_LEN);
        assert_eq!(token.hash, hash(value));
        assert_eq!(presented(SESSION_TOKEN, value), Some(token.hash));
        let other = issue(SESSION_TOKEN).unwrap();
        assert_ne!(other.value.expose_secret(), value);
        assert_eq!(issue(LOGIN_CODE).unwrap().value.expose_secret().len(), 47);
    }

    #[test]
    fn refuses_presented_values_of_another_shape() {
        let token = issue(SESSION_TOKEN).unwrap();
        let value = token.value.expose_secret();
        let body = value.strip_prefix("kbs_").unwrap();
        for bad in [
            format!("kbc_{body}"),
            body.to_owned(),
            format!("kbs_{body}x"),
            format!("kbs_{}", body.get(1..).unwrap()),
            format!("kbs_{}+", body.get(1..).unwrap()),
            format!("kbs_{}=", body.get(1..).unwrap()),
            String::new(),
            "kbs_".to_owned(),
        ] {
            assert_eq!(presented(SESSION_TOKEN, &bad), None, "{bad}");
        }
    }

    #[test]
    fn hashes_with_sha256() {
        assert_eq!(
            base64::encode_url(&hash("abc")),
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
        );
    }

    #[test]
    fn computes_the_rfc_7636_pkce_challenge() {
        let verifier = SecretString::from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(
            pkce_challenge(&verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
