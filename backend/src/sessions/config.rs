//! Settings of the login flow and kanbot sessions: the confidential OIDC
//! client (`OIDC_CLIENT_*`, `OIDC_SCOPES`), `PUBLIC_URL`, the session
//! encryption keys and the session lifetimes.

use std::{env::VarError, fmt, net::IpAddr, path::Path, time::Duration};

use reqwest::Url;
use secrecy::{ExposeSecret, SecretBox, SecretString};

use crate::{
    base64,
    config::{ConfigError, optional, required},
};

const DEFAULT_SCOPES: &str = "openid profile email offline_access";
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_hours(7 * 24);
const DEFAULT_ABSOLUTE_TIMEOUT: Duration = Duration::from_hours(30 * 24);
/// Length of a session encryption key, in bytes.
pub const KEY_BYTES: usize = 32;

/// The login flow's settings.
pub struct SessionConfig {
    /// `OIDC_CLIENT_ID`: kanbot's confidential client.
    pub client_id: String,
    /// `OIDC_CLIENT_SECRET` or the contents of `OIDC_CLIENT_SECRET_FILE`.
    pub client_secret: SecretString,
    /// `OIDC_SCOPES`, space-separated.
    pub scopes: Vec<String>,
    /// `PUBLIC_URL`: kanbot's external base URL, without a trailing slash.
    pub public_url: PublicUrl,
    /// `SESSION_ENCRYPTION_KEYS` or `SESSION_ENCRYPTION_KEYS_FILE`.
    pub keys: SessionKeys,
    /// `SESSION_IDLE_TIMEOUT` (default `7d`).
    pub idle_timeout: Duration,
    /// `SESSION_ABSOLUTE_TIMEOUT` (default `30d`).
    pub absolute_timeout: Duration,
}

/// Why a session setting was refused. Never contains a secret.
#[derive(Debug, thiserror::Error)]
pub enum SessionConfigError {
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("set {0} or {0}_FILE, not both")]
    Both(&'static str),
    #[error("{0} or {0}_FILE is required")]
    Missing(&'static str),
    #[error("{name} {path:?} cannot be read")]
    FileUnreadable {
        name: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "PUBLIC_URL must be an https URL (or http on localhost or a loopback address) \
         without credentials, query or fragment"
    )]
    PublicUrl,
    #[error(
        "SESSION_ENCRYPTION_KEYS must be comma-separated <key id>:<base64 of 32 bytes> entries \
         with distinct key ids of letters, digits, - and _"
    )]
    Keys,
    #[error("{0} must be a duration such as 30m, 12h or 7d")]
    Duration(&'static str),
    #[error("SESSION_IDLE_TIMEOUT must not exceed SESSION_ABSOLUTE_TIMEOUT")]
    IdleAboveAbsolute,
    #[error("OIDC_SCOPES must include openid")]
    ScopesWithoutOpenid,
}

impl SessionConfig {
    /// Reads the login flow's variables through `lookup` (see
    /// [`crate::config::Config::from_lookup`]).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a required variable is missing or any
    /// value is invalid.
    pub fn from_lookup(
        lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    ) -> Result<Self, ConfigError> {
        let client_id = required(lookup, "OIDC_CLIENT_ID")?.trim().to_owned();
        if client_id.is_empty() {
            return Err(SessionConfigError::Empty("OIDC_CLIENT_ID").into());
        }
        let client_secret = secret(lookup, "OIDC_CLIENT_SECRET", "OIDC_CLIENT_SECRET_FILE")?;
        if client_secret.trim().is_empty() {
            return Err(SessionConfigError::Empty("OIDC_CLIENT_SECRET").into());
        }
        let client_secret = SecretString::from(client_secret.trim().to_owned());

        let scopes: Vec<String> = optional(lookup, "OIDC_SCOPES")?
            .filter(|raw| !raw.trim().is_empty())
            .as_deref()
            .unwrap_or(DEFAULT_SCOPES)
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        if !scopes.iter().any(|scope| scope == "openid") {
            return Err(SessionConfigError::ScopesWithoutOpenid.into());
        }

        let public_url = PublicUrl::parse(&required(lookup, "PUBLIC_URL")?)?;
        let keys = SessionKeys::parse(&secret(
            lookup,
            "SESSION_ENCRYPTION_KEYS",
            "SESSION_ENCRYPTION_KEYS_FILE",
        )?)?;
        let idle_timeout = duration(lookup, "SESSION_IDLE_TIMEOUT", DEFAULT_IDLE_TIMEOUT)?;
        let absolute_timeout =
            duration(lookup, "SESSION_ABSOLUTE_TIMEOUT", DEFAULT_ABSOLUTE_TIMEOUT)?;
        if idle_timeout > absolute_timeout {
            return Err(SessionConfigError::IdleAboveAbsolute.into());
        }
        Ok(Self {
            client_id,
            client_secret,
            scopes,
            public_url,
            keys,
            idle_timeout,
            absolute_timeout,
        })
    }
}

/// A secret given directly in `name` or in the file named by `file_name`.
fn secret(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
    file_name: &'static str,
) -> Result<String, ConfigError> {
    let direct = optional(lookup, name)?.filter(|value| !value.is_empty());
    let file = optional(lookup, file_name)?.filter(|value| !value.trim().is_empty());
    match (direct, file) {
        (Some(_), Some(_)) => Err(SessionConfigError::Both(name).into()),
        (Some(value), None) => Ok(value),
        (None, Some(path)) => std::fs::read_to_string(Path::new(path.trim())).map_err(|source| {
            SessionConfigError::FileUnreadable {
                name: file_name,
                path: path.trim().to_owned(),
                source,
            }
            .into()
        }),
        (None, None) => Err(SessionConfigError::Missing(name).into()),
    }
}

/// `30s`, `15m`, `12h` or `7d`; positive.
fn duration(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
    default: Duration,
) -> Result<Duration, ConfigError> {
    let Some(raw) = optional(lookup, name)?.filter(|raw| !raw.trim().is_empty()) else {
        return Ok(default);
    };
    parse_duration(raw.trim()).ok_or_else(|| SessionConfigError::Duration(name).into())
}

fn parse_duration(raw: &str) -> Option<Duration> {
    let unit_at = raw.len().checked_sub(1)?;
    let (number, unit) = (raw.get(..unit_at)?, raw.get(unit_at..)?);
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number: u64 = number.parse().ok()?;
    let seconds_per_unit: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    let seconds = number.checked_mul(seconds_per_unit)?;
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

/// Kanbot's external base URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicUrl(Url);

impl PublicUrl {
    /// `https`, or `http` on `localhost` or a loopback address (browsers
    /// treat those as secure, so `__Host-` cookies still work). No
    /// credentials, query or fragment. A trailing slash is ignored.
    ///
    /// # Errors
    ///
    /// [`SessionConfigError::PublicUrl`] otherwise.
    pub fn parse(raw: &str) -> Result<Self, SessionConfigError> {
        let raw = raw.trim().trim_end_matches('/');
        Url::parse(raw)
            .ok()
            .filter(|url| {
                let secure = match url.scheme() {
                    "https" => url.has_host(),
                    "http" => url.host_str().is_some_and(is_loopback_host),
                    _ => false,
                };
                secure
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
            .map(Self)
            .ok_or(SessionConfigError::PublicUrl)
    }

    /// `scheme://host[:port]`, as browsers send it in `Origin`.
    #[must_use]
    pub fn origin(&self) -> String {
        self.0.origin().ascii_serialization()
    }

    /// `<PUBLIC_URL>/<path>`, `path` without a leading slash.
    #[must_use]
    pub fn join(&self, path: &str) -> String {
        format!("{}/{path}", self.0.as_str().trim_end_matches('/'))
    }
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The ID that tags data encrypted with a key, so the key can be found
/// again after rotation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A session encryption key with its ID.
pub struct SessionKey {
    pub id: KeyId,
    pub key: SecretBox<[u8; KEY_BYTES]>,
}

/// The session encryption keys: the first encrypts, all decrypt.
pub struct SessionKeys {
    current: SessionKey,
    previous: Vec<SessionKey>,
}

impl fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionKeys")
            .field("current", &self.current.id)
            .field(
                "previous",
                &self.previous.iter().map(|key| &key.id).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl SessionKeys {
    /// Parses `kid:base64key[,kid:base64key...]`, surrounding whitespace
    /// ignored. Each key is 32 bytes of standard base64.
    ///
    /// # Errors
    ///
    /// [`SessionConfigError::Keys`] for anything else, an empty list, or a
    /// repeated key ID. The message never contains key material.
    pub fn parse(raw: &str) -> Result<Self, SessionConfigError> {
        let mut keys = Vec::new();
        for entry in raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (id, key) = entry.split_once(':').ok_or(SessionConfigError::Keys)?;
            let id = id.trim();
            if id.is_empty()
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || keys
                    .iter()
                    .any(|existing: &SessionKey| existing.id.as_str() == id)
            {
                return Err(SessionConfigError::Keys);
            }
            let bytes: [u8; KEY_BYTES] = base64::decode_standard(key.trim())
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or(SessionConfigError::Keys)?;
            keys.push(SessionKey {
                id: KeyId(id.to_owned()),
                key: SecretBox::new(Box::new(bytes)),
            });
        }
        let mut keys = keys.into_iter();
        let current = keys.next().ok_or(SessionConfigError::Keys)?;
        Ok(Self {
            current,
            previous: keys.collect(),
        })
    }

    /// The key that encrypts.
    #[must_use]
    pub fn current(&self) -> &SessionKey {
        &self.current
    }

    /// The key with `id`, to decrypt.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&SessionKey> {
        std::iter::once(&self.current)
            .chain(&self.previous)
            .find(|key| key.id.as_str() == id)
    }
}

impl SessionKey {
    /// The key bytes, for the cipher only.
    #[must_use]
    pub fn bytes(&self) -> &[u8; KEY_BYTES] {
        self.key.expose_secret()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// 32 bytes of 0x01 and of 0x02, as base64.
    const KEY_1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const KEY_2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    fn read(vars: &[(&'static str, &str)]) -> Result<SessionConfig, ConfigError> {
        let mut all: HashMap<&'static str, String> = [
            ("OIDC_CLIENT_ID", "kanbot".to_owned()),
            ("OIDC_CLIENT_SECRET", "secret".to_owned()),
            ("PUBLIC_URL", "https://kanbot.example.com".to_owned()),
            ("SESSION_ENCRYPTION_KEYS", format!("k1:{KEY_1}")),
        ]
        .into_iter()
        .collect();
        for (name, value) in vars {
            all.insert(name, (*value).to_owned());
        }
        all.retain(|_, value| value != "<unset>");
        SessionConfig::from_lookup(&move |name| all.get(name).cloned().ok_or(VarError::NotPresent))
    }

    fn error(result: Result<SessionConfig, ConfigError>) -> SessionConfigError {
        match result {
            Err(ConfigError::Session(error)) => error,
            Err(other) => panic!("expected a session error, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn reads_the_settings_with_defaults() {
        let config = read(&[]).unwrap();
        assert_eq!(config.client_id, "kanbot");
        assert_eq!(config.client_secret.expose_secret(), "secret");
        assert_eq!(
            config.scopes,
            ["openid", "profile", "email", "offline_access"]
        );
        assert_eq!(config.public_url.origin(), "https://kanbot.example.com");
        assert_eq!(config.keys.current().id.as_str(), "k1");
        assert_eq!(config.idle_timeout, Duration::from_hours(168));
        assert_eq!(config.absolute_timeout, Duration::from_hours(720));
    }

    #[test]
    fn requires_the_client_and_its_secret() {
        assert!(matches!(
            read(&[("OIDC_CLIENT_ID", "<unset>")]),
            Err(ConfigError::Var {
                name: "OIDC_CLIENT_ID",
                ..
            })
        ));
        assert!(matches!(
            error(read(&[("OIDC_CLIENT_ID", " ")])),
            SessionConfigError::Empty("OIDC_CLIENT_ID")
        ));
        assert!(matches!(
            error(read(&[("OIDC_CLIENT_SECRET", "<unset>")])),
            SessionConfigError::Missing("OIDC_CLIENT_SECRET")
        ));
        assert!(matches!(
            error(read(&[("OIDC_CLIENT_SECRET", " \n")])),
            SessionConfigError::Empty("OIDC_CLIENT_SECRET")
        ));
    }

    fn temp_file(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("kanbot-secret-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn reads_secrets_from_files() {
        let secret = temp_file("from-file\n");
        let keys = temp_file(&format!("k2:{KEY_2},k1:{KEY_1}\n"));
        let config = read(&[
            ("OIDC_CLIENT_SECRET", "<unset>"),
            ("OIDC_CLIENT_SECRET_FILE", secret.to_str().unwrap()),
            ("SESSION_ENCRYPTION_KEYS", "<unset>"),
            ("SESSION_ENCRYPTION_KEYS_FILE", keys.to_str().unwrap()),
        ])
        .unwrap();
        assert_eq!(config.client_secret.expose_secret(), "from-file");
        assert_eq!(config.keys.current().id.as_str(), "k2");
        assert_eq!(config.keys.get("k1").unwrap().bytes(), &[1; KEY_BYTES]);
        std::fs::remove_file(secret).unwrap();
        std::fs::remove_file(keys).unwrap();
    }

    #[test]
    fn refuses_a_secret_and_its_file_together_or_an_unreadable_file() {
        let secret = temp_file("x");
        assert!(matches!(
            error(read(&[(
                "OIDC_CLIENT_SECRET_FILE",
                secret.to_str().unwrap()
            )])),
            SessionConfigError::Both("OIDC_CLIENT_SECRET")
        ));
        std::fs::remove_file(secret).unwrap();
        let unreadable = error(read(&[
            ("OIDC_CLIENT_SECRET", "<unset>"),
            ("OIDC_CLIENT_SECRET_FILE", "/nonexistent/kanbot/secret"),
        ]));
        assert!(matches!(
            unreadable,
            SessionConfigError::FileUnreadable {
                name: "OIDC_CLIENT_SECRET_FILE",
                ..
            }
        ));
    }

    #[test]
    fn reads_scopes() {
        let config = read(&[("OIDC_SCOPES", " openid  groups offline_access ")]).unwrap();
        assert_eq!(config.scopes, ["openid", "groups", "offline_access"]);
        assert!(matches!(
            error(read(&[("OIDC_SCOPES", "profile groups")])),
            SessionConfigError::ScopesWithoutOpenid
        ));
    }

    #[test]
    fn public_url_must_be_secure() {
        for ok in [
            "https://kanbot.example.com",
            "https://kanbot.example.com/",
            "https://example.com/kanbot",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://[::1]:3000",
        ] {
            assert!(PublicUrl::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://kanbot.example.com",
            "http://10.0.0.1",
            "kanbot.example.com",
            "https://user:pw@kanbot.example.com",
            "https://kanbot.example.com?x=1",
            "https://kanbot.example.com#x",
            "ftp://kanbot.example.com",
        ] {
            assert!(
                matches!(PublicUrl::parse(bad), Err(SessionConfigError::PublicUrl)),
                "{bad}"
            );
        }
    }

    #[test]
    fn public_url_joins_paths_and_has_an_origin() {
        let url = PublicUrl::parse("https://example.com:8443/kanbot/").unwrap();
        assert_eq!(
            url.join("auth/callback"),
            "https://example.com:8443/kanbot/auth/callback"
        );
        assert_eq!(url.origin(), "https://example.com:8443");
        let root = PublicUrl::parse("https://kanbot.example.com").unwrap();
        assert_eq!(
            root.join("auth/callback"),
            "https://kanbot.example.com/auth/callback"
        );
    }

    #[test]
    fn parses_session_keys() {
        let keys = SessionKeys::parse(&format!(" new:{KEY_2} , old:{KEY_1} ,")).unwrap();
        assert_eq!(keys.current().id.as_str(), "new");
        assert_eq!(keys.current().bytes(), &[2; KEY_BYTES]);
        assert_eq!(keys.get("old").unwrap().bytes(), &[1; KEY_BYTES]);
        assert_eq!(keys.get("new").unwrap().bytes(), &[2; KEY_BYTES]);
        assert!(keys.get("other").is_none());
        let debug = format!("{keys:?}");
        assert!(debug.contains("new") && !debug.contains("AgIC"), "{debug}");
    }

    #[test]
    fn refuses_bad_session_keys() {
        let short = "AQEBAQ==";
        for bad in [
            String::new(),
            " , ".to_owned(),
            KEY_1.to_owned(),
            format!(":{KEY_1}"),
            format!("k 1:{KEY_1}"),
            format!("k1:{short}"),
            "k1:not base64!".to_owned(),
            format!("k1:{KEY_1},k1:{KEY_2}"),
        ] {
            assert!(
                matches!(SessionKeys::parse(&bad), Err(SessionConfigError::Keys)),
                "{bad}"
            );
            let message = SessionKeys::parse(&bad).err().unwrap().to_string();
            assert!(!message.contains("AQEB"), "{message}");
        }
    }

    #[test]
    fn parses_durations() {
        for (raw, seconds) in [("30s", 30), ("15m", 900), ("12h", 43_200), ("7d", 604_800)] {
            assert_eq!(
                parse_duration(raw),
                Some(Duration::from_secs(seconds)),
                "{raw}"
            );
        }
        for bad in [
            "",
            "d",
            "7",
            "0d",
            "-1d",
            "+1d",
            "1.5h",
            "7w",
            "7 d",
            "99999999999999999999d",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
    }

    #[test]
    fn reads_timeouts() {
        let config = read(&[
            ("SESSION_IDLE_TIMEOUT", "1h"),
            ("SESSION_ABSOLUTE_TIMEOUT", "2d"),
        ])
        .unwrap();
        assert_eq!(config.idle_timeout, Duration::from_hours(1));
        assert_eq!(config.absolute_timeout, Duration::from_hours(48));
        assert!(matches!(
            error(read(&[("SESSION_IDLE_TIMEOUT", "soon")])),
            SessionConfigError::Duration("SESSION_IDLE_TIMEOUT")
        ));
        assert!(matches!(
            error(read(&[("SESSION_IDLE_TIMEOUT", "31d")])),
            SessionConfigError::IdleAboveAbsolute
        ));
    }
}
