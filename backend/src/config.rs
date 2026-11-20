//! Runtime configuration, read from environment variables.

use std::{env::VarError, net::SocketAddr};

use axum::http::HeaderValue;
use reqwest::Url;
use secrecy::SecretString;

use crate::http::client_ip::{InvalidNetwork, TrustedProxies};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:3000";

/// Runtime configuration.
pub struct Config {
    /// Address the HTTP server binds to (`LISTEN_ADDR`, default
    /// `127.0.0.1:3000`).
    pub listen_addr: SocketAddr,
    /// PostgreSQL connection string (`DATABASE_URL`).
    pub database_url: SecretString,
    /// Browser origins allowed to call the API cross-origin
    /// (`CORS_ALLOWED_ORIGINS`, comma-separated, default none), for example
    /// `https://app.example.com,http://localhost:8080`.
    pub cors_allowed_origins: Vec<HeaderValue>,
    /// Reverse proxies whose `X-Forwarded-For` header is trusted
    /// (`TRUSTED_PROXIES`, comma-separated IP addresses and CIDR networks,
    /// default none). Without them, the connection's address is the client.
    pub trusted_proxies: TrustedProxies,
    /// OTLP/HTTP collector that `/telemetry/v1/*` relays the app's telemetry
    /// to (`TELEMETRY_RELAY_UPSTREAM`, for example `http://collector:4318`).
    /// Unset: the relay is off and those routes do not exist.
    pub telemetry_relay_upstream: Option<Url>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("environment variable {name} is missing or not valid UTF-8")]
    Var {
        name: &'static str,
        #[source]
        source: VarError,
    },
    #[error("LISTEN_ADDR is not a valid socket address")]
    ListenAddr(#[source] std::net::AddrParseError),
    #[error(
        "CORS_ALLOWED_ORIGINS entry {0:?} is not an origin such as https://app.example.com \
         (scheme and host, optional port, no path or trailing slash)"
    )]
    CorsOrigin(String),
    #[error("TRUSTED_PROXIES is invalid")]
    TrustedProxies(#[source] InvalidNetwork),
    #[error(
        "TELEMETRY_RELAY_UPSTREAM is not an http or https URL without credentials, query or fragment"
    )]
    RelayUpstream,
}

impl Config {
    /// Reads the configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a required variable is missing or invalid.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(std::env::var)
    }

    /// Reads the configuration through `lookup`, which behaves like
    /// [`std::env::var`]. Tests use this instead of changing the process
    /// environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a required variable is missing or invalid.
    pub fn from_lookup(
        lookup: impl Fn(&'static str) -> Result<String, VarError>,
    ) -> Result<Self, ConfigError> {
        let listen_addr = optional(&lookup, "LISTEN_ADDR")?
            .as_deref()
            .unwrap_or(DEFAULT_LISTEN_ADDR)
            .parse()
            .map_err(ConfigError::ListenAddr)?;

        let database_url = lookup("DATABASE_URL")
            .map(SecretString::from)
            .map_err(|source| ConfigError::Var {
                name: "DATABASE_URL",
                source,
            })?;

        let cors_allowed_origins = optional(&lookup, "CORS_ALLOWED_ORIGINS")?
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(parse_origin)
            .collect::<Result<_, _>>()?;

        let trusted_proxies =
            TrustedProxies::parse_list(&optional(&lookup, "TRUSTED_PROXIES")?.unwrap_or_default())
                .map_err(ConfigError::TrustedProxies)?;

        let telemetry_relay_upstream = optional(&lookup, "TELEMETRY_RELAY_UPSTREAM")?
            .filter(|raw| !raw.trim().is_empty())
            .map(|raw| parse_upstream(&raw))
            .transpose()?;

        Ok(Self {
            listen_addr,
            database_url,
            cors_allowed_origins,
            trusted_proxies,
            telemetry_relay_upstream,
        })
    }
}

/// Reads a variable that may be absent. Present but not UTF-8 is an error.
fn optional(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
) -> Result<Option<String>, ConfigError> {
    match lookup(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(source) => Err(ConfigError::Var { name, source }),
    }
}

/// Accepts `http://` or `https://` followed by a host and optional port, the
/// exact form browsers send in the `Origin` header. Rejects `*`, paths and
/// trailing slashes, which would never match a request.
fn parse_origin(raw: &str) -> Result<HeaderValue, ConfigError> {
    let origin = raw.to_ascii_lowercase();
    let host = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .filter(|host| {
            !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        });
    host.and_then(|_| HeaderValue::from_str(&origin).ok())
        .ok_or_else(|| ConfigError::CorsOrigin(raw.to_owned()))
}

/// An `http(s)` base URL. Credentials belong in the collector's network
/// setup, not in a URL that could end up in logs.
fn parse_upstream(raw: &str) -> Result<Url, ConfigError> {
    Url::parse(raw.trim())
        .ok()
        .filter(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.has_host()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
        .ok_or(ConfigError::RelayUpstream)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::*;
    use secrecy::ExposeSecret;

    use super::*;

    fn lookup(vars: &[(&'static str, &str)]) -> impl Fn(&'static str) -> Result<String, VarError> {
        let vars: HashMap<_, _> = vars.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
        move |name| vars.get(name).cloned().ok_or(VarError::NotPresent)
    }

    #[test]
    fn defaults_listen_addr() {
        let config = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://db")])).unwrap();
        assert_eq!(config.listen_addr, DEFAULT_LISTEN_ADDR.parse().unwrap());
        assert_eq!(config.database_url.expose_secret(), "postgres://db");
        assert_eq!(config.cors_allowed_origins, Vec::<HeaderValue>::new());
    }

    #[test]
    fn reads_listen_addr() {
        let config = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("LISTEN_ADDR", "0.0.0.0:8080"),
        ]))
        .unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:8080".parse().unwrap());
    }

    #[test]
    fn rejects_invalid_listen_addr() {
        let err = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("LISTEN_ADDR", "not-an-addr"),
        ]))
        .err()
        .unwrap();
        assert!(matches!(err, ConfigError::ListenAddr(_)));
    }

    #[test]
    fn requires_database_url() {
        let err = Config::from_lookup(lookup(&[])).err().unwrap();
        assert!(matches!(
            err,
            ConfigError::Var {
                name: "DATABASE_URL",
                source: VarError::NotPresent
            }
        ));
    }

    #[test]
    fn rejects_non_utf8_listen_addr() {
        let err = Config::from_lookup(|_| Err(VarError::NotUnicode(std::ffi::OsString::from("x"))))
            .err()
            .unwrap();
        assert!(matches!(
            err,
            ConfigError::Var {
                name: "LISTEN_ADDR",
                source: VarError::NotUnicode(_)
            }
        ));
    }

    fn origins(raw: &str) -> Result<Vec<HeaderValue>, ConfigError> {
        Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("CORS_ALLOWED_ORIGINS", raw),
        ]))
        .map(|config| config.cors_allowed_origins)
    }

    #[test]
    fn reads_cors_origins() {
        let origins =
            origins(" https://app.example.com , http://localhost:8080,,HTTPS://Upper.Example ")
                .unwrap();
        assert_eq!(
            origins,
            [
                "https://app.example.com",
                "http://localhost:8080",
                "https://upper.example",
            ]
        );
    }

    #[test]
    fn empty_cors_origins_allow_none() {
        assert_eq!(origins("").unwrap(), Vec::<HeaderValue>::new());
    }

    #[test]
    fn rejects_invalid_cors_origins() {
        for bad in [
            "*",
            "app.example.com",
            "ftp://app.example.com",
            "https://",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://user@app.example.com",
            "https://app example.com",
        ] {
            let err = origins(bad).err().unwrap();
            assert!(
                matches!(&err, ConfigError::CorsOrigin(entry) if entry == bad),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_non_utf8_cors_origins() {
        let err = Config::from_lookup(|name| match name {
            "DATABASE_URL" => Ok("postgres://db".to_owned()),
            "CORS_ALLOWED_ORIGINS" => Err(VarError::NotUnicode(std::ffi::OsString::from("x"))),
            _ => Err(VarError::NotPresent),
        })
        .err()
        .unwrap();
        assert!(matches!(
            err,
            ConfigError::Var {
                name: "CORS_ALLOWED_ORIGINS",
                source: VarError::NotUnicode(_)
            }
        ));
    }

    #[test]
    fn reads_trusted_proxies() {
        let config = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("TRUSTED_PROXIES", "10.0.0.0/8, ::1"),
        ]))
        .unwrap();
        assert!(config.trusted_proxies.contains("10.9.9.9".parse().unwrap()));
        assert!(config.trusted_proxies.contains("::1".parse().unwrap()));
        assert!(!config.trusted_proxies.contains("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn trusts_no_proxy_by_default() {
        let config = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://db")])).unwrap();
        assert_eq!(config.trusted_proxies, TrustedProxies::default());
        assert_eq!(config.telemetry_relay_upstream, None);
    }

    #[test]
    fn rejects_invalid_trusted_proxies() {
        let err = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("TRUSTED_PROXIES", "10.0.0.0/8, nope"),
        ]))
        .err()
        .unwrap();
        assert!(
            matches!(err, ConfigError::TrustedProxies(InvalidNetwork(entry)) if entry == "nope")
        );
    }

    fn upstream(raw: &str) -> Result<Option<Url>, ConfigError> {
        Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("TELEMETRY_RELAY_UPSTREAM", raw),
        ]))
        .map(|config| config.telemetry_relay_upstream)
    }

    #[test]
    fn reads_relay_upstream() {
        for raw in [
            "http://collector:4318",
            "https://otel.example.com/otlp/",
            " http://127.0.0.1:4318 ",
        ] {
            assert_eq!(
                upstream(raw)
                    .unwrap()
                    .unwrap()
                    .as_str()
                    .trim_end_matches('/'),
                raw.trim().trim_end_matches('/'),
                "{raw}"
            );
        }
        assert_eq!(upstream("").unwrap(), None);
    }

    #[test]
    fn rejects_invalid_relay_upstream() {
        for bad in [
            "collector:4318",
            "ftp://collector",
            "http://user:secret@collector:4318",
            "http://collector:4318?x=1",
            "http://collector:4318#x",
            "not a url",
        ] {
            let err = upstream(bad).err().unwrap();
            assert!(matches!(err, ConfigError::RelayUpstream), "{bad}");
            assert!(!err.to_string().contains("secret"), "{err}");
        }
    }

    proptest! {
        #[test]
        fn accepts_well_formed_origins(
            origin in "https?://[a-z0-9-]{1,20}(\\.[a-z]{2,6}){0,2}(:[0-9]{1,5})?"
        ) {
            prop_assert_eq!(origins(&origin).unwrap(), [origin.as_str()]);
        }

        #[test]
        fn rejects_origins_with_a_path(
            origin in "https?://[a-z0-9-]{1,20}/[a-z0-9/]{0,10}"
        ) {
            prop_assert!(origins(&origin).is_err());
        }

        #[test]
        fn never_panics(raw in "\\PC*") {
            let _ = origins(&raw);
        }
    }
}
