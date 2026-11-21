//! Runtime configuration, read from environment variables.

use std::{
    env::VarError,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

use axum::http::HeaderValue;
use reqwest::Url;
use secrecy::SecretString;

use crate::{
    auth::config::{OidcConfig, OidcConfigError},
    authz::policies::{Policies, PolicyError},
    http::{
        client_ip::{InvalidNetwork, TrustedProxies},
        middleware::rate_limit::{RateLimit, RateLimits},
    },
    sessions::config::{SessionConfig, SessionConfigError},
};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:3000";
const DEFAULT_MAX_IN_FLIGHT_REQUESTS: NonZeroUsize = match NonZeroUsize::new(512) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_DATABASE_MAX_CONNECTIONS: NonZeroU32 = match NonZeroU32::new(10) {
    Some(value) => value,
    None => NonZeroU32::MIN,
};

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
    /// The OIDC identity provider (`OIDC_*`).
    pub oidc: OidcConfig,
    /// Rate limits (`RATE_LIMIT_*`).
    pub rate_limits: RateLimits,
    /// Requests handled at once by this instance before new ones get a 503
    /// (`MAX_IN_FLIGHT_REQUESTS`, default 512).
    pub max_in_flight_requests: NonZeroUsize,
    /// Database pool size of this instance (`DATABASE_MAX_CONNECTIONS`,
    /// default 10).
    pub database_max_connections: NonZeroU32,
    /// The login flow and sessions (`OIDC_CLIENT_*`, `PUBLIC_URL`,
    /// `SESSION_*`).
    pub sessions: SessionConfig,
    /// The Flutter web build to serve at `/` (`WEB_DIR`, default off).
    /// Holds an `index.html`.
    pub web_dir: Option<PathBuf>,
    /// The built-in policies plus the deployer's `forbid` policies from
    /// `AUTHZ_POLICY_FILE`, if set.
    pub authz: Policies,
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
    #[error("{0} must be a positive whole number")]
    NotPositive(&'static str),
    #[error(transparent)]
    Oidc(#[from] OidcConfigError),
    #[error(transparent)]
    Session(#[from] SessionConfigError),
    #[error("WEB_DIR {0:?} is not a directory with an index.html")]
    WebDir(String),
    #[error("AUTHZ_POLICY_FILE {path:?} cannot be read")]
    AuthzPolicyFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Authz(#[from] PolicyError),
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

        let oidc = OidcConfig::from_lookup(&lookup)?;
        let sessions = SessionConfig::from_lookup(&lookup)?;
        if sessions.client_id == oidc.audience.as_str() {
            return Err(OidcConfigError::AudienceIsClient.into());
        }
        let web_dir = match optional(&lookup, "WEB_DIR")? {
            Some(raw) if !raw.trim().is_empty() => {
                let dir = PathBuf::from(raw.trim());
                if !dir.join("index.html").is_file() {
                    return Err(ConfigError::WebDir(raw.trim().to_owned()));
                }
                Some(dir)
            }
            _ => None,
        };

        let authz = authz_policies(&lookup)?;

        let rate_limits = RateLimits {
            ip: rate_limit(
                &lookup,
                ("RATE_LIMIT_IP_PER_SECOND", "RATE_LIMIT_IP_BURST"),
                RateLimits::DEFAULT.ip,
            )?,
            auth_failure: rate_limit(
                &lookup,
                (
                    "RATE_LIMIT_AUTH_FAILURE_PER_SECOND",
                    "RATE_LIMIT_AUTH_FAILURE_BURST",
                ),
                RateLimits::DEFAULT.auth_failure,
            )?,
            login: rate_limit(
                &lookup,
                ("RATE_LIMIT_LOGIN_PER_SECOND", "RATE_LIMIT_LOGIN_BURST"),
                RateLimits::DEFAULT.login,
            )?,
            user: rate_limit(
                &lookup,
                ("RATE_LIMIT_USER_PER_SECOND", "RATE_LIMIT_USER_BURST"),
                RateLimits::DEFAULT.user,
            )?,
            telemetry: rate_limit(
                &lookup,
                (
                    "RATE_LIMIT_TELEMETRY_PER_SECOND",
                    "RATE_LIMIT_TELEMETRY_BURST",
                ),
                RateLimits::DEFAULT.telemetry,
            )?,
        };
        let max_in_flight_requests = match optional(&lookup, "MAX_IN_FLIGHT_REQUESTS")? {
            Some(raw) => positive_usize("MAX_IN_FLIGHT_REQUESTS", &raw)?,
            None => DEFAULT_MAX_IN_FLIGHT_REQUESTS,
        };
        let database_max_connections = match optional(&lookup, "DATABASE_MAX_CONNECTIONS")? {
            Some(raw) => positive_u32("DATABASE_MAX_CONNECTIONS", &raw)?,
            None => DEFAULT_DATABASE_MAX_CONNECTIONS,
        };

        Ok(Self {
            listen_addr,
            database_url,
            cors_allowed_origins,
            trusted_proxies,
            telemetry_relay_upstream,
            oidc,
            rate_limits,
            max_in_flight_requests,
            database_max_connections,
            sessions,
            web_dir,
            authz,
        })
    }
}

/// A rate limit from its `_PER_SECOND` and `_BURST` variables, each
/// defaulting on its own.
fn rate_limit(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    (per_second_name, burst_name): (&'static str, &'static str),
    default: RateLimit,
) -> Result<RateLimit, ConfigError> {
    let per_second = match optional(lookup, per_second_name)? {
        Some(raw) => positive_u32(per_second_name, &raw)?,
        None => default.per_second,
    };
    let burst = match optional(lookup, burst_name)? {
        Some(raw) => positive_u32(burst_name, &raw)?,
        None => default.burst,
    };
    Ok(RateLimit { per_second, burst })
}

/// A whole number above zero. Zero, a sign, or anything else is refused.
pub(crate) fn positive(name: &'static str, raw: &str) -> Result<NonZeroU64, ConfigError> {
    let raw = raw.trim();
    raw.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| raw.parse::<NonZeroU64>().ok())
        .flatten()
        .ok_or(ConfigError::NotPositive(name))
}

fn positive_u32(name: &'static str, raw: &str) -> Result<NonZeroU32, ConfigError> {
    NonZeroU32::try_from(positive(name, raw)?).map_err(|_| ConfigError::NotPositive(name))
}

fn positive_usize(name: &'static str, raw: &str) -> Result<NonZeroUsize, ConfigError> {
    NonZeroUsize::try_from(positive(name, raw)?).map_err(|_| ConfigError::NotPositive(name))
}

/// Reads a variable that must be present.
pub(crate) fn required(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
) -> Result<String, ConfigError> {
    lookup(name).map_err(|source| ConfigError::Var { name, source })
}

/// Reads a variable that may be absent. Present but not UTF-8 is an error.
pub(crate) fn optional(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
) -> Result<Option<String>, ConfigError> {
    match lookup(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(source) => Err(ConfigError::Var { name, source }),
    }
}

/// The built-in policies, plus the deployer's from `AUTHZ_POLICY_FILE`.
fn authz_policies(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
) -> Result<Policies, ConfigError> {
    match optional(lookup, "AUTHZ_POLICY_FILE")? {
        Some(raw) if !raw.trim().is_empty() => {
            let path = raw.trim();
            let text =
                std::fs::read_to_string(path).map_err(|source| ConfigError::AuthzPolicyFile {
                    path: path.to_owned(),
                    source,
                })?;
            Ok(Policies::with_deployer(&text)?)
        }
        _ => Ok(Policies::builtin()?),
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

    /// The required `OIDC_*` variables, which these tests do not cover
    /// (see `auth::config`).
    const OIDC: [(&str, &str); 9] = [
        ("OIDC_ISSUER", "https://auth.example.com"),
        ("OIDC_AUDIENCE", "kanbot-api"),
        ("OIDC_ROLES_CLAIM", "groups"),
        ("OIDC_ADMIN_ROLE", "kanbot-admin"),
        ("OIDC_USER_ROLE", "kanbot-user"),
        ("OIDC_CLIENT_ID", "kanbot"),
        ("OIDC_CLIENT_SECRET", "secret"),
        ("PUBLIC_URL", "https://kanbot.example.com"),
        (
            "SESSION_ENCRYPTION_KEYS",
            "k1:AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        ),
    ];

    fn lookup(vars: &[(&'static str, &str)]) -> impl Fn(&'static str) -> Result<String, VarError> {
        let vars: HashMap<_, _> = OIDC
            .iter()
            .chain(vars)
            .map(|(k, v)| (*k, (*v).to_owned()))
            .collect();
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

    #[test]
    fn defaults_limits_and_pool_size() {
        let config = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://db")])).unwrap();
        assert_eq!(config.rate_limits, RateLimits::DEFAULT);
        assert_eq!(config.rate_limits.ip.per_second.get(), 2000);
        assert_eq!(config.rate_limits.ip.burst.get(), 4000);
        assert_eq!(config.rate_limits.auth_failure.per_second.get(), 50);
        assert_eq!(config.rate_limits.auth_failure.burst.get(), 500);
        assert_eq!(config.rate_limits.login.per_second.get(), 100);
        assert_eq!(config.rate_limits.login.burst.get(), 500);
        assert_eq!(config.rate_limits.user.per_second.get(), 20);
        assert_eq!(config.rate_limits.user.burst.get(), 100);
        assert_eq!(config.rate_limits.telemetry.per_second.get(), 1);
        assert_eq!(config.rate_limits.telemetry.burst.get(), 20);
        assert_eq!(config.max_in_flight_requests.get(), 512);
        assert_eq!(config.database_max_connections.get(), 10);
    }

    #[test]
    fn reads_limits_and_pool_size() {
        let config = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("RATE_LIMIT_IP_PER_SECOND", "1"),
            ("RATE_LIMIT_IP_BURST", "2"),
            ("RATE_LIMIT_AUTH_FAILURE_PER_SECOND", "3"),
            ("RATE_LIMIT_AUTH_FAILURE_BURST", "4"),
            ("RATE_LIMIT_USER_PER_SECOND", "5"),
            ("RATE_LIMIT_USER_BURST", "6"),
            ("RATE_LIMIT_TELEMETRY_PER_SECOND", "7"),
            ("RATE_LIMIT_TELEMETRY_BURST", " 8 "),
            ("RATE_LIMIT_LOGIN_PER_SECOND", "12"),
            ("RATE_LIMIT_LOGIN_BURST", "13"),
            ("MAX_IN_FLIGHT_REQUESTS", "9"),
            ("DATABASE_MAX_CONNECTIONS", "11"),
        ]))
        .unwrap();
        let limits = config.rate_limits;
        let pairs = [
            limits.ip,
            limits.auth_failure,
            limits.user,
            limits.telemetry,
        ]
        .map(|limit| (limit.per_second.get(), limit.burst.get()));
        assert_eq!(pairs, [(1, 2), (3, 4), (5, 6), (7, 8)]);
        assert_eq!(
            (limits.login.per_second.get(), limits.login.burst.get()),
            (12, 13)
        );
        assert_eq!(config.max_in_flight_requests.get(), 9);
        assert_eq!(config.database_max_connections.get(), 11);
    }

    #[test]
    fn rejects_zero_or_non_numeric_limits() {
        for name in [
            "RATE_LIMIT_IP_PER_SECOND",
            "RATE_LIMIT_IP_BURST",
            "RATE_LIMIT_AUTH_FAILURE_PER_SECOND",
            "RATE_LIMIT_AUTH_FAILURE_BURST",
            "RATE_LIMIT_USER_PER_SECOND",
            "RATE_LIMIT_USER_BURST",
            "RATE_LIMIT_TELEMETRY_PER_SECOND",
            "RATE_LIMIT_TELEMETRY_BURST",
            "RATE_LIMIT_LOGIN_PER_SECOND",
            "RATE_LIMIT_LOGIN_BURST",
            "MAX_IN_FLIGHT_REQUESTS",
            "DATABASE_MAX_CONNECTIONS",
        ] {
            for bad in ["0", "", "-1", "+5", "1.5", "ten", "99999999999999999999"] {
                let result =
                    Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://db"), (name, bad)]));
                assert!(
                    matches!(result, Err(ConfigError::NotPositive(n)) if n == name),
                    "{name}={bad}"
                );
            }
        }
    }

    #[test]
    fn refuses_the_audience_as_the_client_id() {
        let result = Config::from_lookup(lookup(&[
            ("DATABASE_URL", "postgres://db"),
            ("OIDC_CLIENT_ID", "kanbot-api"),
        ]));
        assert!(matches!(
            result,
            Err(ConfigError::Oidc(OidcConfigError::AudienceIsClient))
        ));
    }

    #[test]
    fn reads_the_web_dir() {
        let dir = std::env::temp_dir().join(format!("kanbot-web-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.to_str().unwrap().to_owned();
        let web_dir = |raw: &str| {
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://db"),
                ("WEB_DIR", raw),
            ]))
            .map(|config| config.web_dir)
        };
        assert!(matches!(web_dir(&path), Err(ConfigError::WebDir(p)) if p == path));
        std::fs::write(dir.join("index.html"), "<!doctype html>").unwrap();
        assert_eq!(web_dir(&path).unwrap(), Some(dir.clone()));
        assert_eq!(web_dir(" ").unwrap(), None);
        assert!(matches!(
            web_dir("/nonexistent/kanbot/web"),
            Err(ConfigError::WebDir(_))
        ));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reads_the_deployer_policies() {
        let dir = std::env::temp_dir().join(format!("kanbot-authz-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("policies.cedar");
        let path = file.to_str().unwrap().to_owned();
        let authz = |raw: &str| {
            Config::from_lookup(lookup(&[
                ("DATABASE_URL", "postgres://db"),
                ("AUTHZ_POLICY_FILE", raw),
            ]))
            .map(|config| config.authz)
        };
        assert!(matches!(
            authz(&path).err(),
            Some(ConfigError::AuthzPolicyFile { path: p, .. }) if p == path
        ));
        std::fs::write(&file, r#"@id("all") permit (principal, action, resource);"#).unwrap();
        assert!(matches!(
            authz(&format!(" {path} ")).err(),
            Some(ConfigError::Authz(PolicyError::Permit(_)))
        ));
        std::fs::write(
            &file,
            r#"@id("none") forbid (principal, action, resource);"#,
        )
        .unwrap();
        let policies = authz(&path).ok().unwrap();
        assert_eq!(policies.deployer_policy_ids(), ["deployer.none"]);
        assert_eq!(
            authz(" ").ok().unwrap().deployer_policy_ids(),
            Vec::<String>::new()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn defaults_without_a_web_dir() {
        let config = Config::from_lookup(lookup(&[("DATABASE_URL", "postgres://db")])).unwrap();
        assert_eq!(config.web_dir, None);
        assert_eq!(config.sessions.client_id, "kanbot");
    }

    #[test]
    fn requires_oidc() {
        let err = Config::from_lookup(|name| match name {
            "DATABASE_URL" => Ok("postgres://db".to_owned()),
            _ => Err(VarError::NotPresent),
        })
        .err()
        .unwrap();
        assert!(matches!(
            err,
            ConfigError::Var {
                name: "OIDC_ISSUER",
                source: VarError::NotPresent
            }
        ));
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
