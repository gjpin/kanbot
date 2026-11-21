//! OIDC settings (`OIDC_*`), validated at startup. A value that is set but
//! invalid stops the server: it never falls back to a default.

use std::{env::VarError, net::IpAddr, path::Path, time::Duration};

use reqwest::{Certificate, Url};
use serde_json::{Map, Value};

use crate::config::{ConfigError, optional, required};

const DEFAULT_SUBJECT_CLAIM: &str = "sub";
const DEFAULT_JWKS_TTL: Duration = Duration::from_secs(3600);

/// The OIDC identity provider and the rules tokens from it must follow.
pub struct OidcConfig {
    /// `OIDC_ISSUER`.
    pub issuer: Issuer,
    /// `OIDC_AUDIENCE`: the `aud` value access tokens must contain.
    pub audience: Audience,
    /// `OIDC_ROLES_CLAIM`: where the roles array is in the claims.
    pub roles_claim: ClaimPath,
    /// `OIDC_GROUPS_CLAIM` (default: `OIDC_ROLES_CLAIM`): where the groups
    /// array is, for team sync and Cedar's `principal.groups`.
    pub groups_claim: ClaimPath,
    /// `OIDC_ADMIN_ROLE`: the role that makes a user a platform admin.
    pub admin_role: RoleName,
    /// `OIDC_USER_ROLE`: the role that lets a user in.
    pub user_role: RoleName,
    /// `OIDC_SUBJECT_CLAIM` (default `sub`): the claim that identifies the
    /// user.
    pub subject_claim: ClaimPath,
    /// `OIDC_ALLOWED_CLIENTS`: the clients whose tokens are accepted, or
    /// `None` for any client.
    pub allowed_clients: Option<Vec<ClientId>>,
    /// `OIDC_JWKS_TTL` (seconds, default 3600): how often the keys are
    /// refreshed.
    pub jwks_ttl: Duration,
    /// `OIDC_JWKS_ALLOWED_ORIGINS`: origins besides the issuer's that may
    /// serve the JWKS, as `scheme://host[:port]`.
    pub jwks_allowed_origins: Vec<String>,
    /// `OIDC_CA_FILE`: certificates trusted for the identity
    /// provider, in addition to the
    /// system roots.
    pub extra_root_certificates: Vec<Certificate>,
    /// `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP`: allows `http://` URLs on
    /// numeric loopback hosts. Development and tests only.
    pub allow_insecure_http: bool,
}

/// Why an `OIDC_*` value was refused. Never contains the value of a
/// secret; the CA file path is not one.
#[derive(Debug, thiserror::Error)]
pub enum OidcConfigError {
    #[error(
        "OIDC_ISSUER must be an https URL without credentials, query or fragment \
         (http only on a numeric loopback host with OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP=true)"
    )]
    Issuer,
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error(
        "{0} is not a dot-separated claim path without empty segments, such as realm_access.roles"
    )]
    ClaimPath(&'static str),
    #[error(
        "OIDC_AUDIENCE must differ from OIDC_CLIENT_ID and every OIDC_ALLOWED_CLIENTS entry: \
         ID tokens would pass as access tokens"
    )]
    AudienceIsClient,
    #[error(
        "OIDC_JWKS_ALLOWED_ORIGINS entry {0:?} is not an https origin such as https://keys.example.com"
    )]
    JwksOrigin(String),
    #[error("OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP must be true or false")]
    InsecureFlag,
    #[error("OIDC_CA_FILE {path:?} cannot be read")]
    CaFileUnreadable {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("OIDC_CA_FILE {0:?} holds no valid PEM certificate")]
    CaFileInvalid(String),
}

impl OidcConfig {
    /// Reads the `OIDC_*` variables through `lookup` (see
    /// [`crate::config::Config::from_lookup`]).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a required variable is missing or any
    /// value is invalid.
    pub fn from_lookup(
        lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    ) -> Result<Self, ConfigError> {
        let allow_insecure_http = match optional(lookup, "OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP")?
            .as_deref()
            .map(str::trim)
        {
            None | Some("" | "false") => false,
            Some("true") => true,
            Some(_) => return Err(OidcConfigError::InsecureFlag.into()),
        };
        let issuer = Issuer::parse(&required(lookup, "OIDC_ISSUER")?, allow_insecure_http)?;
        let audience = Audience(non_empty(lookup, "OIDC_AUDIENCE")?);
        let roles_claim = ClaimPath::parse(&required(lookup, "OIDC_ROLES_CLAIM")?)
            .ok_or(OidcConfigError::ClaimPath("OIDC_ROLES_CLAIM"))?;
        let groups_claim = match optional(lookup, "OIDC_GROUPS_CLAIM")? {
            Some(raw) if !raw.trim().is_empty() => {
                ClaimPath::parse(&raw).ok_or(OidcConfigError::ClaimPath("OIDC_GROUPS_CLAIM"))?
            }
            _ => roles_claim.clone(),
        };
        let admin_role = RoleName(non_empty(lookup, "OIDC_ADMIN_ROLE")?);
        let user_role = RoleName(non_empty(lookup, "OIDC_USER_ROLE")?);
        let subject_claim = match optional(lookup, "OIDC_SUBJECT_CLAIM")? {
            Some(raw) if !raw.trim().is_empty() => ClaimPath::parse(&raw),
            _ => ClaimPath::parse(DEFAULT_SUBJECT_CLAIM),
        }
        .ok_or(OidcConfigError::ClaimPath("OIDC_SUBJECT_CLAIM"))?;

        let allowed_clients: Vec<ClientId> = list(lookup, "OIDC_ALLOWED_CLIENTS")?
            .into_iter()
            .map(ClientId)
            .collect();
        if allowed_clients
            .iter()
            .any(|client| client.as_str() == audience.as_str())
        {
            return Err(OidcConfigError::AudienceIsClient.into());
        }
        let allowed_clients = (!allowed_clients.is_empty()).then_some(allowed_clients);

        let jwks_ttl = match optional(lookup, "OIDC_JWKS_TTL")? {
            Some(raw) => Duration::from_secs(crate::config::positive("OIDC_JWKS_TTL", &raw)?.get()),
            None => DEFAULT_JWKS_TTL,
        };
        let jwks_allowed_origins = list(lookup, "OIDC_JWKS_ALLOWED_ORIGINS")?
            .into_iter()
            .map(|raw| parse_origin(&raw, allow_insecure_http))
            .collect::<Result<_, _>>()?;
        let extra_root_certificates = match optional(lookup, "OIDC_CA_FILE")? {
            Some(path) if !path.trim().is_empty() => read_ca_file(Path::new(path.trim()))?,
            _ => Vec::new(),
        };

        Ok(Self {
            issuer,
            audience,
            roles_claim,
            groups_claim,
            admin_role,
            user_role,
            subject_claim,
            allowed_clients,
            jwks_ttl,
            jwks_allowed_origins,
            extra_root_certificates,
            allow_insecure_http,
        })
    }

    /// Whether `url` may be fetched: `https`, or `http` on a numeric
    /// loopback host when insecure HTTP is allowed.
    #[must_use]
    pub fn is_allowed_url(&self, url: &Url) -> bool {
        is_allowed_url(url, self.allow_insecure_http)
    }
}

/// The issuer URL, kept exactly as configured: tokens' `iss` and the
/// discovery document's `issuer` must equal it byte for byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuer {
    raw: String,
    url: Url,
}

impl Issuer {
    fn parse(raw: &str, allow_insecure_http: bool) -> Result<Self, OidcConfigError> {
        let raw = raw.trim();
        let url = Url::parse(raw)
            .ok()
            .filter(|url| {
                is_allowed_url(url, allow_insecure_http)
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
            })
            .ok_or(OidcConfigError::Issuer)?;
        Ok(Self {
            raw: raw.to_owned(),
            url,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// `<issuer>/.well-known/openid-configuration` (`OpenID` Connect
    /// Discovery 1.0, section 4).
    #[must_use]
    pub fn discovery_url(&self) -> Option<Url> {
        Url::parse(&format!(
            "{}/.well-known/openid-configuration",
            self.raw.trim_end_matches('/')
        ))
        .ok()
    }

    /// `scheme://host[:port]`.
    #[must_use]
    pub fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }
}

/// The audience access tokens must be issued for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audience(String);

impl Audience {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An OAuth client ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientId(String);

impl ClientId {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A role name from the roles claim. Never empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleName(String);

impl RoleName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A dot-separated path into the claims, such as `realm_access.roles`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimPath(Vec<String>);

impl ClaimPath {
    /// Parses `raw`, surrounding whitespace ignored. `None` if it is empty
    /// or has an empty segment (`a..b`, `.a`, `a.`).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        raw.split('.')
            .map(|segment| (!segment.is_empty()).then(|| segment.to_owned()))
            .collect::<Option<Vec<_>>>()
            .map(Self)
    }

    /// The value at this path, if every segment but the last names an
    /// object.
    #[must_use]
    pub fn resolve<'a>(&self, claims: &'a Map<String, Value>) -> Option<&'a Value> {
        let (first, rest) = self.0.split_first()?;
        rest.iter()
            .try_fold(claims.get(first)?, |value, segment| value.get(segment))
    }

    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

fn is_allowed_url(url: &Url, allow_insecure_http: bool) -> bool {
    match url.scheme() {
        "https" => url.has_host(),
        "http" => allow_insecure_http && url.host_str().is_some_and(is_numeric_loopback),
        _ => false,
    }
}

/// `127.0.0.1`, `[::1]` and the rest of `127.0.0.0/8`. Not `localhost`,
/// which a resolver could point anywhere.
fn is_numeric_loopback(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

fn parse_origin(raw: &str, allow_insecure_http: bool) -> Result<String, OidcConfigError> {
    Url::parse(raw)
        .ok()
        .filter(|url| {
            is_allowed_url(url, allow_insecure_http)
                && url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && !raw.ends_with('/')
                && url.query().is_none()
                && url.fragment().is_none()
        })
        .map(|url| url.origin().ascii_serialization())
        .ok_or_else(|| OidcConfigError::JwksOrigin(raw.to_owned()))
}

fn read_ca_file(path: &Path) -> Result<Vec<Certificate>, OidcConfigError> {
    let display = path.display().to_string();
    let pem = std::fs::read(path).map_err(|source| OidcConfigError::CaFileUnreadable {
        path: display.clone(),
        source,
    })?;
    Certificate::from_pem_bundle(&pem)
        .ok()
        .filter(|certificates| !certificates.is_empty())
        .ok_or(OidcConfigError::CaFileInvalid(display))
}

fn non_empty(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
) -> Result<String, ConfigError> {
    let value = required(lookup, name)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(OidcConfigError::Empty(name).into());
    }
    Ok(value.to_owned())
}

/// A comma-separated list, entries trimmed, empty entries ignored.
fn list(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
) -> Result<Vec<String>, ConfigError> {
    Ok(optional(lookup, name)?
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    const REQUIRED: [(&str, &str); 5] = [
        ("OIDC_ISSUER", "https://auth.example.com"),
        ("OIDC_AUDIENCE", "kanbot-api"),
        ("OIDC_ROLES_CLAIM", "groups"),
        ("OIDC_ADMIN_ROLE", "kanbot-admin"),
        ("OIDC_USER_ROLE", "kanbot-user"),
    ];

    fn read(extra: &[(&'static str, &str)]) -> Result<OidcConfig, ConfigError> {
        let mut vars: HashMap<&'static str, String> = REQUIRED
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();
        for (name, value) in extra {
            vars.insert(name, (*value).to_owned());
        }
        OidcConfig::from_lookup(&move |name| vars.get(name).cloned().ok_or(VarError::NotPresent))
    }

    fn without(name: &'static str) -> Result<OidcConfig, ConfigError> {
        let vars: HashMap<&'static str, String> = REQUIRED
            .iter()
            .filter(|(key, _)| *key != name)
            .map(|(key, value)| (*key, (*value).to_owned()))
            .collect();
        OidcConfig::from_lookup(&move |key| vars.get(key).cloned().ok_or(VarError::NotPresent))
    }

    fn oidc_error(result: Result<OidcConfig, ConfigError>) -> OidcConfigError {
        match result {
            Err(ConfigError::Oidc(error)) => error,
            Err(other) => panic!("expected an OIDC error, got {other:?}"),
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn reads_the_required_variables_with_defaults() {
        let config = read(&[]).unwrap();
        assert_eq!(config.issuer.as_str(), "https://auth.example.com");
        assert_eq!(config.audience.as_str(), "kanbot-api");
        assert_eq!(config.roles_claim, ClaimPath::parse("groups").unwrap());
        assert_eq!(config.groups_claim, config.roles_claim);
        assert_eq!(config.admin_role.as_str(), "kanbot-admin");
        assert_eq!(config.user_role.as_str(), "kanbot-user");
        assert_eq!(config.subject_claim.segments(), ["sub"]);
        assert_eq!(config.allowed_clients, None);
        assert_eq!(config.jwks_ttl, Duration::from_secs(3600));
        assert_eq!(config.jwks_allowed_origins, Vec::<String>::new());
        assert!(config.extra_root_certificates.is_empty());
        assert!(!config.allow_insecure_http);
    }

    #[test]
    fn the_groups_claim_is_configurable() {
        let config = read(&[("OIDC_GROUPS_CLAIM", "ext.teams")]).unwrap();
        assert_eq!(config.groups_claim.segments(), ["ext", "teams"]);
        assert_eq!(config.roles_claim.segments(), ["groups"]);
        let config = read(&[("OIDC_GROUPS_CLAIM", " ")]).unwrap();
        assert_eq!(config.groups_claim.segments(), ["groups"]);
        assert!(matches!(
            oidc_error(read(&[("OIDC_GROUPS_CLAIM", "a..b")])),
            OidcConfigError::ClaimPath("OIDC_GROUPS_CLAIM")
        ));
    }

    #[test]
    fn each_required_variable_is_required() {
        for (name, _) in REQUIRED {
            assert!(
                matches!(without(name), Err(ConfigError::Var { name: missing, source: VarError::NotPresent }) if missing == name),
                "{name}"
            );
        }
    }

    #[test]
    fn keeps_the_issuer_exactly() {
        for raw in [
            "https://auth.example.com/",
            "https://auth.example.com/realms/kanbot",
        ] {
            let config = read(&[("OIDC_ISSUER", raw)]).unwrap();
            assert_eq!(config.issuer.as_str(), raw);
        }
    }

    #[test]
    fn builds_the_discovery_url() {
        for raw in [
            "https://idp.example.com/realms/k",
            "https://idp.example.com/realms/k/",
        ] {
            let config = read(&[("OIDC_ISSUER", raw)]).unwrap();
            assert_eq!(
                config.issuer.discovery_url().unwrap().as_str(),
                "https://idp.example.com/realms/k/.well-known/openid-configuration"
            );
            assert_eq!(config.issuer.origin(), "https://idp.example.com");
        }
    }

    #[test]
    fn rejects_insecure_or_unusual_issuers() {
        for raw in [
            "http://auth.example.com",
            "http://127.0.0.1:9000",
            "auth.example.com",
            "ftp://auth.example.com",
            "https://user:pw@auth.example.com",
            "https://auth.example.com?x=1",
            "https://auth.example.com#x",
        ] {
            assert!(
                matches!(
                    oidc_error(read(&[("OIDC_ISSUER", raw)])),
                    OidcConfigError::Issuer
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn insecure_flag_allows_http_on_numeric_loopback_only() {
        let insecure = ("OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP", "true");
        for raw in [
            "http://127.0.0.1:9000",
            "http://127.0.0.2",
            "http://[::1]:8080/issuer",
        ] {
            let config = read(&[insecure, ("OIDC_ISSUER", raw)]).unwrap();
            assert!(config.allow_insecure_http, "{raw}");
        }
        for raw in [
            "http://localhost:9000",
            "http://10.0.0.1",
            "http://auth.example.com",
        ] {
            assert!(
                matches!(
                    oidc_error(read(&[insecure, ("OIDC_ISSUER", raw)])),
                    OidcConfigError::Issuer
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn insecure_flag_is_a_boolean() {
        assert!(
            !read(&[("OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP", "false")])
                .unwrap()
                .allow_insecure_http
        );
        for raw in ["1", "yes", "TRUE"] {
            assert!(matches!(
                oidc_error(read(&[("OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP", raw)])),
                OidcConfigError::InsecureFlag
            ));
        }
    }

    #[test]
    fn rejects_empty_values() {
        for name in ["OIDC_AUDIENCE", "OIDC_ADMIN_ROLE", "OIDC_USER_ROLE"] {
            assert!(
                matches!(oidc_error(read(&[(name, "  ")])), OidcConfigError::Empty(n) if n == name),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_claim_paths_with_empty_segments() {
        for name in ["OIDC_ROLES_CLAIM", "OIDC_SUBJECT_CLAIM"] {
            for raw in ["a..b", ".a", "a.", "."] {
                assert!(
                    matches!(oidc_error(read(&[(name, raw)])), OidcConfigError::ClaimPath(n) if n == name),
                    "{name}={raw}"
                );
            }
        }
        assert!(matches!(
            oidc_error(read(&[("OIDC_ROLES_CLAIM", "")])),
            OidcConfigError::ClaimPath("OIDC_ROLES_CLAIM")
        ));
    }

    #[test]
    fn an_empty_subject_claim_setting_means_sub() {
        let config = read(&[("OIDC_SUBJECT_CLAIM", " ")]).unwrap();
        assert_eq!(config.subject_claim.segments(), ["sub"]);
    }

    #[test]
    fn reads_the_subject_claim() {
        let config = read(&[("OIDC_SUBJECT_CLAIM", "oid")]).unwrap();
        assert_eq!(config.subject_claim.segments(), ["oid"]);
    }

    #[test]
    fn reads_allowed_clients() {
        let config = read(&[("OIDC_ALLOWED_CLIENTS", " kanbot, ,ci-bot ")]).unwrap();
        let clients: Vec<_> = config
            .allowed_clients
            .unwrap()
            .iter()
            .map(|client| client.as_str().to_owned())
            .collect();
        assert_eq!(clients, ["kanbot", "ci-bot"]);
        assert_eq!(
            read(&[("OIDC_ALLOWED_CLIENTS", " , ")])
                .unwrap()
                .allowed_clients,
            None
        );
    }

    #[test]
    fn rejects_the_audience_as_an_allowed_client() {
        assert!(matches!(
            oidc_error(read(&[("OIDC_ALLOWED_CLIENTS", "kanbot,kanbot-api")])),
            OidcConfigError::AudienceIsClient
        ));
    }

    #[test]
    fn reads_the_jwks_ttl() {
        assert_eq!(
            read(&[("OIDC_JWKS_TTL", "60")]).unwrap().jwks_ttl,
            Duration::from_secs(60)
        );
        for raw in ["0", "-1", "soon", ""] {
            assert!(
                matches!(
                    read(&[("OIDC_JWKS_TTL", raw)]),
                    Err(ConfigError::NotPositive("OIDC_JWKS_TTL"))
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn reads_jwks_origins() {
        let config = read(&[(
            "OIDC_JWKS_ALLOWED_ORIGINS",
            "https://keys.example.com, https://Other.example:8443",
        )])
        .unwrap();
        assert_eq!(
            config.jwks_allowed_origins,
            ["https://keys.example.com", "https://other.example:8443"]
        );
        for raw in [
            "http://keys.example.com",
            "https://keys.example.com/",
            "https://keys.example.com/jwks",
            "keys.example.com",
        ] {
            assert!(
                matches!(oidc_error(read(&[("OIDC_JWKS_ALLOWED_ORIGINS", raw)])), OidcConfigError::JwksOrigin(entry) if entry == raw),
                "{raw}"
            );
        }
    }

    #[test]
    fn rejects_unreadable_and_invalid_ca_files() {
        assert!(matches!(
            oidc_error(read(&[("OIDC_CA_FILE", "/nonexistent/kanbot/ca.pem")])),
            OidcConfigError::CaFileUnreadable { .. }
        ));
        let dir = std::env::temp_dir().join(format!("kanbot-ca-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, contents) in [
            ("empty.pem", ""),
            ("text.pem", "not a certificate"),
            (
                "broken.pem",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            ),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, contents).unwrap();
            assert!(
                matches!(
                    oidc_error(read(&[("OIDC_CA_FILE", path.to_str().unwrap())])),
                    OidcConfigError::CaFileInvalid(_)
                ),
                "{name}"
            );
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_empty_ca_file_setting_means_none() {
        let config = read(&[("OIDC_CA_FILE", "  ")]).unwrap();
        assert_eq!(config.extra_root_certificates.len(), 0);
    }

    #[test]
    fn reads_a_valid_ca_file() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/oidc/ca.crt");
        let config = read(&[("OIDC_CA_FILE", path)]).unwrap();
        assert_eq!(config.extra_root_certificates.len(), 1);
    }

    #[test]
    fn resolves_claim_paths() {
        let claims = json!({
            "groups": ["a"],
            "realm_access": { "roles": ["b"] },
            "flat": "c",
        });
        let claims = claims.as_object().unwrap();
        let resolve = |path: &str| ClaimPath::parse(path).unwrap().resolve(claims).cloned();
        assert_eq!(resolve("groups"), Some(json!(["a"])));
        assert_eq!(resolve("realm_access.roles"), Some(json!(["b"])));
        assert_eq!(resolve("realm_access.missing"), None);
        assert_eq!(resolve("flat.deeper"), None);
        assert_eq!(resolve("missing"), None);
    }

    proptest! {
        #[test]
        fn parses_dot_separated_segments(segments in prop::collection::vec("[a-zA-Z0-9_:/-]{1,12}", 1..5)) {
            let path = ClaimPath::parse(&segments.join(".")).unwrap();
            prop_assert_eq!(path.segments(), segments.as_slice());
        }

        #[test]
        fn rejects_any_empty_segment(
            before in prop::collection::vec("[a-z]{1,8}", 0..3),
            after in prop::collection::vec("[a-z]{1,8}", 0..3),
        ) {
            let raw = before.into_iter().chain([String::new()]).chain(after).collect::<Vec<_>>().join(".");
            prop_assert!(ClaimPath::parse(&raw).is_none(), "{}", raw);
        }

        #[test]
        fn claim_path_parsing_never_panics(raw in "\\PC*") {
            let _ = ClaimPath::parse(&raw);
        }
    }
}
