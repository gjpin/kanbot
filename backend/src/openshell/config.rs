//! `OPENSHELL_*`: the `OpenShell` gateway kanbot syncs workspace membership
//! with (docs/openshell.md). Unset `OPENSHELL_GATEWAY_URL` turns the
//! integration off.

use std::{env::VarError, path::Path};

use reqwest::Url;
use secrecy::SecretString;

use crate::config::{ConfigError, optional, required};

/// Why an `OPENSHELL_*` value was refused. Never contains a secret.
#[derive(Debug, thiserror::Error)]
pub enum OpenShellConfigError {
    #[error(
        "OPENSHELL_GATEWAY_URL must be an https URL without credentials, path, query or \
         fragment (http only on a numeric loopback host with \
         OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP=true)"
    )]
    GatewayUrl,
    #[error("OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP must be true or false")]
    InsecureFlag,
    #[error("OPENSHELL_TOKEN_EXCHANGE must be true or false")]
    TokenExchangeFlag,
    #[error(
        "OPENSHELL_AUDIENCE must differ from OIDC_AUDIENCE: a token for both services must never exist"
    )]
    SameAudience,
    #[error("OPENSHELL_CA_FILE {path:?} cannot be read")]
    CaFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// The `OpenShell` gateway and how kanbot gets tokens for it.
pub struct OpenShellConfig {
    /// `OPENSHELL_GATEWAY_URL`: the gateway's gRPC endpoint.
    pub gateway: Url,
    /// `OPENSHELL_AUDIENCE`: the audience of the gateway's tokens, for
    /// example `openshell-gateway`. Kanbot refuses tokens that also carry
    /// its own audience.
    pub audience: String,
    /// `OPENSHELL_CLIENT_ID`: kanbot's client for `OpenShell` tokens (the
    /// service account of `client_credentials`, and the requester of token
    /// exchanges).
    pub client_id: String,
    /// `OPENSHELL_CLIENT_SECRET` / `OPENSHELL_CLIENT_SECRET_FILE`.
    pub client_secret: SecretString,
    /// `OPENSHELL_TOKEN_SCOPE`: the `scope` to request, if the identity
    /// provider needs one for the gateway's audience (Entra ID:
    /// `api://<app>/.default`).
    pub token_scope: Option<String>,
    /// `OPENSHELL_TOKEN_EXCHANGE` (default `false`): exchange the user's
    /// token (RFC 8693) for calls a user starts. Only for identity providers
    /// that support it (Keycloak, Okta, authentik 2026.8+).
    pub token_exchange: bool,
    /// `OPENSHELL_CA_FILE`: PEM certificates trusted for the gateway, in
    /// addition to the system roots.
    pub ca_pem: Option<Vec<u8>>,
}

fn flag(
    lookup: &impl Fn(&'static str) -> Result<String, VarError>,
    name: &'static str,
    error: OpenShellConfigError,
) -> Result<bool, ConfigError> {
    match optional(lookup, name)?.as_deref().map(str::trim) {
        None | Some("" | "false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(error.into()),
    }
}

/// `https`, or `http` on a numeric loopback host when allowed; host only.
fn parse_gateway(raw: &str, allow_insecure_http: bool) -> Option<Url> {
    let url = Url::parse(raw.trim()).ok()?;
    let host = url.host_str()?;
    let loopback = host == "127.0.0.1" || host == "[::1]";
    let scheme_ok =
        url.scheme() == "https" || (url.scheme() == "http" && allow_insecure_http && loopback);
    (scheme_ok
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.path(), "" | "/")
        && url.query().is_none()
        && url.fragment().is_none())
    .then_some(url)
}

impl OpenShellConfig {
    /// Reads `OPENSHELL_*`; `None` when `OPENSHELL_GATEWAY_URL` is unset.
    /// `kanbot_audience` is `OIDC_AUDIENCE`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] if a variable is missing or invalid.
    pub fn from_lookup(
        lookup: &impl Fn(&'static str) -> Result<String, VarError>,
        kanbot_audience: &str,
    ) -> Result<Option<Self>, ConfigError> {
        let Some(raw) =
            optional(lookup, "OPENSHELL_GATEWAY_URL")?.filter(|raw| !raw.trim().is_empty())
        else {
            return Ok(None);
        };
        let insecure = flag(
            lookup,
            "OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP",
            OpenShellConfigError::InsecureFlag,
        )?;
        let gateway = parse_gateway(&raw, insecure).ok_or(OpenShellConfigError::GatewayUrl)?;
        let audience = required(lookup, "OPENSHELL_AUDIENCE")?.trim().to_owned();
        if audience.is_empty() {
            return Err(ConfigError::Var {
                name: "OPENSHELL_AUDIENCE",
                source: VarError::NotPresent,
            });
        }
        if audience == kanbot_audience {
            return Err(OpenShellConfigError::SameAudience.into());
        }
        let client_id = required(lookup, "OPENSHELL_CLIENT_ID")?.trim().to_owned();
        let client_secret = SecretString::from(crate::sessions::config::secret(
            lookup,
            "OPENSHELL_CLIENT_SECRET",
            "OPENSHELL_CLIENT_SECRET_FILE",
        )?);
        let token_scope = optional(lookup, "OPENSHELL_TOKEN_SCOPE")?
            .map(|scope| scope.trim().to_owned())
            .filter(|scope| !scope.is_empty());
        let token_exchange = flag(
            lookup,
            "OPENSHELL_TOKEN_EXCHANGE",
            OpenShellConfigError::TokenExchangeFlag,
        )?;
        let ca_pem = match optional(lookup, "OPENSHELL_CA_FILE")? {
            Some(path) if !path.trim().is_empty() => {
                Some(std::fs::read(Path::new(path.trim())).map_err(|source| {
                    OpenShellConfigError::CaFile {
                        path: path.trim().to_owned(),
                        source,
                    }
                })?)
            }
            _ => None,
        };
        Ok(Some(Self {
            gateway,
            audience,
            client_id,
            client_secret,
            token_scope,
            token_exchange,
            ca_pem,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use secrecy::ExposeSecret;

    use super::*;

    fn read(vars: &[(&'static str, &str)]) -> Result<Option<OpenShellConfig>, ConfigError> {
        let vars: HashMap<&'static str, String> = vars
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();
        OpenShellConfig::from_lookup(
            &move |name| vars.get(name).cloned().ok_or(VarError::NotPresent),
            "kanbot-api",
        )
    }

    const BASE: [(&str, &str); 4] = [
        ("OPENSHELL_GATEWAY_URL", "https://openshell.example.com"),
        ("OPENSHELL_AUDIENCE", "openshell-gateway"),
        ("OPENSHELL_CLIENT_ID", "kanbot-openshell"),
        ("OPENSHELL_CLIENT_SECRET", "s3cret"),
    ];

    fn with(extra: &[(&'static str, &str)]) -> Result<Option<OpenShellConfig>, ConfigError> {
        let mut vars = BASE.to_vec();
        vars.retain(|(name, _)| !extra.iter().any(|(other, _)| other == name));
        vars.extend_from_slice(extra);
        read(&vars)
    }

    #[test]
    fn off_without_a_gateway() {
        assert!(read(&[]).unwrap().is_none());
        assert!(read(&[("OPENSHELL_GATEWAY_URL", " ")]).unwrap().is_none());
    }

    #[test]
    fn reads_the_settings() {
        let config = with(&[
            ("OPENSHELL_TOKEN_SCOPE", " api://x/.default "),
            ("OPENSHELL_TOKEN_EXCHANGE", "true"),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(config.gateway.as_str(), "https://openshell.example.com/");
        assert_eq!(config.audience, "openshell-gateway");
        assert_eq!(config.client_id, "kanbot-openshell");
        assert_eq!(config.client_secret.expose_secret(), "s3cret");
        assert_eq!(config.token_scope.as_deref(), Some("api://x/.default"));
        assert!(config.token_exchange);
        assert!(config.ca_pem.is_none());
        let defaults = with(&[]).unwrap().unwrap();
        assert!(!defaults.token_exchange);
        assert_eq!(defaults.token_scope, None);
    }

    #[test]
    fn refuses_insecure_or_odd_gateway_urls() {
        for url in [
            "http://openshell.example.com",
            "http://127.0.0.1:50051",
            "https://user:pw@openshell.example.com",
            "https://openshell.example.com/path",
            "https://openshell.example.com?x=1",
            "openshell.example.com",
        ] {
            assert!(
                matches!(
                    with(&[("OPENSHELL_GATEWAY_URL", url)]),
                    Err(ConfigError::OpenShell(OpenShellConfigError::GatewayUrl))
                ),
                "{url}"
            );
        }
        let local = with(&[
            ("OPENSHELL_GATEWAY_URL", "http://127.0.0.1:50051"),
            ("OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP", "true"),
        ]);
        assert!(local.unwrap().is_some());
        assert!(matches!(
            with(&[
                ("OPENSHELL_GATEWAY_URL", "http://localhost:50051"),
                ("OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP", "true"),
            ]),
            Err(ConfigError::OpenShell(OpenShellConfigError::GatewayUrl))
        ));
        assert!(matches!(
            with(&[("OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP", "yes")]),
            Err(ConfigError::OpenShell(OpenShellConfigError::InsecureFlag))
        ));
        assert!(matches!(
            with(&[("OPENSHELL_TOKEN_EXCHANGE", "1")]),
            Err(ConfigError::OpenShell(
                OpenShellConfigError::TokenExchangeFlag
            ))
        ));
    }

    #[test]
    fn the_audiences_must_differ() {
        assert!(matches!(
            with(&[("OPENSHELL_AUDIENCE", "kanbot-api")]),
            Err(ConfigError::OpenShell(OpenShellConfigError::SameAudience))
        ));
        assert!(matches!(
            with(&[("OPENSHELL_AUDIENCE", " ")]),
            Err(ConfigError::Var {
                name: "OPENSHELL_AUDIENCE",
                ..
            })
        ));
    }

    #[test]
    fn requires_the_client() {
        for name in [
            "OPENSHELL_AUDIENCE",
            "OPENSHELL_CLIENT_ID",
            "OPENSHELL_CLIENT_SECRET",
        ] {
            let vars: Vec<_> = BASE.iter().copied().filter(|(n, _)| *n != name).collect();
            assert!(read(&vars).is_err(), "{name}");
        }
    }

    #[test]
    fn reads_the_ca_file() {
        let path =
            std::env::temp_dir().join(format!("kanbot-openshell-ca-{}", uuid::Uuid::new_v4()));
        let raw = path.to_str().unwrap().to_owned();
        assert!(matches!(
            with(&[("OPENSHELL_CA_FILE", &raw)]),
            Err(ConfigError::OpenShell(OpenShellConfigError::CaFile { .. }))
        ));
        std::fs::write(&path, "pem").unwrap();
        let config = with(&[("OPENSHELL_CA_FILE", &raw)]).unwrap().unwrap();
        assert_eq!(config.ca_pem.as_deref(), Some(&b"pem"[..]));
        std::fs::remove_file(path).unwrap();
    }
}
