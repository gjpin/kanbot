//! OIDC discovery, and the HTTP client used for every call to the identity
//! provider: short timeouts, no redirects, capped response bodies.

use std::time::Duration;

use reqwest::{StatusCode, Url, header};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, de::DeserializeOwned};

use crate::auth::config::OidcConfig;

/// Largest discovery document read, in bytes.
pub const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
/// Largest error body read from a token endpoint, in bytes: enough for
/// the `error` code (RFC 6749, section 5.2), which is all that is kept.
const MAX_ERROR_BYTES: usize = 4 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

/// HTTP client for the identity provider. Cheap to clone.
#[derive(Clone)]
pub struct IdpClient(reqwest::Client);

/// Why a call to the identity provider failed. Carries no response body.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("request failed")]
    Request(#[source] reqwest::Error),
    #[error("unexpected status {0}")]
    Status(StatusCode),
    /// A token or revocation endpoint's error response (`400`, `401`),
    /// with its `error` code when it has a known one.
    #[error("refused with {0}: {1}")]
    Refused(StatusCode, OAuthError),
    #[error("response is larger than {0} bytes")]
    TooLarge(usize),
    #[error("response is not the expected JSON")]
    Json(#[source] serde_json::Error),
}

/// The `error` of a token endpoint's error response (RFC 6749, section
/// 5.2; RFC 8693, section 2.2.2). Only known codes: never text from the
/// response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OAuthError {
    /// The grant (a refresh token, a code, a subject token) is invalid,
    /// expired or revoked: it will not work again.
    InvalidGrant,
    InvalidClient,
    UnauthorizedClient,
    InvalidRequest,
    InvalidScope,
    InvalidTarget,
    UnsupportedGrantType,
    /// No body, no `error`, or a code not listed here.
    Other,
}

impl OAuthError {
    fn parse(code: &str) -> Self {
        match code {
            "invalid_grant" => Self::InvalidGrant,
            "invalid_client" => Self::InvalidClient,
            "unauthorized_client" => Self::UnauthorizedClient,
            "invalid_request" => Self::InvalidRequest,
            "invalid_scope" => Self::InvalidScope,
            "invalid_target" => Self::InvalidTarget,
            "unsupported_grant_type" => Self::UnsupportedGrantType,
            _ => Self::Other,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidClient => "invalid_client",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidTarget => "invalid_target",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl IdpClient {
    /// A client for `config`'s identity provider: it trusts the system
    /// roots plus `OIDC_CA_FILE`, and sends nothing over plain HTTP unless
    /// `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP` is set (the endpoints are
    /// checked when discovered too).
    ///
    /// # Errors
    ///
    /// Returns an error if the TLS backend cannot be initialized.
    pub fn new(config: &OidcConfig) -> Result<Self, reqwest::Error> {
        config
            .extra_root_certificates
            .iter()
            .cloned()
            .fold(
                reqwest::Client::builder()
                    .connect_timeout(CONNECT_TIMEOUT)
                    .timeout(TOTAL_TIMEOUT)
                    .https_only(!config.allow_insecure_http)
                    .redirect(reqwest::redirect::Policy::none()),
                reqwest::ClientBuilder::add_root_certificate,
            )
            .build()
            .map(Self)
    }

    /// GETs `url` and parses its JSON body, reading at most `max_bytes`.
    /// Anything but `200` is an error, redirects included.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError`] on a network error or timeout, another
    /// status, a body over `max_bytes`, or a body that does not parse.
    pub async fn get_json<T: DeserializeOwned>(
        &self,
        url: Url,
        max_bytes: usize,
    ) -> Result<T, FetchError> {
        let response = self
            .0
            .get(url)
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(FetchError::Request)?;
        read_json(response, max_bytes).await
    }

    /// POSTs `form` to `url` (a token endpoint) with HTTP Basic client
    /// authentication (`client_secret_basic`, RFC 6749 section 2.3.1: the
    /// ID and secret are form-encoded first) and parses the JSON answer,
    /// reading at most `max_bytes`. Anything but `200` is an error; of an
    /// error response, only the `error` code is read
    /// ([`FetchError::Refused`]).
    ///
    /// # Errors
    ///
    /// As [`IdpClient::get_json`].
    pub async fn post_form<T: DeserializeOwned>(
        &self,
        url: Url,
        client_id: &str,
        client_secret: &SecretString,
        form: &[(&str, &str)],
        max_bytes: usize,
    ) -> Result<T, FetchError> {
        let response = self.send_form(url, client_id, client_secret, form).await?;
        let response = refused(response).await?;
        read_json(response, max_bytes).await
    }

    /// POSTs `form` like [`IdpClient::post_form`] for an answer without a
    /// body (token revocation, RFC 7009): `Ok` for `200`.
    ///
    /// # Errors
    ///
    /// As [`IdpClient::post_form`].
    pub async fn post_form_empty(
        &self,
        url: Url,
        client_id: &str,
        client_secret: &SecretString,
        form: &[(&str, &str)],
    ) -> Result<(), FetchError> {
        let response = self.send_form(url, client_id, client_secret, form).await?;
        let response = refused(response).await?;
        if response.status() == StatusCode::OK {
            Ok(())
        } else {
            Err(FetchError::Status(response.status()))
        }
    }

    async fn send_form(
        &self,
        url: Url,
        client_id: &str,
        client_secret: &SecretString,
        form: &[(&str, &str)],
    ) -> Result<reqwest::Response, FetchError> {
        self.0
            .post(url)
            .basic_auth(
                form_encode(&[("", client_id)]),
                Some(form_encode(&[("", client_secret.expose_secret())])),
            )
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form_encode(form))
            .send()
            .await
            .map_err(FetchError::Request)
    }
}

/// A `400` or `401` as [`FetchError::Refused`], with the `error` code of
/// its body (read up to [`MAX_ERROR_BYTES`]); any other response as is.
async fn refused(mut response: reqwest::Response) -> Result<reqwest::Response, FetchError> {
    #[derive(Deserialize)]
    struct ErrorBody {
        error: String,
    }
    let status = response.status();
    if status != StatusCode::BAD_REQUEST && status != StatusCode::UNAUTHORIZED {
        return Ok(response);
    }
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len().saturating_add(chunk.len()) > MAX_ERROR_BYTES {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    let error = serde_json::from_slice::<ErrorBody>(&body)
        .map_or(OAuthError::Other, |body| OAuthError::parse(&body.error));
    Err(FetchError::Refused(status, error))
}

/// `application/x-www-form-urlencoded`. A single pair with an empty name
/// encodes just its value.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    let Ok(mut url) = Url::parse("https://form.invalid/") else {
        return String::new();
    };
    url.query_pairs_mut().extend_pairs(pairs);
    let encoded = url.query().unwrap_or_default();
    match pairs {
        [("", _)] => encoded.strip_prefix('=').unwrap_or(encoded).to_owned(),
        _ => encoded.to_owned(),
    }
}

/// The JSON body of a `200` response, read in chunks up to `max_bytes`,
/// whatever `Content-Length` says: a server can lie.
async fn read_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<T, FetchError> {
    if response.status() != StatusCode::OK {
        return Err(FetchError::Status(response.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(FetchError::Request)? {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(FetchError::TooLarge(max_bytes));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(FetchError::Json)
}

/// What kanbot uses from the discovery document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    pub jwks_uri: Url,
    /// Kept for the login flow. `None` when absent or not an allowed URL.
    pub authorization_endpoint: Option<Url>,
    /// Kept for the login flow. `None` when absent or not an allowed URL.
    pub token_endpoint: Option<Url>,
    /// Kept for logout. `None` when absent or not an allowed URL.
    pub end_session_endpoint: Option<Url>,
    /// Kept for logout (RFC 7009). `None` when absent or not an allowed
    /// URL.
    pub revocation_endpoint: Option<Url>,
}

#[derive(Deserialize)]
struct Document {
    issuer: String,
    jwks_uri: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("the discovery URL cannot be built from the issuer")]
    Url,
    #[error("the discovery document could not be fetched")]
    Fetch(#[from] FetchError),
    #[error("the discovery document's issuer differs from OIDC_ISSUER")]
    IssuerMismatch,
    #[error("jwks_uri is not an https URL on the issuer's origin or in OIDC_JWKS_ALLOWED_ORIGINS")]
    JwksUri,
}

/// Fetches and checks `<issuer>/.well-known/openid-configuration`.
///
/// # Errors
///
/// Returns [`DiscoveryError`] if the document cannot be fetched, its
/// `issuer` is not exactly `OIDC_ISSUER`, or its `jwks_uri` is not allowed.
pub async fn discover(
    client: &IdpClient,
    config: &OidcConfig,
) -> Result<Discovery, DiscoveryError> {
    let url = config.issuer.discovery_url().ok_or(DiscoveryError::Url)?;
    let document: Document = client.get_json(url, MAX_DISCOVERY_BYTES).await?;
    if document.issuer != config.issuer.as_str() {
        return Err(DiscoveryError::IssuerMismatch);
    }
    let jwks_uri = Url::parse(&document.jwks_uri)
        .ok()
        .filter(|url| {
            config.is_allowed_url(url) && url.username().is_empty() && url.password().is_none()
        })
        // Only then the origin: an http(s) URL's is cheap.
        .filter(|url| {
            let origin = url.origin().ascii_serialization();
            origin == config.issuer.origin() || config.jwks_allowed_origins.contains(&origin)
        })
        .ok_or(DiscoveryError::JwksUri)?;
    // Any origin: some identity providers serve these from another host
    // than the issuer, and the issuer, which also names the signing keys,
    // is trusted anyway. Never credentials or a fragment in them.
    let endpoint = |raw: Option<String>| {
        raw.and_then(|raw| Url::parse(&raw).ok()).filter(|url| {
            config.is_allowed_url(url)
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
    };
    Ok(Discovery {
        jwks_uri,
        authorization_endpoint: endpoint(document.authorization_endpoint),
        token_endpoint: endpoint(document.token_endpoint),
        end_session_endpoint: endpoint(document.end_session_endpoint),
        revocation_endpoint: endpoint(document.revocation_endpoint),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_encodes_pairs_and_single_values() {
        assert_eq!(
            form_encode(&[
                ("grant_type", "authorization_code"),
                ("redirect_uri", "https://k.example/a b")
            ]),
            "grant_type=authorization_code&redirect_uri=https%3A%2F%2Fk.example%2Fa+b"
        );
        assert_eq!(form_encode(&[("", "kanbot")]), "kanbot");
        assert_eq!(form_encode(&[("", "p@ss:w/rd")]), "p%40ss%3Aw%2Frd");
    }
}
