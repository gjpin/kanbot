//! Programmatic login at the local Authelia (`compose.yaml`), for tests and
//! `cargo run --example dev-token -- <user>`. DEVELOPMENT ONLY.
//!
//! 1. Signs in through Authelia's first-factor API, keeping its session
//!    cookie by hand (no cookie store).
//! 2. Runs the authorization code flow with PKCE (S256), reading each
//!    `Location` header instead of following redirects, and gives the
//!    one-time consent when Authelia asks for it.
//! 3. Exchanges the code at the token endpoint (`client_secret_basic`).
//!
//! Checked against Authelia 4.39.28: `POST /api/firstfactor` with
//! `{username, password, keepMeLoggedIn}`, and `POST /api/oidc/consent`
//! with `{flow_id, client_id, consent, pre_configure}`, which answers
//! `{status, data: {redirect_uri}}`.
//!
//! Written without panics, so the example can use it under the crate's
//! lints.

use std::{fmt, time::Duration};

use reqwest::{Certificate, Client, StatusCode, Url, header, redirect};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The local Authelia.
pub const ISSUER: &str = "https://auth.kanbot.internal:9443";
/// The `kanbot` client in `dev/authelia/configuration.yml`.
pub const CLIENT_ID: &str = "kanbot";
/// Its documented, development-only secret.
pub const CLIENT_SECRET: &str = "kanbot-dev-client-secret";
pub const REDIRECT_URI: &str = "https://localhost:3000/auth/callback";
const SCOPES: &str = "openid profile email groups";
/// The CA that `dev/auth-setup.sh` generates.
pub const CA_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/dev/.generated/ca.crt");
const SESSION_COOKIE: &str = "authelia_session";

/// Why a login failed. Never holds a password, cookie, code or token.
#[derive(Debug)]
pub struct LoginError(String);

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoginError {}

fn fail(step: &str, detail: impl fmt::Display) -> LoginError {
    LoginError(format!("{step}: {detail}"))
}

/// The development password of a user in `dev/authelia/users_database.yml`.
#[must_use]
pub fn dev_password(username: &str) -> String {
    format!("{username}-dev-password")
}

/// An access token for `username` from the local Authelia.
///
/// # Errors
///
/// [`LoginError`] if Authelia is unreachable (is `docker compose up -d`
/// running, and is `auth.kanbot.internal` in `/etc/hosts`?), refuses the
/// login, or answers unexpectedly.
pub async fn access_token(username: &str, password: &str) -> Result<String, LoginError> {
    let client = client()?;
    let cookie = first_factor(&client, username, password).await?;

    let verifier = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let challenge = super::base64url::encode(&Sha256::digest(verifier.as_bytes()));
    let state = uuid::Uuid::new_v4().simple().to_string();
    let authorize = Url::parse_with_params(
        &format!("{ISSUER}/api/oidc/authorization"),
        &[
            ("client_id", CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", SCOPES),
            ("state", &state),
            ("nonce", &uuid::Uuid::new_v4().simple().to_string()),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .map_err(|error| fail("authorization URL", error))?;

    let mut location = redirect_target(&client, &cookie, authorize).await?;
    if location.path().starts_with("/consent/") {
        let consented = consent(&client, &cookie, &location).await?;
        location = redirect_target(&client, &cookie, consented).await?;
    }
    let mut code = None;
    let mut returned_state = None;
    for (name, value) in location.query_pairs() {
        match name.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => returned_state = Some(value.into_owned()),
            _ => {}
        }
    }
    if returned_state.as_deref() != Some(state.as_str()) {
        return Err(fail("authorization", "state mismatch"));
    }
    let code = code.ok_or_else(|| fail("authorization", "no code in the redirect"))?;

    exchange(&client, &code, &verifier).await
}

fn client() -> Result<Client, LoginError> {
    let pem = std::fs::read(CA_FILE).map_err(|error| {
        fail(
            "reading dev/.generated/ca.crt (run dev/auth-setup.sh)",
            error,
        )
    })?;
    let ca = Certificate::from_pem(&pem).map_err(|error| fail("parsing the CA", error))?;
    Client::builder()
        .add_root_certificate(ca)
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| fail("HTTP client", error))
}

/// Signs in; returns the `Cookie` header value of the session.
async fn first_factor(
    client: &Client,
    username: &str,
    password: &str,
) -> Result<String, LoginError> {
    let body = json!({ "username": username, "password": password, "keepMeLoggedIn": false });
    let response = client
        .post(format!("{ISSUER}/api/firstfactor"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|error| fail("first factor", error))?;
    if response.status() != StatusCode::OK {
        return Err(fail("first factor", response.status()));
    }
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split(';').next())
        .find(|pair| pair.starts_with(&format!("{SESSION_COOKIE}=")))
        .map(str::to_owned)
        .ok_or_else(|| fail("first factor", "no session cookie"))
}

/// GETs `url` with the session and returns where it redirects.
async fn redirect_target(client: &Client, cookie: &str, url: Url) -> Result<Url, LoginError> {
    let response = client
        .get(url)
        .header(header::COOKIE, cookie)
        .send()
        .await
        .map_err(|error| fail("authorization", error))?;
    if !response.status().is_redirection() {
        return Err(fail("authorization", response.status()));
    }
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| fail("authorization", "no Location"))?;
    Url::parse(ISSUER)
        .and_then(|base| base.join(location))
        .map_err(|error| fail("authorization redirect", error))
}

/// Gives (and remembers) consent for the flow in `decision`; returns the
/// URL that resumes the authorization.
async fn consent(client: &Client, cookie: &str, decision: &Url) -> Result<Url, LoginError> {
    let flow_id = decision
        .query_pairs()
        .find(|(name, _)| name == "flow_id")
        .map(|(_, value)| value.into_owned())
        .ok_or_else(|| fail("consent", "no flow_id"))?;
    let body = json!({
        "flow_id": flow_id,
        "client_id": CLIENT_ID,
        "consent": true,
        "pre_configure": true,
    });
    let response = client
        .post(format!("{ISSUER}/api/oidc/consent"))
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.to_string())
        .send()
        .await
        .map_err(|error| fail("consent", error))?;
    if response.status() != StatusCode::OK {
        return Err(fail("consent", response.status()));
    }
    let body: Value = serde_json::from_slice(
        &response
            .bytes()
            .await
            .map_err(|error| fail("consent", error))?,
    )
    .map_err(|error| fail("consent", error))?;
    body.pointer("/data/redirect_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("consent", "no redirect_uri"))
        .and_then(|uri| Url::parse(uri).map_err(|error| fail("consent", error)))
}

async fn exchange(client: &Client, code: &str, verifier: &str) -> Result<String, LoginError> {
    // A URL's query is application/x-www-form-urlencoded.
    let form = Url::parse_with_params(
        "https://form.invalid/",
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ],
    )
    .map_err(|error| fail("token request", error))?;
    let response = client
        .post(format!("{ISSUER}/api/oidc/token"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form.query().unwrap_or_default().to_owned())
        .send()
        .await
        .map_err(|error| fail("token request", error))?;
    if response.status() != StatusCode::OK {
        return Err(fail("token request", response.status()));
    }
    let body: Value = serde_json::from_slice(
        &response
            .bytes()
            .await
            .map_err(|error| fail("token response", error))?,
    )
    .map_err(|error| fail("token response", error))?;
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| fail("token response", "no access_token"))
}
