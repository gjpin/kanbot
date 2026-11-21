//! Programmatic login at the local Keycloak (`compose.yaml`,
//! `dev/keycloak/`), for the end-to-end tests. DEVELOPMENT ONLY.
//!
//! Keycloak signs users in with an HTML form, so this reads the form's
//! `action` from the login page, keeps Keycloak's cookies by hand, and
//! posts the dev password. Checked against Keycloak 26.8.2.

use std::time::Duration;

use reqwest::{Certificate, Client, StatusCode, Url, header, redirect};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::authelia::{CA_FILE, dev_password};

/// The local Keycloak's realm.
pub const ISSUER: &str = "https://auth.kanbot.internal:8443/realms/kanbot";
pub const CLIENT_ID: &str = "kanbot";
/// Its documented, development-only secret (`dev/keycloak/kanbot-realm.json`).
pub const CLIENT_SECRET: &str = "kanbot-dev-client-secret";
const REDIRECT_URI: &str = "https://localhost:3000/auth/callback";

/// `application/x-www-form-urlencoded`.
fn form(pairs: &[(&str, &str)]) -> String {
    let mut url = Url::parse("https://form.invalid/").unwrap();
    url.query_pairs_mut().extend_pairs(pairs);
    url.query().unwrap_or_default().to_owned()
}

fn client() -> Client {
    let pem = std::fs::read(CA_FILE).expect("dev/.generated/ca.crt (run dev/auth-setup.sh)");
    Client::builder()
        .add_root_certificate(Certificate::from_pem(&pem).unwrap())
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

/// The `name=value` pairs of a response's cookies.
fn cookies(response: &reqwest::Response) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok()?.split(';').next().map(str::to_owned))
        .collect()
}

/// Signs `username` in with `password` at the login page that
/// `authorization_url` leads to, and returns where Keycloak redirects: the
/// client's redirect URI with the code (or an error).
///
/// # Panics
///
/// If Keycloak is unreachable or answers unexpectedly.
pub async fn authorize(username: &str, password: &str, authorization_url: Url) -> Url {
    let client = client();
    let page = client
        .get(authorization_url)
        .send()
        .await
        .expect("the local Keycloak must be running (see backend/AGENTS.md)");
    assert_eq!(page.status(), StatusCode::OK, "Keycloak's login page");
    let cookie = cookies(&page).join("; ");
    let html = page.text().await.unwrap();
    let action = html
        .split("id=\"kc-form-login\"")
        .nth(1)
        .and_then(|form| form.split("action=\"").nth(1))
        .and_then(|rest| rest.split('"').next())
        .expect("the login form")
        .replace("&amp;", "&");
    let response = client
        .post(action)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[
            ("username", username),
            ("password", password),
            ("credentialId", ""),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FOUND,
        "Keycloak refused the login"
    );
    Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap()
}

/// An access token for `username`, through the authorization code flow
/// with PKCE (`client_secret_basic`).
///
/// # Panics
///
/// If the login fails.
pub async fn access_token(username: &str) -> String {
    let verifier = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let challenge = super::base64url::encode(&Sha256::digest(verifier.as_bytes()));
    let authorize_url = Url::parse_with_params(
        &format!("{ISSUER}/protocol/openid-connect/auth"),
        &[
            ("client_id", CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", "openid profile email"),
            ("state", "state"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .unwrap();
    let callback = authorize(username, &dev_password(username), authorize_url).await;
    let code = callback
        .query_pairs()
        .find(|(name, _)| name == "code")
        .map(|(_, code)| code.into_owned())
        .expect("a code");
    let response = client()
        .post(format!("{ISSUER}/protocol/openid-connect/token"))
        .basic_auth(CLIENT_ID, Some(CLIENT_SECRET))
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", &verifier),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "token exchange");
    let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    body["access_token"].as_str().unwrap().to_owned()
}
