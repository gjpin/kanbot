//! A test identity provider: an axum server on `127.0.0.1:0` that serves
//! OIDC discovery and a JWKS that tests change at runtime, counts the
//! requests it gets, and signs tokens with the fixture keys
//! (`tests/fixtures/oidc/`, test-only) with any header and claims.
//!
//! The app under test reaches it over plain HTTP through
//! `OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP`.
//!
//! Like all test helpers, these panic instead of returning errors.

use std::{
    collections::HashMap,
    env::VarError,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use jsonwebtoken::{Algorithm, EncodingKey};
use kanbot_backend::auth::{
    config::OidcConfig,
    discovery::IdpClient,
    keys::{KeyCache, KeySet},
};
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// Fixture keys served by default. `rsa-b` is held back for rotation tests,
/// `rsa-1024` is too weak to be used.
pub const DEFAULT_KEYS: [&str; 4] = ["rsa-a", "p256", "p384", "ed25519"];

/// What an endpoint answers.
#[derive(Clone)]
pub enum Reply {
    Json(Value),
    Status(StatusCode),
    /// A `302` to this location.
    Redirect(String),
    /// `Json` after a delay.
    Slow(Duration, Value),
    /// This body, with a `Content-Length`.
    Bytes(Vec<u8>),
    /// This body, streamed without a `Content-Length`.
    Chunked(Vec<u8>),
}

#[derive(Default)]
struct Endpoints {
    discovery: Option<Reply>,
    jwks: Option<Reply>,
    discovery_requests: usize,
    jwks_requests: usize,
}

pub struct TestIdp {
    /// `http://127.0.0.1:<port>`, no trailing slash.
    pub issuer: String,
    endpoints: Arc<Mutex<Endpoints>>,
}

impl TestIdp {
    /// Starts the server, serving [`DEFAULT_KEYS`].
    ///
    /// # Panics
    ///
    /// If the listener cannot bind.
    pub async fn start() -> Self {
        let endpoints = Arc::new(Mutex::new(Endpoints::default()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .with_state((issuer.clone(), Arc::clone(&endpoints)));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let idp = Self { issuer, endpoints };
        idp.set_keys(&DEFAULT_KEYS);
        idp
    }

    /// Serves these fixture keys.
    pub fn set_keys(&self, names: &[&str]) {
        let keys: Vec<Value> = names.iter().map(|name| jwk(name)).collect();
        self.set_jwks(Reply::Json(json!({ "keys": keys })));
    }

    /// Answers JWKS requests with `reply`.
    ///
    /// # Panics
    ///
    /// If a request handler panicked.
    pub fn set_jwks(&self, reply: Reply) {
        self.endpoints.lock().unwrap().jwks = Some(reply);
    }

    /// Replaces the default discovery document.
    ///
    /// # Panics
    ///
    /// If a request handler panicked.
    pub fn set_discovery(&self, reply: Reply) {
        self.endpoints.lock().unwrap().discovery = Some(reply);
    }

    /// The default discovery document, to modify and pass to
    /// [`TestIdp::set_discovery`].
    #[must_use]
    pub fn discovery_document(&self) -> Value {
        default_discovery(&self.issuer)
    }

    /// How many JWKS requests it has answered.
    ///
    /// # Panics
    ///
    /// If a request handler panicked.
    #[must_use]
    pub fn jwks_requests(&self) -> usize {
        self.endpoints.lock().unwrap().jwks_requests
    }

    /// How many discovery requests it has answered.
    ///
    /// # Panics
    ///
    /// If a request handler panicked.
    #[must_use]
    pub fn discovery_requests(&self) -> usize {
        self.endpoints.lock().unwrap().discovery_requests
    }

    /// The OIDC configuration for this issuer, plus `extra` variables.
    ///
    /// # Panics
    ///
    /// If the configuration is invalid.
    #[must_use]
    pub fn config(&self, extra: &[(&'static str, &str)]) -> OidcConfig {
        config(&self.issuer, extra)
    }

    /// A key cache for this issuer that has not loaded keys yet.
    ///
    /// # Panics
    ///
    /// If the configuration is invalid.
    #[must_use]
    pub fn key_cache(&self, extra: &[(&'static str, &str)]) -> Arc<KeyCache> {
        let config = self.config(extra);
        let client = IdpClient::new(&config.extra_root_certificates).unwrap();
        Arc::new(KeyCache::new(Arc::new(config), client))
    }

    /// A key cache for this issuer with the keys loaded.
    ///
    /// # Panics
    ///
    /// If the keys cannot be loaded.
    pub async fn loaded_key_cache(&self, extra: &[(&'static str, &str)]) -> Arc<KeyCache> {
        let cache = self.key_cache(extra);
        cache.refresh().await.unwrap();
        cache
    }
}

fn default_discovery(issuer: &str) -> Value {
    json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/jwks"),
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
    })
}

type IdpState = (String, Arc<Mutex<Endpoints>>);

async fn discovery(State((issuer, endpoints)): State<IdpState>) -> Response {
    let reply = {
        let mut endpoints = endpoints.lock().unwrap();
        endpoints.discovery_requests = endpoints.discovery_requests.saturating_add(1);
        endpoints.discovery.clone()
    };
    respond(reply.unwrap_or_else(|| Reply::Json(default_discovery(&issuer)))).await
}

async fn jwks(State((_, endpoints)): State<IdpState>) -> Response {
    let reply = {
        let mut endpoints = endpoints.lock().unwrap();
        endpoints.jwks_requests = endpoints.jwks_requests.saturating_add(1);
        endpoints.jwks.clone()
    };
    respond(reply.unwrap_or(Reply::Status(StatusCode::NOT_FOUND))).await
}

async fn respond(reply: Reply) -> Response {
    match reply {
        Reply::Json(value) => axum::Json(value).into_response(),
        Reply::Status(status) => status.into_response(),
        Reply::Redirect(location) => {
            (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
        }
        Reply::Slow(delay, value) => {
            tokio::time::sleep(delay).await;
            axum::Json(value).into_response()
        }
        Reply::Bytes(body) => ([(header::CONTENT_TYPE, "application/json")], body).into_response(),
        Reply::Chunked(body) => {
            // A stream has no known length, so the body goes out chunked.
            let stream = http_body_util::BodyDataStream::new(http_body_util::Full::new(
                axum::body::Bytes::from(body),
            ));
            (
                [(header::CONTENT_TYPE, "application/json")],
                Body::from_stream(stream),
            )
                .into_response()
        }
    }
}

/// The OIDC configuration for `issuer` (plain HTTP on loopback allowed),
/// plus `extra` variables.
///
/// # Panics
///
/// If the configuration is invalid.
#[must_use]
pub fn config(issuer: &str, extra: &[(&'static str, &str)]) -> OidcConfig {
    let mut vars: HashMap<&'static str, String> = [
        ("OIDC_ISSUER", issuer),
        ("OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP", "true"),
        ("OIDC_AUDIENCE", "kanbot-api"),
        ("OIDC_ROLES_CLAIM", "groups"),
        ("OIDC_ADMIN_ROLE", "kanbot-admin"),
        ("OIDC_USER_ROLE", "kanbot-user"),
    ]
    .into_iter()
    .map(|(name, value)| (name, value.to_owned()))
    .collect();
    for (name, value) in extra {
        vars.insert(name, (*value).to_owned());
    }
    OidcConfig::from_lookup(&move |name| vars.get(name).cloned().ok_or(VarError::NotPresent))
        .unwrap()
}

/// A key cache holding [`DEFAULT_KEYS`] for the unreachable issuer
/// `http://127.0.0.1:1`: ready, without a network.
///
/// # Panics
///
/// If a fixture is missing.
#[must_use]
pub fn static_key_cache() -> Arc<KeyCache> {
    let config = config("http://127.0.0.1:1", &[]);
    let client = IdpClient::new(&[]).unwrap();
    let keys: Vec<Value> = DEFAULT_KEYS.iter().map(|name| jwk(name)).collect();
    Arc::new(KeyCache::with_keys(
        Arc::new(config),
        client,
        KeySet::from_jwks(&keys),
    ))
}

/// A key cache for the unreachable issuer `http://127.0.0.1:1` that never
/// loads keys.
///
/// # Panics
///
/// If the HTTP client cannot be built.
#[must_use]
pub fn unloaded_key_cache() -> Arc<KeyCache> {
    let config = config("http://127.0.0.1:1", &[]);
    Arc::new(KeyCache::new(
        Arc::new(config),
        IdpClient::new(&[]).unwrap(),
    ))
}

fn fixture_path(file: &str) -> String {
    format!("{}/tests/fixtures/oidc/{file}", env!("CARGO_MANIFEST_DIR"))
}

/// The public JWK of a fixture key, with `kid` = its name.
///
/// # Panics
///
/// If the fixture is missing.
#[must_use]
pub fn jwk(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixture_path(&format!("{name}.jwk.json"))).unwrap())
        .unwrap()
}

/// The private key of a fixture.
///
/// # Panics
///
/// If the fixture is missing.
#[must_use]
pub fn encoding_key(name: &str) -> EncodingKey {
    let pem = std::fs::read(fixture_path(&format!("{name}.pem"))).unwrap();
    match name {
        "p256" | "p384" => EncodingKey::from_ec_pem(&pem).unwrap(),
        "ed25519" => EncodingKey::from_ed_pem(&pem).unwrap(),
        _ => EncodingKey::from_rsa_pem(&pem).unwrap(),
    }
}

/// The algorithm a fixture key implies.
#[must_use]
pub fn default_algorithm(name: &str) -> Algorithm {
    match name {
        "p256" => Algorithm::ES256,
        "p384" => Algorithm::ES384,
        "ed25519" => Algorithm::EdDSA,
        _ => Algorithm::RS256,
    }
}

/// Signs `claims` with fixture key `name`, with header
/// `{"alg": <its algorithm>, "typ": "JWT", "kid": name}`.
///
/// # Panics
///
/// If the fixture is missing.
#[must_use]
pub fn sign(name: &str, claims: &Value) -> String {
    let alg = default_algorithm(name);
    sign_with_header(
        &json!({ "alg": alg, "typ": "JWT", "kid": name }),
        &encoding_key(name),
        alg,
        claims,
    )
}

/// Signs `header` and `claims` as given (any fields, any `alg` value) with
/// `key` using `alg`.
///
/// # Panics
///
/// If `key` does not fit `alg`.
#[must_use]
pub fn sign_with_header(
    header: &Value,
    key: &EncodingKey,
    alg: Algorithm,
    claims: &Value,
) -> String {
    let message = format!(
        "{}.{}",
        base64url(header.to_string().as_bytes()),
        base64url(claims.to_string().as_bytes())
    );
    let signature = jsonwebtoken::crypto::sign(message.as_bytes(), key, alg).unwrap();
    format!("{message}.{signature}")
}

/// Unpadded base64url (RFC 4648, section 5).
///
/// # Panics
///
/// Never: every index is below 64.
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let byte = |i: usize| chunk.get(i).copied().unwrap_or(0);
        let n = u32::from_be_bytes([0, byte(0), byte(1), byte(2)]);
        let chars = match chunk.len() {
            1 => 2,
            2 => 3,
            _ => 4,
        };
        for shift in [18_u32, 12, 6, 0].into_iter().take(chars) {
            let index = usize::try_from(n.checked_shr(shift).unwrap() & 0x3f).unwrap();
            out.push(char::from(ALPHABET[index]));
        }
    }
    out
}
