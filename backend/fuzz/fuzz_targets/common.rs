//! What both targets validate against: the test fixture keys
//! (`tests/fixtures/oidc/`, test-only) and a fixed configuration.

use std::{collections::HashMap, env::VarError};

use kanbot_backend::auth::{
    config::OidcConfig,
    keys::KeySet,
    token::{Principal, Rejection, UnverifiedToken},
};

pub const ISSUER: &str = "https://auth.example.com";
/// A fixed time, so runs are reproducible.
pub const NOW: u64 = 1_800_000_000;

const JWKS: [&str; 5] = [
    include_str!("../../tests/fixtures/oidc/rsa-a.jwk.json"),
    include_str!("../../tests/fixtures/oidc/rsa-1024.jwk.json"),
    include_str!("../../tests/fixtures/oidc/p256.jwk.json"),
    include_str!("../../tests/fixtures/oidc/p384.jwk.json"),
    include_str!("../../tests/fixtures/oidc/ed25519.jwk.json"),
];

pub fn keys() -> KeySet {
    let keys: Vec<serde_json::Value> = JWKS
        .iter()
        .map(|jwk| serde_json::from_str(jwk).unwrap())
        .collect();
    KeySet::from_jwks(&keys)
}

pub fn config() -> OidcConfig {
    let vars: HashMap<&str, &str> = HashMap::from([
        ("OIDC_ISSUER", ISSUER),
        ("OIDC_AUDIENCE", "kanbot-api"),
        ("OIDC_ROLES_CLAIM", "realm_access.roles"),
        ("OIDC_ADMIN_ROLE", "kanbot-admin"),
        ("OIDC_USER_ROLE", "kanbot-user"),
        ("OIDC_ALLOWED_CLIENTS", "kanbot-cli"),
    ]);
    OidcConfig::from_lookup(&|name| {
        vars.get(name)
            .map(|value| (*value).to_owned())
            .ok_or(VarError::NotPresent)
    })
    .unwrap()
}

/// Parses and validates `token` as the middleware does.
pub fn validate(token: &str, keys: &KeySet, config: &OidcConfig) -> Result<Principal, Rejection> {
    let unverified = UnverifiedToken::parse(token)?;
    let key = keys.get(unverified.kid()).ok_or(Rejection::UnknownKey)?;
    unverified.verify(&key, config, NOW)
}
