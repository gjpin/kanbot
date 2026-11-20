//! Any JSON as the claims of a correctly signed token (Ed25519 fixture
//! key): the checks behind the signature must never panic, and a token is
//! accepted only if it meets every rule.
#![no_main]

mod common;

use std::sync::LazyLock;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use kanbot_backend::auth::{config::OidcConfig, keys::KeySet, token::PlatformRole};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

static KEYS: LazyLock<KeySet> = LazyLock::new(common::keys);
static CONFIG: LazyLock<OidcConfig> = LazyLock::new(common::config);
static SIGNING_KEY: LazyLock<EncodingKey> = LazyLock::new(|| {
    EncodingKey::from_ed_pem(include_bytes!("../../tests/fixtures/oidc/ed25519.pem")).unwrap()
});

fuzz_target!(|data: &[u8]| {
    let Ok(claims) = serde_json::from_slice::<Value>(data) else {
        return;
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("ed25519".to_owned());
    let Ok(token) = jsonwebtoken::encode(&header, &claims, &SIGNING_KEY) else {
        return;
    };
    if let Ok(principal) = common::validate(&token, &KEYS, &CONFIG) {
        assert_eq!(claims["iss"], common::ISSUER);
        assert!(claims["exp"].as_u64().is_some_and(|exp| exp >= common::NOW - 60));
        assert!(!principal.subject.is_empty());
        assert_eq!(claims["sub"], principal.subject.as_str());
        let roles = &claims["realm_access"]["roles"];
        let has = |role: &str| roles.as_array().is_some_and(|roles| roles.iter().any(|r| r == role));
        match principal.role {
            PlatformRole::Admin => assert!(has("kanbot-admin")),
            PlatformRole::User => assert!(has("kanbot-user") && !has("kanbot-admin")),
        }
        assert_eq!(principal.client_id.as_deref(), Some("kanbot-cli"));
    }
});
