//! Authentication against the test identity provider: discovery, the
//! signing key cache and its refresh rules.

pub mod common;

use std::{sync::Arc, time::Duration};

use axum::http::StatusCode;
use common::idp::{Reply, TestIdp};
use kanbot_backend::auth::{
    discovery::{DiscoveryError, FetchError, IdpClient, MAX_DISCOVERY_BYTES, discover},
    keys::{KeyLookup, MAX_JWKS_BYTES, RefreshError},
};
use serde_json::{Value, json};

fn found(lookup: &KeyLookup) -> bool {
    matches!(lookup, KeyLookup::Found(_))
}

/// A JSON body of exactly `size` bytes.
fn padded_json(size: usize) -> Vec<u8> {
    let overhead = br#"{"keys":[],"pad":""}"#.len();
    let pad = "x".repeat(size.checked_sub(overhead).unwrap());
    let body = json!({ "keys": [], "pad": pad }).to_string().into_bytes();
    assert_eq!(body.len(), size);
    body
}

#[tokio::test]
async fn loads_keys_through_discovery() {
    let idp = TestIdp::start().await;
    let cache = idp.key_cache(&[]);
    assert!(!cache.is_loaded());
    assert!(matches!(cache.key("rsa-a").await, KeyLookup::NotLoaded));

    assert_eq!(cache.refresh().await.unwrap(), 4);

    assert!(cache.is_loaded());
    for kid in ["rsa-a", "p256", "p384", "ed25519"] {
        assert!(found(&cache.key(kid).await), "{kid}");
    }
    let discovery = cache.discovery().unwrap();
    assert_eq!(discovery.jwks_uri.as_str(), format!("{}/jwks", idp.issuer));
    assert_eq!(
        discovery.token_endpoint.as_ref().unwrap().as_str(),
        format!("{}/token", idp.issuer)
    );
    assert_eq!(
        discovery.authorization_endpoint.as_ref().unwrap().as_str(),
        format!("{}/authorize", idp.issuer)
    );
    assert_eq!(discovery.end_session_endpoint, None);
}

#[tokio::test]
async fn keeps_end_session_and_drops_disallowed_endpoints() {
    let idp = TestIdp::start().await;
    let mut document = idp.discovery_document();
    document["end_session_endpoint"] = json!(format!("{}/logout", idp.issuer));
    document["token_endpoint"] = json!("http://idp.example.com/token");
    document["authorization_endpoint"] = json!(format!("{}/authorize#fragment", idp.issuer));
    idp.set_discovery(Reply::Json(document));
    let config = idp.config(&[]);
    let client = IdpClient::new(&[]).unwrap();

    let discovery = discover(&client, &config).await.unwrap();

    assert_eq!(
        discovery.end_session_endpoint.unwrap().as_str(),
        format!("{}/logout", idp.issuer)
    );
    assert_eq!(discovery.token_endpoint, None);
    assert_eq!(discovery.authorization_endpoint, None);

    // Credentials in an endpoint are never used.
    let mut document = idp.discovery_document();
    let with_credentials = idp.issuer.replacen("://", "://user:pass@", 1);
    document["token_endpoint"] = json!(format!("{with_credentials}/token"));
    idp.set_discovery(Reply::Json(document));
    let discovery = discover(&client, &config).await.unwrap();
    assert_eq!(discovery.token_endpoint, None);
}

async fn discovery_error(idp: &TestIdp, extra: &[(&'static str, &str)]) -> DiscoveryError {
    discover(&IdpClient::new(&[]).unwrap(), &idp.config(extra))
        .await
        .unwrap_err()
}

#[tokio::test]
async fn issuer_must_match_exactly() {
    let idp = TestIdp::start().await;
    let mut document = idp.discovery_document();
    document["issuer"] = json!(format!("{}/", idp.issuer));
    idp.set_discovery(Reply::Json(document));

    assert!(matches!(
        discovery_error(&idp, &[]).await,
        DiscoveryError::IssuerMismatch
    ));
}

#[tokio::test]
async fn configured_issuer_with_a_trailing_slash_must_match_too() {
    let idp = TestIdp::start().await;
    let with_slash = format!("{}/", idp.issuer);

    // Discovery is found (the slash is not doubled) but says no slash.
    assert!(matches!(
        discovery_error(&idp, &[("OIDC_ISSUER", &with_slash)]).await,
        DiscoveryError::IssuerMismatch
    ));
    assert_eq!(idp.discovery_requests(), 1);
}

#[tokio::test]
async fn jwks_uri_on_another_origin_needs_the_allowlist() {
    let idp = TestIdp::start().await;
    let keys_host = TestIdp::start().await;
    let mut document = idp.discovery_document();
    document["jwks_uri"] = json!(format!("{}/jwks", keys_host.issuer));
    idp.set_discovery(Reply::Json(document));

    assert!(matches!(
        discovery_error(&idp, &[]).await,
        DiscoveryError::JwksUri
    ));
    assert_eq!(keys_host.jwks_requests(), 0);

    let cache = idp.key_cache(&[("OIDC_JWKS_ALLOWED_ORIGINS", &keys_host.issuer)]);
    assert_eq!(cache.refresh().await.unwrap(), 4);
    assert_eq!(keys_host.jwks_requests(), 1);
    assert_eq!(idp.jwks_requests(), 0);
}

#[tokio::test]
async fn jwks_uri_must_be_an_allowed_url() {
    let idp = TestIdp::start().await;
    for jwks_uri in [
        "http://idp.example.com/jwks".to_owned(),
        "ftp://127.0.0.1/jwks".to_owned(),
        "not a url".to_owned(),
        idp.issuer.replace("http://", "http://user:pw@") + "/jwks",
    ] {
        let mut document = idp.discovery_document();
        document["jwks_uri"] = json!(jwks_uri);
        idp.set_discovery(Reply::Json(document));
        assert!(
            matches!(discovery_error(&idp, &[]).await, DiscoveryError::JwksUri),
            "{jwks_uri}"
        );
    }
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let idp = TestIdp::start().await;
    let target = TestIdp::start().await;
    idp.set_discovery(Reply::Redirect(format!(
        "{}/.well-known/openid-configuration",
        target.issuer
    )));
    assert!(matches!(
        discovery_error(&idp, &[]).await,
        DiscoveryError::Fetch(FetchError::Status(StatusCode::FOUND))
    ));
    assert_eq!(target.discovery_requests(), 0);

    idp.set_discovery(Reply::Json(idp.discovery_document()));
    idp.set_jwks(Reply::Redirect(format!("{}/jwks", target.issuer)));
    let cache = idp.key_cache(&[]);
    assert!(matches!(
        cache.refresh().await,
        Err(RefreshError::Fetch(FetchError::Status(StatusCode::FOUND)))
    ));
    assert_eq!(target.jwks_requests(), 0);
}

#[tokio::test]
async fn other_statuses_and_bad_json_fail() {
    let idp = TestIdp::start().await;
    idp.set_discovery(Reply::Status(StatusCode::INTERNAL_SERVER_ERROR));
    assert!(matches!(
        discovery_error(&idp, &[]).await,
        DiscoveryError::Fetch(FetchError::Status(StatusCode::INTERNAL_SERVER_ERROR))
    ));
    idp.set_discovery(Reply::Bytes(b"{\"issuer\":".to_vec()));
    assert!(matches!(
        discovery_error(&idp, &[]).await,
        DiscoveryError::Fetch(FetchError::Json(_))
    ));
}

#[tokio::test]
async fn oversized_bodies_are_refused_with_or_without_a_length() {
    let idp = TestIdp::start().await;
    let at_limit = {
        let mut document = idp.discovery_document();
        let base = document.to_string().len();
        document["pad"] = json!(
            "x".repeat(
                MAX_DISCOVERY_BYTES
                    .checked_sub(base)
                    .unwrap()
                    .checked_sub(",\"pad\":\"\"".len())
                    .unwrap()
            )
        );
        let body = document.to_string().into_bytes();
        assert_eq!(body.len(), MAX_DISCOVERY_BYTES);
        body
    };
    idp.set_discovery(Reply::Chunked(at_limit.clone()));
    discover(&IdpClient::new(&[]).unwrap(), &idp.config(&[]))
        .await
        .unwrap();

    let mut over = at_limit;
    over.insert(1, b' ');
    for reply in [Reply::Bytes(over.clone()), Reply::Chunked(over)] {
        idp.set_discovery(reply);
        assert!(matches!(
            discovery_error(&idp, &[]).await,
            DiscoveryError::Fetch(FetchError::TooLarge(MAX_DISCOVERY_BYTES))
        ));
    }

    idp.set_discovery(Reply::Json(idp.discovery_document()));
    let cache = idp.key_cache(&[]);
    let mut jwks = padded_json(MAX_JWKS_BYTES);
    idp.set_jwks(Reply::Chunked(jwks.clone()));
    // At the limit it is read, but holds no key.
    assert!(matches!(
        cache.refresh().await,
        Err(RefreshError::NoUsableKeys)
    ));
    jwks.insert(1, b' ');
    for reply in [Reply::Bytes(jwks.clone()), Reply::Chunked(jwks.clone())] {
        idp.set_jwks(reply);
        assert!(matches!(
            cache.refresh().await,
            Err(RefreshError::Fetch(FetchError::TooLarge(MAX_JWKS_BYTES)))
        ));
    }
}

#[tokio::test]
async fn a_large_jwks_is_read() {
    let idp = TestIdp::start().await;
    let keys: Vec<Value> = common::idp::DEFAULT_KEYS
        .iter()
        .map(|name| common::idp::jwk(name))
        .collect();
    // Well above any small limit, below the 256 KiB one.
    let jwks = json!({ "keys": keys, "pad": "x".repeat(200_000) });
    idp.set_jwks(Reply::Chunked(jwks.to_string().into_bytes()));

    assert_eq!(idp.key_cache(&[]).refresh().await.unwrap(), 4);
}

#[tokio::test]
async fn a_large_discovery_document_is_read() {
    let idp = TestIdp::start().await;
    let mut document = idp.discovery_document();
    document["pad"] = json!("x".repeat(50_000));
    idp.set_discovery(Reply::Bytes(document.to_string().into_bytes()));

    discover(&IdpClient::new(&[]).unwrap(), &idp.config(&[]))
        .await
        .unwrap();
}

#[tokio::test]
async fn slow_responses_time_out() {
    let idp = TestIdp::start().await;
    idp.set_discovery(Reply::Slow(Duration::from_secs(30), Value::Null));

    let started = std::time::Instant::now();
    let error = discovery_error(&idp, &[]).await;

    assert!(
        matches!(&error, DiscoveryError::Fetch(FetchError::Request(e)) if e.is_timeout()),
        "{error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn a_failed_or_empty_refresh_keeps_the_previous_keys() {
    let idp = TestIdp::start().await;
    let cache = idp.loaded_key_cache(&[]).await;

    idp.set_jwks(Reply::Json(json!({ "keys": [] })));
    assert!(matches!(
        cache.refresh().await,
        Err(RefreshError::NoUsableKeys)
    ));
    assert!(found(&cache.key("rsa-a").await));

    idp.set_keys(&["rsa-1024"]);
    assert!(matches!(
        cache.refresh().await,
        Err(RefreshError::NoUsableKeys)
    ));
    assert!(found(&cache.key("rsa-a").await));

    idp.set_jwks(Reply::Status(StatusCode::SERVICE_UNAVAILABLE));
    assert!(cache.refresh().await.is_err());
    assert!(found(&cache.key("rsa-a").await));

    idp.set_discovery(Reply::Status(StatusCode::SERVICE_UNAVAILABLE));
    assert!(matches!(
        cache.refresh().await,
        Err(RefreshError::Discovery(_))
    ));
    assert!(found(&cache.key("rsa-a").await));
}

#[tokio::test]
async fn a_successful_refresh_replaces_the_keys() {
    let idp = TestIdp::start().await;
    let cache = idp.loaded_key_cache(&[]).await;

    idp.set_keys(&["rsa-b"]);
    assert_eq!(cache.refresh().await.unwrap(), 1);

    assert!(found(&cache.key("rsa-b").await));
    assert!(matches!(cache.key("rsa-a").await, KeyLookup::Unknown));
}

#[tokio::test]
async fn an_unknown_kid_refreshes_and_finds_a_rotated_key() {
    let idp = TestIdp::start().await;
    let cache = idp.loaded_key_cache(&[]).await;
    let discoveries = idp.discovery_requests();
    idp.set_keys(&["rsa-a", "rsa-b"]);

    assert!(found(&cache.key("rsa-b").await));

    assert_eq!(idp.jwks_requests(), 2);
    // The known jwks_uri is reused.
    assert_eq!(idp.discovery_requests(), discoveries);
}

#[tokio::test]
async fn an_unknown_kid_stays_unknown_after_a_refresh() {
    let idp = TestIdp::start().await;
    let cache = idp.loaded_key_cache(&[]).await;

    assert!(matches!(cache.key("nope").await, KeyLookup::Unknown));
    assert_eq!(idp.jwks_requests(), 2);
    assert!(found(&cache.key("rsa-a").await));
}

#[tokio::test]
async fn unknown_kid_refreshes_are_shared_and_throttled() {
    let idp = TestIdp::start().await;
    let cache = idp.loaded_key_cache(&[]).await;
    assert_eq!(idp.jwks_requests(), 1);

    // Many requests at once share one refresh.
    let mut lookups = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let cache = Arc::clone(&cache);
        lookups.spawn(async move { cache.key("nope").await });
    }
    for lookup in lookups.join_all().await {
        assert!(matches!(lookup, KeyLookup::Unknown));
    }
    assert_eq!(idp.jwks_requests(), 2);

    // Within a second, an unknown kid does not refresh again...
    idp.set_keys(&["rsa-b"]);
    assert!(matches!(cache.key("rsa-b").await, KeyLookup::Unknown));
    assert_eq!(idp.jwks_requests(), 2);

    // ...after it, it does.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(found(&cache.key("rsa-b").await));
    assert_eq!(idp.jwks_requests(), 3);
}

#[tokio::test]
async fn the_refresh_task_retries_until_the_idp_answers() {
    let idp = TestIdp::start().await;
    idp.set_discovery(Reply::Status(StatusCode::SERVICE_UNAVAILABLE));
    let cache = idp.key_cache(&[]);

    let task = cache.spawn_refresh();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!cache.is_loaded());
    assert_eq!(idp.discovery_requests(), 1);

    idp.set_discovery(Reply::Json(idp.discovery_document()));
    for _ in 0..100 {
        if cache.is_loaded() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    task.abort();

    assert!(cache.is_loaded());
    assert_eq!(idp.discovery_requests(), 2);
}

#[tokio::test]
async fn the_refresh_task_refreshes_every_ttl() {
    let idp = TestIdp::start().await;
    let cache = idp.key_cache(&[("OIDC_JWKS_TTL", "1")]);

    let task = cache.spawn_refresh();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    task.abort();

    assert_eq!(idp.jwks_requests(), 3);
}
