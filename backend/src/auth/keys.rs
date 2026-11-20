//! The identity provider's signing keys: parsing the JWKS, and the cache
//! that keeps them fresh.
//!
//! Only keys kanbot can verify safely are kept: RSA of at least 2048 bits,
//! EC P-256 and P-384, and Ed25519, meant for signatures. Anything else is
//! skipped, never an error, so one odd key cannot take authentication down.

use std::{
    collections::HashMap,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, PublicKeyUse},
};
use serde::Deserialize;
use serde_json::Value;
use tokio::{sync::Mutex, time::Instant};

use crate::auth::{
    config::OidcConfig,
    discovery::{self, Discovery, DiscoveryError, FetchError, IdpClient},
};

/// Largest JWKS read, in bytes.
pub const MAX_JWKS_BYTES: usize = 256 * 1024;
/// Smallest RSA modulus accepted, in bits.
pub const MIN_RSA_BITS: usize = 2048;
/// An unknown `kid` refreshes the keys at most this often.
pub const UNKNOWN_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
/// First retry delay after a failed refresh. Doubles up to
/// [`MAX_RETRY_DELAY`], and never exceeds `OIDC_JWKS_TTL`.
const FIRST_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);

/// A key and the one algorithm it may verify.
pub struct VerifyingKey {
    algorithm: Algorithm,
    key: DecodingKey,
}

impl VerifyingKey {
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    #[must_use]
    pub fn decoding_key(&self) -> &DecodingKey {
        &self.key
    }
}

/// Usable signing keys by `kid`.
#[derive(Default)]
pub struct KeySet(HashMap<String, Arc<VerifyingKey>>);

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Value>,
}

impl KeySet {
    /// The usable keys of a JWKS document. Keys without a `kid` cannot be
    /// selected by a token and are skipped too. When two keys share a
    /// `kid`, the first wins.
    #[must_use]
    pub fn from_jwks(keys: &[Value]) -> Self {
        let mut set = HashMap::new();
        for (kid, key) in keys.iter().filter_map(usable_key) {
            set.entry(kid).or_insert_with(|| Arc::new(key));
        }
        Self(set)
    }

    #[must_use]
    pub fn get(&self, kid: &str) -> Option<Arc<VerifyingKey>> {
        self.0.get(kid).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn usable_key(value: &Value) -> Option<(String, VerifyingKey)> {
    let jwk: Jwk = serde_json::from_value(value.clone()).ok()?;
    if !matches!(
        jwk.common.public_key_use,
        None | Some(PublicKeyUse::Signature)
    ) {
        return None;
    }
    let kid = jwk.common.key_id.clone()?;
    let algorithm = algorithm_for(&jwk)?;
    let key = DecodingKey::from_jwk(&jwk).ok()?;
    if let AlgorithmParameters::RSA(_) = jwk.algorithm
        && rsa_modulus_bits(&key)? < MIN_RSA_BITS
    {
        return None;
    }
    Some((kid, VerifyingKey { algorithm, key }))
}

/// The key's algorithm: its `alg` if that is allowed for its type, else
/// the one its type implies. `None` for any other key.
fn algorithm_for(jwk: &Jwk) -> Option<Algorithm> {
    let implied = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Algorithm::RS256,
        AlgorithmParameters::EllipticCurve(params) => match params.curve {
            EllipticCurve::P256 => Algorithm::ES256,
            EllipticCurve::P384 => Algorithm::ES384,
            _ => return None,
        },
        AlgorithmParameters::OctetKeyPair(params) if params.curve == EllipticCurve::Ed25519 => {
            Algorithm::EdDSA
        }
        _ => return None,
    };
    let Some(declared) = jwk.common.key_algorithm else {
        return Some(implied);
    };
    let declared = Algorithm::try_from(declared).ok()?;
    let rsa = [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ];
    let allowed = declared == implied || (implied == Algorithm::RS256 && rsa.contains(&declared));
    allowed.then_some(declared)
}

fn rsa_modulus_bits(key: &DecodingKey) -> Option<usize> {
    let jsonwebtoken::DecodingKeyKind::RsaModulusExponent { n, .. } = key.kind() else {
        return None;
    };
    let mut significant = n.iter().skip_while(|byte| **byte == 0);
    let first = significant.next()?;
    let rest = significant.count();
    rest.checked_mul(8)?
        .checked_add(usize::try_from(8_u32.checked_sub(first.leading_zeros())?).ok()?)
}

/// Why the keys could not be refreshed. The previous keys stay in use.
#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryError),
    #[error("the JWKS could not be fetched")]
    Fetch(#[from] FetchError),
    #[error("the JWKS has no usable key")]
    NoUsableKeys,
}

/// The result of looking up a token's key.
pub enum KeyLookup {
    Found(Arc<VerifyingKey>),
    /// No key with this `kid`, even after a refresh (or the refresh was
    /// throttled).
    Unknown,
    /// No keys have been loaded yet: the service is not ready.
    NotLoaded,
}

/// The current signing keys and discovery document, refreshed in the
/// background. Readers take a short read lock and clone an `Arc`; no lock
/// is ever held across `.await` except the refresh mutex, which serializes
/// refreshes.
pub struct KeyCache {
    config: Arc<OidcConfig>,
    client: IdpClient,
    discovery: RwLock<Option<Arc<Discovery>>>,
    keys: RwLock<Option<Arc<KeySet>>>,
    /// Incremented after every refresh attempt, so requests that waited for
    /// one do not start another.
    refreshes: AtomicU64,
    refresh: Mutex<Option<Instant>>,
}

impl KeyCache {
    /// An empty cache: not ready until [`KeyCache::refresh`] succeeds.
    #[must_use]
    pub fn new(config: Arc<OidcConfig>, client: IdpClient) -> Self {
        Self {
            config,
            client,
            discovery: RwLock::new(None),
            keys: RwLock::new(None),
            refreshes: AtomicU64::new(0),
            refresh: Mutex::new(None),
        }
    }

    /// A cache holding `keys`, which a refresh may replace. For a fixed key
    /// set, as in tests.
    #[must_use]
    pub fn with_keys(config: Arc<OidcConfig>, client: IdpClient, keys: KeySet) -> Self {
        let cache = Self::new(config, client);
        cache.store_keys(keys);
        cache
    }

    #[must_use]
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Whether a usable key set has been loaded.
    #[must_use]
    pub fn is_loaded(&self) -> bool {
        self.keys().is_some()
    }

    /// The latest discovery document, once one has been fetched.
    #[must_use]
    pub fn discovery(&self) -> Option<Arc<Discovery>> {
        self.discovery
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn keys(&self) -> Option<Arc<KeySet>> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn store_keys(&self, keys: KeySet) {
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(keys));
    }

    /// The key for `kid`. An unknown `kid` triggers one refresh, shared by
    /// every request waiting for it and at most once per
    /// [`UNKNOWN_KEY_REFRESH_INTERVAL`]; then the key is looked up again.
    pub async fn key(&self, kid: &str) -> KeyLookup {
        let Some(keys) = self.keys() else {
            return KeyLookup::NotLoaded;
        };
        if let Some(key) = keys.get(kid) {
            return KeyLookup::Found(key);
        }
        let seen = self.refreshes.load(Ordering::Acquire);
        let mut last = self.refresh.lock().await;
        let refreshed_meanwhile = self.refreshes.load(Ordering::Acquire) != seen;
        let throttled = last.is_some_and(|last| last.elapsed() < UNKNOWN_KEY_REFRESH_INTERVAL);
        if !refreshed_meanwhile && !throttled {
            *last = Some(Instant::now());
            if let Err(error) = self.refresh_locked(false).await {
                tracing::warn!(%error, "signing keys could not be refreshed for an unknown key id");
            }
        }
        drop(last);
        match self.keys().and_then(|keys| keys.get(kid)) {
            Some(key) => KeyLookup::Found(key),
            None => KeyLookup::Unknown,
        }
    }

    /// Fetches the discovery document, then the JWKS. On failure, or a
    /// JWKS without usable keys, the previous keys stay in use.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshError`] if either fetch fails or no key is usable.
    pub async fn refresh(&self) -> Result<usize, RefreshError> {
        let _serialized = self.refresh.lock().await;
        self.refresh_locked(true).await
    }

    /// Fetches the JWKS, after the discovery document when `rediscover` is
    /// set or none is known yet. Callers hold the refresh mutex.
    async fn refresh_locked(&self, rediscover: bool) -> Result<usize, RefreshError> {
        let result = async {
            let discovery = if let Some(discovery) = self.discovery().filter(|_| !rediscover) {
                discovery
            } else {
                let discovery = Arc::new(discovery::discover(&self.client, &self.config).await?);
                *self
                    .discovery
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&discovery));
                discovery
            };
            self.fetch_keys(&discovery).await
        }
        .await;
        self.refreshes.fetch_add(1, Ordering::AcqRel);
        result
    }

    async fn fetch_keys(&self, discovery: &Discovery) -> Result<usize, RefreshError> {
        let jwks: Jwks = self
            .client
            .get_json(discovery.jwks_uri.clone(), MAX_JWKS_BYTES)
            .await?;
        let keys = KeySet::from_jwks(&jwks.keys);
        if keys.is_empty() {
            return Err(RefreshError::NoUsableKeys);
        }
        let count = keys.len();
        self.store_keys(keys);
        Ok(count)
    }

    /// Refreshes now, then every `OIDC_JWKS_TTL`. A failed refresh is
    /// retried sooner, with exponential backoff, so the server becomes
    /// ready as soon as the identity provider is reachable.
    pub fn spawn_refresh(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            let ttl = cache.config.jwks_ttl;
            let mut retry_delay = FIRST_RETRY_DELAY;
            loop {
                let delay = match cache.refresh().await {
                    Ok(count) => {
                        tracing::info!(
                            keys = i64::try_from(count).unwrap_or(i64::MAX),
                            "signing keys loaded"
                        );
                        retry_delay = FIRST_RETRY_DELAY;
                        ttl
                    }
                    Err(error) => {
                        tracing::warn!(%error, "signing keys could not be refreshed");
                        let delay = retry_delay.min(ttl);
                        retry_delay = retry_delay.saturating_mul(2).min(MAX_RETRY_DELAY);
                        delay
                    }
                };
                tokio::time::sleep(delay).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/tests/fixtures/oidc/{name}.jwk.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn with(mut jwk: Value, field: &str, value: Value) -> Value {
        jwk[field] = value;
        jwk
    }

    fn algorithm(jwk: &Value) -> Option<Algorithm> {
        let set = KeySet::from_jwks(std::slice::from_ref(jwk));
        set.get(jwk["kid"].as_str()?).map(|key| key.algorithm())
    }

    #[test]
    fn derives_the_algorithm_from_the_key_type() {
        assert_eq!(algorithm(&fixture("rsa-a")), Some(Algorithm::RS256));
        assert_eq!(algorithm(&fixture("p256")), Some(Algorithm::ES256));
        assert_eq!(algorithm(&fixture("p384")), Some(Algorithm::ES384));
        assert_eq!(algorithm(&fixture("ed25519")), Some(Algorithm::EdDSA));
    }

    #[test]
    fn keeps_an_allowed_declared_algorithm() {
        for alg in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
            let expected: Algorithm = alg.parse().unwrap();
            assert_eq!(
                algorithm(&with(fixture("rsa-a"), "alg", json!(alg))),
                Some(expected)
            );
        }
        assert_eq!(
            algorithm(&with(fixture("p256"), "alg", json!("ES256"))),
            Some(Algorithm::ES256)
        );
        assert_eq!(
            algorithm(&with(fixture("ed25519"), "alg", json!("EdDSA"))),
            Some(Algorithm::EdDSA)
        );
    }

    #[test]
    fn skips_keys_whose_algorithm_does_not_fit() {
        for (name, alg) in [
            ("rsa-a", "HS256"),
            ("rsa-a", "ES256"),
            ("rsa-a", "RSA-OAEP"),
            ("rsa-a", "none"),
            ("p256", "ES384"),
            ("p384", "ES256"),
            ("p256", "RS256"),
            ("ed25519", "ES256"),
        ] {
            assert_eq!(
                algorithm(&with(fixture(name), "alg", json!(alg))),
                None,
                "{name} {alg}"
            );
        }
    }

    #[test]
    fn skips_weak_rsa_keys() {
        assert_eq!(algorithm(&fixture("rsa-1024")), None);
    }

    #[test]
    fn skips_keys_not_meant_for_signatures() {
        assert_eq!(
            algorithm(&with(fixture("rsa-a"), "use", json!("enc"))),
            None
        );
        assert_eq!(
            algorithm(&with(fixture("rsa-a"), "use", json!("sig"))),
            Some(Algorithm::RS256)
        );
    }

    #[test]
    fn skips_unsupported_and_malformed_keys_without_failing() {
        let keys = [
            json!({ "kty": "oct", "kid": "hmac", "k": "c2VjcmV0" }),
            json!({ "kty": "EC", "kid": "p521", "crv": "P-521", "x": "AA", "y": "AA" }),
            json!({ "kty": "OKP", "kid": "x25519", "crv": "X25519", "x": "AA" }),
            json!({ "kty": "RSA", "kid": "broken", "n": "!!!", "e": "AQAB" }),
            json!({ "kid": "no-type" }),
            json!("not an object"),
            with(fixture("rsa-b"), "kid", Value::Null),
            fixture("rsa-a"),
        ];
        let set = KeySet::from_jwks(&keys);
        assert_eq!(set.len(), 1);
        assert!(set.get("rsa-a").is_some());
    }

    #[test]
    fn first_key_wins_a_duplicate_kid() {
        let set =
            KeySet::from_jwks(&[fixture("p256"), with(fixture("p384"), "kid", json!("p256"))]);
        assert_eq!(set.len(), 1);
        assert_eq!(set.get("p256").unwrap().algorithm(), Algorithm::ES256);
    }

    #[test]
    fn counts_rsa_modulus_bits() {
        let key = |n: &[u8]| DecodingKey::from_rsa_raw_components(n, &[1, 0, 1]);
        assert_eq!(rsa_modulus_bits(&key(&[0x80, 0])), Some(16));
        assert_eq!(rsa_modulus_bits(&key(&[0, 0, 0x01, 0])), Some(9));
        assert_eq!(rsa_modulus_bits(&key(&[0x7f])), Some(7));
        assert_eq!(rsa_modulus_bits(&key(&[0, 0])), None);
        assert_eq!(rsa_modulus_bits(&DecodingKey::from_ed_der(&[1; 32])), None);
        assert_eq!(rsa_modulus_bits(&key(&[0xff; 256])), Some(2048));
    }
}
