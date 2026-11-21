//! Tokens for the `OpenShell` gateway, from the identity provider's token
//! endpoint:
//!
//! - a service account token (`client_credentials`) for kanbot's own calls,
//!   such as membership sync, cached until shortly before it expires;
//! - for calls a user starts, the user's token exchanged for one with the
//!   gateway's audience (RFC 8693), where the identity provider supports it
//!   (`OPENSHELL_TOKEN_EXCHANGE`); otherwise the service account.
//!
//! Every token is checked before use: it must carry the gateway's audience
//! and must not carry kanbot's, so no token valid for both services is
//! ever sent.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::{auth::keys::KeyCache, openshell::config::OpenShellConfig};

/// Largest token response read.
const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
/// A cached token is replaced this long before it expires.
const EXPIRY_MARGIN_SECONDS: u64 = 30;

const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// Why no token could be had. Never holds a token.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("the identity provider's token endpoint is not known yet")]
    NoTokenEndpoint,
    #[error("the token request failed")]
    Request(#[source] crate::auth::discovery::FetchError),
    #[error("the token is not a JWT with an audience and an expiry")]
    Malformed,
    #[error("the token is not for the gateway's audience")]
    WrongAudience,
    /// The token would also be accepted by kanbot: never sent anywhere.
    #[error("the token is also valid for kanbot")]
    SharedAudience,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// A checked token and when it expires (seconds since the epoch).
struct Checked {
    token: SecretString,
    expires_at: u64,
}

/// Gets tokens for the gateway.
pub struct Credentials {
    config: Arc<OpenShellConfig>,
    keys: Arc<KeyCache>,
    service: Mutex<Option<Checked>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The audiences and expiry of a JWT's payload. The signature is not
/// checked: the token comes straight from the identity provider over TLS,
/// and the gateway verifies it; this only refuses tokens that must not be
/// sent.
fn audiences_and_expiry(token: &str) -> Option<(Vec<String>, u64)> {
    let mut segments = token.split('.');
    let (_, payload, _) = (segments.next()?, segments.next()?, segments.next()?);
    if segments.next().is_some() {
        return None;
    }
    let standard = payload.replace('-', "+").replace('_', "/");
    let claims: Value = serde_json::from_slice(&crate::base64::decode_standard(&standard)?).ok()?;
    let audiences = match claims.get("aud")? {
        Value::String(one) => vec![one.clone()],
        Value::Array(many) => many
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => return None,
    };
    Some((audiences, claims.get("exp")?.as_u64()?))
}

impl Credentials {
    #[must_use]
    pub fn new(config: Arc<OpenShellConfig>, keys: Arc<KeyCache>) -> Self {
        Self {
            config,
            keys,
            service: Mutex::new(None),
        }
    }

    /// Accepts `token` only if it is for the gateway and not for kanbot.
    fn check(&self, token: String) -> Result<Checked, CredentialError> {
        let (audiences, expires_at) =
            audiences_and_expiry(&token).ok_or(CredentialError::Malformed)?;
        let kanbot = self.keys.config().audience.as_str();
        if audiences.iter().any(|audience| audience == kanbot) {
            tracing::warn!(
                "openshell: the identity provider issued a token for both services; not used"
            );
            return Err(CredentialError::SharedAudience);
        }
        if !audiences
            .iter()
            .any(|audience| *audience == self.config.audience)
        {
            return Err(CredentialError::WrongAudience);
        }
        Ok(Checked {
            token: SecretString::from(token),
            expires_at,
        })
    }

    async fn request(&self, form: &[(&str, &str)]) -> Result<Checked, CredentialError> {
        let endpoint = self
            .keys
            .discovery()
            .and_then(|discovery| discovery.token_endpoint.clone())
            .ok_or(CredentialError::NoTokenEndpoint)?;
        let mut form = form.to_vec();
        if let Some(scope) = &self.config.token_scope {
            form.push(("scope", scope));
        }
        let response: TokenResponse = self
            .keys
            .client()
            .post_form(
                endpoint,
                &self.config.client_id,
                &self.config.client_secret,
                &form,
                MAX_TOKEN_RESPONSE_BYTES,
            )
            .await
            .map_err(CredentialError::Request)?;
        self.check(response.access_token)
    }

    /// The service account's token (`client_credentials`), cached until
    /// shortly before it expires.
    ///
    /// # Errors
    ///
    /// [`CredentialError`].
    pub async fn service_token(&self) -> Result<SecretString, CredentialError> {
        let mut cached = self.service.lock().await;
        if let Some(checked) = cached.as_ref()
            && checked.expires_at > now().saturating_add(EXPIRY_MARGIN_SECONDS)
        {
            return Ok(checked.token.clone());
        }
        let fresh = self
            // The audience comes from the identity provider's setup of the
            // client (or OPENSHELL_TOKEN_SCOPE): `audience` is not a
            // standard parameter here, and some providers refuse it.
            .request(&[("grant_type", "client_credentials")])
            .await?;
        let token = fresh.token.clone();
        *cached = Some(fresh);
        Ok(token)
    }

    /// A token for a call `user_token`'s user starts: the user's token
    /// exchanged for the gateway's audience, or the service account's when
    /// token exchange is off.
    ///
    /// # Errors
    ///
    /// [`CredentialError`].
    pub async fn on_behalf_of(
        &self,
        user_token: &SecretString,
    ) -> Result<SecretString, CredentialError> {
        if !self.config.token_exchange {
            return self.service_token().await;
        }
        let checked = self
            .request(&[
                ("grant_type", TOKEN_EXCHANGE),
                ("subject_token", user_token.expose_secret()),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("requested_token_type", ACCESS_TOKEN_TYPE),
                ("audience", &self.config.audience),
            ])
            .await?;
        Ok(checked.token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64::encode_url;

    fn jwt(claims: &Value) -> String {
        format!(
            "{}.{}.sig",
            encode_url(br#"{"alg":"RS256"}"#),
            encode_url(claims.to_string().as_bytes())
        )
    }

    #[test]
    fn reads_audiences_and_expiry() {
        assert_eq!(
            audiences_and_expiry(&jwt(&serde_json::json!({"aud": "a", "exp": 5}))),
            Some((vec!["a".to_owned()], 5))
        );
        assert_eq!(
            audiences_and_expiry(&jwt(&serde_json::json!({"aud": ["a", 1, "b"], "exp": 9}))),
            Some((vec!["a".to_owned(), "b".to_owned()], 9))
        );
        for claims in [
            serde_json::json!({"exp": 5}),
            serde_json::json!({"aud": "a"}),
            serde_json::json!({"aud": 3, "exp": 5}),
            serde_json::json!({"aud": "a", "exp": "soon"}),
        ] {
            assert_eq!(audiences_and_expiry(&jwt(&claims)), None, "{claims}");
        }
        for token in ["opaque", "a.b", "a.b.c.d", "a.!!.c"] {
            assert_eq!(audiences_and_expiry(token), None, "{token}");
        }
    }
}
