//! Tokens for the `OpenShell` gateway, from the identity provider's token
//! endpoint:
//!
//! - a service account token (`client_credentials`) for kanbot's own calls,
//!   such as membership sync, cached until shortly before it expires;
//! - for calls a user starts, the user's token exchanged for one with the
//!   gateway's audience (RFC 8693), where the identity provider supports it
//!   (`OPENSHELL_TOKEN_EXCHANGE`); otherwise the service account.
//!
//! Every token is verified before use like any other (signature with the
//! identity provider's keys, issuer, expiry) and must carry the gateway's
//! audience and not kanbot's, so no token valid for both services is ever
//! sent. An exchanged token must name the user whose token was exchanged.

use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::{
    auth::{
        discovery::FetchError,
        keys::{KeyCache, KeyLookup},
        token::{Rejection, UnverifiedToken},
    },
    openshell::config::OpenShellConfig,
};

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
    /// The identity provider's keys have not loaded: nothing can be
    /// verified yet.
    #[error("the identity provider's keys have not loaded")]
    KeysNotLoaded,
    #[error("the token request failed")]
    Request(#[source] FetchError),
    /// A token that does not verify (signature, issuer, expiry), or the
    /// user's own token is no valid kanbot token.
    #[error("the token does not verify: {}", .0.reason())]
    Invalid(Rejection),
    #[error("the token is not for the gateway's audience")]
    WrongAudience,
    /// The token would also be accepted by kanbot: never sent anywhere.
    #[error("the token is also valid for kanbot")]
    SharedAudience,
    /// The exchanged token names someone else than the user.
    #[error("the exchanged token is for another subject")]
    WrongSubject,
}

impl CredentialError {
    /// Whether the identity provider refused the request (`400`/`401` from
    /// its token endpoint), as opposed to failing.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        matches!(self, Self::Request(FetchError::Refused(..)))
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// A verified token, its subject and when it expires (seconds since the
/// epoch).
struct Checked {
    token: SecretString,
    subject: Option<String>,
    expires_at: u64,
}

/// A token for a call a user starts.
pub struct UserToken {
    pub token: SecretString,
    /// The subject the gateway will see: the user's, after an exchange;
    /// `None` for the service account's token.
    pub subject: Option<String>,
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
        .map_or(u64::MAX, |since| since.as_secs())
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

    /// Whether calls a user starts use the user's exchanged token.
    #[must_use]
    pub fn exchanges_tokens(&self) -> bool {
        self.config.token_exchange
    }

    /// The parsed token and its key.
    async fn key_for<'t>(
        &self,
        token: &'t str,
    ) -> Result<(UnverifiedToken<'t>, Arc<crate::auth::keys::VerifyingKey>), CredentialError> {
        let unverified = UnverifiedToken::parse(token).map_err(CredentialError::Invalid)?;
        match self.keys.key(unverified.kid()).await {
            KeyLookup::Found(key) => Ok((unverified, key)),
            KeyLookup::Unknown => Err(CredentialError::Invalid(Rejection::UnknownKey)),
            KeyLookup::NotLoaded | KeyLookup::Busy => Err(CredentialError::KeysNotLoaded),
        }
    }

    /// Accepts `token` only if it verifies, is for the gateway and not for
    /// kanbot.
    async fn check(&self, token: String) -> Result<Checked, CredentialError> {
        let (unverified, key) = self.key_for(&token).await?;
        let verified = unverified
            .verify_foreign(&key, self.keys.config(), &self.config.audience, now())
            .map_err(|rejection| match rejection {
                Rejection::WrongAudience => CredentialError::WrongAudience,
                other => CredentialError::Invalid(other),
            })?;
        let kanbot = self.keys.config().audience.as_str();
        if verified.audiences.iter().any(|audience| audience == kanbot) {
            tracing::warn!(
                "openshell: the identity provider issued a token for both services; not used"
            );
            return Err(CredentialError::SharedAudience);
        }
        Ok(Checked {
            subject: verified.subject,
            expires_at: verified.expires_at,
            token: SecretString::from(token),
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
        self.check(response.access_token).await
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
    /// token exchange is off. The user's token must be a valid kanbot
    /// token, and the exchanged one must name the same subject.
    ///
    /// # Errors
    ///
    /// [`CredentialError`].
    pub async fn on_behalf_of(
        &self,
        user_token: &SecretString,
    ) -> Result<UserToken, CredentialError> {
        if !self.config.token_exchange {
            return Ok(UserToken {
                token: self.service_token().await?,
                subject: None,
            });
        }
        let (unverified, key) = self.key_for(user_token.expose_secret()).await?;
        let user = unverified
            .verify(&key, self.keys.config(), now())
            .map_err(CredentialError::Invalid)?;
        let checked = self
            .request(&[
                ("grant_type", TOKEN_EXCHANGE),
                ("subject_token", user_token.expose_secret()),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("requested_token_type", ACCESS_TOKEN_TYPE),
                ("audience", &self.config.audience),
            ])
            .await?;
        if checked.subject.as_deref() != Some(user.subject.as_str()) {
            return Err(CredentialError::WrongSubject);
        }
        Ok(UserToken {
            token: checked.token,
            subject: checked.subject,
        })
    }
}
