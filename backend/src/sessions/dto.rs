//! Request and response types of the `/auth` routes.

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::{
    error::{AppError, FieldError},
    sessions::model::{AppRedirect, CodeChallenge, LoginRequest},
};

/// Which app signs in.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PlatformDto {
    Web,
    Native,
}

/// `GET /auth/login` parameters.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct LoginQuery {
    /// `web` or `native`.
    #[param(inline)]
    pub platform: PlatformDto,
    /// Native only: `dev.sideral.kanbot:/auth/done`, or
    /// `http://127.0.0.1:<port>/auth/done` on Windows and Linux.
    pub redirect_uri: Option<String>,
    /// Native only: the S256 PKCE challenge of the app's verifier.
    pub code_challenge: Option<String>,
    /// Native only: `S256`.
    pub code_challenge_method: Option<String>,
}

impl TryFrom<LoginQuery> for LoginRequest {
    type Error = AppError;

    fn try_from(query: LoginQuery) -> Result<Self, AppError> {
        match query.platform {
            PlatformDto::Web => {
                let extra = [
                    ("/redirect_uri", query.redirect_uri.is_some()),
                    ("/code_challenge", query.code_challenge.is_some()),
                    (
                        "/code_challenge_method",
                        query.code_challenge_method.is_some(),
                    ),
                ];
                let errors: Vec<FieldError> = extra
                    .into_iter()
                    .filter(|(_, present)| *present)
                    .map(|(pointer, _)| FieldError::new(pointer, "not_allowed"))
                    .collect();
                if errors.is_empty() {
                    Ok(Self::Web)
                } else {
                    Err(AppError::Validation(errors))
                }
            }
            PlatformDto::Native => {
                let mut errors = Vec::new();
                let redirect = match query.redirect_uri.as_deref() {
                    None => {
                        errors.push(FieldError::new("/redirect_uri", "required"));
                        None
                    }
                    Some(raw) => AppRedirect::parse(raw).or_else(|| {
                        errors.push(FieldError::new("/redirect_uri", "not_allowed"));
                        None
                    }),
                };
                let challenge = match query.code_challenge.as_deref() {
                    None => {
                        errors.push(FieldError::new("/code_challenge", "required"));
                        None
                    }
                    Some(raw) => CodeChallenge::parse(raw).or_else(|| {
                        errors.push(FieldError::new("/code_challenge", "invalid"));
                        None
                    }),
                };
                match query.code_challenge_method.as_deref() {
                    Some("S256") => {}
                    None => errors.push(FieldError::new("/code_challenge_method", "required")),
                    Some(_) => {
                        errors.push(FieldError::new("/code_challenge_method", "not_allowed"));
                    }
                }
                match (redirect, challenge) {
                    (Some(redirect), Some(challenge)) if errors.is_empty() => Ok(Self::Native {
                        redirect,
                        challenge,
                    }),
                    _ => Err(AppError::Validation(errors)),
                }
            }
        }
    }
}

/// A secret in a request body. Never printed or logged.
pub struct SecretInput(SecretString);

impl SecretInput {
    #[must_use]
    pub fn secret(&self) -> &SecretString {
        &self.0
    }
}

impl<'de> Deserialize<'de> for SecretInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(SecretString::from(value)))
    }
}

/// `POST /auth/token`: a native app redeems its one-time code.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TokenRequest {
    /// The `code` the app received at its redirect URI.
    #[schema(value_type = String)]
    pub code: SecretInput,
    /// The PKCE verifier whose S256 challenge the app sent to `/auth/login`
    /// (RFC 7636: 43 to 128 characters of `A-Z a-z 0-9 - . _ ~`).
    #[schema(value_type = String)]
    pub code_verifier: SecretInput,
}

impl TokenRequest {
    /// Field errors for a verifier that RFC 7636 does not allow.
    #[must_use]
    pub fn invalid_fields(&self) -> Vec<FieldError> {
        let verifier = self.code_verifier.secret().expose_secret();
        let valid = (43..=128).contains(&verifier.len())
            && verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        if valid {
            Vec::new()
        } else {
            vec![FieldError::new("/code_verifier", "invalid")]
        }
    }
}

/// A native app's session.
#[derive(Serialize, ToSchema)]
pub struct TokenResponse {
    /// Send as `Authorization: Bearer <session_token>`. Store it only in
    /// the platform's secure storage.
    pub session_token: String,
    /// When the session ends at the latest (RFC 3339, UTC). It can end
    /// sooner: when idle, on logout, or when the identity provider refuses
    /// to refresh it.
    pub expires_at: String,
}

/// What an app needs to know before signing in.
#[derive(Serialize, ToSchema)]
pub struct AuthConfig {
    /// Where to start a sign-in (`?platform=web` or `?platform=native&...`).
    pub login_url: String,
    /// Whether this instance relays the app's telemetry. Each user still
    /// decides (`telemetry_opt_in`).
    pub telemetry_available: bool,
    /// The server's version.
    pub version: String,
}

/// The outcome of a sign-out.
#[derive(Serialize, ToSchema)]
pub struct LogoutResponse {
    /// Where to send the browser to sign out of the identity provider too,
    /// when it supports that (RP-initiated logout). `null` otherwise.
    pub logout_url: Option<String>,
}
