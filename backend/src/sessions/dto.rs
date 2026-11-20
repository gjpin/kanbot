//! Request and response types of the `/auth` routes.

use serde::Deserialize;
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
