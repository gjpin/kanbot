//! Checks the other features ask of the `OpenShell` integration.

use secrecy::SecretString;

use crate::{
    error::{AppError, FieldError},
    openshell::{OpenShell, gateway::GatewayError, model::MemberRole, model::WorkspaceName},
};

/// Whether `workspace` may be linked to an organization:
///
/// - with token exchange, the linking user must be an admin of the
///   workspace in `OpenShell` (asked with their own exchanged token);
///   being able to see it is not enough, since the sync then makes the
///   organization's admins workspace admins;
/// - without, it must exist for the service account.
///
/// `user_token` gives the user's own access token; it is only asked for
/// (a database read for a session) when token exchange is on.
///
/// # Errors
///
/// - a validation error on `/workspace` (`not_found`) when it does not
///   exist;
/// - [`AppError::Forbidden`] when the identity provider refuses the
///   exchange, the gateway refuses the user, or the user is no admin of it;
/// - [`AppError::Unavailable`] when no token or answer can be had.
pub async fn check_link(
    openshell: &OpenShell,
    workspace: &WorkspaceName,
    user_token: impl AsyncFnOnce() -> Result<SecretString, AppError>,
) -> Result<(), AppError> {
    let not_found = || AppError::Validation(vec![FieldError::new("/workspace", "not_found")]);
    let gateway_error = |error: GatewayError| match error {
        GatewayError::NotFound => not_found(),
        GatewayError::Refused => AppError::Forbidden,
        error => {
            tracing::warn!(%error, "openshell: workspace lookup failed");
            AppError::Unavailable
        }
    };
    if !openshell.credentials.exchanges_tokens() {
        let token = openshell
            .credentials
            .service_token()
            .await
            .map_err(|error| {
                tracing::warn!(%error, "openshell: no service token");
                AppError::Unavailable
            })?;
        return match openshell.gateway.workspace_exists(&token, workspace).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(not_found()),
            Err(error) => Err(gateway_error(error)),
        };
    }
    let user_token = user_token().await?;
    let token = openshell
        .credentials
        .on_behalf_of(&user_token)
        .await
        .map_err(|error| {
            tracing::warn!(%error, "openshell: no token for the user");
            if error.is_refusal() {
                AppError::Forbidden
            } else {
                AppError::Unavailable
            }
        })?;
    let subject = token.subject.ok_or(AppError::Unavailable)?;
    let members = openshell
        .gateway
        .members(&token.token, workspace)
        .await
        .map_err(gateway_error)?;
    let admin = members
        .iter()
        .any(|member| member.subject == subject && member.role == Some(MemberRole::Admin));
    if admin {
        Ok(())
    } else {
        tracing::info!("openshell: only a workspace admin may link the workspace");
        Err(AppError::Forbidden)
    }
}
