//! Business rules for users.

use sqlx::PgPool;

use crate::{
    auth::token::Principal,
    error::AppError,
    users::{
        model::{AuthenticatedUser, UserId},
        repo,
    },
};

/// The user for a validated principal, created on first sight.
///
/// # Errors
///
/// [`AppError::AccountDisabled`] if the user has been disabled, or a
/// database error.
pub async fn authenticate(
    db: &PgPool,
    principal: &Principal,
) -> Result<AuthenticatedUser, AppError> {
    // A concurrent first sign-in can hide the row from this statement's
    // snapshot; the second try sees it.
    let seen = match repo::record_seen(db, principal).await? {
        Some(seen) => seen,
        None => repo::record_seen(db, principal)
            .await?
            .ok_or(AppError::Database(sqlx::Error::RowNotFound))?,
    };
    if seen.disabled {
        tracing::info!(user.id = %seen.id.as_uuid(), "disabled user refused");
        return Err(AppError::AccountDisabled);
    }
    Ok(AuthenticatedUser {
        id: seen.id,
        role: principal.role,
        display_name: principal.display_name.clone(),
        telemetry_opt_in: seen.telemetry_opt_in,
    })
}

/// Sets whether the user's app may send telemetry.
///
/// # Errors
///
/// [`AppError::NotFound`] if the user no longer exists, or a database
/// error.
pub async fn set_telemetry_opt_in(db: &PgPool, id: UserId, opt_in: bool) -> Result<(), AppError> {
    if repo::set_telemetry_opt_in(db, id, opt_in).await? {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}
