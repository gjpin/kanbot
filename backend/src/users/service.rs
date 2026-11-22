//! Business rules for users.

use sqlx::PgPool;

use crate::{
    auth::token::Principal,
    authz::{
        model::{Action, Actor, Resource},
        policies::Policies,
        service::{self as authz, allowed_actions},
    },
    error::AppError,
    users::{
        model::{AuthenticatedUser, UserId, UserQuery, UserSummary},
        repo,
    },
};

/// Most users a search returns.
pub const SEARCH_LIMIT: i64 = 20;

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
        groups_claimed: principal.groups.is_some(),
        groups: principal.groups.clone().unwrap_or(seen.groups),
        client_id: principal.client_id.clone(),
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

/// Disables the user: every request of theirs is refused from now on
/// (`account_disabled`), and their kanbot sessions end at once.
///
/// # Errors
///
/// [`AppError::NotFound`] if the user does not exist, or a database
/// error.
pub async fn disable(db: &PgPool, id: UserId) -> Result<(), AppError> {
    let mut tx = db.begin().await?;
    if !repo::disable(&mut tx, id).await? {
        return Err(AppError::NotFound);
    }
    crate::sessions::service::end_user_sessions(&mut tx, id).await?;
    tx.commit().await?;
    tracing::info!(user.id = %id.as_uuid(), "user disabled");
    Ok(())
}

/// Refuses a user who does not exist or is disabled, as someone to add to
/// an organization or a team: [`AppError::NotFound`], as `GET /users`
/// does not list them either.
///
/// # Errors
///
/// [`AppError::NotFound`], or a database error.
pub async fn require_active(db: &PgPool, id: UserId) -> Result<(), AppError> {
    if repo::is_active(db, id).await? {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// Ends every kanbot session of the user (for a user found disabled).
///
/// # Errors
///
/// A database error.
pub async fn end_sessions(db: &PgPool, id: UserId) -> Result<(), AppError> {
    let mut conn = db.acquire().await?;
    let ended = crate::sessions::service::end_user_sessions(&mut conn, id).await?;
    tracing::info!(
        user.id = %id.as_uuid(),
        sessions = i64::try_from(ended).unwrap_or(i64::MAX),
        "sessions of a disabled user ended"
    );
    Ok(())
}

/// Users whose display name contains `query`, for adding admins and
/// members. Disabled users are left out.
///
/// # Errors
///
/// [`AppError::Forbidden`] unless `actor` may `searchUsers` (platform
/// admins, organization admins and team maintainers), or a database error.
pub async fn search(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    query: &UserQuery,
) -> Result<Vec<UserSummary>, AppError> {
    authz::require(db, policies, actor, Action::SearchUsers, Resource::Platform).await?;
    Ok(repo::search(db, query, SEARCH_LIMIT).await?)
}

/// The instance-wide actions `actor` may do (`createOrganization`,
/// `createTeam`, `searchUsers`, `viewAudit`).
///
/// # Errors
///
/// A database error.
pub async fn platform_permissions(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
) -> Result<Vec<Action>, AppError> {
    let actions = [
        Action::CreateOrganization,
        Action::CreateTeam,
        Action::SearchUsers,
        Action::ViewAudit,
    ];
    let requests = actions.map(|action| (action, Resource::Platform));
    let decisions = authz::decisions(db, policies, actor, &requests).await?;
    Ok(allowed_actions(&actions, &decisions))
}
