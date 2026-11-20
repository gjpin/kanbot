//! Shared extractors.

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{auth::token::PlatformRole, error::AppError, users::model::AuthenticatedUser};

/// The authenticated user. Without one (no credentials), the request is
/// refused with `401` and `WWW-Authenticate: Bearer`.
pub struct AuthUser(pub AuthenticatedUser);

impl<S: Send + Sync> FromRequestParts<S> for AuthUser {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<AuthenticatedUser>()
                .cloned()
                .map(Self)
                .ok_or(AppError::Unauthorized),
        )
    }
}

/// An authenticated platform admin: `401` without a user, `403` for any
/// other user.
pub struct RequireAdmin(pub AuthenticatedUser);

impl<S: Send + Sync> FromRequestParts<S> for RequireAdmin {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        if user.role == PlatformRole::Admin {
            Ok(Self(user))
        } else {
            Err(AppError::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::*;
    use crate::users::model::UserId;

    fn parts(user: Option<AuthenticatedUser>) -> Parts {
        let mut request = Request::new(());
        if let Some(user) = user {
            request.extensions_mut().insert(user);
        }
        request.into_parts().0
    }

    fn user(role: PlatformRole) -> AuthenticatedUser {
        AuthenticatedUser {
            id: UserId::new(),
            role,
            display_name: None,
            telemetry_opt_in: false,
        }
    }

    #[tokio::test]
    async fn auth_user_needs_a_user() {
        let alice = user(PlatformRole::User);
        let AuthUser(found) = AuthUser::from_request_parts(&mut parts(Some(alice.clone())), &())
            .await
            .unwrap();
        assert_eq!(found, alice);
        assert!(matches!(
            AuthUser::from_request_parts(&mut parts(None), &()).await,
            Err(AppError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn require_admin_needs_an_admin() {
        let admin = user(PlatformRole::Admin);
        let RequireAdmin(found) =
            RequireAdmin::from_request_parts(&mut parts(Some(admin.clone())), &())
                .await
                .unwrap();
        assert_eq!(found, admin);
        assert!(matches!(
            RequireAdmin::from_request_parts(&mut parts(Some(user(PlatformRole::User))), &()).await,
            Err(AppError::Forbidden)
        ));
        assert!(matches!(
            RequireAdmin::from_request_parts(&mut parts(None), &()).await,
            Err(AppError::Unauthorized)
        ));
    }
}
