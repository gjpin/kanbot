//! Shared extractors.

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    auth::{middleware::CurrentSession, token::PlatformRole},
    authz::model::{Actor, Via},
    error::AppError,
    http::client_ip::ClientIp,
    sessions::model::Platform,
    users::model::AuthenticatedUser,
};

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

/// The authenticated user as an authorization [`Actor`]: how they
/// authenticated (session cookie, session token or access token) and from
/// which address. `401` without a user.
pub struct Caller(pub Actor);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        let via = match parts.extensions.get::<CurrentSession>() {
            Some(CurrentSession {
                kind: Platform::Web,
                ..
            }) => Via::Web,
            Some(CurrentSession {
                kind: Platform::Native,
                ..
            }) => Via::Native,
            None => Via::Bearer,
        };
        let ClientIp(ip) = *parts
            .extensions
            .get::<ClientIp>()
            .ok_or(AppError::Internal("no client address"))?;
        Ok(Self(Actor { user, via, ip }))
    }
}

/// The user's own access token, for a call to another service on their
/// behalf: the one a bearer request presented, or the identity provider
/// token stored with the session. Never log it.
pub struct UserAccessToken(pub secrecy::SecretString);

impl FromRequestParts<crate::state::AppState> for UserAccessToken {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::state::AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(session) = parts.extensions.get::<CurrentSession>() {
            let token = crate::sessions::service::stored_access_token(
                &state.db,
                &state.sessions,
                session.id,
            )
            .await?;
            return Ok(Self(token));
        }
        parts
            .extensions
            .get::<crate::auth::middleware::BearerToken>()
            .map(|bearer| Self(bearer.0.clone()))
            .ok_or(AppError::Unauthorized)
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
            groups: Vec::new(),
            client_id: None,
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
    async fn caller_says_how_and_from_where() {
        let alice = user(PlatformRole::User);
        let ip: std::net::IpAddr = "2001:db8::7".parse().unwrap();
        for (session, via) in [
            (None, Via::Bearer),
            (Some(Platform::Web), Via::Web),
            (Some(Platform::Native), Via::Native),
        ] {
            let mut parts = parts(Some(alice.clone()));
            parts.extensions.insert(ClientIp(ip));
            if let Some(kind) = session {
                parts.extensions.insert(CurrentSession {
                    id: uuid::Uuid::new_v4(),
                    kind,
                    from_cookie: kind == Platform::Web,
                });
            }
            let Caller(actor) = Caller::from_request_parts(&mut parts, &()).await.unwrap();
            assert_eq!(
                actor,
                Actor {
                    user: alice.clone(),
                    via,
                    ip
                }
            );
        }
        assert!(matches!(
            Caller::from_request_parts(&mut parts(None), &()).await,
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            Caller::from_request_parts(&mut parts(Some(alice)), &()).await,
            Err(AppError::Internal(_))
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
