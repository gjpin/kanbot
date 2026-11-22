//! Shared extractors.

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    auth::middleware::CurrentSession,
    authz::model::{Actor, Via},
    error::AppError,
    http::client_ip::ClientIp,
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

/// The authenticated user as an authorization [`Actor`]: how they
/// authenticated (session cookie, session token or access token) and from
/// which address. `401` without a user.
pub struct Caller(pub Actor);

impl<S: Send + Sync> FromRequestParts<S> for Caller {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        // How this request was authenticated: a web session's token sent as
        // a bearer header is a session token, not the browser's cookie.
        let via = match parts.extensions.get::<CurrentSession>() {
            Some(CurrentSession {
                from_cookie: true, ..
            }) => Via::Web,
            Some(CurrentSession { .. }) => Via::Native,
            None => Via::Bearer,
        };
        let ClientIp(ip) = *parts
            .extensions
            .get::<ClientIp>()
            .ok_or(AppError::Internal("no client address"))?;
        Ok(Self(Actor { user, via, ip }))
    }
}

/// Where the user's own access token is, for a call to another service on
/// their behalf: the one a bearer request presented, or the identity
/// provider token stored with the session. Nothing is read until
/// [`UserAccessToken::get`]. Never log it.
pub enum UserAccessToken {
    Bearer(secrecy::SecretString),
    Session(uuid::Uuid),
}

impl UserAccessToken {
    /// The token; for a session, read from the database and opened.
    ///
    /// # Errors
    ///
    /// [`AppError::Unauthorized`] if the session is gone, or another
    /// [`AppError`].
    pub async fn get(
        self,
        state: &crate::state::AppState,
    ) -> Result<secrecy::SecretString, AppError> {
        match self {
            Self::Bearer(token) => Ok(token),
            Self::Session(id) => {
                crate::sessions::service::stored_access_token(&state.db, &state.sessions, id).await
            }
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for UserAccessToken {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let found = match parts.extensions.get::<CurrentSession>() {
            Some(session) => Some(Self::Session(session.id)),
            None => parts
                .extensions
                .get::<crate::auth::middleware::BearerToken>()
                .map(|bearer| Self::Bearer(bearer.0.clone())),
        };
        std::future::ready(found.ok_or(AppError::Unauthorized))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::Request;

    use super::*;
    use crate::{auth::token::PlatformRole, sessions::model::Platform, users::model::UserId};

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
            groups_claimed: true,
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
            (Some((Platform::Web, true)), Via::Web),
            (Some((Platform::Native, false)), Via::Native),
            // A web session's token in a bearer header is not the cookie.
            (Some((Platform::Web, false)), Via::Native),
        ] {
            let mut parts = parts(Some(alice.clone()));
            parts.extensions.insert(ClientIp(ip));
            if let Some((kind, from_cookie)) = session {
                parts.extensions.insert(CurrentSession {
                    id: uuid::Uuid::new_v4(),
                    kind,
                    from_cookie,
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
}
