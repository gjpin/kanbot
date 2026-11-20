//! Handlers of the `/auth` routes. They are public: they are how a user
//! gets credentials in the first place.

use axum::{
    extract::{Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Redirect, Response},
};
use secrecy::ExposeSecret;

use crate::{
    error::AppError,
    http::problem::Problem,
    sessions::{dto::LoginQuery, model::LoginRequest, service},
    state::AppState,
};

/// Binds a web login attempt to the browser that started it.
pub const LOGIN_COOKIE: &str = "__Host-kanbot_login";

/// Starts a sign-in: redirects the browser to the identity provider.
///
/// The web app navigates here; native apps open it in the system browser
/// with their redirect URI and PKCE challenge.
#[utoipa::path(
    get,
    path = "/auth/login",
    tag = "auth",
    params(LoginQuery),
    responses(
        (status = SEE_OTHER, description = "To the identity provider's sign-in page.",
         headers(("Location" = String, description = "The authorization URL."))),
        (status = BAD_REQUEST, description = "Unknown or malformed parameters.",
         body = Problem, content_type = "application/problem+json"),
        (status = UNPROCESSABLE_ENTITY, description = "Parameters that do not fit the platform, or a redirect URI that is not the app's.",
         body = Problem, content_type = "application/problem+json"),
        (status = SERVICE_UNAVAILABLE, description = "The identity provider has not been discovered yet.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let request = LoginRequest::try_from(query)?;
    let start = service::start_login(&state.db, &state.keys, &state.sessions, &request).await?;
    let mut response = Redirect::to(start.authorization_url.as_str()).into_response();
    if let Some(binding) = start.browser_binding {
        let cookie = format!(
            "{LOGIN_COOKIE}={}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax",
            binding.expose_secret()
        );
        let cookie = HeaderValue::from_str(&cookie).map_err(|_| AppError::Internal("cookie"))?;
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}
