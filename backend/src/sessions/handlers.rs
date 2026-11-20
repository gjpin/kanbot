//! Handlers of the `/auth` routes. They are public: they are how a user
//! gets credentials in the first place.

use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Redirect, Response},
};
use reqwest::Url;
use secrecy::ExposeSecret;

use crate::{
    error::AppError,
    http::problem::Problem,
    sessions::{
        dto::LoginQuery,
        model::LoginRequest,
        service::{self, CallbackParams, Destination, LoginOutcome},
    },
    state::AppState,
};

/// Binds a web login attempt to the browser that started it.
pub const LOGIN_COOKIE: &str = "__Host-kanbot_login";
/// The web app's session.
pub const SESSION_COOKIE: &str = "__Host-kanbot_session";

/// The value of cookie `name` in the request, if exactly one is sent.
#[must_use]
pub fn cookie<'h>(headers: &'h HeaderMap, name: &str) -> Option<&'h str> {
    let mut values = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .filter(|(key, _)| *key == name)
        .map(|(_, value)| value);
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

/// A `Set-Cookie` header value for a `__Host-` cookie: `Secure`,
/// `HttpOnly`, `Path=/`, no `Domain`.
fn set_cookie(
    name: &str,
    value: &str,
    max_age_seconds: u64,
    same_site: &str,
) -> Result<HeaderValue, AppError> {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Max-Age={max_age_seconds}; HttpOnly; Secure; SameSite={same_site}"
    ))
    .map_err(|_| AppError::Internal("cookie"))
}

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
        // Lax: it must come back on the IdP's redirect to the callback.
        let cookie = set_cookie(LOGIN_COOKIE, binding.expose_secret(), 600, "Lax")?;
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(response)
}

/// Where the identity provider sends the browser back. Finishes the
/// sign-in and redirects to the app: the web app with its session cookie
/// (to `/`, or `/login?error=...`), a native app with a one-time code
/// (`<redirect_uri>?code=...`, or `?error=...`). The `error` is
/// `access_denied`, `login_failed` or `no_role`, never more.
#[utoipa::path(
    get,
    path = "/auth/callback",
    tag = "auth",
    params(
        ("state" = Option<String>, Query, description = "The state sent with the authorization request."),
        ("code" = Option<String>, Query, description = "The authorization code."),
        ("error" = Option<String>, Query, description = "The identity provider's error, instead of a code."),
    ),
    responses(
        (status = SEE_OTHER, description = "To the app, with the outcome.",
         headers(("Location" = String, description = "The app."))),
        (status = INTERNAL_SERVER_ERROR, description = "A server failure.",
         body = Problem, content_type = "application/problem+json"),
        (status = SERVICE_UNAVAILABLE, description = "The database is unavailable.",
         body = Problem, content_type = "application/problem+json"),
    ),
)]
pub(super) async fn callback(
    State(state): State<AppState>,
    // Not a typed struct: identity providers add their own parameters
    // (`iss`, `scope`, `session_state`), which are ignored.
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let params = CallbackParams {
        state: query.get("state").map(String::as_str),
        code: query.get("code").map(String::as_str),
        error: query.get("error").map(String::as_str),
    };
    let outcome = service::finish_login(
        &state.db,
        &state.keys,
        &state.sessions,
        &params,
        cookie(&headers, LOGIN_COOKIE),
    )
    .await?;
    let config = &state.sessions;
    let mut response = match &outcome {
        LoginOutcome::WebSession { .. } => Redirect::to(&config.public_url.join("")),
        LoginOutcome::NativeCode { redirect, code } => {
            Redirect::to(&with_query(redirect, "code", code.expose_secret())?)
        }
        LoginOutcome::Failed { destination, error } => match destination {
            Destination::Web => Redirect::to(&with_query(
                &config.public_url.join("login"),
                "error",
                error.as_str(),
            )?),
            Destination::App(redirect) => {
                Redirect::to(&with_query(redirect, "error", error.as_str())?)
            }
        },
    }
    .into_response();
    let headers = response.headers_mut();
    if let LoginOutcome::WebSession { token } = &outcome {
        headers.append(
            header::SET_COOKIE,
            set_cookie(
                SESSION_COOKIE,
                token.expose_secret(),
                config.absolute_timeout.as_secs(),
                "Strict",
            )?,
        );
    }
    // The login cookie has done its job, whatever the outcome.
    headers.append(header::SET_COOKIE, set_cookie(LOGIN_COOKIE, "", 0, "Lax")?);
    Ok(response)
}

/// `base` with `name=value` added to its query.
fn with_query(base: &str, name: &str, value: &str) -> Result<String, AppError> {
    let mut url = Url::parse(base).map_err(|_| AppError::Internal("redirect URI"))?;
    url.query_pairs_mut().append_pair(name, value);
    Ok(url.to_string())
}
