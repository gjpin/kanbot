//! Prints an access token for a user of the local Authelia, for `curl`:
//!
//! ```sh
//! cargo run --example dev-token -- alice
//! curl -H "Authorization: Bearer $(cargo run -q --example dev-token -- alice)" \
//!   http://127.0.0.1:3000/me
//! ```
//!
//! With `--sign-in <kanbot login URL>`, it plays the system browser for a
//! native app's sign-in instead: it opens kanbot's `/auth/login` URL, signs
//! the user in at Authelia, and delivers the one-time code to the app's
//! loopback redirect (Windows and Linux). The frontend's Linux end-to-end
//! test registers it as the default browser
//! (`frontend/integration_test/README.md`):
//!
//! ```sh
//! cargo run --example dev-token -- alice --sign-in 'http://localhost:3000/auth/login?platform=native&...'
//! ```
//!
//! DEVELOPMENT ONLY: it signs in with the user's documented dev password
//! (`dev/authelia/users_database.yml`). Needs `sh dev/auth-setup.sh`,
//! `docker compose up -d` and `127.0.0.1 auth.kanbot.internal` in
//! `/etc/hosts`; `--sign-in` also needs the backend running with
//! `dev/dev.env`.
#![forbid(unsafe_code)]

#[path = "../tests/common/authelia.rs"]
mod authelia;
#[path = "../tests/common/base64url.rs"]
mod base64url;

use std::{io::Write, time::Duration};

use reqwest::{Client, Response, Url, header, redirect};

const USAGE: &str =
    "usage: cargo run --example dev-token -- <username> [--sign-in <kanbot login URL>]";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let username = args.next().ok_or(USAGE)?;
    let sign_in_url = match args.next().as_deref() {
        None => None,
        Some("--sign-in") => Some(Url::parse(&args.next().ok_or(USAGE)?)?),
        Some(_) => return Err(USAGE.into()),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if let Some(url) = sign_in_url {
        return runtime.block_on(sign_in(&username, url));
    }
    let token = runtime.block_on(authelia::access_token(
        &username,
        &authelia::dev_password(&username),
    ))?;
    writeln!(std::io::stdout(), "{token}")?;
    Ok(())
}

/// Where a redirect response points.
fn location(response: &Response) -> Result<Url, Box<dyn std::error::Error>> {
    if !response.status().is_redirection() {
        return Err(format!("expected a redirect, got {}", response.status()).into());
    }
    let target = response
        .headers()
        .get(header::LOCATION)
        .ok_or("redirect without Location")?
        .to_str()?;
    Ok(response.url().join(target)?)
}

/// Follows a native sign-in from kanbot's `/auth/login` to the app.
async fn sign_in(username: &str, login: Url) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder()
        .redirect(redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    // kanbot sends the browser to the identity provider...
    let authorization = location(&client.get(login).send().await?)?;
    // ...where the user signs in and consents...
    let callback =
        authelia::authorize(username, &authelia::dev_password(username), authorization).await?;
    // ...then kanbot hands the app its one-time code.
    let app = location(&client.get(callback).send().await?)?;
    if app.host_str() != Some("127.0.0.1") {
        return Err(format!(
            "not a loopback redirect: {}",
            app.origin().ascii_serialization()
        )
        .into());
    }
    // The app answers its own loopback redirect: an error there would
    // otherwise only show as the app never signing in.
    client.get(app).send().await?.error_for_status()?;
    Ok(())
}
