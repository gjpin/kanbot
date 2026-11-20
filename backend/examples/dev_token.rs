//! Prints an access token for a user of the local Authelia, for `curl`:
//!
//! ```sh
//! cargo run --example dev-token -- alice
//! curl -H "Authorization: Bearer $(cargo run -q --example dev-token -- alice)" \
//!   http://127.0.0.1:3000/me
//! ```
//!
//! DEVELOPMENT ONLY: it signs in with the user's documented dev password
//! (`dev/authelia/users_database.yml`). Needs `sh dev/auth-setup.sh`,
//! `docker compose up -d` and `127.0.0.1 auth.kanbot.internal` in
//! `/etc/hosts`.
#![forbid(unsafe_code)]

#[path = "../tests/common/authelia.rs"]
mod authelia;
#[path = "../tests/common/base64url.rs"]
mod base64url;

use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = std::env::args()
        .nth(1)
        .ok_or("usage: cargo run --example dev-token -- <username>")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let token = runtime.block_on(authelia::access_token(
        &username,
        &authelia::dev_password(&username),
    ))?;
    writeln!(std::io::stdout(), "{token}")?;
    Ok(())
}
