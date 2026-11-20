//! Writes the API's `OpenAPI` document. Run from `backend/` after changing a
//! route or a request/response type, and commit the result:
//!
//! ```sh
//! cargo run --bin openapi -- openapi.json
//! ```
//!
//! `tests/openapi.rs` fails while the committed document is out of date.
#![forbid(unsafe_code)]

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("usage: openapi <output.json>")]
    Usage,
    #[error("failed to serialize the document")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to write the document")]
    Write(#[from] std::io::Error),
}

fn main() -> Result<(), Error> {
    let mut args = std::env::args_os().skip(1);
    let (Some(path), None) = (args.next(), args.next()) else {
        return Err(Error::Usage);
    };
    let mut json = serde_json::to_string_pretty(&kanbot_backend::http::openapi())?;
    json.push('\n');
    std::fs::write(PathBuf::from(path), json)?;
    Ok(())
}
