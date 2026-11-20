//! Any bytes as a bearer token: parsing and validation must never panic,
//! and must refuse everything (no input carries a valid signature).
#![no_main]

mod common;

use std::sync::LazyLock;

use kanbot_backend::auth::{config::OidcConfig, keys::KeySet};
use libfuzzer_sys::fuzz_target;

static KEYS: LazyLock<KeySet> = LazyLock::new(common::keys);
static CONFIG: LazyLock<OidcConfig> = LazyLock::new(common::config);

fuzz_target!(|data: &[u8]| {
    if let Ok(token) = std::str::from_utf8(data) {
        assert!(common::validate(token, &KEYS, &CONFIG).is_err());
    }
});
