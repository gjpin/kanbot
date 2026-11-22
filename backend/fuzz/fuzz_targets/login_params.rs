//! The sign-in's untrusted parameters (`/auth/login`, `/auth/callback`,
//! `/auth/token`, the session cookie, in one or more Cookie headers): the
//! parsers never panic, and accept only what they promise.
#![no_main]

use axum::http::{HeaderMap, HeaderValue, header};
use kanbot_backend::sessions::{
    SESSION_COOKIE, cookie,
    model::{APP_REDIRECT_URI, AppRedirect, CodeChallenge},
    secrets::{self, LOGIN_CODE, SESSION_TOKEN},
};
use libfuzzer_sys::fuzz_target;

fn base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut parts = text.splitn(5, '\n');
    let redirect = parts.next().unwrap_or_default();
    let challenge = parts.next().unwrap_or_default();
    let secret = parts.next().unwrap_or_default();
    let cookies = parts.next().unwrap_or_default();
    // A second Cookie header (HTTP/2 sends one per cookie).
    let more_cookies = parts.next();

    if let Some(parsed) = AppRedirect::parse(redirect) {
        assert_eq!(parsed.as_str(), redirect);
        if redirect != APP_REDIRECT_URI {
            let port = redirect
                .strip_prefix("http://127.0.0.1:")
                .and_then(|rest| rest.strip_suffix("/auth/done"))
                .expect("only the loopback form remains");
            assert!(port.parse::<u16>().is_ok() && !port.starts_with('0'));
        }
    }

    if let Some(parsed) = CodeChallenge::parse(challenge) {
        assert_eq!(parsed.as_str(), challenge);
        assert!(challenge.len() == 43 && base64url(challenge));
    }

    for prefix in [LOGIN_CODE, SESSION_TOKEN] {
        if let Some(hash) = secrets::presented(prefix, secret) {
            let encoded = secret.strip_prefix(prefix).expect("has the prefix");
            assert!(encoded.len() == 43 && base64url(encoded));
            assert_eq!(hash, secrets::hash(secret));
        }
    }

    if let Ok(value) = HeaderValue::from_str(cookies) {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, value);
        let mut all = cookies.to_owned();
        if let Some(more) = more_cookies.and_then(|more| HeaderValue::from_str(more).ok()) {
            all.push(';');
            all.push_str(more.to_str().unwrap_or_default());
            headers.append(header::COOKIE, more);
        }
        if let Some(found) = cookie(&headers, SESSION_COOKIE) {
            // Exactly one session cookie, in any of the headers.
            let pairs = all
                .split(';')
                .filter_map(|pair| pair.trim().split_once('='))
                .filter(|(name, _)| *name == SESSION_COOKIE);
            assert_eq!(pairs.map(|(_, value)| value).collect::<Vec<_>>(), [found]);
        }
    }
});
