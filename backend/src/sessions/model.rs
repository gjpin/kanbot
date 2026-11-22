//! Domain types of the login flow.

use crate::sessions::secrets;

/// The app's application ID, `dev.sideral.kanbot` on every platform. Its
/// private-use URL scheme receives the login handoff on mobile and macOS.
pub const APP_SCHEME: &str = "dev.sideral.kanbot";
/// Where mobile and macOS apps receive their one-time code.
pub const APP_REDIRECT_URI: &str = "dev.sideral.kanbot:/auth/done";
/// Where Windows and Linux apps receive it: `flutter_web_auth_2` listens on
/// `127.0.0.1` (not `localhost`, which may resolve to `::1`).
const LOOPBACK_PREFIX: &str = "http://127.0.0.1:";
const LOOPBACK_PATH: &str = "/auth/done";

/// How long a login attempt may take: its row, and the web login cookie
/// that binds it to the browser.
pub const ATTEMPT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(600);

/// Which app is signing in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// The web app: the session is an `HttpOnly` cookie.
    Web,
    /// A native app: the session token is handed over with a one-time code.
    Native,
}

impl Platform {
    /// The stored form (`login_attempts.platform`, `sessions.kind`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "web" => Some(Self::Web),
            "native" => Some(Self::Native),
            _ => None,
        }
    }
}

/// Where a native app receives its one-time code: [`APP_REDIRECT_URI`], or
/// `http://127.0.0.1:<port>/auth/done` on Windows and Linux. Nothing else,
/// so a code can only go back to the app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppRedirect(String);

impl AppRedirect {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw == APP_REDIRECT_URI {
            return Some(Self(raw.to_owned()));
        }
        let port = raw
            .strip_prefix(LOOPBACK_PREFIX)?
            .strip_suffix(LOOPBACK_PATH)?;
        // Digits only, no leading zero: one spelling per port.
        let valid = !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|b| b.is_ascii_digit())
            && !port.starts_with('0')
            && port.parse::<u16>().is_ok();
        valid.then(|| Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An S256 PKCE challenge (RFC 7636): 43 base64url characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeChallenge(String);

impl CodeChallenge {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        (raw.len() == 43
            && raw
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        .then(|| Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `verifier` is the one this challenge was made from.
    #[must_use]
    pub fn matches(&self, verifier: &secrecy::SecretString) -> bool {
        secrets::pkce_challenge(verifier) == self.0
    }
}

/// What a login is for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginRequest {
    Web,
    Native {
        redirect: AppRedirect,
        challenge: CodeChallenge,
    },
}

impl LoginRequest {
    #[must_use]
    pub const fn platform(&self) -> Platform {
        match self {
            Self::Web => Platform::Web,
            Self::Native { .. } => Platform::Native,
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    #[test]
    fn platforms_have_their_stored_form() {
        for platform in [Platform::Web, Platform::Native] {
            assert_eq!(Platform::parse(platform.as_str()), Some(platform));
        }
        assert_eq!(Platform::parse("Web"), None);
        assert_eq!(Platform::parse("cli"), None);
    }

    #[test]
    fn accepts_only_the_app_redirects() {
        for ok in [
            "dev.sideral.kanbot:/auth/done",
            "http://127.0.0.1:1/auth/done",
            "http://127.0.0.1:43210/auth/done",
            "http://127.0.0.1:65535/auth/done",
        ] {
            assert_eq!(AppRedirect::parse(ok).unwrap().as_str(), ok);
        }
        for bad in [
            "dev.sideral.kanbot:/auth/done?x=1",
            "dev.sideral.kanbot://auth/done",
            "com.example.kanbot:/auth/done",
            "http://localhost:43210/auth/done",
            "http://127.0.0.1/auth/done",
            "http://127.0.0.1:0/auth/done",
            "http://127.0.0.1:065535/auth/done",
            "http://127.0.0.1:65536/auth/done",
            "http://127.0.0.1:443/auth/done/",
            "http://127.0.0.1:443/other",
            "http://127.0.0.1:44a/auth/done",
            "https://127.0.0.1:443/auth/done",
            "http://127.0.0.1:443@evil.example/auth/done",
            "https://evil.example/auth/done",
        ] {
            assert_eq!(AppRedirect::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn code_challenges_are_s256_shaped_and_checked() {
        let verifier = SecretString::from("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        let challenge =
            CodeChallenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").unwrap();
        assert!(challenge.matches(&verifier));
        assert!(!challenge.matches(&SecretString::from("other")));
        for bad in [
            "",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMx",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
        ] {
            assert_eq!(CodeChallenge::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn requests_know_their_platform() {
        assert_eq!(LoginRequest::Web.platform(), Platform::Web);
        let native = LoginRequest::Native {
            redirect: AppRedirect::parse(APP_REDIRECT_URI).unwrap(),
            challenge: CodeChallenge::parse("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").unwrap(),
        };
        assert_eq!(native.platform(), Platform::Native);
    }
}
