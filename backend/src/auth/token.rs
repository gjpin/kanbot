//! Access-token validation: a pure function of the token, its key, the
//! configuration and the current time.
//!
//! [`UnverifiedToken::parse`] checks the token's shape and header and names
//! the key it needs; [`UnverifiedToken::verify`] checks the signature and
//! claims and yields the [`Principal`]. Every failure is a [`Rejection`]
//! with a bounded reason, recorded in a metric and never sent to the
//! client.

use jsonwebtoken::{Algorithm, Validation, errors::ErrorKind};
use serde_json::{Map, Value};

use crate::auth::{
    config::{Issuer, OidcConfig},
    keys::VerifyingKey,
};

/// Largest token accepted, in bytes.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Clock skew allowed for `exp`, `nbf` and `iat`, in seconds.
pub const LEEWAY_SECONDS: u64 = 60;

/// Why a token was refused. [`Rejection::reason`] is the metric attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Malformed,
    TooLarge,
    UnknownKey,
    BadSignature,
    BadAlgorithm,
    Expired,
    NotYetValid,
    WrongIssuer,
    WrongAudience,
    MissingClaim,
    /// Valid, but with neither the user nor the admin role: `403`.
    NoRole,
    ClientNotAllowed,
    /// A kanbot session token that is unknown or expired.
    SessionInvalid,
    /// A kanbot session the identity provider ended (refresh refused).
    SessionEnded,
}

impl Rejection {
    /// A fixed, bounded string for the `reason` metric attribute.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::TooLarge => "too_large",
            Self::UnknownKey => "unknown_key",
            Self::BadSignature => "bad_signature",
            Self::BadAlgorithm => "bad_algorithm",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongAudience => "wrong_audience",
            Self::MissingClaim => "missing_claim",
            Self::NoRole => "no_role",
            Self::ClientNotAllowed => "client_not_allowed",
            Self::SessionInvalid => "session_invalid",
            Self::SessionEnded => "session_ended",
        }
    }
}

/// A user's platform role, from the roles claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformRole {
    Admin,
    User,
}

impl PlatformRole {
    /// The stored form (`users.platform_role`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::User => "user",
        }
    }
}

/// Longest display name kept, in characters; longer ones are cut.
pub const MAX_DISPLAY_NAME_CHARS: usize = 200;

/// Who a valid token speaks for. Its `Debug` leaves out the personal data.
#[derive(Clone, PartialEq, Eq)]
pub struct Principal {
    pub issuer: String,
    /// The value of `OIDC_SUBJECT_CLAIM`.
    pub subject: String,
    pub role: PlatformRole,
    /// `azp`, `client_id` or `cid`, whichever comes first.
    pub client_id: Option<String>,
    /// `name`, else `preferred_username`. Personal data: never log it.
    pub display_name: Option<String>,
    /// The string values of the groups claim (`OIDC_GROUPS_CLAIM`), or
    /// `None` when the token has no such claim (another client, a scope not
    /// requested): then nothing is known about the user's groups, which is
    /// not the same as having none. Personal data: never log it.
    pub groups: Option<Vec<String>>,
    /// The token's `exp`, in seconds since the Unix epoch.
    pub expires_at: u64,
}

impl std::fmt::Debug for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Principal")
            .field("issuer", &self.issuer)
            .field("role", &self.role)
            .field("client_id", &self.client_id)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What a verified token for another service (the `OpenShell` gateway)
/// carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignToken {
    /// Every audience of the token.
    pub audiences: Vec<String>,
    /// The value of `OIDC_SUBJECT_CLAIM`, if any. Personal data in
    /// general: never log it.
    pub subject: Option<String>,
    /// The token's `exp`, in seconds since the Unix epoch.
    pub expires_at: u64,
}

/// What kanbot uses from a verified ID token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdToken {
    pub subject: String,
    /// The `nonce` claim; the caller checks it against the login attempt.
    pub nonce: Option<String>,
}

/// A token whose shape and header are acceptable, not yet verified.
pub struct UnverifiedToken<'a> {
    token: &'a str,
    kid: String,
    algorithm: Algorithm,
}

impl<'a> UnverifiedToken<'a> {
    /// Checks the size, the three base64url segments, and the header: it
    /// must name a `kid` and an asymmetric `alg`, and have no `crit`.
    ///
    /// # Errors
    ///
    /// [`Rejection::TooLarge`], [`Rejection::Malformed`] (also for opaque
    /// tokens and `alg: none`) or [`Rejection::BadAlgorithm`] (`HS*`).
    pub fn parse(token: &'a str) -> Result<Self, Rejection> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(Rejection::TooLarge);
        }
        let segments: Vec<&str> = token.split('.').collect();
        let is_base64url = |segment: &&str| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        if segments.len() != 3 || !segments.iter().all(is_base64url) {
            return Err(Rejection::Malformed);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| Rejection::Malformed)?;
        if header.crit.is_some() || !acceptable_type(header.typ.as_deref()) {
            return Err(Rejection::Malformed);
        }
        let kid = header.kid.ok_or(Rejection::Malformed)?;
        if matches!(
            header.alg,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        ) {
            return Err(Rejection::BadAlgorithm);
        }
        Ok(Self {
            token,
            kid,
            algorithm: header.alg,
        })
    }

    /// The `kid` of the key that must verify this token.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Verifies the signature with `key` and the claims against `config`
    /// at `now` (seconds since the Unix epoch).
    ///
    /// # Errors
    ///
    /// The first [`Rejection`] found, checked in this order: algorithm and
    /// signature, required claims, issuer, audience, times, subject,
    /// roles, client.
    pub fn verify(
        &self,
        key: &VerifyingKey,
        config: &OidcConfig,
        now: u64,
    ) -> Result<Principal, Rejection> {
        if self.algorithm != key.algorithm() {
            return Err(Rejection::BadAlgorithm);
        }
        let mut validation = Validation::new(key.algorithm());
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&[config.issuer.as_str()]);
        validation.set_audience(&[config.audience.as_str()]);
        // Times are checked below against `now`, not the system clock.
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let claims =
            jsonwebtoken::decode::<Map<String, Value>>(self.token, key.decoding_key(), &validation)
                .map_err(|error| rejection(error.kind()))?
                .claims;

        // `iss` must be one string, not an array that contains it.
        if claims.get("iss").and_then(Value::as_str) != Some(config.issuer.as_str()) {
            return Err(Rejection::WrongIssuer);
        }
        let expires_at = check_times(&claims, now)?;

        let subject = config
            .subject_claim
            .resolve(&claims)
            .and_then(Value::as_str)
            .filter(|subject| !subject.is_empty())
            .ok_or(Rejection::MissingClaim)?
            .to_owned();

        let strings = |value: Option<&Value>| match value {
            Some(Value::Array(values)) => Some(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        };
        let roles = strings(config.roles_claim.resolve(&claims)).ok_or(Rejection::NoRole)?;
        let has = |role: &str| roles.iter().any(|candidate| candidate == role);
        let role = if has(config.admin_role.as_str()) {
            PlatformRole::Admin
        } else if has(config.user_role.as_str()) {
            PlatformRole::User
        } else {
            return Err(Rejection::NoRole);
        };

        let client_id = ["azp", "client_id", "cid"]
            .iter()
            .find_map(|claim| {
                claims
                    .get(*claim)
                    .and_then(Value::as_str)
                    .filter(|client| !client.is_empty())
            })
            .map(str::to_owned);
        if let Some(allowed) = &config.allowed_clients
            && !allowed
                .iter()
                .any(|allowed| Some(allowed.as_str()) == client_id.as_deref())
        {
            return Err(Rejection::ClientNotAllowed);
        }

        let display_name = ["name", "preferred_username"]
            .iter()
            .find_map(|claim| claims.get(*claim).and_then(Value::as_str))
            .filter(|name| !name.is_empty() && !name.contains('\0'))
            .map(|name| name.chars().take(MAX_DISPLAY_NAME_CHARS).collect());

        // Optional. A group the database cannot store (NUL) cannot name a
        // team either.
        let groups = strings(config.groups_claim.resolve(&claims)).map(|groups| {
            groups
                .into_iter()
                .filter(|group| !group.contains('\0'))
                .collect()
        });

        Ok(Principal {
            issuer: config.issuer.as_str().to_owned(),
            subject,
            role,
            client_id,
            display_name,
            groups,
            expires_at,
        })
    }
}

impl UnverifiedToken<'_> {
    /// Verifies an ID token from the login flow (`OpenID` Connect Core,
    /// section 3.1.3.7): the signature with `key`, `iss` exactly `issuer`,
    /// `aud` containing `client_id`, `azp` equal to `client_id` when present
    /// (and required with several audiences), and the times at `now`.
    ///
    /// # Errors
    ///
    /// The first [`Rejection`] found.
    pub fn verify_id_token(
        &self,
        key: &VerifyingKey,
        issuer: &Issuer,
        client_id: &str,
        now: u64,
    ) -> Result<IdToken, Rejection> {
        if self.algorithm != key.algorithm() {
            return Err(Rejection::BadAlgorithm);
        }
        let mut validation = Validation::new(key.algorithm());
        // `iat` is required in ID tokens (OpenID Connect Core, section 2).
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.set_issuer(&[issuer.as_str()]);
        validation.set_audience(&[client_id]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let claims =
            jsonwebtoken::decode::<Map<String, Value>>(self.token, key.decoding_key(), &validation)
                .map_err(|error| rejection(error.kind()))?
                .claims;
        if claims.get("iss").and_then(Value::as_str) != Some(issuer.as_str()) {
            return Err(Rejection::WrongIssuer);
        }
        check_times(&claims, now)?;
        let several_audiences =
            matches!(claims.get("aud"), Some(Value::Array(audiences)) if audiences.len() > 1);
        match claims.get("azp") {
            Some(azp) if azp.as_str() != Some(client_id) => return Err(Rejection::WrongAudience),
            None if several_audiences => return Err(Rejection::WrongAudience),
            _ => {}
        }
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .filter(|subject| !subject.is_empty())
            .ok_or(Rejection::MissingClaim)?
            .to_owned();
        Ok(IdToken {
            subject,
            nonce: claims
                .get("nonce")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }
}

impl UnverifiedToken<'_> {
    /// Verifies a token kanbot obtained for another service: the signature
    /// with `key`, `iss` exactly `issuer`, `aud` containing `audience`, and
    /// the times at `now`. Nothing about kanbot's own audience or roles:
    /// the caller decides what else it needs.
    ///
    /// # Errors
    ///
    /// The first [`Rejection`] found.
    pub fn verify_foreign(
        &self,
        key: &VerifyingKey,
        config: &OidcConfig,
        audience: &str,
        now: u64,
    ) -> Result<ForeignToken, Rejection> {
        if self.algorithm != key.algorithm() {
            return Err(Rejection::BadAlgorithm);
        }
        let mut validation = Validation::new(key.algorithm());
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[config.issuer.as_str()]);
        validation.set_audience(&[audience]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        let claims =
            jsonwebtoken::decode::<Map<String, Value>>(self.token, key.decoding_key(), &validation)
                .map_err(|error| rejection(error.kind()))?
                .claims;
        if claims.get("iss").and_then(Value::as_str) != Some(config.issuer.as_str()) {
            return Err(Rejection::WrongIssuer);
        }
        let expires_at = check_times(&claims, now)?;
        let audiences = match claims.get("aud") {
            Some(Value::String(one)) => vec![one.clone()],
            Some(Value::Array(many)) => many
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            _ => return Err(Rejection::WrongAudience),
        };
        let subject = config
            .subject_claim
            .resolve(&claims)
            .and_then(Value::as_str)
            .filter(|subject| !subject.is_empty())
            .map(str::to_owned);
        Ok(ForeignToken {
            audiences,
            subject,
            expires_at,
        })
    }
}

/// The header's `typ`: absent, or one that names a JWT access or ID token
/// (RFC 7519, RFC 9068), in any case. Other typed JWTs, such as logout
/// tokens, `DPoP` proofs or security events, are not tokens kanbot accepts.
fn acceptable_type(typ: Option<&str>) -> bool {
    typ.is_none_or(|typ| {
        ["jwt", "at+jwt", "application/jwt", "application/at+jwt"]
            .iter()
            .any(|allowed| typ.eq_ignore_ascii_case(allowed))
    })
}

/// `exp` must not be past, `nbf` and `iat` (when present) not in the
/// future, each with [`LEEWAY_SECONDS`]. Returns `exp`.
fn check_times(claims: &Map<String, Value>, now: u64) -> Result<u64, Rejection> {
    let time = |claim: &str| -> Result<Option<u64>, Rejection> {
        claims
            .get(claim)
            .map(|value| value.as_u64().ok_or(Rejection::Malformed))
            .transpose()
    };
    let exp = time("exp")?.ok_or(Rejection::MissingClaim)?;
    if exp.saturating_add(LEEWAY_SECONDS) < now {
        return Err(Rejection::Expired);
    }
    let latest = now.saturating_add(LEEWAY_SECONDS);
    if time("nbf")?.is_some_and(|nbf| nbf > latest) || time("iat")?.is_some_and(|iat| iat > latest)
    {
        return Err(Rejection::NotYetValid);
    }
    Ok(exp)
}

fn rejection(kind: &ErrorKind) -> Rejection {
    match kind {
        ErrorKind::InvalidSignature
        | ErrorKind::InvalidEcdsaKey
        | ErrorKind::InvalidEddsaKey
        | ErrorKind::InvalidRsaKey(_) => Rejection::BadSignature,
        ErrorKind::InvalidAlgorithm
        | ErrorKind::InvalidAlgorithmName
        | ErrorKind::UnsupportedAlgorithm
        | ErrorKind::MissingAlgorithm => Rejection::BadAlgorithm,
        ErrorKind::MissingRequiredClaim(_) => Rejection::MissingClaim,
        ErrorKind::InvalidIssuer => Rejection::WrongIssuer,
        ErrorKind::InvalidClaimFormat(claim) if claim == "iss" => Rejection::WrongIssuer,
        ErrorKind::InvalidAudience => Rejection::WrongAudience,
        ErrorKind::InvalidClaimFormat(claim) if claim == "aud" => Rejection::WrongAudience,
        ErrorKind::ExpiredSignature => Rejection::Expired,
        ErrorKind::ImmatureSignature => Rejection::NotYetValid,
        _ => Rejection::Malformed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_are_the_documented_metric_values() {
        let all = [
            (Rejection::Malformed, "malformed"),
            (Rejection::TooLarge, "too_large"),
            (Rejection::UnknownKey, "unknown_key"),
            (Rejection::BadSignature, "bad_signature"),
            (Rejection::BadAlgorithm, "bad_algorithm"),
            (Rejection::Expired, "expired"),
            (Rejection::NotYetValid, "not_yet_valid"),
            (Rejection::WrongIssuer, "wrong_issuer"),
            (Rejection::WrongAudience, "wrong_audience"),
            (Rejection::MissingClaim, "missing_claim"),
            (Rejection::NoRole, "no_role"),
            (Rejection::ClientNotAllowed, "client_not_allowed"),
            (Rejection::SessionInvalid, "session_invalid"),
            (Rejection::SessionEnded, "session_ended"),
        ];
        for (rejection, reason) in all {
            assert_eq!(rejection.reason(), reason);
        }
    }

    #[test]
    fn roles_have_their_stored_form() {
        assert_eq!(PlatformRole::Admin.as_str(), "admin");
        assert_eq!(PlatformRole::User.as_str(), "user");
    }

    #[test]
    fn maps_library_errors_to_reasons() {
        for (kind, expected) in [
            (ErrorKind::InvalidSignature, Rejection::BadSignature),
            (ErrorKind::InvalidEcdsaKey, Rejection::BadSignature),
            (ErrorKind::InvalidEddsaKey, Rejection::BadSignature),
            (
                ErrorKind::InvalidRsaKey(String::new()),
                Rejection::BadSignature,
            ),
            (ErrorKind::InvalidAlgorithm, Rejection::BadAlgorithm),
            (ErrorKind::InvalidAlgorithmName, Rejection::BadAlgorithm),
            (ErrorKind::UnsupportedAlgorithm, Rejection::BadAlgorithm),
            (ErrorKind::MissingAlgorithm, Rejection::BadAlgorithm),
            (
                ErrorKind::MissingRequiredClaim("exp".into()),
                Rejection::MissingClaim,
            ),
            (ErrorKind::InvalidIssuer, Rejection::WrongIssuer),
            (
                ErrorKind::InvalidClaimFormat("iss".into()),
                Rejection::WrongIssuer,
            ),
            (ErrorKind::InvalidAudience, Rejection::WrongAudience),
            (
                ErrorKind::InvalidClaimFormat("aud".into()),
                Rejection::WrongAudience,
            ),
            (
                ErrorKind::InvalidClaimFormat("sub".into()),
                Rejection::Malformed,
            ),
            (ErrorKind::ExpiredSignature, Rejection::Expired),
            (ErrorKind::ImmatureSignature, Rejection::NotYetValid),
            (ErrorKind::InvalidToken, Rejection::Malformed),
        ] {
            assert_eq!(rejection(&kind), expected, "{kind:?}");
        }
    }

    #[test]
    fn checks_times_with_leeway() {
        use serde_json::json;
        let check = |claims: Value| check_times(claims.as_object().unwrap(), 1_000_000);
        assert_eq!(check(json!({ "exp": 1_000_000 })), Ok(1_000_000));
        assert_eq!(check(json!({ "exp": 999_940 })), Ok(999_940));
        assert_eq!(check(json!({ "exp": 999_939 })), Err(Rejection::Expired));
        assert_eq!(
            check(json!({ "exp": 1_000_000, "nbf": 1_000_060 })),
            Ok(1_000_000)
        );
        assert_eq!(
            check(json!({ "exp": 1_000_000, "nbf": 1_000_061 })),
            Err(Rejection::NotYetValid)
        );
        assert_eq!(
            check(json!({ "exp": 1_000_000, "iat": 1_000_060 })),
            Ok(1_000_000)
        );
        assert_eq!(
            check(json!({ "exp": 1_000_000, "iat": 1_000_061 })),
            Err(Rejection::NotYetValid)
        );
        assert_eq!(check(json!({})), Err(Rejection::MissingClaim));
        assert_eq!(check(json!({ "exp": "soon" })), Err(Rejection::Malformed));
        assert_eq!(check(json!({ "exp": 1.5 })), Err(Rejection::Malformed));
        assert_eq!(
            check(json!({ "exp": 1_000_000, "nbf": -1 })),
            Err(Rejection::Malformed)
        );
        assert_eq!(
            check(json!({ "exp": 1_000_000, "iat": "now" })),
            Err(Rejection::Malformed)
        );
    }
}
