//! The slugs and names of organizations and teams.

use crate::error::FieldError;

/// Collects `result`'s error as a field error at `pointer` in `errors`.
/// `Some(value)` if `result` is valid.
pub fn checked<T>(
    errors: &mut Vec<FieldError>,
    pointer: &'static str,
    result: Result<T, NameError>,
) -> Option<T> {
    result
        .map_err(|error| errors.push(FieldError::new(pointer, error.code())))
        .ok()
}

/// A URL-safe identifier: 1 to 63 lowercase ASCII letters, digits and
/// hyphens, not starting or ending with a hyphen. Unique per kind.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Slug(String);

/// Why a slug or name was refused, as a field error code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameError {
    Required,
    TooLong,
    Invalid,
}

impl NameError {
    /// The field error code (`required`, `too_long`, `invalid`).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::TooLong => "too_long",
            Self::Invalid => "invalid",
        }
    }
}

const MAX_SLUG_CHARS: usize = 63;
const MAX_NAME_CHARS: usize = 200;

impl Slug {
    /// # Errors
    ///
    /// [`NameError`] if `raw` is not a slug.
    pub fn parse(raw: &str) -> Result<Self, NameError> {
        if raw.is_empty() {
            return Err(NameError::Required);
        }
        // Characters first: a long slug of other characters is invalid, not
        // just too long.
        let allowed = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
        if !raw.bytes().all(allowed) || raw.starts_with('-') || raw.ends_with('-') {
            return Err(NameError::Invalid);
        }
        if raw.len() > MAX_SLUG_CHARS {
            return Err(NameError::TooLong);
        }
        Ok(Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// A display name: 1 to 200 characters after trimming, without control
/// characters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name(String);

impl Name {
    /// Trims `raw`, then validates it.
    ///
    /// # Errors
    ///
    /// [`NameError`] if `raw` is not a name.
    pub fn parse(raw: &str) -> Result<Self, NameError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(NameError::Required);
        }
        if trimmed.chars().count() > MAX_NAME_CHARS {
            return Err(NameError::TooLong);
        }
        if trimmed.chars().any(char::is_control) {
            return Err(NameError::Invalid);
        }
        Ok(Self(trimmed.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn slugs() {
        for valid in ["a", "a-b", "0", "team-42", &"a".repeat(63)] {
            assert_eq!(Slug::parse(valid).unwrap().as_str(), valid);
        }
        let long = "a".repeat(64);
        let long_and_wrong = "é".repeat(40);
        for (invalid, error) in [
            ("", NameError::Required),
            (long.as_str(), NameError::TooLong),
            (long_and_wrong.as_str(), NameError::Invalid),
            ("-a", NameError::Invalid),
            ("a-", NameError::Invalid),
            ("A", NameError::Invalid),
            ("a_b", NameError::Invalid),
            ("a b", NameError::Invalid),
            ("é", NameError::Invalid),
        ] {
            assert_eq!(Slug::parse(invalid), Err(error), "{invalid:?}");
        }
    }

    #[test]
    fn names() {
        assert_eq!(
            Name::parse("  Platform team ").unwrap().as_str(),
            "Platform team"
        );
        assert_eq!(
            Name::parse(&"é".repeat(200)).unwrap().as_str(),
            "é".repeat(200)
        );
        assert_eq!(Name::parse(" \t"), Err(NameError::Required));
        assert_eq!(Name::parse(&"n".repeat(201)), Err(NameError::TooLong));
        assert_eq!(Name::parse("a\u{0}b"), Err(NameError::Invalid));
        assert_eq!(Name::parse("a\nb"), Err(NameError::Invalid));
    }

    #[test]
    fn checked_collects_field_errors() {
        let mut errors = Vec::new();
        assert_eq!(
            checked(&mut errors, "/slug", Slug::parse("ok")),
            Some(Slug::parse("ok").unwrap())
        );
        assert_eq!(checked(&mut errors, "/slug", Slug::parse("-")), None);
        assert_eq!(checked(&mut errors, "/name", Name::parse("")), None);
        assert_eq!(
            errors,
            [
                FieldError::new("/slug", "invalid"),
                FieldError::new("/name", "required")
            ]
        );
    }

    #[test]
    fn error_codes() {
        assert_eq!(NameError::Required.code(), "required");
        assert_eq!(NameError::TooLong.code(), "too_long");
        assert_eq!(NameError::Invalid.code(), "invalid");
    }

    proptest! {
        #[test]
        fn slugs_match_the_database_check(raw in "[a-z0-9-]{0,70}|\\PC{0,10}") {
            // migrations/…_organizations.sql: ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$
            let bytes = raw.as_bytes();
            let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
            let expected = (1..=63).contains(&bytes.len())
                && edge(bytes.first())
                && edge(bytes.last())
                && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
            prop_assert_eq!(Slug::parse(&raw).is_ok(), expected);
        }
    }
}
