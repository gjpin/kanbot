//! Domain types of the `OpenShell` integration.

/// An `OpenShell` workspace's name: 1 to 128 characters, no control
/// characters or whitespace. `OpenShell` checks its own rules.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkspaceName(String);

impl WorkspaceName {
    const MAX_CHARS: usize = 128;

    /// `None` if `raw` cannot be a workspace name.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let valid = !raw.is_empty()
            && raw.chars().count() <= Self::MAX_CHARS
            && !raw.chars().any(|c| c.is_control() || c.is_whitespace());
        valid.then(|| Self(raw.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A member's role in an `OpenShell` workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MemberRole {
    User,
    Admin,
}

impl MemberRole {
    /// The stored form (`openshell_members.role`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
        }
    }

    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "user" => Some(Self::User),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_names() {
        for valid in ["default", "team-a", "a", &"w".repeat(128)] {
            assert_eq!(WorkspaceName::parse(valid).unwrap().as_str(), valid);
        }
        for invalid in ["", "a b", "a\nb", "\t", &"w".repeat(129)] {
            assert_eq!(WorkspaceName::parse(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn roles_round_trip() {
        for role in [MemberRole::User, MemberRole::Admin] {
            assert_eq!(MemberRole::parse(role.as_str()), Some(role));
        }
        assert_eq!(MemberRole::parse("owner"), None);
        assert!(MemberRole::User < MemberRole::Admin);
    }
}
