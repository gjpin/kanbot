//! Domain types of the `OpenShell` integration.

/// An `OpenShell` workspace's name. Workspaces have Kubernetes-style
/// names: a DNS-1123 subdomain, 1 to 253 lowercase letters, digits, `-`
/// and `.`, starting and ending with a letter or digit. The database
/// checks the same.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct WorkspaceName(String);

impl WorkspaceName {
    const MAX_CHARS: usize = 253;

    /// `None` if `raw` cannot be a workspace name.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
        let valid = !raw.is_empty()
            && raw.len() <= Self::MAX_CHARS
            && raw.chars().all(|c| alphanumeric(c) || c == '-' || c == '.')
            && raw.starts_with(alphanumeric)
            && raw.ends_with(alphanumeric);
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
        for valid in ["default", "team-a", "a", "a.b-2", "0", &"w".repeat(253)] {
            assert_eq!(WorkspaceName::parse(valid).unwrap().as_str(), valid);
        }
        for invalid in [
            "",
            "a b",
            "a\nb",
            "\t",
            "Team",
            "a/b",
            "a\\b",
            "..",
            "-a",
            "a-",
            ".a",
            "é",
            "a\u{200b}b",
            &"w".repeat(254),
        ] {
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
