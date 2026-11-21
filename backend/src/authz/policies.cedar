// Kanbot's built-in policies: every grant. Deployers may add forbid policies
// only (AUTHZ_POLICY_FILE), so nothing outside this file can widen access.
// Each policy's @id becomes its policy ID "builtin.<id>" in the audit log.

@id("platform-admins")
permit (principal, action, resource)
when { principal.platformRole == "admin" };

@id("organization-admins")
permit (
  principal,
  action in [
    Kanbot::Action::"read",
    Kanbot::Action::"write",
    Kanbot::Action::"manageOrganization",
    Kanbot::Action::"manageOrganizationAdmins",
    Kanbot::Action::"manageTeamLinks"
  ],
  resource is Kanbot::Organization
)
when { resource.admins.contains(principal) };

@id("organization-readers")
permit (principal, action == Kanbot::Action::"read", resource is Kanbot::Organization)
when { principal in resource.readers };

@id("organization-writers")
permit (principal, action == Kanbot::Action::"write", resource is Kanbot::Organization)
when { principal in resource.writers };

@id("team-maintainers")
permit (
  principal,
  action in [Kanbot::Action::"manageTeam", Kanbot::Action::"manageTeamMembers"],
  resource is Kanbot::Team
)
when { resource.maintainers.contains(principal) };

// Members see their teams. Organization admins see every team, to link
// them to their organization.
@id("team-viewers")
permit (principal, action == Kanbot::Action::"viewTeam", resource is Kanbot::Team)
when { principal in resource || principal.organizationAdmin };

@id("team-creators")
permit (principal, action == Kanbot::Action::"createTeam", resource is Kanbot::Platform)
when { principal.organizationAdmin };

// To add admins or members, organization admins and team maintainers
// find users by name.
@id("user-searchers")
permit (principal, action == Kanbot::Action::"searchUsers", resource is Kanbot::Platform)
when { principal.organizationAdmin || principal.teamMaintainer };
