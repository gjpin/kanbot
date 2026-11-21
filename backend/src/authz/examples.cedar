// The deployer policy examples of docs/authorization.md, kept identical to
// it. src/authz/policies/tests.rs checks that each one is accepted.
// Not loaded by anything.

// Contractors may read, never write.
@id("contractors-read-only")
forbid (principal, action == Kanbot::Action::"write", resource)
when { principal.groups.contains("contractors") };

// Administration only from the office network, and never with a bare
// access token.
@id("admin-from-the-office")
forbid (
  principal,
  action in [
    Kanbot::Action::"manageOrganizationAdmins",
    Kanbot::Action::"manageTeamLinks",
    Kanbot::Action::"setTeamIdpGroup",
    Kanbot::Action::"deleteOrganization"
  ],
  resource
)
unless { context.ip.isInRange(ip("10.0.0.0/8")) && context.via != "bearer" };

// Scripts (a CI client) may read but change nothing.
@id("ci-reads-only")
forbid (principal, action, resource)
when { principal has clientId && principal.clientId == "kanbot-ci" }
unless { action == Kanbot::Action::"read" };

// Freeze one organization, admins included.
@id("freeze-legacy")
forbid (
  principal,
  action in [Kanbot::Action::"write", Kanbot::Action::"manageTeamLinks"],
  resource == Kanbot::Organization::"6f1c2b8e-9a43-4a57-9d2e-0c6b3f1d2a10"
);
