// Deployer policies for the local stack (AUTHZ_POLICY_FILE in dev.env).
// Forbid only; see docs/authorization.md.

// The dev user dave is in the contractors group.
@id("contractors-read-only")
forbid (principal, action == Kanbot::Action::"write", resource)
when { principal.groups.contains("contractors") };
