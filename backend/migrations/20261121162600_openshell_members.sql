-- OpenShell membership sync (docs/openshell.md). An organization can be
-- linked to one OpenShell workspace, and a workspace to one organization.
CREATE UNIQUE INDEX organizations_openshell_workspace
  ON organizations (openshell_workspace)
  WHERE openshell_workspace IS NOT NULL;

-- The members kanbot added to OpenShell workspaces. Sync only ever changes
-- or removes these: members added in OpenShell some other way are left
-- alone. Keyed by workspace, so members of a workspace whose organization
-- was unlinked or deleted are still known and can be removed.
CREATE TABLE openshell_members (
  workspace text NOT NULL,
  subject   text NOT NULL,
  role      text NOT NULL CHECK (role IN ('user', 'admin')),
  PRIMARY KEY (workspace, subject)
);
