-- Wakes the OpenShell membership sync (docs/openshell.md) when what it
-- reads changes, on every instance: NOTIFY reaches all listeners, after the
-- change commits, once per transaction and channel.
CREATE FUNCTION kanbot_openshell_changed() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_notify('kanbot_openshell', '');
  RETURN NULL;
END;
$$;

CREATE TRIGGER openshell_changed AFTER INSERT OR UPDATE OR DELETE ON organization_admins
  FOR EACH STATEMENT EXECUTE FUNCTION kanbot_openshell_changed();
CREATE TRIGGER openshell_changed AFTER INSERT OR UPDATE OR DELETE ON organization_teams
  FOR EACH STATEMENT EXECUTE FUNCTION kanbot_openshell_changed();
CREATE TRIGGER openshell_changed AFTER INSERT OR UPDATE OR DELETE ON team_members
  FOR EACH STATEMENT EXECUTE FUNCTION kanbot_openshell_changed();
CREATE TRIGGER openshell_changed AFTER DELETE OR UPDATE OF openshell_workspace ON organizations
  FOR EACH STATEMENT EXECUTE FUNCTION kanbot_openshell_changed();
-- Not on every sign-in: only what decides membership.
CREATE TRIGGER openshell_changed AFTER UPDATE OF disabled_at, groups, platform_role ON users
  FOR EACH ROW
  WHEN (OLD.disabled_at IS DISTINCT FROM NEW.disabled_at
        OR OLD.groups IS DISTINCT FROM NEW.groups
        OR OLD.platform_role IS DISTINCT FROM NEW.platform_role)
  EXECUTE FUNCTION kanbot_openshell_changed();

-- Workspace names are Kubernetes-style names (DNS-1123 subdomains).
ALTER TABLE organizations ADD CONSTRAINT organizations_openshell_workspace_name CHECK (
  openshell_workspace ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'
);
ALTER TABLE openshell_members ADD CONSTRAINT openshell_members_workspace_name CHECK (
  workspace ~ '^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$'
);
