-- Authorization (docs/authorization.md): organizations, instance-wide teams,
-- the links that give teams read or write access to organizations, and the
-- audit log of changes to them. Cedar decides; these tables are its data.

-- Kanbot's features belong to an organization.
CREATE TABLE organizations (
  id                  uuid PRIMARY KEY,
  slug                text NOT NULL UNIQUE
                      CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  name                text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  -- The linked OpenShell workspace (phase 7 of docs/plan/auth.md).
  openshell_workspace text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Users who manage an organization: its settings, admins and team links.
CREATE TABLE organization_admins (
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  user_id         uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX organization_admins_user_id ON organization_admins (user_id);

-- Teams belong to the instance, not to an organization. With idp_group set,
-- the members are the users whose groups claim contains it.
CREATE TABLE teams (
  id         uuid PRIMARY KEY,
  slug       text NOT NULL UNIQUE
             CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  idp_group  text UNIQUE CHECK (char_length(idp_group) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- manual: added through the API. idp: added by the group sync, read-only.
CREATE TABLE team_members (
  team_id uuid NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  role    text NOT NULL CHECK (role IN ('member', 'maintainer')),
  source  text NOT NULL CHECK (source IN ('manual', 'idp')),
  PRIMARY KEY (team_id, user_id)
);
CREATE INDEX team_members_user_id ON team_members (user_id);

-- A team's access to an organization. write implies read.
CREATE TABLE organization_teams (
  organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
  team_id         uuid NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
  access          text NOT NULL CHECK (access IN ('read', 'write')),
  PRIMARY KEY (organization_id, team_id)
);
CREATE INDEX organization_teams_team_id ON organization_teams (team_id);

-- Who changed what, and which policies allowed it. details holds IDs and
-- enumerated values only: never names or other personal data.
CREATE TABLE audit_log (
  id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  at            timestamptz NOT NULL DEFAULT now(),
  actor_user_id uuid NOT NULL REFERENCES users (id),
  action        text NOT NULL,
  target_type   text NOT NULL CHECK (target_type IN ('organization', 'team')),
  target_id     uuid NOT NULL,
  policy_ids    text[] NOT NULL,
  details       jsonb NOT NULL DEFAULT '{}'
);

-- So a single-user instance never has to think about organizations.
INSERT INTO organizations (id, slug, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default');
