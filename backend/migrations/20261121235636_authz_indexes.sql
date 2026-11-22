-- Maintainers of a team, read by every authorization decision that
-- involves the team (authz::repo::team_facts): without this index a large
-- synced team is scanned in full to find its few maintainers.
CREATE INDEX team_members_maintainers ON team_members (team_id, user_id)
  WHERE role = 'maintainer';

-- Deleting a user checks audit_log's foreign key to it.
CREATE INDEX audit_log_actor_user_id ON audit_log (actor_user_id);
