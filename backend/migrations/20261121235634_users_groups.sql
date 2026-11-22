-- The groups claim (OIDC_GROUPS_CLAIM) of the user's last token that had
-- one. Decisions made without a request, such as the OpenShell membership
-- sync, and requests whose token has no groups claim, use it.
ALTER TABLE users ADD COLUMN groups text[] NOT NULL DEFAULT '{}';
