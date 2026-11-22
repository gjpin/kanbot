-- A refresh in progress: set by the request that refreshes the session's
-- tokens, so no other one uses the same refresh token, without holding a
-- row lock or a connection while the identity provider answers. A lease
-- that is not cleared (the instance died) runs out.
ALTER TABLE sessions ADD COLUMN refreshing_until timestamptz;

-- Native sessions whose one-time code was never redeemed, for cleanup.
CREATE INDEX sessions_unredeemed ON sessions (created_at) WHERE token_hash IS NULL;
