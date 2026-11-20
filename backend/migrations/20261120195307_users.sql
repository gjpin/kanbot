-- Users who have signed in at the OIDC identity provider. A user is the
-- pair (issuer, subject); kanbot has no accounts of its own.
CREATE TABLE users (
  id               uuid PRIMARY KEY,
  issuer           text NOT NULL,
  subject          text NOT NULL,
  display_name     text,
  platform_role    text NOT NULL CHECK (platform_role IN ('admin', 'user')),
  telemetry_opt_in boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  disabled_at      timestamptz,
  UNIQUE (issuer, subject)
);
